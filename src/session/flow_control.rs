use super::ClientSession;
use crate::abr::AbrStatusSnapshot;
use crate::config::WebScreenMode;
use crate::platform::{CaptureHandle, EncodedFrame, FrameReceiver, FrameSender, FrameWaker};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Instant;
use tracing::{debug, info};


#[derive(Default)]
struct RttTracker {
    /// Bounded FIFO of send timestamps (ms since `epoch`) for in-flight frames so pipelined
    /// sends (`in_flight >= 2`) match each ACK against the oldest in-flight frame instead of the
    /// most recently transmitted frame (prevents Uniform[0, 16.7ms] RTT aliasing at 60fps).
    send_times_ms: VecDeque<u64>,
    ewma_rtt_ms_x10: Option<u64>,
    /// Timestamp (ms since `epoch`) of the most recent EWMA update so stale samples expire
    /// instead of freezing ABR on an old congestion spike.
    last_rtt_sample_ms: Option<u64>,
}

const MAX_RTT_TIMESTAMP_QUEUE: usize = 16;
const RTT_STALE_EXPIRY_MS: u64 = 3000;

/// Client-ACK backpressure controller (`FrameReceived` / `PictureRendered`).
///
/// Only strictly throttles once the client has actually sent at least one ACK (so older
/// clients that don't emit ACKs are never stalled), avoids double-counting clients that emit
/// both `FrameReceived` and `PictureRendered`, wakes the streaming thread immediately on ACK,
/// and includes a 120ms safety probe so packet loss never deadlocks the stream.
pub struct FlowControl {
    max_in_flight: AtomicU32,
    in_flight: AtomicU32,
    acked_ever: AtomicBool,
    seen_picture_rendered: AtomicBool,
    epoch: Instant,
    last_sent_ms: AtomicU64,
    last_ack_ms: AtomicU64,
    rtt: Mutex<RttTracker>,
    dropped_frames: AtomicU64,
    waker: Mutex<Option<(u64, FrameWaker)>>,
}

impl FlowControl {
    pub fn new(max_in_flight: u32) -> Self {
        Self {
            max_in_flight: AtomicU32::new(max_in_flight),
            in_flight: AtomicU32::new(0),
            acked_ever: AtomicBool::new(false),
            seen_picture_rendered: AtomicBool::new(false),
            epoch: Instant::now(),
            last_sent_ms: AtomicU64::new(0),
            last_ack_ms: AtomicU64::new(0),
            rtt: Mutex::new(RttTracker::default()),
            dropped_frames: AtomicU64::new(0),
            waker: Mutex::new(None),
        }
    }

    pub fn set_waker_for_gen(&self, gen: u64, waker: FrameWaker) {
        if let Ok(mut g) = self.waker.lock() {
            *g = Some((gen, waker));
        }
    }

    pub fn clear_waker_if_gen(&self, gen: u64) {
        if let Ok(mut g) = self.waker.lock() {
            if g.as_ref().map(|(cur_gen, _)| *cur_gen) == Some(gen) {
                *g = None;
            }
        }
    }

    pub(super) fn wake_streamer(&self) {
        if let Ok(g) = self.waker.lock() {
            if let Some((_, ref w)) = *g {
                w.wake();
            }
        }
    }

    pub fn set_max_in_flight(&self, max_in_flight: u32) {
        self.max_in_flight.store(max_in_flight, Ordering::Relaxed);
        self.wake_streamer();
    }

    pub fn max_in_flight(&self) -> u32 {
        self.max_in_flight.load(Ordering::Relaxed)
    }

    fn elapsed_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    /// Returns `true` if a new frame may be sent now, or `false` if it should wait for backpressure.
    pub fn try_acquire_send(&self) -> bool {
        self.try_acquire_send_at(self.elapsed_ms(), true)
    }

    /// Acquire a send slot without falsely inflating `dropped_frames` when a held `pending_frame`
    /// is merely re-checking readiness (real overwrites are counted via [`Self::record_drops`]).
    pub fn try_acquire_send_no_drop_count(&self) -> bool {
        self.try_acquire_send_at(self.elapsed_ms(), false)
    }

    /// Logical-clock variant of [`Self::try_acquire_send`] for zero-sleep deterministic fuzzing.
    pub fn try_acquire_send_at(&self, now: u64, count_drop: bool) -> bool {
        let limit = self.max_in_flight.load(Ordering::Relaxed);
        if limit == 0 || !self.acked_ever.load(Ordering::Acquire) {
            self.last_sent_ms.store(now, Ordering::Relaxed);
            self.record_send_timestamp(now, 4);
            return true;
        }
        const ACK_EXPIRE_MS: u64 = 500;
        let last = self.last_sent_ms.load(Ordering::Relaxed);
        let last_ack = self.last_ack_ms.load(Ordering::Relaxed);
        let mut cur = self.in_flight.load(Ordering::Acquire);
        // Idle decay: if >500ms passed since the last transmitted frame, reset leftover in_flight.
        if cur > 0 && now.saturating_sub(last) >= ACK_EXPIRE_MS {
            self.in_flight.store(0, Ordering::Release);
            if let Ok(mut g) = self.rtt.lock() {
                g.send_times_ms.clear();
            }
            cur = 0;
        } else if cur > 0 {
            // Prune expired send timestamps (>500ms) from dropped ACKs; when ACKs are actively
            // flowing, reclaim leaked phantom `in_flight` tokens so pipeline depth self-heals!
            // During a live blackhole (`now - last_ack >= 500`), keep `in_flight` clamped so we
            // only probe every 120ms without bursting.
            let mut expired = 0u32;
            if let Ok(mut g) = self.rtt.lock() {
                while let Some(&oldest) = g.send_times_ms.front() {
                    if now.saturating_sub(oldest) >= ACK_EXPIRE_MS {
                        g.send_times_ms.pop_front();
                        expired = expired.saturating_add(1);
                    } else {
                        break;
                    }
                }
            }
            if expired > 0 && now.saturating_sub(last_ack) < ACK_EXPIRE_MS {
                cur = self.subtract_in_flight(expired);
            }
        }
        if cur < limit {
            self.in_flight.fetch_add(1, Ordering::AcqRel);
            self.last_sent_ms.store(now, Ordering::Relaxed);
            self.record_send_timestamp(now, (limit as usize).max(1));
            return true;
        }
        // Safety release: if >120ms passed without any ACK, allow 1 probe frame without clobbering
        // any concurrent ACK decrements (atomic CAS bounded to `limit`). Always record `now` so
        // the first post-blackhole ACK measures true live RTT instead of a stale 1.9s timestamp.
        if now.saturating_sub(last) >= 120 {
            loop {
                let next = (cur + 1).min(limit);
                match self.in_flight.compare_exchange_weak(
                    cur,
                    next,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => break,
                    Err(actual) => cur = actual,
                }
            }
            self.last_sent_ms.store(now, Ordering::Relaxed);
            self.record_send_timestamp(now, (limit as usize).max(1));
            return true;
        }
        if count_drop {
            self.dropped_frames.fetch_add(1, Ordering::Relaxed);
        }
        false
    }

    fn subtract_in_flight(&self, delta: u32) -> u32 {
        let mut cur = self.in_flight.load(Ordering::Acquire);
        loop {
            let next = cur.saturating_sub(delta);
            match self.in_flight.compare_exchange_weak(
                cur,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return next,
                Err(actual) => cur = actual,
            }
        }
    }

    fn record_send_timestamp(&self, now: u64, cap: usize) {
        if let Ok(mut g) = self.rtt.lock() {
            let cap = cap.clamp(1, MAX_RTT_TIMESTAMP_QUEUE);
            while g.send_times_ms.len() >= cap {
                g.send_times_ms.pop_front();
            }
            g.send_times_ms.push_back(now);
        }
    }

    pub fn record_drops(&self, n: u64) {
        if n > 0 {
            self.dropped_frames.fetch_add(n, Ordering::Relaxed);
        }
    }

    fn decrement_in_flight_at(&self, now: u64) {
        const ACK_EXPIRE_MS: u64 = 500;
        self.acked_ever.store(true, Ordering::Release);
        self.last_ack_ms.store(now, Ordering::Relaxed);
        let mut expired = 0u32;
        if let Ok(mut g) = self.rtt.lock() {
            // Discard expired timestamps (>500ms) from lost ACKs and reclaim their leaked tokens.
            while let Some(&oldest) = g.send_times_ms.front() {
                let age = now.saturating_sub(oldest);
                if (age > ACK_EXPIRE_MS && g.send_times_ms.len() > 1) || age > 2000 {
                    g.send_times_ms.pop_front();
                    expired = expired.saturating_add(1);
                } else {
                    break;
                }
            }
            if let Some(sent_at) = g.send_times_ms.pop_front() {
                let sample_ms = now.saturating_sub(sent_at);
                if sample_ms <= 2000 {
                    let sample_x10 = sample_ms * 10;
                    let next = match g.ewma_rtt_ms_x10 {
                        None => sample_x10,
                        Some(prev) => (prev * 3 + sample_x10) / 4,
                    };
                    g.ewma_rtt_ms_x10 = Some(next);
                    g.last_rtt_sample_ms = Some(now);
                }
            }
        }
        let _ = self.subtract_in_flight(1u32.saturating_add(expired));
        self.wake_streamer();
    }

    /// Smoothed client ACK round-trip latency (milliseconds), if a fresh ACK sample arrived
    /// within the last 3 seconds (stale samples expire so old spikes never trap ABR).
    pub fn ewma_rtt_ms(&self) -> Option<f64> {
        self.ewma_rtt_ms_at(self.elapsed_ms())
    }

    pub fn ewma_rtt_ms_at(&self, now: u64) -> Option<f64> {
        self.rtt
            .lock()
            .ok()
            .and_then(|g| {
                let last_ms = g.last_rtt_sample_ms?;
                if now.saturating_sub(last_ms) > RTT_STALE_EXPIRY_MS {
                    return None;
                }
                g.ewma_rtt_ms_x10
            })
            .map(|v| v as f64 / 10.0)
    }

    /// Record a `FrameReceived` acknowledgment from the client.
    /// Ignored once the client has demonstrated `PictureRendered` end-to-end ACKs to prevent double-counting.
    pub fn on_frame_received(&self) {
        self.on_frame_received_at(self.elapsed_ms());
    }

    pub fn on_frame_received_at(&self, now: u64) {
        if self.seen_picture_rendered.load(Ordering::Acquire) {
            return;
        }
        self.decrement_in_flight_at(now);
    }

    /// Record a `PictureRendered` end-to-end acknowledgment from the client.
    pub fn on_picture_rendered(&self) {
        self.on_picture_rendered_at(self.elapsed_ms());
    }

    pub fn on_picture_rendered_at(&self, now: u64) {
        let was_seen = self.seen_picture_rendered.swap(true, Ordering::AcqRel);
        if !was_seen {
            // Reset EWMA when transitioning from network-only `FrameReceived` to end-to-end
            // `PictureRendered` so early low-RTT transport ACKs never poison render-RTT baselines.
            if let Ok(mut g) = self.rtt.lock() {
                g.ewma_rtt_ms_x10 = None;
                g.last_rtt_sample_ms = None;
            }
        }
        self.decrement_in_flight_at(now);
    }

    /// Record a generic ACK (used in tests).
    pub fn on_ack(&self) {
        self.decrement_in_flight_at(self.elapsed_ms());
    }

    pub fn in_flight(&self) -> u32 {
        self.in_flight.load(Ordering::Acquire)
    }

    /// Clear in-flight counter and stale RTT samples when attaching a new data channel or resuming (`StartStream`).
    pub fn reset_in_flight(&self) {
        self.in_flight.store(0, Ordering::Release);
        if let Ok(mut g) = self.rtt.lock() {
            g.send_times_ms.clear();
            g.ewma_rtt_ms_x10 = None;
            g.last_rtt_sample_ms = None;
        }
        self.wake_streamer();
    }

    pub fn dropped_frames(&self) -> u64 {
        self.dropped_frames.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(super) fn clear_send_timestamps_for_test(&self) {
        if let Ok(mut g) = self.rtt.lock() {
            g.send_times_ms.clear();
        }
    }
}

pub(super) type SharedCaptureHandle = Arc<Mutex<Box<dyn CaptureHandle>>>;

pub(super) struct ActiveCapture {
    pub(super) id: u64,
    pub(super) handle: SharedCaptureHandle,
    pub(super) stop_flag: Arc<AtomicBool>,
    pub(super) actual_size: Arc<Mutex<(u32, u32)>>,
    pub(super) abr_status: Arc<Mutex<AbrStatusSnapshot>>,
    pub(super) stream_thread: Option<thread::JoinHandle<()>>,
    pub(super) cursor_thread: Option<thread::JoinHandle<()>>,
}

impl ActiveCapture {
    pub(super) fn shutdown(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        if let Ok(mut h) = self.handle.lock() {
            h.stop();
        }
        if let Some(t) = self.stream_thread.take() {
            let _ = t.join();
        }
        if let Some(t) = self.cursor_thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for ActiveCapture {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[derive(Debug, Clone)]
pub(super) struct LowPowerSnapshot {
    pub(super) p2p_relay_enabled: bool,
    pub(super) max_web_viewers: usize,
    pub(super) fps: u32,
    pub(super) bitrate_mbps: u32,
    pub(super) hidpi: u32,
    pub(super) polling: crate::user_config::PollingConfigSection,
}

#[derive(Default)]
pub(super) struct WebAbrAccum {
    pub(super) sent_frames: u64,
    pub(super) dropped_frames: u64,
    pub(super) send_ms_sum: u64,
    pub(super) max_send_ms: u64,
}

pub(super) struct WebSubscriberEntry {
    pub(super) id: u64,
    pub(super) peer: String,
    pub(super) session_tag: Option<String>,
    pub(super) fingerprint: Option<String>,
    pub(super) label: Option<String>,
    pub(super) is_admin: bool,
    pub(super) connected_at: Instant,
    pub(super) visible: Arc<AtomicBool>,
    pub(super) tx: FrameSender,
    pub(super) unblock_io: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl WebSubscriberEntry {
    pub(super) fn kick(&self) {
        self.tx.close();
        if let Some(ref f) = self.unblock_io {
            f();
        }
    }
}

/// RAII subscription to the extended display's H.264 Annex-B frame broadcast for a Web viewer.
pub struct WebStreamSubscription {
    pub id: u64,
    pub rx: FrameReceiver,
    pub(super) subscribers: Arc<Mutex<Vec<WebSubscriberEntry>>>,
    pub(super) standalone_capture: Arc<Mutex<Option<ActiveCapture>>>,
    pub(super) sessions: Arc<Mutex<HashMap<String, ClientSession>>>,
    pub(super) web_screen_mode: Arc<AtomicU8>,
    pub(super) web_follow_ipad_session_id: Arc<AtomicU64>,
    pub(super) web_source_epoch: Arc<AtomicU64>,
    pub(super) last_ipad_web_frame: super::CachedWebFrameSlot,
    pub(super) host_lock_paused_ipad: Arc<AtomicBool>,
    pub(super) host_lock_paused_web: Arc<AtomicBool>,
    pub(super) web_lock_disconnecting: Arc<AtomicBool>,
    pub(super) last_global_activity: Arc<Mutex<Instant>>,
    pub(super) last_web_activity: Arc<Mutex<Instant>>,
    pub(super) activity_signal: Arc<(Mutex<u64>, Condvar)>,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn sync_capture_pause_states_inner(
    standalone_capture: &Arc<Mutex<Option<ActiveCapture>>>,
    sessions: &Arc<Mutex<HashMap<String, ClientSession>>>,
    subscribers: &Arc<Mutex<Vec<WebSubscriberEntry>>>,
    web_screen_mode: &Arc<AtomicU8>,
    web_follow_ipad_session_id: &Arc<AtomicU64>,
    web_source_epoch: &Arc<AtomicU64>,
    last_ipad_web_frame: &super::CachedWebFrameSlot,
    host_lock_paused_ipad: &Arc<AtomicBool>,
    host_lock_paused_web: &Arc<AtomicBool>,
    web_lock_disconnect_blocking: bool,
) {
    let mut updates: Vec<(SharedCaptureHandle, bool)> = Vec::new();
    {
        // Consistent lock order: `standalone_web_capture` -> `sessions` -> `web_subscribers`.
        let standalone = standalone_capture.lock().unwrap();
        let sess_map = sessions.lock().unwrap();
        let subs = subscribers.lock().unwrap();
        let visible_web_viewers = subs
            .iter()
            .filter(|s| s.visible.load(Ordering::Acquire))
            .count();
        let web_wants_frames = visible_web_viewers > 0
            && !host_lock_paused_web.load(Ordering::Acquire)
            && !web_lock_disconnect_blocking;
        if let Some(ref cap) = *standalone {
            updates.push((cap.handle.clone(), !web_wants_frames));
        }
        let dedicated_web =
            WebScreenMode::from_u8(web_screen_mode.load(Ordering::Acquire)) != WebScreenMode::FollowIpad;
        let follow_owner = web_follow_ipad_session_id.load(Ordering::Acquire);
        let owner_alive = follow_owner != 0
            && sess_map
                .values()
                .any(|s| s.id == follow_owner && s.capture.is_some());
        let first_active_sid = if owner_alive {
            follow_owner
        } else {
            let candidate = sess_map
                .values()
                .filter(|s| s.capture.is_some())
                .map(|s| s.id)
                .min()
                .unwrap_or(0);
            if !dedicated_web && web_wants_frames && candidate != 0 {
                // Deterministically commit the chosen FollowIpad owner so `flow_control` and
                // `data_channel` never disagree on which iPad stays unpaused for Web viewers.
                match web_follow_ipad_session_id.compare_exchange(
                    follow_owner,
                    candidate,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => {
                        // Re-verify mode AFTER CAS (Iter-9 P2-B1) and bump `web_source_epoch` +
                        // clear `last_ipad_web_frame` on ownership handover so dead iPad #1's
                        // cached IDR can NEVER be served under iPad #2's stream (Iter-9 P1-B1).
                        if WebScreenMode::from_u8(web_screen_mode.load(Ordering::Acquire))
                            != WebScreenMode::FollowIpad
                        {
                            let _ = web_follow_ipad_session_id.compare_exchange(
                                candidate,
                                0,
                                Ordering::AcqRel,
                                Ordering::Acquire,
                            );
                            0
                        } else {
                            web_source_epoch.fetch_add(1, Ordering::AcqRel);
                            if let Ok(mut lf) = last_ipad_web_frame.lock() {
                                *lf = None;
                            }
                            candidate
                        }
                    }
                    Err(actual)
                        if actual != 0
                            && sess_map
                                .values()
                                .any(|s| s.id == actual && s.capture.is_some()) =>
                    {
                        actual
                    }
                    Err(_) => candidate,
                }
            } else {
                if follow_owner != 0 {
                    let _ = web_follow_ipad_session_id.compare_exchange(
                        follow_owner,
                        0,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    );
                }
                candidate
            }
        };
        let ipad_lock_paused = host_lock_paused_ipad.load(Ordering::Acquire);
        for sess in sess_map.values() {
            if let Some(ref cap) = sess.capture {
                let ipad_paused =
                    sess.stream_paused.load(Ordering::Acquire) || ipad_lock_paused;
                // Only the single FollowIpad owner iPad needs to stay unpaused for visible Web viewers;
                // non-owner paused iPads can cleanly pause & release their IOPMAssertion (PWR-1).
                let is_web_owner = !dedicated_web && sess.id == first_active_sid;
                let should_pause = if is_web_owner && web_wants_frames {
                    false
                } else {
                    ipad_paused
                };
                updates.push((cap.handle.clone(), should_pause));
            }
        }
    }
    for (hdl, paused) in updates {
        if let Ok(mut g) = hdl.lock() {
            if let Err(e) = g.set_paused(paused) {
                debug!("Capture set_paused({paused}) failed: {e:#}");
            }
            if !paused {
                g.request_keyframe();
            }
        }
    }
}

impl Drop for WebStreamSubscription {
    fn drop(&mut self) {
        let now = Instant::now();
        if let Ok(mut ts) = self.last_global_activity.lock() {
            *ts = now;
        }
        if let Ok(mut ts) = self.last_web_activity.lock() {
            *ts = now;
        }
        {
            let mut subs = self.subscribers.lock().unwrap();
            subs.retain(|s| s.id != self.id);
        }
        {
            let (lock, cvar) = &*self.activity_signal;
            if let Ok(mut seq) = lock.lock() {
                *seq = seq.wrapping_add(1);
            }
            cvar.notify_all();
        }
        // Lock order: `standalone_capture` -> `subscribers` (never held by stream_thread).
        // Re-check `subscribers.is_empty()` under `standalone_capture` to eliminate TOCTOU race
        // with a concurrently subscribing Viewer 2.
        let cap_opt = {
            let mut cap_guard = self.standalone_capture.lock().unwrap();
            let subs = self.subscribers.lock().unwrap();
            if subs.is_empty() {
                cap_guard.take()
            } else {
                None
            }
        };
        if let Some(mut cap) = cap_opt {
            info!("Last Web viewer disconnected — releasing standalone extended virtual display");
            cap.shutdown();
        }
        // In shared (follow-iPad) mode, if the last Web viewer disconnected while the iPad was
        // paused (StopStream / lock-pause), immediately pause the iPad capture & release IOPMAssertion.
        sync_capture_pause_states_inner(
            &self.standalone_capture,
            &self.sessions,
            &self.subscribers,
            &self.web_screen_mode,
            &self.web_follow_ipad_session_id,
            &self.web_source_epoch,
            &self.last_ipad_web_frame,
            &self.host_lock_paused_ipad,
            &self.host_lock_paused_web,
            self.web_lock_disconnecting.load(Ordering::Acquire),
        );
    }
}

/// Compute a deterministic non-zero 32-bit FNV-1a serial number from a device identifier
/// so macOS WindowServer recognizes the same virtual display across reconnects and preserves
/// display arrangement, scaling, and window positions.
pub(super) fn extract_sps_hex(annex_b: &[u8]) -> Option<String> {
    let nals = crate::fmp4::split_annexb_nals(annex_b);
    let sps = nals
        .into_iter()
        .find(|n| !n.is_empty() && (n[0] & 0x1F) == 7)?;
    let mut s = String::with_capacity(sps.len() * 2);
    for b in sps {
        use std::fmt::Write as _;
        let _ = write!(&mut s, "{b:02x}");
    }
    Some(s)
}

pub(super) fn stable_display_serial(seed: &str) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for b in seed.as_bytes() {
        hash ^= *b as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    if hash == 0 {
        0x4944_0001
    } else {
        hash
    }
}

static NEXT_WEB_FRAME_SEQ: AtomicU64 = AtomicU64::new(1);

pub(super) fn send_frame_to_web_subscribers_tagged(
    subscribers: &Arc<Mutex<Vec<WebSubscriberEntry>>>,
    source_epoch: u64,
    frame: Arc<EncodedFrame>,
) {
    let Ok(mut subs) = subscribers.lock() else {
        return;
    };
    if subs.is_empty() {
        return;
    }
    let seq = NEXT_WEB_FRAME_SEQ.fetch_add(1, Ordering::Relaxed);
    subs.retain(|s| {
        if !s.visible.load(Ordering::Acquire) {
            // Hidden tab paused: skip waking WS writer while keeping the subscription alive
            // (`WebStreamSubscription::drop` removes entries on disconnect).
            return true;
        }
        s.tx.send_latest_shared_tagged(seq, source_epoch, frame.clone())
    });
}

pub(super) fn broadcast_to_web_subscribers_tagged(
    subscribers: &Arc<Mutex<Vec<WebSubscriberEntry>>>,
    last_frame: &super::CachedWebFrameSlot,
    source_epoch: u64,
    frame: Arc<EncodedFrame>,
) {
    // Only cache IDR keyframes tagged with `source_epoch` so joining/resuming viewers never receive
    // a bare P-frame or a stale IDR from a previous epoch (Iter-7 P1-B1).
    if frame.is_keyframe {
        if let Ok(mut lf) = last_frame.lock() {
            *lf = Some((source_epoch, frame.clone()));
        }
    }
    send_frame_to_web_subscribers_tagged(subscribers, source_epoch, frame);
}

