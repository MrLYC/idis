use super::flow_control::{
    extract_sps_hex, send_frame_to_web_subscribers_tagged, stable_display_serial, ActiveCapture,
};
use super::SessionRegistry;
use crate::abr::{
    tier_spec, AbrController, AbrStatusSnapshot, AbrTargets, AbrWindowSample, InFlightController,
};
use crate::config::WebScreenMode;
use crate::platform::{
    clamp_pixel_dimensions, CaptureParams, CursorState, EncodedFrame, RecvFrameError,
};
use crate::protocol::messages::{
    build_cursor_image_packet, build_cursor_position_packet, build_cursor_visible_packet,
    build_udp_cursor_position_packet, decode_input_event, describe_archived_bplist,
};
use crate::protocol::video::{build_video_header, COMPRESSION_H264};
use crate::transport::SharedFrameWriter;
use anyhow::{anyhow, Result};
use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

impl SessionRegistry {
    pub fn attach_data_channel(&self, key: &str, data_writer: SharedFrameWriter) -> Result<(u64, u64)> {
        self.attach_data_channel_checked(key, None, data_writer)
    }

    /// Checked variant validating optional `expected_session_id` (USB race guard) and session
    /// authorization before attaching the Data channel.
    pub fn attach_data_channel_checked(
        &self,
        key: &str,
        expected_session_id: Option<u64>,
        data_writer: SharedFrameWriter,
    ) -> Result<(u64, u64)> {
        let data_gen = self.next_session_id.fetch_add(1, Ordering::Relaxed);
        let (
            session_id,
            hs,
            fingerprint,
            tel_writer,
            flow,
            is_usb,
            udp_cursor_enabled,
            stream_paused,
            prev_capture,
            prev_dw,
            prev_stuck_mouse,
        ) = {
            let mut map = self.sessions.lock().unwrap();
            let sess = map
                .get_mut(key)
                .ok_or_else(|| anyhow!("data channel arrived for unknown client {key}"))?;
            if let Some(eid) = expected_session_id {
                if sess.id != eid {
                    return Err(anyhow!(
                        "data channel rejected: session_id mismatch for {key} (expected {eid}, current {})",
                        sess.id
                    ));
                }
            }
            if !sess.authorized {
                return Err(anyhow!("data channel rejected: session {key} not authorized"));
            }
            let hs = sess
                .handshake
                .clone()
                .ok_or_else(|| anyhow!("data channel arrived before Handshake for {key}"))?;
            let prev_capture = sess.capture.take();
            let prev_dw = sess.data_writer.replace(data_writer.clone());
            let prev_stuck_mouse = sess.mouse_left_down.take();
            sess.suppress_right_click_tail = false;
            sess.data_generation = data_gen;
            sess.flow.reset_in_flight();
            sess.stream_paused.store(false, Ordering::Release);
            sess.data_detached_at = None;
            sess.last_activity = Instant::now();
            (
                sess.id,
                hs,
                sess.fingerprint.clone(),
                sess.telemetry_writer.clone(),
                sess.flow.clone(),
                sess.is_usb,
                sess.udp_cursor_enabled.clone(),
                sess.stream_paused.clone(),
                prev_capture,
                prev_dw,
                prev_stuck_mouse,
            )
        };
        // Close old socket FIRST (lock-free shutdown), release any stuck mouse button, join old
        // capture threads, and release FollowIpad ownership before starting the replacement capture.
        if let Some(old_dw) = prev_dw {
            old_dw.close();
        }
        if let Some(mut prev) = prev_capture {
            Self::release_stuck_mouse_handle(&prev.handle, prev_stuck_mouse);
            prev.shutdown();
            if self
                .web_follow_ipad_session_id
                .compare_exchange(session_id, 0, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                if self.web_screen_mode() == crate::config::WebScreenMode::FollowIpad {
                    self.bump_web_source_epoch();
                }
                if let Ok(mut lf) = self.last_ipad_web_frame.lock() {
                    *lf = None;
                }
            }
        }
        // Cancel any pending follow-iPad standalone Web fallback grace timer and stop standalone Web
        // capture before starting the iPad capture so both pipelines never interleave frames.
        if let Ok(mut g) = self.standalone_web_resume_after.lock() {
            *g = None;
        }
        self.stop_standalone_web_capture_if_following_ipad();

        let vs = self.effective_video_for_fingerprint(fingerprint.as_deref());
        let trust_store_v = self.trust_store.clone();
        let fingerprint_v = fingerprint.clone();
        let low_power_v = self.low_power.clone();
        if !self.is_low_power() {
            if let Some(dev) = fingerprint
                .as_deref()
                .and_then(|fp| self.trust_store.get_device(fp))
            {
                if !dev.prefs.is_empty() {
                    info!(
                        "[{key}] Applied per-device saved preferences for {} ({}x{}, {}fps, {}Mbps, {}x HiDPI)",
                        dev.fingerprint, vs.width, vs.height, vs.fps, vs.bitrate_mbps, vs.hidpi
                    );
                }
            }
        }
        let eff_hidpi = if self.backend.supports_hidpi() {
            vs.hidpi
        } else {
            1
        };
        let (w, h) = Self::resolve_dimensions_for_settings(&hs, &vs, self.backend.supports_hidpi());
        let eff_edge = Self::effective_ipad_max_pixel_edge(&hs, &vs);
        let fps = vs.fps.max(1);
        info!(
            "[{key}] Starting capture ({:?}) at {w}x{h} @ {fps}fps, {}Mbps H.264 (hidpi={}x, integer_scale={}, max_edge={eff_edge}px, proto v{}, max_in_flight={})",
            self.config.mode,
            vs.bitrate_mbps,
            eff_hidpi,
            vs.integer_scale,
            hs.data_protocol_version,
            if self.is_auto_max_in_flight() {
                "auto".to_string()
            } else {
                self.max_in_flight().to_string()
            }
        );

        let initial_show_cursor = !self.is_client_cursor();
        let (mut cap_handle, frame_rx) = match self.backend.start_capture(&CaptureParams {
            mode: self.config.mode,
            display_id: self.config.display_id,
            capture_rect: self.config.capture_rect,
            width: w,
            height: h,
            hidpi: eff_hidpi,
            max_pixel_edge: eff_edge,
            fps,
            bitrate_mbps: vs.bitrate_mbps,
            all_intra: self.config.all_intra,
            encoder: self.config.encoder.clone(),
            ffmpeg_path: self.config.ffmpeg_path.clone(),
            show_cursor: initial_show_cursor,
            client_name: hs.name.clone(),
            display_serial: stable_display_serial(if !hs.uid.is_empty() {
                &hs.uid
            } else {
                &hs.name
            }),
        }) {
            Ok(v) => {
                self.clear_capture_error();
                v
            }
            Err(e) => {
                self.record_capture_error("ipad", &e);
                error!("[{key}] failed to start display capture/encoder: {e:#}");
                sentry::integrations::anyhow::capture_anyhow(&e);
                // Clear & close the stored data_writer so client isn't hung on an open dead socket,
                // and restore standalone Web capture if follow-iPad mode had just stopped it.
                let failed_dw = {
                    let mut map = self.sessions.lock().unwrap();
                    map.get_mut(key)
                        .filter(|s| s.id == session_id && s.data_generation == data_gen)
                        .and_then(|s| {
                            s.data_detached_at = Some(Instant::now());
                            s.data_writer.take()
                        })
                };
                if let Some(dw) = failed_dw {
                    dw.close();
                }
                self.resume_standalone_web_capture_if_needed();
                self.sync_capture_pause_states();
                return Err(e);
            }
        };
        if self.is_low_power() {
            let _ = cap_handle.set_low_power(true);
        }

        let frame_waker = frame_rx.waker();
        let cap_id = self.next_capture_id.fetch_add(1, Ordering::Relaxed);
        let shared_handle = Arc::new(Mutex::new(cap_handle));
        let stop_flag = Arc::new(AtomicBool::new(false));
        let init_pix = clamp_pixel_dimensions(w * eff_hidpi.max(1), h * eff_hidpi.max(1), eff_edge);
        let actual_size = Arc::new(Mutex::new(init_pix));
        let supports_live_abr_v = self.backend.capabilities().live_abr_quality;
        let abr_status = Arc::new(Mutex::new(AbrStatusSnapshot {
            enabled: supports_live_abr_v && vs.adaptive_quality,
            tier: 0,
            scale_pct: 100,
            target_fps: fps,
            target_bitrate_mbps: vs.bitrate_mbps,
            rtt_ms: None,
            unfocused_fps_halved: false,
        }));

        // Video frame streaming thread with ACK backpressure, Web viewer fan-out, tiered ABR,
        // and optional cursor-focus half-FPS power saving.
        let proto_ver = hs.data_protocol_version;
        let stop_v = stop_flag.clone();
        let dw = data_writer.clone();
        let key_v = key.to_string();
        let flow_v = flow.clone();
        let web_subs_v = self.web_subscribers.clone();
        let last_ipad_f_v = self.last_ipad_web_frame.clone();
        let web_screen_mode_v = self.web_screen_mode.clone();
        let web_follow_sid_v = self.web_follow_ipad_session_id.clone();
        let web_source_epoch_v = self.web_source_epoch.clone();
        let sessions_v = self.sessions.clone();
        let my_session_id_v = session_id;
        let paused_v = stream_paused.clone();
        let host_lock_paused_ipad_v = self.host_lock_paused_ipad.clone();
        let host_lock_paused_web_v = self.host_lock_paused_web.clone();
        let web_lock_disconnecting_v = self.web_lock_disconnecting.clone();
        let size_v = actual_size.clone();
        let abr_status_v = abr_status.clone();
        let hdl_v = shared_handle.clone();
        let video_v = self.video.clone();
        let video_gen_v = self.ipad_video_settings_gen.clone();
        let auto_mif_v = self.auto_max_in_flight.clone();
        let all_intra_v = self.config.all_intra;
        let is_usb_v = is_usb;
        let hs_v = hs.clone();
        let stream_thread = thread::spawn(move || {
            let mut sent_frames: u64 = 0;
            let mut last_logged_size = (0u32, 0u32);
            // Bounded consecutive-frame pacing queue for iPad:
            // - All-intra mode keeps cap=1 (latest independent IDR only, zero lag).
            // - IPPP mode buffers up to 4 consecutive P-frames (~66ms@60fps / ~133ms@30fps),
            //   paired with the 4-frame upstream bounded FIFO channel, absorbing brief Wi-Fi
            //   micro-stalls cleanly without exceeding 180ms stale latency (Invariant VID-1).
            let pending_cap: usize = if all_intra_v { 1 } else { 4 };
            const MAX_PENDING_AGE: Duration = Duration::from_millis(180);
            let mut pending_queue: VecDeque<(Instant, Arc<EncodedFrame>)> =
                VecDeque::with_capacity(pending_cap);
            let mut last_sent_idr: Option<Arc<EncodedFrame>> = None;
            // Separate upstream slot DPB gate (affects both iPad & shared Web) from iPad-local
            // DPB gate (StopStream / iPad lock-pause / iPad pending_queue overflow) so iPad congestion
            // or pause NEVER starves shared-mode Web viewers!
            let mut slot_awaiting_idr = true;
            let mut ipad_awaiting_idr = true;
            let mut last_kf_req = Instant::now() - Duration::from_secs(1);
            let mut was_paused = false;
            let mut stats_started = Instant::now();
            let mut stats_frames: u64 = 0;
            let mut stats_bytes: u64 = 0;
            let mut stats_max_bytes: usize = 0;
            let mut stats_non_idr_drops: u64 = 0;

            // ABR & adaptive in-flight window 1s sliding accumulators
            let mut abr = AbrController::new(Instant::now());
            let mut inflight_ctrl = InFlightController::new(is_usb_v, Instant::now());
            let mut last_video_gen = video_gen_v.load(Ordering::Acquire);
            let mut abr_win_start = Instant::now();
            let mut abr_win_sent: u64 = 0;
            let mut abr_win_flow_blocked: u64 = 0;
            let mut abr_win_send_ms_sum: u64 = 0;
            let mut abr_win_max_send_ms: u64 = 0;
            let mut abr_prev_drops_total: u64 = flow_v.dropped_frames();
            let mut pending_abr_apply: Option<(u8, u8, AbrTargets)> = None;
            let mut last_focus_check = Instant::now() - Duration::from_secs(1);
            let mut last_cursor_on_ipad = Instant::now();
            let mut desired_unfocused_halved = false;
            let mut applied_unfocused_halved = false;
            let mut last_applied_stream: Option<(u32, u32, u32)> = None;
            let mut web_follow_needs_idr = true;
            let mut last_web_source_epoch = web_source_epoch_v.load(Ordering::Acquire);
            const UNFOCUSED_GRACE: Duration = Duration::from_millis(1500);

            while !stop_v.load(Ordering::SeqCst) {
                let is_paused = paused_v.load(Ordering::Acquire)
                    || host_lock_paused_ipad_v.load(Ordering::Acquire);
                let wait = if !is_paused && !pending_queue.is_empty() {
                    Duration::from_millis(2)
                } else {
                    Duration::from_millis(120)
                };
                let mut skip_send_phase = false;
                match frame_rx.recv_timeout_shared(wait) {
                    Ok((_seq, frame, slot_overwritten)) => {
                        if slot_overwritten > 0 {
                            if !is_paused {
                                flow_v.record_drops(slot_overwritten);
                            }
                            if !all_intra_v {
                                if !pending_queue.is_empty() {
                                    if !is_paused {
                                        flow_v.record_drops(pending_queue.len() as u64);
                                    }
                                    pending_queue.clear();
                                }
                                let got_fresh_idr = frame.is_keyframe
                                    && crate::protocol::annexb::is_self_contained_idr(&frame.annex_b);
                                if !got_fresh_idr {
                                    slot_awaiting_idr = true;
                                    ipad_awaiting_idr = true;
                                    if last_kf_req.elapsed() >= Duration::from_millis(250) {
                                        last_kf_req = Instant::now();
                                        if let Ok(hdl) = hdl_v.try_lock() {
                                            hdl.request_keyframe();
                                        }
                                    }
                                }
                            }
                        }
                        // Load `web_source_epoch` BEFORE lock flags (preserving Release-Acquire order with
                        // `lock_policy.rs`, which sets lock flags before bumping `web_source_epoch`; Iter-8 P1-B1).
                        let cur_web_epoch = web_source_epoch_v.load(Ordering::Acquire);
                        let ipad_locked_pause = host_lock_paused_ipad_v.load(Ordering::Acquire);
                        let web_locked_pause = host_lock_paused_web_v.load(Ordering::Acquire);
                        let web_locked_disc = web_lock_disconnecting_v.load(Ordering::Acquire);
                        if ipad_locked_pause && (web_locked_pause || web_locked_disc) {
                            was_paused = true;
                            pending_queue.clear();
                            last_sent_idr = None;
                            slot_awaiting_idr = true;
                            ipad_awaiting_idr = true;
                            skip_send_phase = true;
                        } else {
                            let mut accept_frame = true;
                            if all_intra_v {
                                if !frame.is_keyframe
                                    || !crate::protocol::annexb::is_self_contained_idr(
                                        &frame.annex_b,
                                    )
                                {
                                    stats_non_idr_drops += 1;
                                    debug!(
                                        "[{key_v}] Dropping non-IDR / incomplete H.264 frame ({}B) in --all-intra mode",
                                        frame.annex_b.len()
                                    );
                                    accept_frame = false;
                                }
                            } else if frame.is_keyframe {
                                if !crate::protocol::annexb::is_self_contained_idr(&frame.annex_b) {
                                    stats_non_idr_drops += 1;
                                    slot_awaiting_idr = true;
                                    ipad_awaiting_idr = true;
                                    accept_frame = false;
                                } else {
                                    slot_awaiting_idr = false;
                                    ipad_awaiting_idr = false;
                                }
                            } else if slot_awaiting_idr {
                                stats_non_idr_drops += 1;
                                if last_kf_req.elapsed() >= Duration::from_millis(250) {
                                    last_kf_req = Instant::now();
                                    if let Ok(hdl) = hdl_v.try_lock() {
                                        hdl.request_keyframe();
                                    }
                                }
                                accept_frame = false;
                            }

                            if accept_frame {
                                if (frame.width, frame.height) != last_logged_size {
                                    last_logged_size = (frame.width, frame.height);
                                    if let Ok(mut g) = size_v.lock() {
                                        *g = last_logged_size;
                                    }
                                    info!(
                                        "[{key_v}] Active video stream pixel resolution: {}x{}",
                                        frame.width, frame.height
                                    );
                                    crate::debug_trace::record(
                                        "stream",
                                        "resolution_changed",
                                        serde_json::json!({
                                            "key": key_v,
                                            "pixel_width": frame.width,
                                            "pixel_height": frame.height,
                                            "frame_bytes": frame.annex_b.len(),
                                            "sps_hex": extract_sps_hex(&frame.annex_b),
                                        }),
                                    );
                                }
                                // Fan out to shared-mode Web viewers BEFORE iPad-local pause/congestion gates!
                                // Only ONE primary iPad session fans out in FollowIpad mode so multiple
                                // concurrent iPads never interleave incompatible IPPP GOPs into one MSE decoder.
                                if cur_web_epoch != last_web_source_epoch {
                                    last_web_source_epoch = cur_web_epoch;
                                    web_follow_needs_idr = true;
                                }
                                let web_blocked_now = web_locked_pause
                                    || web_locked_disc
                                    || host_lock_paused_web_v.load(Ordering::Acquire)
                                    || web_lock_disconnecting_v.load(Ordering::Acquire);
                                if !web_blocked_now
                                    && !stop_v.load(Ordering::Acquire)
                                    && WebScreenMode::from_u8(
                                        web_screen_mode_v.load(Ordering::Acquire),
                                    ) == WebScreenMode::FollowIpad
                                {
                                    let mut owner = web_follow_sid_v.load(Ordering::Acquire);
                                    let mut broadcast_epoch = cur_web_epoch;
                                    if owner != my_session_id_v {
                                        let (owner_alive, self_alive) = sessions_v
                                            .try_lock()
                                            .map(|m| {
                                                let oa = owner != 0
                                                    && m.values().any(|s| {
                                                        s.id == owner && s.capture.is_some()
                                                    });
                                                let sa = m.values().any(|s| {
                                                    s.id == my_session_id_v && s.capture.is_some()
                                                });
                                                (oa, sa)
                                            })
                                            .unwrap_or((true, false));
                                        if !owner_alive
                                            && self_alive
                                            && !stop_v.load(Ordering::Acquire)
                                            && web_follow_sid_v
                                                .compare_exchange(
                                                    owner,
                                                    my_session_id_v,
                                                    Ordering::AcqRel,
                                                    Ordering::Acquire,
                                                )
                                                .is_ok()
                                        {
                                            // Re-verify mode & stop AFTER CAS so a concurrent mode leave
                                            // or teardown never leaves `web_follow_ipad_session_id` stuck (Iter-8 P2-B3).
                                            if stop_v.load(Ordering::Acquire)
                                                || WebScreenMode::from_u8(
                                                    web_screen_mode_v.load(Ordering::Acquire),
                                                ) != WebScreenMode::FollowIpad
                                            {
                                                let _ = web_follow_sid_v.compare_exchange(
                                                    my_session_id_v,
                                                    0,
                                                    Ordering::AcqRel,
                                                    Ordering::Acquire,
                                                );
                                                owner = 0;
                                            } else {
                                                owner = my_session_id_v;
                                                broadcast_epoch =
                                                    web_source_epoch_v.fetch_add(1, Ordering::AcqRel) + 1;
                                                last_web_source_epoch = broadcast_epoch;
                                                // Freshly claimed FollowIpad ownership (failover from dead iPad):
                                                // clear stale cached IDR and gate Web fan-out until THIS iPad emits a live IDR!
                                                web_follow_needs_idr = true;
                                                if let Ok(mut lf) = last_ipad_f_v.lock() {
                                                    *lf = None;
                                                }
                                                if let Ok(hdl) = hdl_v.try_lock() {
                                                    hdl.request_keyframe();
                                                }
                                            }
                                        }
                                    }
                                    if owner == my_session_id_v
                                        && !stop_v.load(Ordering::Acquire)
                                        && !host_lock_paused_web_v.load(Ordering::Acquire)
                                        && !web_lock_disconnecting_v.load(Ordering::Acquire)
                                        && WebScreenMode::from_u8(
                                            web_screen_mode_v.load(Ordering::Acquire),
                                        ) == WebScreenMode::FollowIpad
                                        && web_follow_sid_v.load(Ordering::Acquire)
                                            == my_session_id_v
                                    {
                                        if frame.is_keyframe {
                                            web_follow_needs_idr = false;
                                            if let Ok(mut lf) = last_ipad_f_v.lock() {
                                                *lf = Some((broadcast_epoch, frame.clone()));
                                            }
                                            send_frame_to_web_subscribers_tagged(
                                                &web_subs_v,
                                                broadcast_epoch,
                                                frame.clone(),
                                            );
                                        } else if !web_follow_needs_idr {
                                            send_frame_to_web_subscribers_tagged(
                                                &web_subs_v,
                                                broadcast_epoch,
                                                frame.clone(),
                                            );
                                        } else if last_kf_req.elapsed() >= Duration::from_millis(250) {
                                            last_kf_req = Instant::now();
                                            if let Ok(hdl) = hdl_v.try_lock() {
                                                hdl.request_keyframe();
                                            }
                                        }
                                    } else {
                                        // Not currently the FollowIpad owner; require a fresh IDR before
                                        // fanning out if we later take over ownership.
                                        web_follow_needs_idr = true;
                                    }
                                } else {
                                    // Leaving FollowIpad mode (Main/Independent) or host-locked Web pause:
                                    // require a fresh IDR before resuming FollowIpad Web fan-out (P1-B1).
                                    web_follow_needs_idr = true;
                                }
                                if ipad_locked_pause || paused_v.load(Ordering::Acquire) {
                                    was_paused = true;
                                    pending_queue.clear();
                                    if ipad_locked_pause {
                                        last_sent_idr = None;
                                    }
                                    ipad_awaiting_idr = true;
                                    skip_send_phase = true;
                                } else if !all_intra_v && !frame.is_keyframe && ipad_awaiting_idr {
                                    stats_non_idr_drops += 1;
                                    let lim = flow_v.max_in_flight();
                                    let kf_interval = if lim == 0 || flow_v.in_flight() < lim {
                                        Duration::from_millis(120)
                                    } else {
                                        Duration::from_millis(250)
                                    };
                                    if last_kf_req.elapsed() >= kf_interval {
                                        last_kf_req = Instant::now();
                                        if let Ok(hdl) = hdl_v.try_lock() {
                                            hdl.request_keyframe();
                                        }
                                    }
                                } else if frame.is_keyframe {
                                    // Fresh self-contained IDR resets the iPad queue cleanly to latest state.
                                    if !pending_queue.is_empty() {
                                        flow_v.record_drops(pending_queue.len() as u64);
                                        pending_queue.clear();
                                    }
                                    pending_queue.push_back((Instant::now(), frame));
                                } else if pending_queue.len() < pending_cap {
                                    // Keep consecutive P-frame chain intact while waiting briefly for iPad ACK.
                                    pending_queue.push_back((Instant::now(), frame));
                                } else {
                                    // Sustained iPad stall (>4 consecutive frames): count ALL dropped
                                    // frames accurately (queued + incoming) and resync on IDR.
                                    let dropped_now = (pending_queue.len() as u64) + 1;
                                    flow_v.record_drops(dropped_now);
                                    stats_non_idr_drops += dropped_now;
                                    pending_queue.clear();
                                    if !all_intra_v {
                                        ipad_awaiting_idr = true;
                                        let lim = flow_v.max_in_flight();
                                        let kf_interval = if lim == 0 || flow_v.in_flight() < lim {
                                            Duration::from_millis(120)
                                        } else {
                                            Duration::from_millis(250)
                                        };
                                        if last_kf_req.elapsed() >= kf_interval {
                                            last_kf_req = Instant::now();
                                            if let Ok(hdl) = hdl_v.try_lock() {
                                                hdl.request_keyframe();
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(RecvFrameError::Timeout) => {
                        let cur_web_epoch = web_source_epoch_v.load(Ordering::Acquire);
                        let follow_owner = web_follow_sid_v.load(Ordering::Acquire);
                        let in_follow_mode =
                            WebScreenMode::from_u8(web_screen_mode_v.load(Ordering::Acquire))
                                == WebScreenMode::FollowIpad;
                        if cur_web_epoch != last_web_source_epoch
                            || !in_follow_mode
                            || host_lock_paused_web_v.load(Ordering::Acquire)
                            || web_lock_disconnecting_v.load(Ordering::Acquire)
                            || (follow_owner != 0 && follow_owner != my_session_id_v)
                        {
                            last_web_source_epoch = cur_web_epoch;
                            web_follow_needs_idr = true;
                        }
                        let shared_web_needs_kf = (slot_awaiting_idr
                            || (web_follow_needs_idr
                                && (follow_owner == my_session_id_v || follow_owner == 0)))
                            && in_follow_mode
                            && !host_lock_paused_web_v.load(Ordering::Acquire)
                            && !web_lock_disconnecting_v.load(Ordering::Acquire)
                            && web_subs_v
                                .lock()
                                .ok()
                                .is_some_and(|s| s.iter().any(|e| e.visible.load(Ordering::Acquire)));
                        let ipad_needs_kf =
                            !is_paused && (ipad_awaiting_idr || slot_awaiting_idr);
                        if !all_intra_v
                            && (ipad_needs_kf || shared_web_needs_kf)
                            && last_kf_req.elapsed() >= Duration::from_millis(500)
                        {
                            last_kf_req = Instant::now();
                            if let Ok(hdl) = hdl_v.try_lock() {
                                hdl.request_keyframe();
                            }
                        }
                    }
                    Err(RecvFrameError::Disconnected) => {
                        // Capture backend terminated unexpectedly — close data writer so session tears down.
                        if !stop_v.load(Ordering::SeqCst) {
                            warn!("[{key_v}] capture frame channel closed unexpectedly — closing data socket");
                            dw.close();
                        }
                        break;
                    }
                }

                // Re-read pause state AFTER recv_timeout so a `StartStream` or host unlock wakeup
                // resumes immediately without waiting an extra 120ms cycle.
                let is_paused = paused_v.load(Ordering::Acquire)
                    || host_lock_paused_ipad_v.load(Ordering::Acquire);
                if is_paused {
                    was_paused = true;
                    pending_queue.clear();
                    if host_lock_paused_ipad_v.load(Ordering::Acquire) {
                        // Clear cached pre-lock IDR even on the quiet/Timeout path (when hardware
                        // SCStream pause prevents any frames from arriving) so unlock never flashes
                        // a stale pre-lock frame before a live post-unlock IDR arrives.
                        last_sent_idr = None;
                    }
                    ipad_awaiting_idr = true;
                    skip_send_phase = true;
                } else if was_paused {
                    // On StartStream resume, if a fresh live IDR did not already arrive in this tick,
                    // seed pending_queue from THIS session's own last sent IDR for instant static display
                    // while keeping `ipad_awaiting_idr = true` until a live IDR arrives!
                    was_paused = false;
                    let already_got_live_idr = pending_queue
                        .back()
                        .is_some_and(|(_, f)| f.is_keyframe);
                    if !already_got_live_idr {
                        ipad_awaiting_idr = true;
                        if pending_queue.is_empty() {
                            if let Some(idr) = last_sent_idr.clone() {
                                pending_queue.push_back((Instant::now(), idr));
                            }
                        }
                        if let Ok(hdl) = hdl_v.try_lock() {
                            hdl.request_keyframe();
                        }
                    }
                }

                // Enforce wall-clock age cap on queued IPPP frames (protects low-FPS 10-15fps modes
                // from delivering 267-400ms stale frames).
                if !skip_send_phase && !all_intra_v {
                    if let Some((enqueued_at, first_f)) = pending_queue.front() {
                        if !first_f.is_keyframe && enqueued_at.elapsed() > MAX_PENDING_AGE {
                            let stale_n = pending_queue.len() as u64;
                            flow_v.record_drops(stale_n);
                            stats_non_idr_drops += stale_n;
                            pending_queue.clear();
                            ipad_awaiting_idr = true;
                            if last_kf_req.elapsed() >= Duration::from_millis(120) {
                                last_kf_req = Instant::now();
                                if let Ok(hdl) = hdl_v.try_lock() {
                                    hdl.request_keyframe();
                                }
                            }
                        }
                    }
                }

                // Drain at most 2 queued frames per loop iteration so `frame_rx` is polled promptly
                // and shared-mode Web viewers never suffer `slot_overwritten > 0` during catch-up bursts.
                let mut send_failed = false;
                let mut drained_this_tick: usize = 0;
                while !skip_send_phase && drained_this_tick < 2 {
                    let Some((_, frame)) = pending_queue.front().cloned() else {
                        break;
                    };
                    if !flow_v.try_acquire_send_no_drop_count() {
                        // Hold consecutive P-frames so once an ACK wakes us, the intact chain drains smoothly!
                        abr_win_flow_blocked = abr_win_flow_blocked.saturating_add(1);
                        break;
                    }
                    pending_queue.pop_front();
                    drained_this_tick += 1;
                    let frame_len = frame.annex_b.len();
                    let (hdr, hdr_len) = build_video_header(
                        frame.width,
                        frame.height,
                        frame.bytes_per_row,
                        COMPRESSION_H264,
                        proto_ver,
                    );
                    let send_t0 = Instant::now();
                    if let Err(e) = dw.send_frame_parts(&[&hdr[..hdr_len], &frame.annex_b]) {
                        warn!("[{key_v}] video send failed after {sent_frames} frames: {e:#}");
                        dw.close();
                        send_failed = true;
                        break;
                    }
                    let send_ms = send_t0.elapsed().as_millis() as u64;
                    abr_win_sent += 1;
                    abr_win_send_ms_sum += send_ms;
                    abr_win_max_send_ms = abr_win_max_send_ms.max(send_ms);

                    if frame.is_keyframe {
                        last_sent_idr = Some(frame);
                    }
                    sent_frames += 1;
                    stats_frames += 1;
                    stats_bytes += frame_len as u64;
                    stats_max_bytes = stats_max_bytes.max(frame_len);
                    if sent_frames == 1 || sent_frames.is_multiple_of(300) {
                        debug!(
                            "[{key_v}] streamed frame #{sent_frames} ({}x{}, {}B H.264, in_flight={}, backpressure_drops={})",
                            last_logged_size.0,
                            last_logged_size.1,
                            frame_len,
                            flow_v.in_flight(),
                            flow_v.dropped_frames()
                        );
                    }
                }
                if send_failed {
                    break;
                }

                // Check for runtime video setting / ResolutionChange / OrientationChange generation bumps
                // BEFORE the 200ms focus-FPS check so a stale ABR tier can never overwrite a fresh
                // `reconfigure()` (P1-B3).
                let cur_video_gen = video_gen_v.load(Ordering::Acquire);
                if cur_video_gen != last_video_gen {
                    last_video_gen = cur_video_gen;
                    abr.reset(Instant::now());
                    pending_abr_apply = None;
                    last_applied_stream = None;
                    applied_unfocused_halved = false;
                    last_sent_idr = None;
                }

                // Fast cursor-focus check (~200ms): halve iPad FPS after 1.5s unfocused and restore
                // full FPS instantaneously (<200ms) the moment the cursor enters the iPad display.
                // Only runs on backends that support live stream FPS/quality updates (`live_abr_quality`)
                // so Linux/Windows FFmpeg backends never waste cursor polling or misreport halved FPS.
                if supports_live_abr_v
                    && !is_paused
                    && last_focus_check.elapsed() >= Duration::from_millis(200)
                {
                    last_focus_check = Instant::now();
                    let want_half_unfocused = video_v
                        .lock()
                        .map(|v| v.half_fps_when_unfocused)
                        .unwrap_or(false);
                    if !want_half_unfocused {
                        desired_unfocused_halved = false;
                        last_cursor_on_ipad = Instant::now();
                    } else if let Ok(hdl) = hdl_v.try_lock() {
                        if let Some(cur) = hdl.query_cursor() {
                            if cur.visible {
                                last_cursor_on_ipad = Instant::now();
                                desired_unfocused_halved = false;
                            } else if !desired_unfocused_halved
                                && last_cursor_on_ipad.elapsed() >= UNFOCUSED_GRACE
                            {
                                desired_unfocused_halved = true;
                            }
                        }
                    }
                    if desired_unfocused_halved != applied_unfocused_halved
                        && !stop_v.load(Ordering::SeqCst)
                    {
                        let dev_prefs = fingerprint_v
                            .as_deref()
                            .and_then(|fp| trust_store_v.get_device(fp))
                            .map(|d| d.prefs);
                        let cur_vs = Self::overlay_device_prefs(
                            video_v.lock().unwrap().clone(),
                            dev_prefs.as_ref(),
                            low_power_v.load(Ordering::Acquire),
                        );
                        let live_hs = sessions_v
                            .try_lock()
                            .ok()
                            .and_then(|m| m.get(&key_v).and_then(|s| s.handshake.clone()))
                            .unwrap_or_else(|| hs_v.clone());
                        let base_edge = Self::effective_ipad_max_pixel_edge(&live_hs, &cur_vs);
                        let targets = AbrTargets::compute(
                            abr.tier(),
                            cur_vs.fps.max(5),
                            cur_vs.bitrate_mbps.max(2),
                            base_edge,
                        );
                        let eff_fps = if desired_unfocused_halved {
                            (targets.fps / 2).max(5)
                        } else {
                            targets.fps
                        };
                        if let Ok(mut hdl) = hdl_v.try_lock() {
                            if last_applied_stream
                                == Some((eff_fps, targets.bitrate_mbps, targets.max_pixel_edge))
                            {
                                applied_unfocused_halved = desired_unfocused_halved;
                            } else {
                                info!(
                                    "[{key_v}] Cursor focus {}: streaming FPS -> {eff_fps}fps (base={}fps)",
                                    if desired_unfocused_halved { "left iPad" } else { "entered iPad" },
                                    targets.fps
                                );
                                if let Err(e) = hdl.update_stream_quality(
                                    eff_fps,
                                    targets.bitrate_mbps,
                                    targets.max_pixel_edge,
                                ) {
                                    warn!("[{key_v}] Focus FPS update failed (will retry): {e:#}");
                                } else {
                                    last_applied_stream = Some((
                                        eff_fps,
                                        targets.bitrate_mbps,
                                        targets.max_pixel_edge,
                                    ));
                                    applied_unfocused_halved = desired_unfocused_halved;
                                    if let Ok(mut st) = abr_status_v.lock() {
                                        st.target_fps = eff_fps;
                                        st.unfocused_fps_halved = eff_fps < targets.fps;
                                    }
                                }
                            }
                        }
                    }
                }

                // Evaluate network-adaptive quality (ABR) once per second.
                if abr_win_start.elapsed() >= Duration::from_secs(1) {
                    let now = Instant::now();
                    let cur_gen = video_gen_v.load(Ordering::Acquire);
                    let dev_prefs = fingerprint_v
                        .as_deref()
                        .and_then(|fp| trust_store_v.get_device(fp))
                        .map(|d| d.prefs);
                    let cur_vs = Self::overlay_device_prefs(
                        video_v.lock().unwrap().clone(),
                        dev_prefs.as_ref(),
                        low_power_v.load(Ordering::Acquire),
                    );
                    let live_hs = sessions_v
                        .try_lock()
                        .ok()
                        .and_then(|m| m.get(&key_v).and_then(|s| s.handshake.clone()))
                        .unwrap_or_else(|| hs_v.clone());
                    let base_edge = Self::effective_ipad_max_pixel_edge(&live_hs, &cur_vs);
                    let cur_drops_total = flow_v.dropped_frames();
                    let win_drops = cur_drops_total.saturating_sub(abr_prev_drops_total);
                    abr_prev_drops_total = cur_drops_total;

                    let avg_send_ms = if abr_win_sent > 0 {
                        abr_win_send_ms_sum as f64 / abr_win_sent as f64
                    } else {
                        0.0
                    };
                    let rtt_ms = flow_v.ewma_rtt_ms();
                    let limit = flow_v.max_in_flight();
                    let sample = AbrWindowSample {
                        sent_frames: abr_win_sent,
                        dropped_frames: win_drops,
                        avg_send_ms,
                        max_send_ms: abr_win_max_send_ms,
                        avg_ack_rtt_ms: rtt_ms,
                        in_flight_saturated: limit > 0 && abr_win_flow_blocked > 0,
                    };

                    let abr_active = supports_live_abr_v && cur_vs.adaptive_quality;
                    abr.set_sensitivity(cur_vs.abr_sensitivity);
                    let mut target_change: Option<(u8, u8)> = None;
                    if cur_gen != last_video_gen {
                        last_video_gen = cur_gen;
                        abr.reset(now);
                        pending_abr_apply = None;
                        last_applied_stream = None;
                        applied_unfocused_halved = false;
                        last_sent_idr = None;
                    } else if !abr_active {
                        let prev_t = abr.tier();
                        if abr.reset(now) {
                            target_change = Some((prev_t, 0));
                        }
                    } else {
                        let prev_t = abr.tier();
                        if let Some(new_t) = abr.evaluate(&sample, now) {
                            target_change = Some((prev_t, new_t));
                        }
                    }

                    let targets = AbrTargets::compute(
                        abr.tier(),
                        cur_vs.fps.max(5),
                        cur_vs.bitrate_mbps.max(2),
                        base_edge,
                    );
                    let eff_fps = if applied_unfocused_halved {
                        (targets.fps / 2).max(5)
                    } else {
                        targets.fps
                    };
                    if let Ok(mut st) = abr_status_v.lock() {
                        *st = AbrStatusSnapshot {
                            enabled: abr_active,
                            tier: targets.tier,
                            scale_pct: targets.scale_pct,
                            target_fps: eff_fps,
                            target_bitrate_mbps: targets.bitrate_mbps,
                            rtt_ms: rtt_ms.map(|r| r.round() as u32),
                            unfocused_fps_halved: eff_fps < targets.fps,
                        };
                    }

                    // Adaptive in-flight window control (when auto mode is active).
                    if auto_mif_v.load(Ordering::Acquire) {
                        // Reconcile live flow window with controller state after manual -> auto transitions (Iter-9 P2-C1).
                        if flow_v.max_in_flight() != inflight_ctrl.limit() {
                            flow_v.set_max_in_flight(inflight_ctrl.limit());
                        }
                        if let Some(new_limit) = inflight_ctrl.evaluate(&sample, targets.fps, now) {
                            let old_limit = flow_v.max_in_flight();
                            flow_v.set_max_in_flight(new_limit);
                            info!(
                                "[{key_v}] Auto max_in_flight {old_limit} -> {new_limit} ({}, fps={}, avg_send={:.1}ms, rtt={})",
                                if is_usb_v { "USB" } else { "Wi-Fi" },
                                targets.fps,
                                sample.avg_send_ms,
                                rtt_ms
                                    .map(|r| format!("{r:.0}ms"))
                                    .unwrap_or_else(|| "n/a".to_string())
                            );
                            crate::debug_trace::record(
                                "abr",
                                "in_flight_window_change",
                                serde_json::json!({
                                    "key": key_v,
                                    "transport": if is_usb_v { "usb" } else { "wifi" },
                                    "from": old_limit,
                                    "to": new_limit,
                                    "target_fps": targets.fps,
                                    "avg_send_ms": sample.avg_send_ms,
                                    "rtt_ms": rtt_ms,
                                }),
                            );
                        }
                    } else {
                        inflight_ctrl.sync_manual(flow_v.max_in_flight(), now);
                    }

                    if let Some((old_t, new_t)) = target_change {
                        pending_abr_apply = Some((old_t, new_t, targets));
                    }
                    if let Some((old_t, new_t, apply_t)) = pending_abr_apply {
                        if !stop_v.load(Ordering::SeqCst) {
                            if let Ok(mut hdl) = hdl_v.try_lock() {
                                let spec = tier_spec(new_t);
                                info!(
                                    "[{key_v}] ABR tier {old_t} -> {new_t} ({}): {}% stream, {}fps, {}Mbps, max_edge={}px (win sent={}, drops={}, avg_send={:.1}ms, rtt={})",
                                    spec.label,
                                    apply_t.scale_pct,
                                    apply_t.fps,
                                    apply_t.bitrate_mbps,
                                    apply_t.max_pixel_edge,
                                    sample.sent_frames,
                                    sample.dropped_frames,
                                    sample.avg_send_ms,
                                    rtt_ms
                                        .map(|r| format!("{r:.0}ms"))
                                        .unwrap_or_else(|| "n/a".to_string())
                                );
                                crate::debug_trace::record(
                                    "abr",
                                    "tier_change",
                                    serde_json::json!({
                                        "key": key_v,
                                        "from_tier": old_t,
                                        "to_tier": new_t,
                                        "scale_pct": apply_t.scale_pct,
                                        "target_fps": apply_t.fps,
                                        "target_bitrate_mbps": apply_t.bitrate_mbps,
                                        "target_max_edge": apply_t.max_pixel_edge,
                                        "win_sent": sample.sent_frames,
                                        "win_drops": sample.dropped_frames,
                                        "avg_send_ms": sample.avg_send_ms,
                                        "max_send_ms": sample.max_send_ms,
                                        "rtt_ms": rtt_ms,
                                    }),
                                );
                                let apply_fps = if desired_unfocused_halved {
                                    (apply_t.fps / 2).max(5)
                                } else {
                                    apply_t.fps
                                };
                                if let Err(e) = hdl.update_stream_quality(
                                    apply_fps,
                                    apply_t.bitrate_mbps,
                                    apply_t.max_pixel_edge,
                                ) {
                                    warn!("[{key_v}] ABR stream quality update failed (will retry): {e:#}");
                                } else {
                                    last_applied_stream = Some((
                                        apply_fps,
                                        apply_t.bitrate_mbps,
                                        apply_t.max_pixel_edge,
                                    ));
                                    applied_unfocused_halved = desired_unfocused_halved;
                                    pending_abr_apply = None;
                                    if let Ok(mut st) = abr_status_v.lock() {
                                        st.target_fps = apply_fps;
                                        st.target_bitrate_mbps = apply_t.bitrate_mbps;
                                        st.unfocused_fps_halved = apply_fps < apply_t.fps;
                                    }
                                }
                            }
                        }
                    }

                    abr_win_start = now;
                    abr_win_sent = 0;
                    abr_win_flow_blocked = 0;
                    abr_win_send_ms_sum = 0;
                    abr_win_max_send_ms = 0;
                }

                if crate::debug_trace::is_enabled()
                    && stats_started.elapsed() >= Duration::from_secs(2)
                {
                    let elapsed_ms = stats_started.elapsed().as_millis() as u64;
                    let avg_bytes = stats_bytes.checked_div(stats_frames).unwrap_or(0);
                    crate::debug_trace::record(
                        "stream",
                        "stats",
                        serde_json::json!({
                            "key": key_v,
                            "window_ms": elapsed_ms,
                            "pixel_width": last_logged_size.0,
                            "pixel_height": last_logged_size.1,
                            "sent_frames_window": stats_frames,
                            "sent_frames_total": sent_frames,
                            "avg_frame_bytes": avg_bytes,
                            "max_frame_bytes": stats_max_bytes,
                            "in_flight": flow_v.in_flight(),
                            "backpressure_drops_total": flow_v.dropped_frames(),
                            "non_idr_drops_window": stats_non_idr_drops,
                            "abr_tier": abr.tier(),
                            "paused": is_paused,
                        }),
                    );
                    stats_started = Instant::now();
                    stats_frames = 0;
                    stats_bytes = 0;
                    stats_max_bytes = 0;
                    stats_non_idr_drops = 0;
                }
            }
            flow_v.clear_waker_if_gen(data_gen);
            debug!(
                "[{key_v}] video streaming loop stopped (sent={sent_frames}, backpressure_drops={})",
                flow_v.dropped_frames()
            );
        });

        // Cursor handling (hot-toggleable at runtime via Web Admin `client_cursor`):
        // - `client_cursor == false` (default): OS cursor is composited directly into video frames;
        //   cursor thread stays idle (0 cursor polling) and hides any client-side overlay on iPad.
        // - `client_cursor == true`: 120Hz (8ms) ultra-low-latency cursor updates using the 9-byte
        //   native UDP cursor channel on Wi-Fi (when `udp_port > 0` and not disabled) or Telemetry
        //   fallback, throttling cursor PNG polling to ~8Hz so touch input never contends on locks.
        let cursor_thread = if hs.supports_telemetry_cursor || (!is_usb && hs.udp_port > 0) {
            let stop_c = stop_flag.clone();
            let hdl_c = shared_handle.clone();
            let tw_c = tel_writer.clone();
            let udp_flag = udp_cursor_enabled.clone();
            let paused_c = stream_paused.clone();
            let host_lock_paused_c = self.host_lock_paused_ipad.clone();
            let client_cursor_c = self.client_cursor.clone();
            let supports_tel_cursor = hs.supports_telemetry_cursor;
            let udp_target = if !is_usb && hs.udp_port > 0 {
                key.parse::<IpAddr>()
                    .ok()
                    .map(|ip| SocketAddr::new(ip, hs.udp_port))
            } else {
                None
            };
            let udp_sock = udp_target.and_then(|addr| {
                let bind_addr = if addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
                UdpSocket::bind(bind_addr).ok().map(|s| (s, addr))
            });
            if udp_sock.is_none() {
                udp_flag.store(false, Ordering::Release);
            }
            let key_c = key.to_string();
            let polling_c = self.polling.clone();
            let size_c = actual_size.clone();
            let flow_c = flow.clone();
            let is_usb_c = is_usb;
            Some(thread::spawn(move || {
                let mut prev: Option<CursorState> = None;
                let mut prev_png_hash: u64 = 0;
                let mut prev_stream_size: (u32, u32) = (0, 0);
                let mut last_png_poll = Instant::now() - Duration::from_secs(1);
                let mut udp_err_streak: u32 = 0;
                let mut last_motion = Instant::now();
                let mut was_enabled = client_cursor_c.load(Ordering::Acquire);
                if was_enabled {
                    if let Some((_, addr)) = &udp_sock {
                        info!("[{key_c}] Enabled 120Hz ultra-low-latency UDP cursor channel -> {addr}");
                    }
                } else if supports_tel_cursor {
                    if let Ok(bytes) = build_cursor_visible_packet(false).encode() {
                        let _ = tw_c.send_frame(&bytes);
                    }
                }
                while !stop_c.load(Ordering::SeqCst) {
                    let enabled = client_cursor_c.load(Ordering::Acquire);
                    if !enabled {
                        if was_enabled {
                            was_enabled = false;
                            prev = None;
                            prev_png_hash = 0;
                            if let Some((ref sock, target)) = udp_sock {
                                if udp_flag.load(Ordering::Acquire) {
                                    let hide_pkt = build_udp_cursor_position_packet(0, 0, false);
                                    let _ = sock.send_to(&hide_pkt, target);
                                }
                            }
                            if supports_tel_cursor {
                                if let Ok(bytes) = build_cursor_visible_packet(false).encode() {
                                    let _ = tw_c.send_frame(&bytes);
                                }
                            }
                        }
                        thread::sleep(Duration::from_millis(100));
                        continue;
                    }
                    if !was_enabled {
                        was_enabled = true;
                        prev = None;
                        prev_png_hash = 0;
                        if let Some((_, addr)) = &udp_sock {
                            info!("[{key_c}] Enabled 120Hz ultra-low-latency UDP cursor channel -> {addr}");
                        }
                    }
                    if paused_c.load(Ordering::Acquire)
                        || host_lock_paused_c.load(Ordering::Acquire)
                    {
                        thread::sleep(Duration::from_millis(50));
                        continue;
                    }
                    // Non-blocking lock for position (~10us) so `SCStream updateConfiguration:`
                    // during ABR/focus shifts never blocks cursor_thread or piles up contention.
                    let cur = match hdl_c.try_lock() {
                        Ok(g) => g.query_cursor(),
                        Err(_) => {
                            thread::sleep(Duration::from_millis(4));
                            continue;
                        }
                    };
                    if let Some(mut c) = cur {
                        let cur_stream_size = size_c.lock().map(|g| *g).unwrap_or((0, 0));
                        let size_changed = cur_stream_size != prev_stream_size;
                        let mut png_updated = false;

                        // Poll cursor PNG only when Telemetry cursor is supported, on first
                        // visibility, stream resolution/ABR change, or every ~125ms wall-clock
                        // (independent of active cursor_poll_ms so 50ms Wi-Fi fallback stays snappy).
                        if supports_tel_cursor
                            && c.visible
                            && (prev_png_hash == 0
                                || size_changed
                                || last_png_poll.elapsed() >= Duration::from_millis(125))
                        {
                            if let Ok(g) = hdl_c.try_lock() {
                                prev_stream_size = cur_stream_size;
                                last_png_poll = Instant::now();
                                let png = g.cursor_image_png_if_changed(&mut prev_png_hash);
                                drop(g);
                                if let Some(img) = png {
                                    let img_len = img.len();
                                    if let Ok(bytes) = build_cursor_image_packet(img).encode() {
                                        if tw_c.send_frame(&bytes).is_err() {
                                            break;
                                        }
                                    }
                                    debug!(
                                        "[{key_c}] Sent ChangeCursorImage ({img_len}B PNG, stream={}x{})",
                                        cur_stream_size.0, cur_stream_size.1
                                    );
                                    png_updated = true;
                                    // Re-query cursor position once so the hotspot offset matches the newly pushed PNG.
                                    if let Some(fresh) =
                                        hdl_c.try_lock().ok().and_then(|g2| g2.query_cursor())
                                    {
                                        c = fresh;
                                    }
                                } else if prev_png_hash == 0 {
                                    debug!("[{key_c}] cursor_image_png_if_changed() returned None while cursor visible");
                                }
                            }
                        }

                        let vis_changed = prev.map(|p| p.visible != c.visible).unwrap_or(true);
                        let pos_changed = png_updated
                            || prev.map(|p| p.x != c.x || p.y != c.y).unwrap_or(true);

                        let mut pos_suppressed = false;
                        if vis_changed || (c.visible && pos_changed) {
                            last_motion = Instant::now();
                            let use_udp = udp_sock.is_some() && udp_flag.load(Ordering::Acquire);
                            if use_udp {
                                if let Some((ref sock, target)) = udp_sock {
                                    let pkt = build_udp_cursor_position_packet(c.x, c.y, c.visible);
                                    match sock.send_to(&pkt, target) {
                                        Ok(_) => udp_err_streak = 0,
                                        Err(e) => {
                                            udp_err_streak += 1;
                                            let fatal = matches!(
                                                e.kind(),
                                                io::ErrorKind::PermissionDenied
                                                    | io::ErrorKind::InvalidInput
                                                    | io::ErrorKind::AddrNotAvailable
                                            );
                                            if fatal || udp_err_streak >= 5 {
                                                warn!(
                                                    "[{key_c}] UDP cursor send to {target} failed ({e}); falling back to Telemetry cursor"
                                                );
                                                udp_flag.store(false, Ordering::Release);
                                            }
                                        }
                                    }
                                }
                                if vis_changed && supports_tel_cursor {
                                    if let Ok(bytes) =
                                        build_cursor_visible_packet(c.visible).encode()
                                    {
                                        if tw_c.send_frame(&bytes).is_err() {
                                            break;
                                        }
                                    }
                                }
                            } else if supports_tel_cursor {
                                if vis_changed {
                                    if let Ok(bytes) =
                                        build_cursor_visible_packet(c.visible).encode()
                                    {
                                        if tw_c.send_frame(&bytes).is_err() {
                                            break;
                                        }
                                    }
                                    debug!(
                                        "[{key_c}] Sent ChangeCursorVisible({}) via telemetry (pos={},{})",
                                        c.visible, c.x, c.y
                                    );
                                }
                                // Telemetry TCP shares the exact runloop and socket that carries
                                // video `PictureRendered` ACKs on legacy iOS clients (`udp_port=0`).
                                // Defer intermediate position bplists while the video ACK window is
                                // saturated so cursor traffic never starves video ACKs, preserving
                                // `prev`'s last sent (x,y) so the final resting position flushes
                                // immediately once ACKs drain.
                                let flow_lim = flow_c.max_in_flight();
                                let video_ack_saturated =
                                    !is_usb_c && flow_lim > 0 && flow_c.in_flight() >= flow_lim;
                                if c.visible && pos_changed {
                                    if video_ack_saturated {
                                        pos_suppressed = true;
                                    } else if let Ok(bytes) =
                                        build_cursor_position_packet(c.x, c.y).encode()
                                    {
                                        if tw_c.send_frame(&bytes).is_err() {
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        if pos_suppressed {
                            let (last_x, last_y) = prev
                                .map(|p| (p.x, p.y))
                                .unwrap_or((u32::MAX, u32::MAX));
                            prev = Some(CursorState {
                                x: last_x,
                                y: last_y,
                                visible: c.visible,
                            });
                        } else {
                            prev = Some(c);
                        }
                    }
                    let base_ms = polling_c
                        .lock()
                        .map(|p| p.cursor_poll_ms)
                        .unwrap_or(8);
                    let using_udp = udp_sock.is_some() && udp_flag.load(Ordering::Acquire);
                    // Wi-Fi Telemetry TCP fallback (`udp_port=0`) serializes ~600B bplists on the
                    // same runloop as video ACKs — cap fallback polling to <=20Hz (50ms); keep USB
                    // responsive (>=60Hz / 16ms) and native 9-byte UDP at full `base_ms` (125Hz).
                    let active_ms = if using_udp {
                        base_ms
                    } else if is_usb_c {
                        base_ms.max(16)
                    } else {
                        base_ms.max(50)
                    };
                    let sleep_ms = if last_motion.elapsed() > Duration::from_millis(500) {
                        active_ms.max(50)
                    } else {
                        active_ms
                    };
                    thread::sleep(Duration::from_millis(sleep_ms));
                }
            }))
        } else {
            None
        };

        let mut active = Some(ActiveCapture {
            id: cap_id,
            handle: shared_handle,
            stop_flag,
            actual_size,
            abr_status,
            stream_thread: Some(stream_thread),
            cursor_thread,
        });
        let displaced = {
            let mut map = self.sessions.lock().unwrap();
            if let Some(sess) = map.get_mut(key) {
                if sess.id == session_id && sess.data_generation == data_gen {
                    sess.flow.set_waker_for_gen(data_gen, frame_waker);
                    std::mem::replace(&mut sess.capture, active.take())
                } else {
                    None
                }
            } else {
                None
            }
        };
        // Always shut down any displaced or orphaned ActiveCapture OUTSIDE `sessions` lock!
        if let Some(mut prev) = displaced {
            prev.shutdown();
        }
        if let Some(mut orphan) = active {
            data_writer.close();
            orphan.shutdown();
            self.schedule_standalone_web_resume_after(Duration::from_secs(6));
            return Err(anyhow!(
                "data channel attachment superseded or closed during start_capture"
            ));
        } else {
            // Re-sync OS cursor visibility in case `client_cursor` was toggled during blocking `start_capture()` (P2-B3).
            let want_show_cursor = !self.is_client_cursor();
            if want_show_cursor != initial_show_cursor {
                let hdl_opt = self
                    .sessions
                    .lock()
                    .unwrap()
                    .get(key)
                    .filter(|s| s.id == session_id && s.data_generation == data_gen)
                    .and_then(|s| s.capture.as_ref().map(|c| c.handle.clone()));
                if let Some(hdl) = hdl_opt {
                    if let Ok(mut g) = hdl.lock() {
                        let _ = g.set_show_cursor(want_show_cursor);
                    }
                }
            }
            // Re-stop standalone Web capture in follow-iPad mode in case a Web viewer subscribed during `start_capture()`.
            self.stop_standalone_web_capture_if_following_ipad();
            // Immediately sync hardware capture pause state in case host lock or stream pause is already active.
            self.sync_capture_pause_states();
            // Clear dedup for iPad window-routing rules so newly connected iPad pulls matching windows once.
            self.on_ipad_screen_online_for_window_rules();
            // Wake main thread so macOS immediately pumps CoreGraphics display reconfiguration notifications.
            self.notify_lifecycle_wakeup();
        }
        Ok((session_id, data_gen))
    }

    /// Synthesize a safety `MouseUp` outside `self.sessions` lock so an abrupt disconnect,
    /// screen lock, or view-only switch mid-drag never leaves the host left mouse button stuck.
    pub(super) fn release_stuck_mouse_handle(
        handle: &super::flow_control::SharedCaptureHandle,
        pos: Option<(f64, f64)>,
    ) {
        if let Some((x, y)) = pos {
            if let Ok(g) = handle.lock() {
                let _ = g.inject_input(&crate::protocol::messages::InputEvent::MouseUp {
                    x,
                    y,
                    double_click: false,
                });
            }
        }
    }

    /// Release any held left mouse buttons across all active iPad sessions (used when toggling
    /// view-only or pausing iPad input on host screen lock).
    pub(super) fn release_all_stuck_mouse_buttons(&self) {
        let pending: Vec<(super::flow_control::SharedCaptureHandle, (f64, f64))> = {
            let mut map = self.sessions.lock().unwrap();
            let mut out = Vec::new();
            for sess in map.values_mut() {
                sess.suppress_right_click_tail = false;
                sess.edge_gesture.reset();
                if let Some(pos) = sess.mouse_left_down.take() {
                    if let Some(ref cap) = sess.capture {
                        out.push((cap.handle.clone(), pos));
                    }
                }
            }
            out
        };
        for (hdl, pos) in pending {
            Self::release_stuck_mouse_handle(&hdl, Some(pos));
        }
    }

    /// Detach a session's Data channel & capture only if both `session_id` and `data_generation`
    /// still match (preserves healthy Telemetry so legacy iDisplay can reopen Data on resume/blip).
    pub fn close_data_attachment_if_match(&self, key: &str, session_id: u64, data_gen: u64) {
        let (cap_opt, dw_opt, stuck_mouse) = {
            let mut map = self.sessions.lock().unwrap();
            if let Some(sess) = map
                .get_mut(key)
                .filter(|s| s.id == session_id && s.data_generation == data_gen)
            {
                sess.data_detached_at = Some(Instant::now());
                sess.suppress_right_click_tail = false;
                sess.edge_gesture.reset();
                (
                    sess.capture.take(),
                    sess.data_writer.take(),
                    sess.mouse_left_down.take(),
                )
            } else {
                (None, None, None)
            }
        };
        let detached = cap_opt.is_some() || dw_opt.is_some();
        if detached {
            self.record_external_activity();
        }
        // Close socket and release any stuck mouse button + join capture/writer threads BEFORE
        // releasing `web_follow_ipad_session_id`, bumping `web_source_epoch`, and clearing
        // `last_ipad_web_frame` so the dying iPad thread can NEVER re-claim ownership or poison
        // the cache under the new epoch (Iter-8 P1-B2).
        if let Some(dw) = dw_opt {
            dw.close();
        }
        if let Some(mut cap) = cap_opt {
            Self::release_stuck_mouse_handle(&cap.handle, stuck_mouse);
            cap.shutdown();
        }
        let mut was_follow_owner = false;
        if detached {
            if self
                .web_follow_ipad_session_id
                .compare_exchange(session_id, 0, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                was_follow_owner = true;
                if self.web_screen_mode() == crate::config::WebScreenMode::FollowIpad {
                    self.bump_web_source_epoch();
                }
                if let Ok(mut lf) = self.last_ipad_web_frame.lock() {
                    *lf = None;
                }
            }
            if was_follow_owner {
                self.sync_capture_pause_states();
                self.request_active_keyframes();
            }
            // Delay standalone Web virtual display spin-up by 6s in follow-iPad mode so a brief
            // iPad Wi-Fi blip/reconnect does not thrash macOS virtual displays (`168 -> 169 -> 170`).
            self.schedule_standalone_web_resume_after(Duration::from_secs(6));
        }
    }

    /// Handle incoming client-to-host bytes on the Data channel (`MSMTouchEvent` / `MSMKeyboardEvent` / `MSMWheelEvent`).
    pub fn handle_data_bytes(&self, key: &str, bytes: &[u8]) -> Result<()> {
        self.handle_data_bytes_for_session(key, None, None, bytes)
    }

    /// Session/generation-scoped data input handler so displaced Data sockets cannot inject input
    /// or refresh activity on a newer reconnected session.
    pub fn handle_data_bytes_for_session(
        &self,
        key: &str,
        expected_session_id: Option<u64>,
        expected_data_gen: Option<u64>,
        bytes: &[u8],
    ) -> Result<()> {
        let (handle_opt, actual_session_id, stream_size) = {
            let mut map = self.sessions.lock().unwrap();
            let Some(sess) = map.get_mut(key).filter(|s| {
                expected_session_id.is_none_or(|eid| s.id == eid)
                    && expected_data_gen.is_none_or(|dg| s.data_generation == dg)
            }) else {
                return Ok(());
            };
            sess.last_activity = Instant::now();
            let sz = sess
                .capture
                .as_ref()
                .and_then(|c| c.actual_size.lock().ok().map(|g| *g))
                .unwrap_or((0, 0));
            (sess.capture.as_ref().map(|c| c.handle.clone()), sess.id, sz)
        };
        if handle_opt.is_none() {
            return Ok(());
        }
        self.input_counters.received.fetch_add(1, Ordering::Relaxed);
        if self.host_lock_paused_ipad.load(Ordering::Acquire)
            || self.is_ipad_lock_disconnect_blocking()
        {
            self.input_counters
                .dropped_locked
                .fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        let gestures_cfg = self.gestures_config();
        let input_allowed = self.is_input_allowed();
        if !input_allowed && !gestures_cfg.has_any_active_action() {
            let n = self
                .input_counters
                .dropped_view_only
                .fetch_add(1, Ordering::Relaxed);
            if n == 0 || n == 20 {
                warn!(
                    "[{key}] Ignoring incoming remote touch/keyboard input because remote input is disabled (pass --allow-input or enable it in Web Admin Console)"
                );
                crate::debug_trace::record(
                    "input",
                    "ignored_view_only",
                    serde_json::json!({ "key": key, "len": bytes.len(), "dropped_count": n + 1 }),
                );
            }
            return Ok(());
        }
        let caps = self.backend.capabilities();
        let has_accessibility =
            !caps.accessibility_permission_required || caps.accessibility_granted;
        if input_allowed && !has_accessibility && !gestures_cfg.has_any_session_control_action() {
            let n = self
                .input_counters
                .dropped_no_permission
                .fetch_add(1, Ordering::Relaxed);
            if n == 0 || n == 20 {
                warn!(
                    "[{key}] Dropping incoming remote input because OS Accessibility permission is NOT granted (if you upgraded idis or switched to launchd, remove and re-add idis in System Settings -> Privacy & Security -> Accessibility)"
                );
                crate::debug_trace::record(
                    "input",
                    "dropped_no_accessibility",
                    serde_json::json!({ "key": key, "len": bytes.len(), "dropped_count": n + 1 }),
                );
            }
            return Ok(());
        }
        // Extract 1 or more `bplist` input payloads from USB PeerTalk / Wi-Fi Canal framing:
        // handles raw `bplist`, single or coalesced `[u32_le len][bplist...]`, single or coalesced
        // `[u32_be len][bplist...]`, and small (<=32B) protocol prefix headers before `bplist`.
        let payloads = extract_bplist_payloads(bytes);
        let mut last_err: Option<anyhow::Error> = None;
        for payload in payloads {
            let event = match decode_input_event(payload) {
                Ok(Some(ev)) => ev,
                Ok(None) => {
                    self.input_counters
                        .decode_errors
                        .fetch_add(1, Ordering::Relaxed);
                    static UNKNOWN_INPUT_LOGS: AtomicU32 = AtomicU32::new(0);
                    if UNKNOWN_INPUT_LOGS.fetch_add(1, Ordering::Relaxed) < 8 {
                        let head_hex: String = payload
                            .iter()
                            .take(16)
                            .map(|b| format!("{b:02x}"))
                            .collect();
                        let desc = describe_archived_bplist(payload)
                            .unwrap_or_else(|| "unparseable".to_string());
                        warn!(
                            "[{key}] Received unrecognized input object on Data channel (len={}, head={head_hex}, {desc})",
                            payload.len()
                        );
                        crate::debug_trace::record(
                            "input",
                            "unrecognized_object",
                            serde_json::json!({ "key": key, "len": payload.len(), "head_hex": head_hex, "desc": desc }),
                        );
                    }
                    continue;
                }
                Err(e) => {
                    self.input_counters
                        .decode_errors
                        .fetch_add(1, Ordering::Relaxed);
                    static DECODE_ERR_LOGS: AtomicU32 = AtomicU32::new(0);
                    if DECODE_ERR_LOGS.fetch_add(1, Ordering::Relaxed) < 8 {
                        let head_hex: String = bytes
                            .iter()
                            .take(24)
                            .map(|b| format!("{b:02x}"))
                            .collect();
                        warn!(
                            "[{key}] Failed to decode input packet on Data channel (len={}, head={head_hex}): {e:#}",
                            bytes.len()
                        );
                        crate::debug_trace::record(
                            "input",
                            "decode_error",
                            serde_json::json!({ "key": key, "len": bytes.len(), "head_hex": head_hex, "err": format!("{e:#}") }),
                        );
                    }
                    last_err = Some(e);
                    continue;
                }
            };

            let decision = {
                let mut map = self.sessions.lock().unwrap();
                if self.host_lock_paused_ipad.load(Ordering::Acquire)
                    || self.is_ipad_lock_disconnect_blocking()
                {
                    super::gestures::GestureDecision::Swallow
                } else if let Some(sess) = map.get_mut(key).filter(|s| {
                    expected_session_id.is_none_or(|eid| s.id == eid)
                        && expected_data_gen.is_none_or(|dg| s.data_generation == dg)
                }) {
                    sess.edge_gesture
                        .on_event(&event, stream_size, &gestures_cfg, Instant::now())
                } else {
                    super::gestures::GestureDecision::Swallow
                }
            };

            let events_to_inject: Vec<crate::protocol::messages::InputEvent> = match decision {
                super::gestures::GestureDecision::Swallow => continue,
                super::gestures::GestureDecision::Trigger {
                    slot,
                    action,
                    start_x,
                    start_y,
                } => {
                    let disconnected = self.execute_edge_gesture(
                        key,
                        actual_session_id,
                        &handle_opt,
                        slot,
                        action,
                        start_x,
                        start_y,
                        has_accessibility,
                    )?;
                    if disconnected {
                        break;
                    }
                    continue;
                }
                super::gestures::GestureDecision::Passthrough => vec![event],
                super::gestures::GestureDecision::Replay(evts) => evts,
            };

            for ev in events_to_inject {
                if !self.is_input_allowed() {
                    self.input_counters
                        .dropped_view_only
                        .fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                if !has_accessibility {
                    self.input_counters
                        .dropped_no_permission
                        .fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let should_inject = {
                    let mut map = self.sessions.lock().unwrap();
                    if !self.is_input_allowed()
                        || self.host_lock_paused_ipad.load(Ordering::Acquire)
                        || self.is_ipad_lock_disconnect_blocking()
                    {
                        false
                    } else if let Some(sess) = map.get_mut(key).filter(|s| {
                        expected_session_id.is_none_or(|eid| s.id == eid)
                            && expected_data_gen.is_none_or(|dg| s.data_generation == dg)
                    }) {
                        match &ev {
                            crate::protocol::messages::InputEvent::MouseDown {
                                x,
                                y,
                                right_click,
                                ..
                            } => {
                                if *right_click {
                                    sess.suppress_right_click_tail = true;
                                    sess.mouse_left_down = None;
                                } else {
                                    sess.suppress_right_click_tail = false;
                                    sess.mouse_left_down = Some((*x, *y));
                                }
                                true
                            }
                            crate::protocol::messages::InputEvent::MouseDragged { x, y } => {
                                if sess.suppress_right_click_tail {
                                    false
                                } else {
                                    if sess.mouse_left_down.is_some() {
                                        sess.mouse_left_down = Some((*x, *y));
                                    }
                                    true
                                }
                            }
                            crate::protocol::messages::InputEvent::MouseUp { .. } => {
                                if sess.suppress_right_click_tail {
                                    sess.suppress_right_click_tail = false;
                                    false
                                } else {
                                    sess.mouse_left_down = None;
                                    true
                                }
                            }
                            _ => true,
                        }
                    } else {
                        false
                    }
                };
                if should_inject {
                    if let Some(ref hdl) = handle_opt {
                        if let Ok(g) = hdl.lock() {
                            g.inject_input(&ev)?;
                            self.input_counters.injected.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
        }
        if let Some(e) = last_err {
            return Err(e);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_edge_gesture(
        &self,
        key: &str,
        session_id: u64,
        handle_opt: &Option<super::flow_control::SharedCaptureHandle>,
        slot: crate::user_config::EdgeGestureSlot,
        action: crate::user_config::GestureAction,
        start_x: f64,
        start_y: f64,
        has_accessibility: bool,
    ) -> Result<bool> {
        use crate::user_config::{parse_hotkey_spec, GestureAction};

        if action.is_none() {
            return Ok(false);
        }
        if action.requires_host_input() {
            if !self.is_input_allowed() {
                self.input_counters
                    .dropped_view_only
                    .fetch_add(1, Ordering::Relaxed);
                *self.last_gesture.lock().unwrap() = Some(super::gestures::LastGestureSnapshot::now(
                    slot,
                    &action,
                    key,
                    None,
                    Some("已关闭远程触控".to_string()),
                ));
                return Ok(false);
            }
            if !has_accessibility {
                self.input_counters
                    .dropped_no_permission
                    .fetch_add(1, Ordering::Relaxed);
                *self.last_gesture.lock().unwrap() = Some(super::gestures::LastGestureSnapshot::now(
                    slot,
                    &action,
                    key,
                    None,
                    Some("缺少系统辅助功能权限".to_string()),
                ));
                return Ok(false);
            }
        }

        self.input_counters
            .gestures_triggered
            .fetch_add(1, Ordering::Relaxed);
        info!(
            "[{key}] Edge gesture triggered: {} -> {}",
            slot.as_str(),
            action.describe()
        );
        crate::debug_trace::record(
            "gesture",
            "triggered",
            serde_json::json!({
                "key": key,
                "slot": slot.as_str(),
                "action": action.describe(),
            }),
        );

        let mut detail: Option<String> = None;
        let mut blocked_reason: Option<String> = None;
        let mut disconnected = false;
        match &action {
            GestureAction::None => {}
            GestureAction::TogglePause => {
                let toggled = {
                    let map = self.sessions.lock().unwrap();
                    if let Some(sess) = map.get(key).filter(|s| s.id == session_id) {
                        let next = !sess.stream_paused.load(Ordering::Acquire);
                        sess.stream_paused.store(next, Ordering::Release);
                        if !next {
                            sess.flow.reset_in_flight();
                        }
                        Some(next)
                    } else {
                        None
                    }
                };
                if let Some(paused) = toggled {
                    info!("[{key}] Gesture TogglePause -> stream_paused={paused}");
                    self.sync_capture_pause_states();
                }
            }
            GestureAction::Disconnect => {
                info!("[{key}] Gesture Disconnect -> closing iPad session");
                self.close_session_if_id(key, session_id);
                disconnected = true;
            }
            GestureAction::ToggleInput => {
                let next = !self.is_input_allowed();
                self.set_input_allowed(next);
            }
            GestureAction::ToggleLowPower => {
                let next = !self.is_low_power();
                self.set_low_power(next);
            }
            GestureAction::CyclePreset => {
                let (active, presets) = self.list_presets();
                if let Some(next_name) = if presets.is_empty() {
                    None
                } else {
                    let next_idx = active
                        .as_deref()
                        .and_then(|cur| presets.iter().position(|p| p.name == cur))
                        .map(|i| (i + 1) % presets.len())
                        .unwrap_or(0);
                    Some(presets[next_idx].name.clone())
                } {
                    if let Err(e) = self.apply_preset(&next_name) {
                        warn!("[{key}] Gesture CyclePreset({next_name}) failed: {e:#}");
                        blocked_reason = Some(format!("切换预设失败: {e}"));
                    }
                }
            }
            GestureAction::ApplyPreset { preset } => {
                if let Err(e) = self.apply_preset(preset) {
                    warn!("[{key}] Gesture ApplyPreset({preset}) failed: {e:#}");
                    blocked_reason = Some(format!("应用预设失败: {e}"));
                }
            }
            GestureAction::RequestKeyframe => {
                if let Some(ref hdl) = handle_opt {
                    if let Ok(g) = hdl.lock() {
                        g.request_keyframe();
                    }
                }
            }
            GestureAction::Screenshot => {
                let base_dir = crate::user_config::resolve_screenshot_base_dir(
                    &self.gestures_config().screenshot_dir,
                );
                let parts = super::gestures::local_date_time_now();
                let mut seq = 0u64;
                let (dated_dir, mut dest_path) =
                    super::gestures::build_screenshot_target_path(&base_dir, parts, seq);
                while dest_path.exists() && seq < 1000 {
                    seq += 1;
                    dest_path =
                        super::gestures::build_screenshot_target_path(&base_dir, parts, seq).1;
                }
                match std::fs::create_dir_all(&dated_dir) {
                    Ok(()) => {
                        if let Some(ref hdl) = handle_opt {
                            match hdl.lock() {
                                Ok(g) => match g.save_screenshot_png(&dest_path) {
                                    Ok(()) => {
                                        let saved = dest_path.to_string_lossy().into_owned();
                                        info!("[{key}] Gesture Screenshot saved to {saved}");
                                        detail = Some(saved);
                                    }
                                    Err(e) => {
                                        warn!("[{key}] Gesture Screenshot failed: {e:#}");
                                        blocked_reason = Some(format!("截屏保存失败: {e}"));
                                    }
                                },
                                Err(_) => {
                                    blocked_reason = Some("采集句柄不可用".to_string());
                                }
                            }
                        } else {
                            blocked_reason = Some("当前无活跃画面采集".to_string());
                        }
                    }
                    Err(e) => {
                        warn!(
                            "[{key}] Gesture Screenshot failed to create directory {}: {e:#}",
                            dated_dir.display()
                        );
                        blocked_reason = Some(format!("创建目录失败: {e}"));
                    }
                }
            }
            GestureAction::Hotkey { keys } => match parse_hotkey_spec(keys) {
                Ok(parsed) => {
                    if let Some(ref hdl) = handle_opt {
                        if let Ok(g) = hdl.lock() {
                            g.inject_input(&parsed.to_input_event())?;
                            self.input_counters.injected.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                Err(e) => {
                    warn!("[{key}] Gesture Hotkey({keys}) invalid: {e:#}");
                    blocked_reason = Some(format!("快捷键无效: {e}"));
                }
            },
            GestureAction::RightClick => {
                if let Some(ref hdl) = handle_opt {
                    if let Ok(g) = hdl.lock() {
                        g.inject_input(&crate::protocol::messages::InputEvent::MouseDown {
                            x: start_x,
                            y: start_y,
                            right_click: true,
                            tap_count: 1,
                        })?;
                        self.input_counters.injected.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            GestureAction::Scroll { delta } => {
                if let Some(ref hdl) = handle_opt {
                    if let Ok(g) = hdl.lock() {
                        g.inject_input(&crate::protocol::messages::InputEvent::Scroll {
                            dx: 0.0,
                            dy: *delta as f64,
                        })?;
                        self.input_counters.injected.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }

        *self.last_gesture.lock().unwrap() = Some(super::gestures::LastGestureSnapshot::now(
            slot,
            &action,
            key,
            detail,
            blocked_reason,
        ));
        Ok(disconnected)
    }
}

/// Extract one or more `bplist` payloads from a Data-channel / USB PeerTalk frame.
pub(super) fn extract_bplist_payloads(bytes: &[u8]) -> Vec<&[u8]> {
    if bytes.starts_with(b"bplist") {
        return vec![bytes];
    }
    // Try coalesced `[u32_le len][bplist...]` and `[u32_be len][bplist...]` streams.
    // If a trailing coalesced chunk is truncated, preserve any already-validated leading chunks.
    let mut best_prefix: Vec<&[u8]> = Vec::new();
    for big_endian in [false, true] {
        let mut out = Vec::new();
        let mut off = 0usize;
        let mut ok = true;
        while off + 4 <= bytes.len() {
            let len = if big_endian {
                u32::from_be_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
                    as usize
            } else {
                u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
                    as usize
            };
            off += 4;
            if len < 8 || off + len > bytes.len() || !bytes[off..off + len].starts_with(b"bplist") {
                ok = false;
                break;
            }
            out.push(&bytes[off..off + len]);
            off += len;
        }
        if ok && off == bytes.len() && !out.is_empty() {
            return out;
        }
        if out.len() > best_prefix.len() {
            best_prefix = out;
        }
    }
    if !best_prefix.is_empty() {
        return best_prefix;
    }
    // Fallback: locate an embedded `bplist` marker after a small (<=32B) transport header.
    let scan_limit = bytes.len().min(38);
    if let Some(pos) = bytes[..scan_limit]
        .windows(6)
        .position(|w| w == b"bplist")
    {
        return vec![&bytes[pos..]];
    }
    vec![bytes]
}
