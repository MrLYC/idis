use super::flow_control::{sync_capture_pause_states_inner, SharedCaptureHandle};
use super::SessionRegistry;
use crate::config::LockAction;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tracing::{debug, info};

impl SessionRegistry {
    pub fn notify_lifecycle_wakeup(&self) {
        let (lock, cvar) = &*self.activity_signal;
        if let Ok(mut seq) = lock.lock() {
            *seq = seq.wrapping_add(1);
        }
        cvar.notify_all();
    }

    pub fn record_external_activity(&self) {
        if let Ok(mut ts) = self.last_global_activity.lock() {
            *ts = Instant::now();
        }
        self.notify_lifecycle_wakeup();
    }

    /// True if any iPad session (including pre-auth/handshaking), Web viewer, or ephemeral standalone virtual display is currently active.
    pub fn has_any_sessions_or_viewers(&self) -> bool {
        !self.sessions.lock().unwrap().is_empty()
            || !self.web_subscribers.lock().unwrap().is_empty()
            || self.has_standalone_virtual_displays()
    }

    /// Block with zero periodic CPU wakeups while idle until either:
    /// - `stop` becomes `true`,
    /// - a session or Web viewer connects (or `notify_lifecycle_wakeup()` fires), or
    /// - `max_wait` elapses (when `--idle-exit-secs > 0`).
    ///
    /// Uses a generation-snapshot check so `activity_signal` remains a strict leaf lock (never
    /// nested with `sessions`/`web_subscribers`) while guaranteeing zero lost wakeups.
    pub fn wait_idle(&self, stop: &AtomicBool, max_wait: Option<Duration>) {
        let (lock, cvar) = &*self.activity_signal;
        let observed_seq = *lock.lock().unwrap();
        if stop.load(Ordering::SeqCst) || self.has_any_sessions_or_viewers() {
            return;
        }
        let guard = lock.lock().unwrap();
        if *guard != observed_seq || stop.load(Ordering::SeqCst) {
            return;
        }
        let _guard = match max_wait {
            Some(dur) if dur.is_zero() => guard,
            Some(dur) => {
                cvar.wait_timeout_while(guard, dur, |seq| {
                    *seq == observed_seq && !stop.load(Ordering::SeqCst)
                })
                .unwrap()
                .0
            }
            None => cvar
                .wait_while(guard, |seq| {
                    *seq == observed_seq && !stop.load(Ordering::SeqCst)
                })
                .unwrap(),
        };
    }

    pub fn lifecycle_seq(&self) -> u64 {
        *self.activity_signal.0.lock().unwrap()
    }

    /// Zero-polling condvar wait keyed to a previously observed `lifecycle_seq()` so callers can
    /// inspect state, compute an exact deadline, and sleep with zero lost-wakeup races.
    pub fn wait_lifecycle_since(
        &self,
        observed_seq: u64,
        stop_a: &AtomicBool,
        stop_g: &AtomicBool,
        max_wait: Option<Duration>,
    ) {
        let (lock, cvar) = &*self.activity_signal;
        let guard = lock.lock().unwrap();
        if *guard != observed_seq || stop_a.load(Ordering::SeqCst) || stop_g.load(Ordering::SeqCst) {
            return;
        }
        let _guard = match max_wait {
            Some(dur) if dur.is_zero() => guard,
            Some(dur) => {
                cvar.wait_timeout_while(guard, dur, |seq| {
                    *seq == observed_seq
                        && !stop_a.load(Ordering::SeqCst)
                        && !stop_g.load(Ordering::SeqCst)
                })
                .unwrap()
                .0
            }
            None => cvar
                .wait_while(guard, |seq| {
                    *seq == observed_seq
                        && !stop_a.load(Ordering::SeqCst)
                        && !stop_g.load(Ordering::SeqCst)
                })
                .unwrap(),
        };
    }

    /// Sleep up to `max_wait` during active sessions, waking immediately if `stop` is set or
    /// `notify_lifecycle_wakeup()` fires (e.g. display creation/reconfigure so macOS drains its
    /// main `CFRunLoop` promptly even when `main_loop_ms` is configured high).
    pub fn wait_active_tick(&self, stop: &AtomicBool, max_wait: Duration) {
        if stop.load(Ordering::SeqCst) || max_wait.is_zero() {
            return;
        }
        let (lock, cvar) = &*self.activity_signal;
        let guard = lock.lock().unwrap();
        let observed_seq = *guard;
        if stop.load(Ordering::SeqCst) {
            return;
        }
        let _ = cvar.wait_timeout_while(guard, max_wait, |seq| {
            *seq == observed_seq && !stop.load(Ordering::SeqCst)
        });
    }

    /// Called when the host detects a sleep/wake clock jump so active sessions and `--idle-exit-secs`
    /// receive a clean post-wake grace window instead of being instantaneously reaped on wake.
    pub fn on_system_wake(&self) {
        let now = Instant::now();
        self.record_external_activity();
        self.record_wifi_activity();
        self.record_web_activity();
        if let Ok(mut g) = self.wake_grace_until.lock() {
            *g = Some(now + Duration::from_secs(15));
        }
        if let Ok(mut map) = self.sessions.lock() {
            for sess in map.values_mut() {
                if sess.authorized {
                    sess.last_activity = now;
                    if sess.data_detached_at.is_some() {
                        sess.data_detached_at = Some(now);
                    }
                    if sess.capture.is_none() && sess.authorized_at.is_some() {
                        sess.authorized_at = Some(now);
                    }
                }
            }
        }
    }

    pub fn lock_action_ipad(&self) -> LockAction {
        *self.lock_action_ipad.lock().unwrap()
    }

    pub fn lock_action_web(&self) -> LockAction {
        *self.lock_action_web.lock().unwrap()
    }

    /// Backwards-compatible shorthand returning the iPad lock policy.
    pub fn lock_action(&self) -> LockAction {
        self.lock_action_ipad()
    }

    pub fn lock_delay_secs(&self) -> u64 {
        self.lock_delay_secs.load(Ordering::Acquire)
    }

    pub fn set_lock_delay_secs(&self, secs: u64) {
        let clamped = secs.min(3600);
        let prev = self.lock_delay_secs.swap(clamped, Ordering::AcqRel);
        if prev != clamped {
            info!("Host screen-lock grace delay updated: {prev}s -> {clamped}s");
            self.persist_config_patch(|c| c.lock_delay_secs = clamped);
        }
        self.tick_host_lock_policy();
    }

    pub fn set_lock_action_ipad(&self, action: LockAction) {
        let prev = {
            let mut g = self.lock_action_ipad.lock().unwrap();
            let p = *g;
            *g = action;
            p
        };
        if prev != action {
            info!("Host screen-lock policy (iPad) updated: {prev:?} -> {action:?}");
            crate::debug_trace::record(
                "lifecycle",
                "lock_action_changed",
                serde_json::json!({ "target": "ipad", "from": prev, "to": action }),
            );
            self.persist_config_patch(|c| c.lock_action_ipad = action);
        }
        self.refresh_lock_policy_if_locked();
    }

    pub fn set_lock_action_web(&self, action: LockAction) {
        let prev = {
            let mut g = self.lock_action_web.lock().unwrap();
            let p = *g;
            *g = action;
            p
        };
        if prev != action {
            info!("Host screen-lock policy (Web) updated: {prev:?} -> {action:?}");
            crate::debug_trace::record(
                "lifecycle",
                "lock_action_changed",
                serde_json::json!({ "target": "web", "from": prev, "to": action }),
            );
            self.persist_config_patch(|c| c.lock_action_web = action);
        }
        self.refresh_lock_policy_if_locked();
    }

    /// Legacy unified setter: updates both iPad and Web lock-screen policies.
    pub fn set_lock_action(&self, action: LockAction) {
        self.set_lock_action_ipad(action);
        self.set_lock_action_web(action);
    }

    pub(super) fn refresh_lock_policy_if_locked(&self) {
        let transition = {
            let _lg = self.host_lock_mutex.lock().unwrap();
            if !self.is_host_screen_locked() {
                None
            } else if self.lock_action_ipad() == LockAction::Keep
                && self.lock_action_web() == LockAction::Keep
            {
                self.host_lock_enforced.store(false, Ordering::SeqCst);
                let ep = self.lock_state_epoch.fetch_add(1, Ordering::AcqRel) + 1;
                Some((false, ep))
            } else if self.host_lock_enforced.load(Ordering::Acquire) {
                let ep = self.lock_state_epoch.fetch_add(1, Ordering::AcqRel) + 1;
                Some((true, ep))
            } else {
                let delay = Duration::from_secs(self.lock_delay_secs());
                let elapsed_ok = self
                    .host_locked_since
                    .lock()
                    .ok()
                    .and_then(|g| *g)
                    .is_some_and(|since| since.elapsed() >= delay);
                if elapsed_ok {
                    self.host_lock_enforced.store(true, Ordering::SeqCst);
                    let ep = self.lock_state_epoch.fetch_add(1, Ordering::AcqRel) + 1;
                    Some((true, ep))
                } else {
                    None
                }
            }
        };
        if let Some((enforced, ep)) = transition {
            self.apply_host_lock_state(enforced, ep);
        }
    }

    pub fn is_host_screen_locked(&self) -> bool {
        self.host_screen_locked.load(Ordering::Acquire)
    }

    pub fn is_host_lock_enforced(&self) -> bool {
        self.host_lock_enforced.load(Ordering::Acquire)
    }

    pub fn is_host_lock_paused_ipad(&self) -> bool {
        self.host_lock_paused_ipad.load(Ordering::Acquire)
    }

    pub fn is_host_lock_paused_web(&self) -> bool {
        self.host_lock_paused_web.load(Ordering::Acquire)
    }

    pub fn lock_state_epoch(&self) -> u64 {
        self.lock_state_epoch.load(Ordering::Acquire)
    }

    /// True while the host screen is locked, grace delay has elapsed, and iPad lock policy is `disconnect`.
    pub fn is_ipad_lock_disconnect_blocking(&self) -> bool {
        self.is_host_screen_locked()
            && self.host_lock_enforced.load(Ordering::Acquire)
            && self.lock_action_ipad() == LockAction::Disconnect
    }

    /// True while the host screen is locked, grace delay has elapsed, and Web lock policy is `disconnect`.
    pub fn is_web_lock_disconnect_blocking(&self) -> bool {
        self.is_host_screen_locked()
            && self.host_lock_enforced.load(Ordering::Acquire)
            && self.lock_action_web() == LockAction::Disconnect
    }

    /// True while the host screen is locked (including during grace delay for existing sessions)
    /// and Web lock policy is `disconnect`, so NEW incoming Web viewers are rejected immediately.
    pub fn is_web_lock_disconnect_admit_blocked(&self) -> bool {
        self.is_host_screen_locked() && self.lock_action_web() == LockAction::Disconnect
    }

    /// Lazily synchronize cached host screen-lock state with the live OS lock status.
    ///
    /// Because the main loop skips periodic `is_host_screen_locked()` WindowServer IPC while idle,
    /// admission paths (iPad handshake, Web `/ws/stream`, `subscribe_web_stream`, `/api/admin/state`)
    /// call this on demand so:
    /// 1. Unlocking the host while idle immediately clears a prior `on-lock=disconnect` lockout.
    /// 2. Locking the host while idle is enforced immediately on incoming connections without
    ///    granting a fresh `lock_delay_secs` window of live streaming on an already-locked screen.
    pub fn refresh_host_lock_state_now(&self, enforce_immediately_if_locked: bool) {
        if !self.backend.capabilities().screen_lock_detection {
            return;
        }
        let cur_locked = self.backend.is_host_screen_locked();
        let prev_locked = self.is_host_screen_locked();
        let has_active_auth = if cur_locked && enforce_immediately_if_locked {
            let map = self.sessions.lock().unwrap();
            let subs = self.web_subscribers.lock().unwrap();
            map.values().any(|s| s.authorized) || !subs.is_empty()
        } else {
            false
        };
        if cur_locked != prev_locked {
            if cur_locked && enforce_immediately_if_locked {
                // If an authorized iPad/Web session is already active when an incoming probe
                // observes the OS lock transition before the 1s main-loop poll, preserve the
                // configured grace delay for existing active sessions (P1-A1).
                self.on_host_screen_lock_changed_with_grace(true, has_active_auth);
            } else {
                self.on_host_screen_lock_changed(cur_locked);
            }
        } else if cur_locked {
            if enforce_immediately_if_locked && !self.is_host_lock_enforced() {
                // Only escalate an active grace countdown into global enforcement when NO authorized
                // session or viewer is currently protected by the grace period (e.g. waking from idle).
                // Incoming unauthenticated probes during an active session's grace delay must NOT
                // prematurely kill already-streaming authorized devices (Bug A4).
                if has_active_auth {
                    self.tick_host_lock_policy();
                    return;
                }
                let ep_opt = {
                    let _lg = self.host_lock_mutex.lock().unwrap();
                    if !self.is_host_screen_locked() || self.is_host_lock_enforced() {
                        return;
                    }
                    let act_ipad = self.lock_action_ipad();
                    let act_web = self.lock_action_web();
                    if act_ipad == LockAction::Keep && act_web == LockAction::Keep {
                        None
                    } else {
                        self.host_lock_enforced.store(true, Ordering::SeqCst);
                        Some(self.lock_state_epoch.fetch_add(1, Ordering::AcqRel) + 1)
                    }
                };
                if let Some(ep) = ep_opt {
                    self.apply_host_lock_state(true, ep);
                }
            } else {
                self.tick_host_lock_policy();
            }
        }
    }

    /// Called by the main loop whenever the host OS screen lock state transitions.
    pub fn on_host_screen_lock_changed(&self, locked: bool) {
        self.on_host_screen_lock_changed_with_grace(locked, true);
    }

    pub fn on_host_screen_lock_changed_with_grace(&self, locked: bool, allow_grace_delay: bool) {
        let (act_ipad, act_web, delay, apply_now) = {
            let _lg = self.host_lock_mutex.lock().unwrap();
            let prev = self.host_screen_locked.swap(locked, Ordering::SeqCst);
            if prev == locked {
                return;
            }
            let ep = self.lock_state_epoch.fetch_add(1, Ordering::AcqRel) + 1;
            let act_ipad = self.lock_action_ipad();
            let act_web = self.lock_action_web();
            let delay = if allow_grace_delay {
                self.lock_delay_secs()
            } else {
                0
            };
            let apply_now = if locked {
                if let Ok(mut since) = self.host_locked_since.lock() {
                    *since = Some(Instant::now());
                }
                if act_ipad == LockAction::Keep && act_web == LockAction::Keep {
                    self.host_lock_enforced.store(false, Ordering::SeqCst);
                    info!("Host screen locked — applying lock policies (ipad={act_ipad:?}, web={act_web:?})");
                    Some((false, ep))
                } else if delay == 0 {
                    self.host_lock_enforced.store(true, Ordering::SeqCst);
                    info!("Host screen locked — applying lock policies (ipad={act_ipad:?}, web={act_web:?})");
                    Some((true, ep))
                } else {
                    self.host_lock_enforced.store(false, Ordering::SeqCst);
                    info!(
                        "Host screen locked — will apply lock policies (ipad={act_ipad:?}, web={act_web:?}) after {delay}s grace delay unless unlocked"
                    );
                    // Apply unenforced state for this epoch so any residual enforced flags from a
                    // superseded unlock (e.g. unlock -> rapid re-lock with grace) are cleared (P2-A3).
                    Some((false, ep))
                }
            } else {
                if let Ok(mut since) = self.host_locked_since.lock() {
                    *since = None;
                }
                self.host_lock_enforced.store(false, Ordering::SeqCst);
                info!("Host screen unlocked (lock policies: ipad={act_ipad:?}, web={act_web:?})");
                Some((false, ep))
            };
            (act_ipad, act_web, delay, apply_now)
        };
        crate::debug_trace::record(
            "lifecycle",
            "host_screen_lock",
            serde_json::json!({ "locked": locked, "policy_ipad": act_ipad, "policy_web": act_web, "delay_secs": delay }),
        );
        if let Some((enforced, ep)) = apply_now {
            self.apply_host_lock_state(enforced, ep);
        }
    }

    /// Called periodically by the main loop to enforce delayed lock policies once
    /// `--on-lock-delay-secs` has elapsed while the host screen remains locked.
    pub fn tick_host_lock_policy(&self) {
        let transition = {
            let _lg = self.host_lock_mutex.lock().unwrap();
            if !self.is_host_screen_locked() {
                None
            } else if self.lock_action_ipad() == LockAction::Keep
                && self.lock_action_web() == LockAction::Keep
            {
                if self.host_lock_enforced.swap(false, Ordering::SeqCst) {
                    let ep = self.lock_state_epoch.fetch_add(1, Ordering::AcqRel) + 1;
                    Some((false, ep))
                } else {
                    None
                }
            } else if self.host_lock_enforced.load(Ordering::Acquire) {
                None
            } else {
                let delay = Duration::from_secs(self.lock_delay_secs());
                let elapsed_ok = self
                    .host_locked_since
                    .lock()
                    .ok()
                    .and_then(|g| *g)
                    .is_some_and(|since| since.elapsed() >= delay);
                if elapsed_ok {
                    self.host_lock_enforced.store(true, Ordering::SeqCst);
                    let ep = self.lock_state_epoch.fetch_add(1, Ordering::AcqRel) + 1;
                    Some((true, ep))
                } else {
                    None
                }
            }
        };
        if let Some((enforced, ep)) = transition {
            self.apply_host_lock_state(enforced, ep);
        }
    }

    fn apply_host_lock_state(&self, locked: bool, epoch: u64) {
        let _apply_guard = self.lock_apply_mutex.lock().unwrap();
        if self.lock_state_epoch.load(Ordering::Acquire) != epoch {
            return;
        }
        let act_ipad = self.lock_action_ipad();
        let act_web = self.lock_action_web();

        // 1) Web lock enforcement FIRST (so if both disconnect, closing iPad doesn't spuriously spin up standalone Web).
        let web_blocking = locked && act_web == LockAction::Disconnect;
        let was_web_disconnecting = self
            .web_lock_disconnecting
            .swap(web_blocking, Ordering::AcqRel);
        match (locked, act_web) {
            (true, LockAction::Pause) => {
                if self.lock_state_epoch.load(Ordering::Acquire) != epoch {
                    return;
                }
                let was = self.host_lock_paused_web.swap(true, Ordering::SeqCst);
                if !was {
                    info!("Host locked (web=pause): pausing Web viewer transmission");
                }
                // Clear cached pre-lock IDRs and bump source epoch so unlock waits for a live
                // post-unlock IDR instead of flashing a stale pre-lock preview (P2-B2).
                self.bump_web_source_epoch();
                if let Ok(mut lf) = self.last_ipad_web_frame.lock() {
                    *lf = None;
                }
                if let Ok(mut lf) = self.last_standalone_web_frame.lock() {
                    *lf = None;
                }
            }
            (true, LockAction::Disconnect) => {
                if self.lock_state_epoch.load(Ordering::Acquire) != epoch {
                    return;
                }
                self.host_lock_paused_web.store(false, Ordering::SeqCst);
                self.bump_web_source_epoch();
                if let Ok(mut lf) = self.last_ipad_web_frame.lock() {
                    *lf = None;
                }
                if let Ok(mut lf) = self.last_standalone_web_frame.lock() {
                    *lf = None;
                }
                info!("Host locked (web=disconnect): disconnecting all Web viewers and releasing standalone Web virtual display");
                self.kick_all_web_viewers();
            }
            (true, LockAction::Keep) | (false, _) => {
                if self.lock_state_epoch.load(Ordering::Acquire) != epoch {
                    return;
                }
                let was = self.host_lock_paused_web.swap(false, Ordering::SeqCst);
                if was || was_web_disconnecting {
                    info!("Resuming Web viewer transmission after host unlock or policy change");
                    // Bump source epoch & clear any residual cached IDRs when exiting lock-disconnect
                    // or lock-pause so reconnecting viewers always wait for a fresh post-unlock IDR (Iter-8 P1-B1).
                    self.bump_web_source_epoch();
                    if let Ok(mut lf) = self.last_ipad_web_frame.lock() {
                        *lf = None;
                    }
                    if let Ok(mut lf) = self.last_standalone_web_frame.lock() {
                        *lf = None;
                    }
                    // Re-start standalone Web capture if all iPads were disconnected while locked & paused.
                    self.resume_standalone_web_capture_if_needed();
                    // Trigger a live IDR keyframe on resume (never re-inject stale cached IDR with
                    // a fake sequence number into SharedWebMuxer).
                    self.request_active_keyframes();
                }
            }
        }

        // 2) iPad lock enforcement
        if self.lock_state_epoch.load(Ordering::Acquire) != epoch {
            return;
        }
        match (locked, act_ipad) {
            (true, LockAction::Pause) => {
                let was = self.host_lock_paused_ipad.swap(true, Ordering::SeqCst);
                if !was {
                    info!("Host locked (ipad=pause): pausing iPad video/cursor/input transmission while keeping sessions & virtual displays alive");
                }
            }
            (true, LockAction::Disconnect) => {
                self.host_lock_paused_ipad.store(false, Ordering::SeqCst);
                info!("Host locked (ipad=disconnect): disconnecting all iPad sessions and releasing their virtual displays");
                self.close_all_ipad_sessions();
            }
            (true, LockAction::Keep) | (false, _) => {
                let was = self.host_lock_paused_ipad.swap(false, Ordering::SeqCst);
                if was {
                    info!("Resuming iPad video/cursor/input transmission after host unlock or policy change");
                    let now = Instant::now();
                    if let Ok(mut map) = self.sessions.lock() {
                        for sess in map.values_mut() {
                            if sess.authorized {
                                sess.last_activity = now;
                                if sess.data_detached_at.is_some() {
                                    sess.data_detached_at = Some(now);
                                }
                                if sess.capture.is_none() && sess.authorized_at.is_some() {
                                    sess.authorized_at = Some(now);
                                }
                            }
                            sess.flow.wake_streamer();
                        }
                    }
                }
            }
        }
        self.sync_capture_pause_states();
    }

    /// Synchronize true backend capture pause/resume state across standalone Web and iPad captures.
    /// In shared (follow-iPad) mode, an iPad capture is only truly paused when BOTH the iPad and
    /// all visible Web viewers are paused/absent.
    pub(super) fn sync_capture_pause_states(&self) {
        sync_capture_pause_states_inner(
            &self.standalone_web_capture,
            &self.sessions,
            &self.web_subscribers,
            &self.web_screen_mode,
            &self.web_follow_ipad_session_id,
            &self.web_source_epoch,
            &self.last_ipad_web_frame,
            &self.host_lock_paused_ipad,
            &self.host_lock_paused_web,
            self.is_web_lock_disconnect_blocking(),
        );
    }

    /// Ask all active capture encoders to emit an immediate IDR keyframe (used on Web viewer join,
    /// P2P fallback, MSE queue recovery, and tab foreground resume).
    pub fn request_active_keyframes(&self) {
        let mut handles: Vec<SharedCaptureHandle> = Vec::new();
        {
            if let Ok(standalone) = self.standalone_web_capture.lock() {
                if let Some(ref cap) = *standalone {
                    handles.push(cap.handle.clone());
                }
            }
            if let Ok(sessions) = self.sessions.lock() {
                for sess in sessions.values() {
                    if let Some(ref cap) = sess.capture {
                        handles.push(cap.handle.clone());
                    }
                }
            }
        }
        for hdl in handles {
            if let Ok(g) = hdl.try_lock() {
                g.request_keyframe();
            }
        }
    }

    /// Update a Web viewer's tab visibility (background tabs pause WS push & allow idle capture pause).
    pub fn set_web_viewer_visible(&self, viewer_id: u64, visible: bool) {
        let changed = {
            let subs = self.web_subscribers.lock().unwrap();
            if let Some(entry) = subs.iter().find(|s| s.id == viewer_id) {
                entry.visible.swap(visible, Ordering::AcqRel) != visible
            } else {
                false
            }
        };
        if changed {
            self.sync_capture_pause_states();
            if visible {
                self.request_active_keyframes();
            }
        }
    }

    /// Record a direct WebSocket viewer write latency / overwrite drop sample for standalone Web ABR.
    pub fn record_web_viewer_write_sample(&self, write_ms: u64, dropped: u64) {
        if let Ok(mut acc) = self.web_abr_accum.lock() {
            if write_ms > 0 || dropped == 0 {
                acc.sent_frames = acc.sent_frames.saturating_add(1);
                acc.send_ms_sum = acc.send_ms_sum.saturating_add(write_ms);
                acc.max_send_ms = acc.max_send_ms.max(write_ms);
            }
            if dropped > 0 {
                acc.dropped_frames = acc.dropped_frames.saturating_add(dropped);
            }
        }
    }

    pub(super) fn apply_low_power_to_captures(&self, enabled: bool) {
        let mut handles: Vec<SharedCaptureHandle> = Vec::new();
        {
            if let Ok(standalone) = self.standalone_web_capture.lock() {
                if let Some(ref cap) = *standalone {
                    handles.push(cap.handle.clone());
                }
            }
            if let Ok(sessions) = self.sessions.lock() {
                for sess in sessions.values() {
                    if let Some(ref cap) = sess.capture {
                        handles.push(cap.handle.clone());
                    }
                }
            }
        }
        for hdl in handles {
            if let Ok(mut g) = hdl.lock() {
                if let Err(e) = g.set_low_power(enabled) {
                    debug!("Capture set_low_power({enabled}) failed: {e:#}");
                }
            }
        }
    }

    pub(super) fn in_wake_grace(&self) -> bool {
        self.wake_grace_until
            .lock()
            .ok()
            .and_then(|g| *g)
            .is_some_and(|until| Instant::now() < until)
    }

    /// Returns `None` while at least one authorized/pending screen session or Web viewer is active;
    /// otherwise returns how long the process has been idle since startup or the last activity.
    pub fn idle_duration(&self) -> Option<Duration> {
        let has_sessions = self
            .sessions
            .lock()
            .unwrap()
            .values()
            .any(|s| s.authorized || s.awaiting_confirm);
        let has_viewers = !self.web_subscribers.lock().unwrap().is_empty();
        let has_vds = self.has_standalone_virtual_displays();
        if has_sessions || has_viewers || has_vds {
            return None;
        }
        Some(self.last_global_activity.lock().unwrap().elapsed())
    }

}
