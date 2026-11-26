use super::flow_control::{
    broadcast_to_web_subscribers_tagged, stable_display_serial, ActiveCapture, WebAbrAccum,
    WebStreamSubscription, WebSubscriberEntry,
};
use super::{SessionRegistry, SessionSnapshot, WebScreenSnapshot, WebViewerSnapshot};
use crate::abr::{AbrController, AbrStatusSnapshot, AbrTargets, AbrWindowSample};
use crate::config::{CaptureMode, WebScreenMode};
use crate::platform::{
    clamp_pixel_dimensions, latest_frame_channel, CaptureParams, RecvFrameError,
};
use anyhow::{anyhow, Result};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tracing::{info, warn};

impl SessionRegistry {
    pub fn supports_hidpi(&self) -> bool {
        self.backend.supports_hidpi()
    }

    pub fn supports_independent_web_screen(&self) -> bool {
        self.backend.supports_virtual_display()
            && self.config.mode == crate::config::CaptureMode::Extend
    }

    pub fn web_screen_mode(&self) -> WebScreenMode {
        WebScreenMode::from_u8(self.web_screen_mode.load(Ordering::Acquire))
    }

    pub fn is_web_independent_screen(&self) -> bool {
        self.web_screen_mode() == WebScreenMode::Independent
    }

    pub fn current_web_stream_source(&self) -> &'static str {
        let standalone = self.standalone_web_capture.lock().unwrap();
        let map = self.sessions.lock().unwrap();
        let mode = self.web_screen_mode();
        if standalone.is_some() {
            if mode == WebScreenMode::Main {
                "main"
            } else {
                "standalone"
            }
        } else if mode == WebScreenMode::FollowIpad && map.values().any(|s| s.capture.is_some()) {
            "ipad"
        } else {
            "idle"
        }
    }

    pub fn web_screen_info(&self) -> WebScreenSnapshot {
        let vs = self.video_settings();
        let low_power = self.is_low_power();
        let trusted_prefs: std::collections::HashMap<String, crate::trust::DevicePreferences> = self
            .trust_store
            .list()
            .into_iter()
            .map(|d| (d.fingerprint, d.prefs))
            .collect();
        let supports_hidpi = self.backend.supports_hidpi();
        let eff_web_hidpi = if supports_hidpi { vs.web_hidpi.max(1) } else { 1 };
        let mode = self.web_screen_mode();
        let independent = mode == WebScreenMode::Independent;
        let supported = self.supports_independent_web_screen();
        // Consistent lock order: `standalone_web_capture` -> `sessions` -> `web_subscribers`.
        let standalone = self.standalone_web_capture.lock().unwrap();
        let map = self.sessions.lock().unwrap();
        let subs = self.web_subscribers.lock().unwrap();

        if let Some(ref cap) = *standalone {
            let (lw, lh) = self.resolve_web_dimensions(&vs);
            let (w, h) = cap
                .actual_size
                .lock()
                .ok()
                .map(|g| *g)
                .filter(|&(aw, ah)| aw > 0 && ah > 0)
                .unwrap_or((lw * eff_web_hidpi, lh * eff_web_hidpi));
            return WebScreenSnapshot {
                mode,
                independent,
                supported,
                active: true,
                source: if mode == WebScreenMode::Main {
                    "main"
                } else {
                    "standalone"
                }
                .to_string(),
                width: w,
                height: h,
                logical_width: lw,
                logical_height: lh,
                hidpi: eff_web_hidpi,
            };
        }

        if mode == WebScreenMode::FollowIpad {
            let follow_sid = self.web_follow_ipad_session_id.load(Ordering::Acquire);
            let owner_sess = if follow_sid != 0 {
                map.values()
                    .find(|s| s.id == follow_sid && s.capture.is_some())
            } else {
                None
            };
            if let Some(sess) = owner_sess.or_else(|| map.values().find(|s| s.capture.is_some())) {
                let dev_prefs = sess
                    .fingerprint
                    .as_deref()
                    .and_then(|fp| trusted_prefs.get(&fp.to_ascii_lowercase()));
                let sess_vs = Self::overlay_device_prefs(vs.clone(), dev_prefs, low_power);
                let eff_ipad_hidpi = if supports_hidpi {
                    sess_vs.hidpi.max(1)
                } else {
                    1
                };
                let (lw, lh) = sess
                    .handshake
                    .as_ref()
                    .map(|hs| Self::resolve_dimensions_for_settings(hs, &sess_vs, supports_hidpi))
                    .unwrap_or((0, 0));
                let (w, h) = sess
                    .capture
                    .as_ref()
                    .and_then(|c| c.actual_size.lock().ok().map(|g| *g))
                    .filter(|&(aw, ah)| aw > 0 && ah > 0)
                    .unwrap_or((lw, lh));
                return WebScreenSnapshot {
                    mode,
                    independent,
                    supported,
                    active: !subs.is_empty(),
                    source: "ipad".to_string(),
                    width: w,
                    height: h,
                    logical_width: lw,
                    logical_height: lh,
                    hidpi: eff_ipad_hidpi,
                };
            }
        }

        let (lw, lh) = self.resolve_web_dimensions(&vs);
        WebScreenSnapshot {
            mode,
            independent,
            supported,
            active: false,
            source: "idle".to_string(),
            width: 0,
            height: 0,
            logical_width: lw,
            logical_height: lh,
            hidpi: eff_web_hidpi,
        }
    }

    /// Toggle whether Web viewers always use an independent virtual extended display (`true`)
    /// or reuse an active iPad extended display when one is connected (`false`).
    pub fn set_web_independent_screen(&self, enabled: bool) -> Result<bool> {
        let target = if enabled {
            WebScreenMode::Independent
        } else {
            WebScreenMode::FollowIpad
        };
        let applied = self.set_web_screen_mode_inner(target, true)?;
        Ok(applied == WebScreenMode::Independent)
    }

    /// Set the Web screen source mode (`follow_ipad`, `independent`, or `main`) live.
    pub fn set_web_screen_mode(&self, mode: WebScreenMode) -> Result<WebScreenMode> {
        self.set_web_screen_mode_inner(mode, true)
    }

    /// Pre-validate whether switching to `mode` is supported and within `max_extended_screens`
    /// BEFORE `handle_admin_settings` mutates unrelated fields (`max_web_viewers`, `p2p_relay_enabled`)
    /// (Iter-7 P2-C3).
    pub fn validate_web_screen_mode_switch(
        &self,
        mode: WebScreenMode,
        pending_max_ext: Option<usize>,
        pending_max_web: Option<usize>,
    ) -> Result<()> {
        if mode != WebScreenMode::Independent {
            return Ok(());
        }
        if !self.supports_independent_web_screen() {
            return Err(anyhow!(
                "当前平台或采集模式不支持独立虚拟扩展屏（仅 macOS Extend 模式支持）"
            ));
        }
        if pending_max_web == Some(0) {
            return Ok(());
        }
        let standalone = self.standalone_web_capture.lock().unwrap();
        let map = self.sessions.lock().unwrap();
        let subs = self.web_subscribers.lock().unwrap();
        let max_ext = pending_max_ext
            .map(|v| v.min(32))
            .unwrap_or_else(|| self.max_extended_screens());
        let auth_sessions = map.values().filter(|s| s.authorized).count();
        let already_has_virtual_standalone =
            standalone.is_some() && self.web_screen_mode() != WebScreenMode::Main;
        if !subs.is_empty()
            && !already_has_virtual_standalone
            && max_ext > 0
            && (auth_sessions + 1) > max_ext
        {
            return Err(anyhow!(
                "扩展屏数量已达上限（{max_ext}，当前已有 {auth_sessions} 块设备扩展屏，无法切换为独立虚拟扩展屏）"
            ));
        }
        Ok(())
    }

    pub(super) fn set_web_screen_mode_inner(
        &self,
        mode: WebScreenMode,
        persist: bool,
    ) -> Result<WebScreenMode> {
        let _mode_guard = self.web_mode_lock.lock().unwrap();
        if mode == WebScreenMode::Independent && !self.supports_independent_web_screen() {
            return Err(anyhow!(
                "当前平台或采集模式不支持独立虚拟扩展屏（仅 macOS Extend 模式支持）"
            ));
        }
        // Enforce `max_extended_screens` before switching live into Independent mode when
        // Web viewers are connected and authorized iPads already saturate the virtual-screen quota.
        if mode == WebScreenMode::Independent {
            let standalone = self.standalone_web_capture.lock().unwrap();
            let map = self.sessions.lock().unwrap();
            let subs = self.web_subscribers.lock().unwrap();
            let max_ext = self.max_extended_screens();
            let auth_sessions = map.values().filter(|s| s.authorized).count();
            let already_has_virtual_standalone =
                standalone.is_some() && self.web_screen_mode() != WebScreenMode::Main;
            if !subs.is_empty()
                && !already_has_virtual_standalone
                && max_ext > 0
                && (auth_sessions + 1) > max_ext
            {
                return Err(anyhow!(
                    "扩展屏数量已达上限（{max_ext}，当前已有 {auth_sessions} 块设备扩展屏，无法切换为独立虚拟扩展屏）"
                ));
            }
        }
        let prev_mode = self.web_screen_mode();
        if mode == prev_mode {
            if persist && self.persisted_baseline.lock().unwrap().web_screen_mode != mode {
                self.persist_config_patch(|c| {
                    c.web_screen_mode = mode;
                    c.web_independent_screen = mode == WebScreenMode::Independent;
                });
            }
            return Ok(mode);
        }

        info!("Runtime setting updated: web_screen_mode={:?}", mode);
        crate::debug_trace::record(
            "web_screen",
            "mode_changed",
            serde_json::json!({
                "mode": mode.as_str(),
                "independent": mode == WebScreenMode::Independent,
            }),
        );

        // Under `web_mode_lock`, tear down any existing standalone/main capture BEFORE switching
        // `web_screen_mode` or spawning a replacement capture so frames NEVER interleave.
        let prev_cap = {
            let mut standalone = self.standalone_web_capture.lock().unwrap();
            let map = self.sessions.lock().unwrap();
            let has_ipad = map.values().any(|s| s.capture.is_some());
            // Keep existing standalone virtual screen only when switching FollowIpad <-> Independent
            // with no iPad connected (both use the exact same virtual extended display).
            let same_virtual_backing = matches!(
                (prev_mode, mode),
                (WebScreenMode::FollowIpad, WebScreenMode::Independent)
                    | (WebScreenMode::Independent, WebScreenMode::FollowIpad)
            ) && !has_ipad;
            if same_virtual_backing {
                None
            } else {
                standalone.take()
            }
        };
        if let Some(mut cap) = prev_cap {
            cap.shutdown();
            if let Ok(mut lf) = self.last_standalone_web_frame.lock() {
                *lf = None;
            }
        }

        if mode != WebScreenMode::FollowIpad {
            // Publish the new non-FollowIpad mode FIRST so no racing iPad thread can re-claim
            // `web_follow_ipad_session_id` before clearing owner, cached IDR, and bumping epoch (Iter-8 P2-B3).
            self.web_screen_mode.store(mode.as_u8(), Ordering::Release);
            self.web_follow_ipad_session_id.store(0, Ordering::Release);
            if let Ok(mut lf) = self.last_ipad_web_frame.lock() {
                *lf = None;
            }
            self.bump_web_source_epoch();
        } else {
            self.bump_web_source_epoch();
            self.web_screen_mode.store(mode.as_u8(), Ordering::Release);
        }
        let (has_viewers, has_ipad) = {
            let map = self.sessions.lock().unwrap();
            let subs = self.web_subscribers.lock().unwrap();
            (!subs.is_empty(), map.values().any(|s| s.capture.is_some()))
        };
        let need_dedicated = has_viewers && (mode != WebScreenMode::FollowIpad || !has_ipad);
        if need_dedicated {
            if let Err(e) = self.ensure_standalone_web_capture_locked() {
                self.web_screen_mode
                    .store(prev_mode.as_u8(), Ordering::Release);
                self.bump_web_source_epoch();
                // Restore previous dedicated standalone/main capture if we tore it down before
                // the failed switch so active Web viewers never remain stuck black (Iter-6 P2-A4).
                if has_viewers && (prev_mode != WebScreenMode::FollowIpad || !has_ipad) {
                    let _ = self.ensure_standalone_web_capture_locked();
                }
                self.sync_capture_pause_states();
                self.request_active_keyframes();
                return Err(e);
            }
        }
        self.sync_capture_pause_states();
        self.request_active_keyframes();
        if persist {
            self.persist_config_patch(|c| {
                c.web_screen_mode = mode;
                c.web_independent_screen = mode == WebScreenMode::Independent;
            });
        }
        Ok(mode)
    }

    pub fn list_sessions(&self) -> Vec<SessionSnapshot> {
        let base_vs = self.video_settings();
        let low_power = self.is_low_power();
        let trusted_prefs: std::collections::HashMap<String, crate::trust::DevicePreferences> = self
            .trust_store
            .list()
            .into_iter()
            .map(|d| (d.fingerprint, d.prefs))
            .collect();
        let supports_hidpi = self.backend.supports_hidpi();
        let map = self.sessions.lock().unwrap();
        let mut out: Vec<SessionSnapshot> = map
            .iter()
            .map(|(key, s)| {
                let dev_prefs = s
                    .fingerprint
                    .as_deref()
                    .and_then(|fp| trusted_prefs.get(&fp.to_ascii_lowercase()));
                let vs = Self::overlay_device_prefs(base_vs.clone(), dev_prefs, low_power);
                let eff_hidpi = if supports_hidpi { vs.hidpi.max(1) } else { 1 };
                let (phys_w, phys_h) = s
                    .handshake
                    .as_ref()
                    .map(|hs| hs.effective_resolution())
                    .unwrap_or((0, 0));
                let (lw, lh) = s
                    .handshake
                    .as_ref()
                    .map(|hs| Self::resolve_dimensions_for_settings(hs, &vs, supports_hidpi))
                    .unwrap_or((0, 0));
                let (w, h) = s
                    .capture
                    .as_ref()
                    .and_then(|c| c.actual_size.lock().ok().map(|g| *g))
                    .filter(|&(aw, ah)| aw > 0 && ah > 0)
                    .unwrap_or((lw, lh));
                let backing_exact = lw > 0 && lh > 0 && w == lw * eff_hidpi && h == lh * eff_hidpi;
                let panel_exact = if phys_w > 0 && phys_h > 0 && w > 0 && h > 0 {
                    (phys_w % w == 0 || w % phys_w == 0) && (phys_h % h == 0 || h % phys_h == 0)
                } else {
                    true
                };
                let is_pixel_exact = backing_exact && panel_exact;
                SessionSnapshot {
                    id: s.id,
                    key: key.clone(),
                    transport: if s.is_usb { "usb" } else { "wifi" }.to_string(),
                    fingerprint: s.fingerprint.clone(),
                    uid: s.handshake.as_ref().map(|hs| hs.uid.clone()),
                    name: s.handshake.as_ref().map(|hs| hs.name.clone()),
                    model: s.handshake.as_ref().map(|hs| hs.model.clone()),
                    authorized: s.authorized,
                    awaiting_confirm: s.awaiting_confirm,
                    streaming: s.capture.is_some(),
                    width: w,
                    height: h,
                    native_width: phys_w,
                    native_height: phys_h,
                    logical_width: lw,
                    logical_height: lh,
                    hidpi: eff_hidpi,
                    integer_scale: vs.integer_scale,
                    is_pixel_exact,
                    connected_secs: s.connected_at.elapsed().as_secs(),
                    idle_secs: s.last_activity.elapsed().as_secs(),
                    in_flight: s.flow.in_flight(),
                    max_in_flight: s.flow.max_in_flight(),
                    auto_max_in_flight: self.is_auto_max_in_flight(),
                    dropped_frames: s.flow.dropped_frames(),
                    abr: s
                        .capture
                        .as_ref()
                        .and_then(|c| c.abr_status.lock().ok().map(|g| *g)),
                }
            })
            .collect();
        out.sort_by_key(|s| s.id);
        out
    }

    pub fn list_web_viewers(&self) -> Vec<WebViewerSnapshot> {
        let subs = self.web_subscribers.lock().unwrap();
        subs.iter()
            .map(|s| WebViewerSnapshot {
                id: s.id,
                peer: s.peer.clone(),
                fingerprint: s.fingerprint.clone(),
                label: s.label.clone(),
                connected_secs: s.connected_at.elapsed().as_secs(),
            })
            .collect()
    }

    pub fn kick_web_viewer(&self, id: u64) -> Option<Option<String>> {
        let mut kicked_fp = None;
        let removed = {
            let mut subs = self.web_subscribers.lock().unwrap();
            let before = subs.len();
            subs.retain(|s| {
                if s.id == id {
                    kicked_fp = Some(s.fingerprint.clone());
                    s.tx.close();
                    false
                } else {
                    true
                }
            });
            subs.len() < before
        };
        self.stop_standalone_web_capture_if_no_viewers();
        if removed { kicked_fp } else { None }
    }

    pub fn kick_web_viewers_by_tag(&self, tag: &str) -> usize {
        let removed = {
            let mut subs = self.web_subscribers.lock().unwrap();
            let before = subs.len();
            subs.retain(|s| {
                if s.session_tag.as_deref() == Some(tag) {
                    s.tx.close();
                    false
                } else {
                    true
                }
            });
            before - subs.len()
        };
        self.stop_standalone_web_capture_if_no_viewers();
        removed
    }

    pub fn kick_web_viewers_by_fingerprint(&self, fingerprint: &str) -> usize {
        let Some(norm_fp) = crate::trust::normalize_fingerprint(fingerprint) else {
            return 0;
        };
        let removed = {
            let mut subs = self.web_subscribers.lock().unwrap();
            let before = subs.len();
            subs.retain(|s| {
                if s.fingerprint
                    .as_deref()
                    .is_some_and(|fp| fp.eq_ignore_ascii_case(&norm_fp))
                {
                    s.tx.close();
                    false
                } else {
                    true
                }
            });
            before - subs.len()
        };
        self.stop_standalone_web_capture_if_no_viewers();
        removed
    }

    pub fn kick_web_viewers_unless(&self, keep: impl Fn(bool, Option<&str>) -> bool) -> usize {
        let removed = {
            let mut subs = self.web_subscribers.lock().unwrap();
            let before = subs.len();
            subs.retain(|s| {
                if keep(s.is_admin, s.fingerprint.as_deref()) {
                    true
                } else {
                    s.tx.close();
                    false
                }
            });
            before - subs.len()
        };
        self.stop_standalone_web_capture_if_no_viewers();
        removed
    }

    pub fn kick_all_web_viewers_with_fingerprints(&self) -> Vec<String> {
        let fps = {
            let mut subs = self.web_subscribers.lock().unwrap();
            let mut out = Vec::new();
            for s in subs.drain(..) {
                if let Some(fp) = s.fingerprint {
                    out.push(fp);
                }
                s.tx.close();
            }
            out
        };
        self.stop_standalone_web_capture_if_no_viewers();
        fps
    }

    pub fn kick_all_web_viewers(&self) -> usize {
        let count = {
            let mut subs = self.web_subscribers.lock().unwrap();
            let n = subs.len();
            for s in subs.drain(..) {
                s.tx.close();
            }
            n
        };
        self.stop_standalone_web_capture_if_no_viewers();
        count
    }

    pub(super) fn stop_standalone_web_capture_if_no_viewers(&self) {
        let cap_opt = {
            let mut cap = self.standalone_web_capture.lock().unwrap();
            let subs = self.web_subscribers.lock().unwrap();
            if subs.is_empty() {
                cap.take()
            } else {
                None
            }
        };
        if let Some(mut c) = cap_opt {
            c.shutdown();
        }
    }

    pub(super) fn ensure_standalone_web_capture(&self) -> Result<()> {
        let _mode_guard = self.web_mode_lock.lock().unwrap();
        self.ensure_standalone_web_capture_locked()
    }

    fn ensure_standalone_web_capture_locked(&self) -> Result<()> {
        // Check under consistent lock order (`standalone_web_capture` -> `sessions` -> `web_subscribers`)
        // then RELEASE all locks BEFORE calling blocking `backend.start_capture()` (outer `web_mode_lock`
        // already serializes standalone capture startup).
        if self.is_web_lock_disconnect_admit_blocked() || self.is_host_lock_paused_web() {
            return Ok(());
        }
        let screen_mode = self.web_screen_mode();
        {
            let standalone_guard = self.standalone_web_capture.lock().unwrap();
            if standalone_guard.is_some() {
                return Ok(());
            }
            let map = self.sessions.lock().unwrap();
            let subs = self.web_subscribers.lock().unwrap();
            if subs.is_empty()
                || (screen_mode == WebScreenMode::FollowIpad
                    && map.values().any(|s| s.capture.is_some()))
            {
                return Ok(());
            }
            if screen_mode != WebScreenMode::Main {
                let max_ext = self.max_extended_screens();
                let auth_sessions = map.values().filter(|s| s.authorized).count();
                if max_ext > 0 && (auth_sessions + 1) > max_ext {
                    return Err(anyhow!(
                        "扩展屏数量已达上限（{max_ext}，当前已有 {auth_sessions} 块设备扩展屏）"
                    ));
                }
            }
        }
        if let Ok(mut lf) = self.last_standalone_web_frame.lock() {
            *lf = None;
        }
        let vs = self.video_settings();
        let (w, h) = self.resolve_web_dimensions(&vs);
        let eff_hidpi = if self.backend.supports_hidpi() {
            vs.web_hidpi
        } else {
            1
        };
        let web_edge = Self::effective_web_max_pixel_edge(&vs);
        let fps = vs.web_fps.max(1);
        let watch_main = screen_mode == WebScreenMode::Main;
        let capture_mode = if watch_main {
            CaptureMode::Main
        } else {
            self.config.mode
        };
        info!(
            "Starting {} capture for Web viewer ({w}x{h} @ {fps}fps, {}Mbps, hidpi={}x, max_edge={web_edge}px, {:?})",
            if watch_main {
                "host main display"
            } else {
                "standalone extended display"
            },
            vs.web_bitrate_mbps,
            eff_hidpi,
            capture_mode
        );
        let (mut cap_handle, frame_rx) = self.backend.start_capture(&CaptureParams {
            mode: capture_mode,
            display_id: if watch_main { 0 } else { self.config.display_id },
            capture_rect: if watch_main {
                None
            } else {
                self.config.capture_rect
            },
            width: w,
            height: h,
            hidpi: eff_hidpi,
            max_pixel_edge: web_edge,
            fps,
            bitrate_mbps: vs.web_bitrate_mbps,
            all_intra: self.config.all_intra,
            encoder: self.config.encoder.clone(),
            ffmpeg_path: self.config.ffmpeg_path.clone(),
            show_cursor: true,
            client_name: if watch_main {
                "Web Main Display".to_string()
            } else {
                "Web Viewer".to_string()
            },
            display_serial: if watch_main {
                0
            } else {
                stable_display_serial("idis-web-viewer")
            },
        })?;
        if self.is_low_power() {
            let _ = cap_handle.set_low_power(true);
        }

        let cap_id = self.next_capture_id.fetch_add(1, Ordering::Relaxed);
        let shared_handle = Arc::new(Mutex::new(cap_handle));
        let stop_flag = Arc::new(AtomicBool::new(false));
        let init_pix = clamp_pixel_dimensions(w * eff_hidpi.max(1), h * eff_hidpi.max(1), web_edge);
        let actual_size = Arc::new(Mutex::new(init_pix));
        let supports_live_abr_v = self.backend.capabilities().live_abr_quality;
        let abr_status = Arc::new(Mutex::new(AbrStatusSnapshot {
            enabled: supports_live_abr_v && vs.adaptive_quality,
            tier: 0,
            scale_pct: 100,
            target_fps: fps,
            target_bitrate_mbps: vs.web_bitrate_mbps,
            rtt_ms: None,
            unfocused_fps_halved: false,
        }));
        let stop_v = stop_flag.clone();
        let subs_v = self.web_subscribers.clone();
        let last_f = self.last_standalone_web_frame.clone();
        let standalone_arc = self.standalone_web_capture.clone();
        let size_v = actual_size.clone();
        let host_lock_paused_web_v = self.host_lock_paused_web.clone();
        let hdl_v = shared_handle.clone();
        let all_intra_v = self.config.all_intra;
        let video_v = self.video.clone();
        let video_gen_v = self.web_video_settings_gen.clone();
        let web_source_epoch_v = self.web_source_epoch.clone();
        let capture_epoch = self.bump_web_source_epoch();
        let web_abr_acc_v = self.web_abr_accum.clone();
        let abr_status_v = abr_status.clone();
        let stream_thread = thread::spawn(move || {
            let mut last_logged_size = (0u32, 0u32);
            let mut unexpected_disconnect = false;
            let mut awaiting_idr = true;
            let mut last_web_source_epoch = capture_epoch;
            let mut last_kf_req = Instant::now() - Duration::from_secs(1);
            let mut abr = AbrController::new(Instant::now());
            let mut last_video_gen = video_gen_v.load(Ordering::Acquire);
            let mut abr_win_start = Instant::now();
            let mut pending_abr_apply: Option<(u8, u8, AbrTargets)> = None;
            while !stop_v.load(Ordering::SeqCst) {
                match frame_rx.recv_timeout_shared(Duration::from_millis(200)) {
                    Ok((_seq, frame, ov)) => {
                        if stop_v.load(Ordering::Acquire) {
                            break;
                        }
                        let cur_epoch = web_source_epoch_v.load(Ordering::Acquire);
                        if cur_epoch != last_web_source_epoch {
                            // Live epoch bump (e.g. host lock-pause -> unlock, or FollowIpad <->
                            // Independent sharing the same virtual backing): re-sync our producer
                            // tag and require a fresh self-contained IDR so viewers never drop
                            // every post-transition frame forever (Iter-6 P0-B1).
                            last_web_source_epoch = cur_epoch;
                            awaiting_idr = true;
                        }
                        if ov > 0 && !all_intra_v {
                            awaiting_idr = true;
                            if last_kf_req.elapsed() >= Duration::from_millis(250) {
                                last_kf_req = Instant::now();
                                if let Ok(hdl) = hdl_v.try_lock() {
                                    hdl.request_keyframe();
                                }
                            }
                        }
                        if host_lock_paused_web_v.load(Ordering::Acquire) {
                            awaiting_idr = true;
                            continue;
                        }
                        if all_intra_v {
                            if !frame.is_keyframe
                                || !crate::protocol::annexb::is_self_contained_idr(&frame.annex_b)
                            {
                                continue;
                            }
                        } else if frame.is_keyframe {
                            if !crate::protocol::annexb::is_self_contained_idr(&frame.annex_b) {
                                awaiting_idr = true;
                                continue;
                            }
                            awaiting_idr = false;
                        } else if awaiting_idr {
                            if last_kf_req.elapsed() >= Duration::from_millis(250) {
                                last_kf_req = Instant::now();
                                if let Ok(hdl) = hdl_v.try_lock() {
                                    hdl.request_keyframe();
                                }
                            }
                            continue;
                        }
                        if (frame.width, frame.height) != last_logged_size {
                            last_logged_size = (frame.width, frame.height);
                            if let Ok(mut g) = size_v.lock() {
                                *g = last_logged_size;
                            }
                            info!(
                                "[web-stream] Active video stream pixel resolution: {}x{}",
                                frame.width, frame.height
                            );
                        }
                        if stop_v.load(Ordering::Acquire) {
                            break;
                        }
                        broadcast_to_web_subscribers_tagged(
                            &subs_v,
                            &last_f,
                            last_web_source_epoch,
                            frame,
                        );
                    }
                    Err(RecvFrameError::Timeout) => {
                        if stop_v.load(Ordering::Acquire) {
                            break;
                        }
                        let cur_epoch = web_source_epoch_v.load(Ordering::Acquire);
                        if cur_epoch != last_web_source_epoch {
                            last_web_source_epoch = cur_epoch;
                            awaiting_idr = true;
                        }
                        if host_lock_paused_web_v.load(Ordering::Acquire) {
                            awaiting_idr = true;
                        }
                        let has_visible_viewer = subs_v
                            .lock()
                            .ok()
                            .is_some_and(|s| s.iter().any(|e| e.visible.load(Ordering::Acquire)));
                        if !all_intra_v
                            && awaiting_idr
                            && has_visible_viewer
                            && !host_lock_paused_web_v.load(Ordering::Acquire)
                            && last_kf_req.elapsed() >= Duration::from_millis(500)
                        {
                            last_kf_req = Instant::now();
                            if let Ok(hdl) = hdl_v.try_lock() {
                                hdl.request_keyframe();
                            }
                        }
                    }
                    Err(RecvFrameError::Disconnected) => {
                        if !stop_v.load(Ordering::SeqCst) {
                            unexpected_disconnect = true;
                        }
                        break;
                    }
                }

                // Evaluate standalone Web ABR once per second based on direct WS viewer write latency & drops.
                if abr_win_start.elapsed() >= Duration::from_secs(1) {
                    let now = Instant::now();
                    let has_visible_viewer = subs_v
                        .lock()
                        .ok()
                        .is_some_and(|s| s.iter().any(|e| e.visible.load(Ordering::Acquire)));
                    if host_lock_paused_web_v.load(Ordering::Acquire) || !has_visible_viewer {
                        if let Ok(mut acc) = web_abr_acc_v.lock() {
                            *acc = WebAbrAccum::default();
                        }
                        abr_win_start = now;
                        continue;
                    }
                    let cur_gen = video_gen_v.load(Ordering::Acquire);
                    let cur_vs = video_v.lock().unwrap().clone();
                    let base_edge = Self::effective_web_max_pixel_edge(&cur_vs);
                    let (sent, drops, sum_ms, max_ms) = {
                        let mut acc = web_abr_acc_v.lock().unwrap();
                        let out = (
                            acc.sent_frames,
                            acc.dropped_frames,
                            acc.send_ms_sum,
                            acc.max_send_ms,
                        );
                        *acc = WebAbrAccum::default();
                        out
                    };
                    let avg_send_ms = if sent > 0 {
                        sum_ms as f64 / sent as f64
                    } else {
                        0.0
                    };
                    let sample = AbrWindowSample {
                        sent_frames: sent,
                        dropped_frames: drops,
                        avg_send_ms,
                        max_send_ms: max_ms,
                        avg_ack_rtt_ms: None,
                        in_flight_saturated: false,
                    };
                    let abr_active = supports_live_abr_v && cur_vs.adaptive_quality;
                    abr.set_sensitivity(cur_vs.abr_sensitivity);
                    let mut target_change: Option<(u8, u8)> = None;
                    if cur_gen != last_video_gen {
                        last_video_gen = cur_gen;
                        abr.reset(now);
                        pending_abr_apply = None;
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
                        cur_vs.web_fps.max(5),
                        cur_vs.web_bitrate_mbps.max(2),
                        base_edge,
                    );
                    if let Ok(mut st) = abr_status_v.lock() {
                        *st = AbrStatusSnapshot {
                            enabled: abr_active,
                            tier: targets.tier,
                            scale_pct: targets.scale_pct,
                            target_fps: targets.fps,
                            target_bitrate_mbps: targets.bitrate_mbps,
                            rtt_ms: None,
                            unfocused_fps_halved: false,
                        };
                    }
                    if let Some((old_t, new_t)) = target_change {
                        pending_abr_apply = Some((old_t, new_t, targets));
                    }
                    if let Some((old_t, new_t, apply_t)) = pending_abr_apply {
                        if !stop_v.load(Ordering::SeqCst) {
                            if let Ok(mut hdl) = hdl_v.try_lock() {
                                info!(
                                    "[web-stream] Standalone Web ABR tier {old_t} -> {new_t}: {}fps, {}Mbps, max_edge={}px (sent={sent}, drops={drops}, avg_write={avg_send_ms:.1}ms)",
                                    apply_t.fps, apply_t.bitrate_mbps, apply_t.max_pixel_edge
                                );
                                if let Err(e) = hdl.update_stream_quality(
                                    apply_t.fps,
                                    apply_t.bitrate_mbps,
                                    apply_t.max_pixel_edge,
                                ) {
                                    warn!("[web-stream] ABR stream quality update failed (will retry): {e:#}");
                                } else {
                                    pending_abr_apply = None;
                                }
                            }
                        }
                    }
                    abr_win_start = now;
                }
            }
            if unexpected_disconnect {
                warn!("[web-stream] Standalone capture backend terminated unexpectedly — clearing stale handle");
                if let Ok(mut lf) = last_f.lock() {
                    *lf = None;
                }
                // Spawn cleanup on a separate thread so ActiveCapture::shutdown() never joins itself.
                thread::spawn(move || {
                    let dead = {
                        let mut guard = standalone_arc.lock().unwrap();
                        if guard.as_ref().map(|c| c.id) == Some(cap_id) {
                            guard.take()
                        } else {
                            None
                        }
                    };
                    if let Some(mut c) = dead {
                        c.shutdown();
                    }
                });
            }
        });
        let new_cap = ActiveCapture {
            id: cap_id,
            handle: shared_handle,
            stop_flag,
            actual_size,
            abr_status,
            stream_thread: Some(stream_thread),
            cursor_thread: None,
        };
        let orphan = {
            let mut standalone_guard = self.standalone_web_capture.lock().unwrap();
            let map = self.sessions.lock().unwrap();
            let subs = self.web_subscribers.lock().unwrap();
            let still_needed = standalone_guard.is_none()
                && !subs.is_empty()
                && !self.is_web_lock_disconnect_admit_blocked()
                && !self.is_host_lock_paused_web()
                && self.web_screen_mode() == screen_mode
                && (screen_mode != WebScreenMode::FollowIpad
                    || !map.values().any(|s| s.capture.is_some()));
            if still_needed {
                *standalone_guard = Some(new_cap);
                None
            } else {
                Some(new_cap)
            }
        };
        if let Some(mut cap) = orphan {
            cap.shutdown();
        } else {
            // Immediately pause hardware capture if all viewers are already hidden or host is lock-paused.
            self.sync_capture_pause_states();
        }
        Ok(())
    }

    pub(super) fn stop_standalone_web_capture_if_following_ipad(&self) {
        let _mode_guard = self.web_mode_lock.lock().unwrap();
        let prev = {
            let mut guard = self.standalone_web_capture.lock().unwrap();
            if self.web_screen_mode() != WebScreenMode::FollowIpad {
                None
            } else {
                guard.take()
            }
        };
        if let Some(mut cap) = prev {
            // Shut down the old standalone thread BEFORE bumping `web_source_epoch` so it can never
            // observe the bumped epoch while exiting (Iter-6 P0-B1).
            cap.shutdown();
            self.bump_web_source_epoch();
            if let Ok(mut lf) = self.last_standalone_web_frame.lock() {
                *lf = None;
            }
        }
    }

    /// Subscribe a browser viewer to the extended display H.264 stream.
    /// Enforces `max_web_viewers` (0 = Web viewing disabled) and `max_extended_screens` when
    /// spawning a standalone virtual extended display (host main-screen viewing does not consume
    /// a virtual extended display slot).
    pub fn subscribe_web_stream(
        &self,
        peer: String,
        session_tag: Option<String>,
    ) -> Result<WebStreamSubscription> {
        self.subscribe_web_stream_with_identity(peer, session_tag, None, None, false)
    }

    pub fn subscribe_web_stream_with_identity(
        &self,
        peer: String,
        session_tag: Option<String>,
        fingerprint: Option<String>,
        label: Option<String>,
        is_admin: bool,
    ) -> Result<WebStreamSubscription> {
        self.record_external_activity();
        self.refresh_host_lock_state_now(true);
        if self.is_web_lock_disconnect_admit_blocked() {
            return Err(anyhow!("host screen is locked (on_lock_web=disconnect)"));
        }
        let max_viewers = self.max_web_viewers();
        if max_viewers == 0 {
            return Err(anyhow!(
                "网页观看已关闭（当前网页观看上限为 0，请在管理后台「网页扩展屏配置」调大观看上限）"
            ));
        }
        let sub_id = self.next_session_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = latest_frame_channel();
        let use_standalone = {
            // Consistent lock order: `standalone_web_capture` -> `sessions` -> `web_subscribers`.
            let standalone = self.standalone_web_capture.lock().unwrap();
            let map = self.sessions.lock().unwrap();
            let mut subs = self.web_subscribers.lock().unwrap();
            // Re-check lock-disconnect admission INSIDE `web_subscribers` lock so admission is
            // totally ordered against `kick_all_web_viewers()` (P1-A2 / NoConnectedWhenDisconnectEnforced).
            if self.is_web_lock_disconnect_admit_blocked() {
                return Err(anyhow!("host screen is locked (on_lock_web=disconnect)"));
            }
            if subs.len() >= max_viewers {
                // If the same authenticated browser session is reconnecting/switching tabs before
                // its previous WebSocket finishes tearing down, replace that stale viewer cleanly
                // instead of rejecting the user's own reconnect with HTTP 429.
                let same_idx = if let Some(ref tag) = session_tag {
                    subs.iter()
                        .position(|s| s.session_tag.as_deref() == Some(tag.as_str()))
                } else {
                    let parse_peer_ip = |p: &str| -> Option<IpAddr> {
                        p.parse::<SocketAddr>()
                            .map(|sa| sa.ip())
                            .ok()
                            .or_else(|| {
                                p.rsplit_once(':')
                                    .map(|(ip, _)| ip.trim_matches(['[', ']']))
                                    .unwrap_or(p)
                                    .parse::<IpAddr>()
                                    .ok()
                            })
                    };
                    let peer_ip_opt = parse_peer_ip(&peer);
                    let peer_raw = peer.rsplit_once(':').map(|(ip, _)| ip).unwrap_or(&peer);
                    subs.iter().position(|s| {
                        if s.session_tag.is_some() {
                            return false;
                        }
                        if let (Some(a), Some(b)) = (peer_ip_opt, parse_peer_ip(&s.peer)) {
                            a == b || (a.is_loopback() && b.is_loopback())
                        } else {
                            s.peer.rsplit_once(':').map(|(ip, _)| ip).unwrap_or(&s.peer) == peer_raw
                        }
                    })
                };
                if let Some(idx) = same_idx {
                    let old = subs.remove(idx);
                    old.tx.close();
                }
            }
            if subs.len() >= max_viewers {
                return Err(anyhow!(
                    "网页观看人数已达上限（{max_viewers}）"
                ));
            }
            let screen_mode = self.web_screen_mode();
            let has_ipad = map.values().any(|s| s.capture.is_some());
            let want_standalone = screen_mode != WebScreenMode::FollowIpad || !has_ipad;
            let consumes_virtual_slot = want_standalone && screen_mode != WebScreenMode::Main;
            let max_ext = self.max_extended_screens();
            let auth_sessions = map.values().filter(|s| s.authorized).count();
            if consumes_virtual_slot
                && standalone.is_none()
                && max_ext > 0
                && (auth_sessions + 1) > max_ext
            {
                return Err(anyhow!(
                    "扩展屏数量已达上限（{max_ext}，当前已有 {auth_sessions} 块设备扩展屏）"
                ));
            }
            subs.push(WebSubscriberEntry {
                id: sub_id,
                peer,
                session_tag,
                fingerprint,
                label,
                is_admin,
                connected_at: Instant::now(),
                visible: Arc::new(AtomicBool::new(true)),
                tx,
            });
            want_standalone
        };
        // Wake the idle main loop AFTER inserting into `web_subscribers` so `wait_idle()` never
        // misses the newly active viewer (prevents lost-wakeup race).
        self.record_web_activity();
        self.notify_lifecycle_wakeup();

        if use_standalone {
            if let Err(e) = self.ensure_standalone_web_capture() {
                let mut subs = self.web_subscribers.lock().unwrap();
                subs.retain(|s| s.id != sub_id);
                return Err(e);
            }
        }
        // Always sync capture pause states on viewer join (e.g. Viewer 2 joining while Viewer 1
        // had paused standalone capture in a background tab, or shared-mode iPad paused).
        self.sync_capture_pause_states();
        self.request_active_keyframes();

        Ok(WebStreamSubscription {
            id: sub_id,
            rx,
            subscribers: self.web_subscribers.clone(),
            standalone_capture: self.standalone_web_capture.clone(),
            sessions: self.sessions.clone(),
            web_screen_mode: self.web_screen_mode.clone(),
            web_follow_ipad_session_id: self.web_follow_ipad_session_id.clone(),
            web_source_epoch: self.web_source_epoch.clone(),
            last_ipad_web_frame: self.last_ipad_web_frame.clone(),
            host_lock_paused_ipad: self.host_lock_paused_ipad.clone(),
            host_lock_paused_web: self.host_lock_paused_web.clone(),
            web_lock_disconnecting: self.web_lock_disconnecting.clone(),
            last_global_activity: self.last_global_activity.clone(),
            last_web_activity: self.last_web_activity.clone(),
            activity_signal: self.activity_signal.clone(),
        })
    }

}
