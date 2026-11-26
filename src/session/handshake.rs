use super::flow_control::FlowControl;
use super::{ClientSession, ConfirmDecision, PendingDevice, SessionRegistry, VideoSettings};
use crate::config::QualityPreset;
use crate::platform::compute_integer_scaled_logical;
use crate::protocol::keyed_archive::{now_apple_secs, ArchivedValue};
use crate::protocol::messages::{
    build_access_confirmed_packet, build_access_declined_packet, build_video_port_packet,
    parse_archived_i32, parse_archived_u32, ClientHandshake, MessagePacket, MessageType,
};
use crate::transport::SharedFrameWriter;
use crate::trust::{compute_device_fingerprint, normalize_fingerprint, DevicePreferences};
use anyhow::{anyhow, Result};
use std::io::{self, IsTerminal, Write};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

impl SessionRegistry {
    pub fn is_authorized(&self, key: &str) -> bool {
        self.sessions
            .lock()
            .ok()
            .and_then(|map| map.get(key).map(|s| s.authorized))
            .unwrap_or(false)
    }

    pub fn is_authorized_id(&self, key: &str, session_id: u64) -> bool {
        self.sessions
            .lock()
            .ok()
            .and_then(|map| map.get(key).map(|s| s.id == session_id && s.authorized))
            .unwrap_or(false)
    }

    pub fn has_session_id(&self, key: &str, session_id: u64) -> bool {
        self.sessions
            .lock()
            .ok()
            .and_then(|map| map.get(key).map(|s| s.id == session_id))
            .unwrap_or(false)
    }

    /// Disconnect any active iPad sessions and Web viewers whose device fingerprint matches a
    /// revoked trust record and are no longer authorized by any remaining trust entry.
    pub fn disconnect_sessions_matching(&self, fingerprint: &str) -> usize {
        let Some(norm_fp) = normalize_fingerprint(fingerprint) else {
            return 0;
        };
        let keys: Vec<String> = {
            let map = self.sessions.lock().unwrap();
            map.iter()
                .filter(|(_, s)| {
                    s.fingerprint.as_deref() == Some(norm_fp.as_str())
                        && !self.trust_store.is_trusted(s.fingerprint.as_deref())
                })
                .map(|(k, _)| k.clone())
                .collect()
        };
        let mut n = keys.len();
        for k in keys {
            self.close_session(&k);
        }
        if !self.trust_store.is_trusted(Some(&norm_fp)) {
            n += self.kick_web_viewers_by_fingerprint(&norm_fp);
        }
        n
    }

    /// Return a human-readable reason why a Data connection for `key` is currently unauthorized.
    pub fn unauthorized_data_reason(&self, key: &str) -> &'static str {
        if !self.is_ip_allowed(key) {
            return "IP not in --allow-ip";
        }
        let Ok(map) = self.sessions.lock() else {
            return "session registry unavailable";
        };
        match map.get(key) {
            None => "no active telemetry session for this IP (connected to data port directly, or prior telemetry session already closed)",
            Some(s) if s.awaiting_confirm => "telemetry session is waiting for trust confirmation",
            Some(s) if !s.authorized => "telemetry session has not completed Handshake/authorization yet",
            Some(_) => "authorized",
        }
    }

    /// Check whether a Wi-Fi source IP is permitted by `--allow-ip` (empty list allows all IPs).
    /// Canonicalizes IPv4-mapped IPv6 addresses (`::ffff:192.168.1.42` == `192.168.1.42`).
    pub fn is_ip_allowed(&self, ip: &str) -> bool {
        if self.config.allow_ips.is_empty() {
            return true;
        }
        let canon = |s: &str| -> Option<IpAddr> {
            s.trim().parse::<IpAddr>().ok().map(|a| match a {
                IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
                other => other,
            })
        };
        let target = canon(ip);
        self.config.allow_ips.iter().any(|allowed| {
            allowed == ip || (target.is_some() && canon(allowed) == target)
        })
    }

    pub fn register_telemetry(
        &self,
        key: String,
        telemetry_writer: SharedFrameWriter,
        data_port: u16,
        is_usb: bool,
    ) -> Option<u64> {
        if !is_usb && !self.is_ip_allowed(&key) {
            warn!("[{key}] Rejected Wi-Fi connection: source IP not in --allow-ip");
            return None;
        }
        let in_wake = self.in_wake_grace();
        let (id, replaced) = {
            let mut map = self.sessions.lock().unwrap();
            if let Some(existing) = map.get(&key) {
                if existing.authorized {
                    // Protect a live streaming session from unauthenticated same-IP hijack, while
                    // allowing immediate reconnect if the prior TCP socket closed cleanly or during wake grace.
                    let active_stream = !in_wake
                        && existing.capture.is_some()
                        && !existing.telemetry_writer.is_peer_closed()
                        && existing.last_activity.elapsed() < Duration::from_secs(3);
                    if active_stream {
                        warn!(
                            "[{key}] Rejected unauthenticated reconnect attempt: active authorized session already exists"
                        );
                        return None;
                    }
                }
            }
            // Guard against pre-auth Wi-Fi slot exhaustion: cap concurrent unauthenticated sessions.
            // Note: `max_extended_screens` is enforced in `on_handshake` once the device fingerprint
            // is computed so a returning device on a new DHCP IP can supersede its own stale session.
            if !is_usb && !map.contains_key(&key) {
                let unauth_count = map.values().filter(|s| !s.authorized).count();
                if unauth_count >= 4 {
                    warn!("[{key}] Rejected Wi-Fi connection: too many concurrent unauthenticated sessions");
                    return None;
                }
            }
            // Wake main loop lifecycle without resetting `--idle-exit-secs` timer pre-auth
            // (rejected handshakes & LAN probes must never reset idle exit).
            if !is_usb {
                self.record_wifi_activity();
            }
            self.notify_lifecycle_wakeup();
            let replaced = map.remove(&key);
            let id = self.next_session_id.fetch_add(1, Ordering::Relaxed);
            let now = Instant::now();
            map.insert(
                key.clone(),
                ClientSession {
                    id,
                    data_generation: 0,
                    is_usb,
                    fingerprint: None,
                    data_port,
                    telemetry_writer,
                    pending_usb_data_writer: None,
                    data_writer: None,
                    handshake: None,
                    authorized: false,
                    authorized_at: None,
                    data_detached_at: None,
                    awaiting_confirm: false,
                    connected_at: now,
                    last_activity: now,
                    flow: Arc::new(FlowControl::new(self.initial_session_max_in_flight())),
                    udp_cursor_enabled: Arc::new(AtomicBool::new(!is_usb)),
                    stream_paused: Arc::new(AtomicBool::new(false)),
                    capture: None,
                },
            );
            (id, replaced)
        };
        // Tear down the replaced session's capture & sockets outside the lock so stale
        // reader threads exit promptly and cannot interfere with the new session.
        self.teardown_session(&key, replaced);
        self.notify_lifecycle_wakeup();
        Some(id)
    }

    pub fn register_usb_telemetry(
        &self,
        key: String,
        telemetry_writer: SharedFrameWriter,
        usb_data_writer: SharedFrameWriter,
        data_port: u16,
    ) -> Option<u64> {
        // Always allow pre-auth USB registration (1 slot per physical USB DeviceID) so `on_handshake`
        // can match the device fingerprint and seamlessly supersede the same iPad's stale Wi-Fi or
        // old-USB session even when `max_extended_screens = 1`. Distinct devices are declined in `on_handshake`.
        let (id, replaced) = {
            let mut map = self.sessions.lock().unwrap();
            // Note: do NOT call `record_external_activity()` until Handshake arrives so an idle
            // plugged-in USB iPad does not perpetually defeat `--idle-exit-secs`.
            let replaced = map.remove(&key);
            let id = self.next_session_id.fetch_add(1, Ordering::Relaxed);
            let now = Instant::now();
            map.insert(
                key.clone(),
                ClientSession {
                    id,
                    data_generation: 0,
                    is_usb: true,
                    fingerprint: None,
                    data_port,
                    telemetry_writer,
                    pending_usb_data_writer: Some(usb_data_writer),
                    data_writer: None,
                    handshake: None,
                    authorized: false,
                    authorized_at: None,
                    data_detached_at: None,
                    awaiting_confirm: false,
                    connected_at: now,
                    last_activity: now,
                    flow: Arc::new(FlowControl::new(self.initial_session_max_in_flight())),
                    udp_cursor_enabled: Arc::new(AtomicBool::new(false)),
                    stream_paused: Arc::new(AtomicBool::new(false)),
                    capture: None,
                },
            );
            (id, replaced)
        };
        self.teardown_session(&key, replaced);
        self.notify_lifecycle_wakeup();
        Some(id)
    }

    pub(super) fn touch_activity(&self, key: &str, expected_session_id: Option<u64>) {
        if let Ok(mut map) = self.sessions.lock() {
            if let Some(sess) = map
                .get_mut(key)
                .filter(|s| expected_session_id.is_none_or(|eid| s.id == eid))
            {
                sess.last_activity = Instant::now();
            }
        }
    }

    /// Close any sessions that have:
    /// 1. Disconnected while awaiting user approval (immediately cancels ghost approval prompts),
    /// 2. Been authorized over Wi-Fi for >=15s without establishing a Data channel (e.g. blocked data port),
    /// 3. Had no telemetry/ping/input activity longer than `ping_timeout_secs` (when enabled).
    ///
    /// Returns the number of reaped sessions.
    pub fn reap_timed_out_sessions(&self) -> usize {
        let limit = if self.config.ping_timeout_secs == 0 {
            None
        } else {
            Some(Duration::from_secs(self.config.ping_timeout_secs))
        };
        let count = self.reap_timed_out_inner(limit);
        self.tick_pending_standalone_web_resume();
        count
    }

    pub fn reap_timed_out_with_limit(&self, timeout: Duration) -> usize {
        self.reap_timed_out_inner(Some(timeout))
    }

    fn reap_timed_out_inner(&self, ping_timeout: Option<Duration>) -> usize {
        enum ReapReason {
            PeerClosedWhilePending,
            DataChannelNeverConnected(u16),
            PingTimeout(u64),
        }
        const DATA_CHANNEL_TIMEOUT: Duration = Duration::from_secs(15);
        let expired: Vec<(String, u64, ReapReason)> = {
            let map = self.sessions.lock().unwrap();
            map.iter()
                .filter_map(|(k, s)| {
                    if s.awaiting_confirm {
                        if s.telemetry_writer.is_peer_closed() {
                            return Some((k.clone(), s.id, ReapReason::PeerClosedWhilePending));
                        }
                        return None;
                    }
                    if !s.is_usb
                        && s.authorized
                        && s.capture.is_none()
                        && !self.host_lock_paused_ipad.load(Ordering::Acquire)
                    {
                        if let Some(since) = s.data_detached_at.or(s.authorized_at) {
                            if since.elapsed() >= DATA_CHANNEL_TIMEOUT {
                                return Some((
                                    k.clone(),
                                    s.id,
                                    ReapReason::DataChannelNeverConnected(s.data_port),
                                ));
                            }
                        }
                    }
                    if let Some(timeout) = ping_timeout {
                        if !(s.is_usb && !s.authorized)
                            && !self.host_lock_paused_ipad.load(Ordering::Acquire)
                            && s.last_activity.elapsed() >= timeout
                        {
                            return Some((
                                k.clone(),
                                s.id,
                                ReapReason::PingTimeout(timeout.as_secs()),
                            ));
                        }
                    }
                    None
                })
                .collect()
        };
        let count = expired.len();
        for (key, id, reason) in expired {
            match reason {
                ReapReason::PeerClosedWhilePending => {
                    info!(
                        "[{key}] Peer disconnected while awaiting approval — cancelling pending prompt"
                    );
                }
                ReapReason::DataChannelNeverConnected(dp) => {
                    warn!(
                        "[{key}] Telemetry authorized but Wi-Fi data TCP port {dp} did not connect within 15s (check firewall/NAT) — closing half-connected session"
                    );
                }
                ReapReason::PingTimeout(secs) => {
                    warn!(
                        "[{key}] Client ping/activity timeout ({secs}s) — closing session and releasing virtual display"
                    );
                }
            }
            self.close_session_if_id(&key, id);
        }
        count
    }

    pub fn active_session_count(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }

    /// Handle an incoming `NSKeyedArchiver`-encoded `MSMMessagePacket` on Telemetry.
    pub fn handle_telemetry_bytes(&self, key: &str, bytes: &[u8]) -> Result<()> {
        self.handle_telemetry_bytes_for_session(key, None, bytes)
    }

    /// Session-ID-scoped telemetry handler so a stale displaced socket's late packets
    /// (e.g. `DisconnectMonitor` or `StopStream`) can never kill or mutate a newer session.
    pub fn handle_telemetry_bytes_for_session(
        &self,
        key: &str,
        expected_session_id: Option<u64>,
        bytes: &[u8],
    ) -> Result<()> {
        if let Some(eid) = expected_session_id {
            let matches = self
                .sessions
                .lock()
                .ok()
                .and_then(|map| map.get(key).map(|s| s.id == eid))
                .unwrap_or(false);
            if !matches {
                debug!("[{key}] Ignoring telemetry packet from displaced session id={eid}");
                return Ok(());
            }
        }
        let authorized = match expected_session_id {
            Some(eid) => self.is_authorized_id(key, eid),
            None => self.is_authorized(key),
        };
        let pkt = match MessagePacket::decode(bytes) {
            Ok(p) => p,
            Err(e) => {
                // Compatibility: some USB PeerTalk / iDisplay builds may send raw `MSMTouchEvent` /
                // `MSMKeyboardEvent` / `MSMWheelEvent` bplists on Telemetry (PT type 100).
                if authorized
                    && crate::protocol::messages::decode_input_event(bytes)
                        .ok()
                        .flatten()
                        .is_some()
                {
                    return self.handle_data_bytes_for_session(key, expected_session_id, None, bytes);
                }
                return Err(e);
            }
        };
        if authorized {
            self.touch_activity(key, expected_session_id);
        } else if !matches!(
            (pkt.msg_type, pkt.name_method.as_str()),
            (MessageType::Send, "Handshake")
                | (MessageType::Send, "DisconnectMonitor")
                | (MessageType::Request, "Ping")
        ) {
            // Do not execute pre-auth state-mutating handlers or touch activity, and ignore
            // benign early client packets so legitimate iDisplay clients are not abruptly dropped.
            debug!(
                "[{key}] Ignoring pre-auth telemetry method {:?}/{} until Handshake completes",
                pkt.msg_type, pkt.name_method
            );
            return Ok(());
        }
        if !matches!(
            (pkt.msg_type, pkt.name_method.as_str()),
            (MessageType::Send, "FrameReceived") | (MessageType::Send, "PictureRendered")
        ) {
            debug!(
                "[{key}] Telemetry recv: type={:?} method={}",
                pkt.msg_type, pkt.name_method
            );
        }

        match (pkt.msg_type, pkt.name_method.as_str()) {
            (MessageType::Send, "Handshake") => {
                self.on_handshake(key, expected_session_id, &pkt.param)
            }
            (MessageType::Request, "Ping") => self.on_ping(key, expected_session_id, &pkt),
            (MessageType::Send, "OrientationChange") => {
                self.on_orientation_change(key, expected_session_id, &pkt.param)
            }
            (MessageType::Send, "ResolutionChange") => {
                self.on_resolution_change(key, expected_session_id, &pkt.param)
            }
            (MessageType::Send, "DisconnectMonitor") => {
                info!("[{key}] Client requested DisconnectMonitor");
                if let Some(eid) = expected_session_id {
                    self.close_session_if_id(key, eid);
                } else {
                    self.close_session(key);
                }
                Ok(())
            }
            (MessageType::Send, "FrameReceived") => {
                let flow_opt = {
                    let map = self.sessions.lock().unwrap();
                    map.get(key)
                        .filter(|s| expected_session_id.is_none_or(|eid| s.id == eid))
                        .map(|s| s.flow.clone())
                };
                if let Some(flow) = flow_opt {
                    flow.on_frame_received();
                }
                Ok(())
            }
            (MessageType::Send, "PictureRendered") => {
                let flow_opt = {
                    let map = self.sessions.lock().unwrap();
                    map.get(key)
                        .filter(|s| expected_session_id.is_none_or(|eid| s.id == eid))
                        .map(|s| s.flow.clone())
                };
                if let Some(flow) = flow_opt {
                    flow.on_picture_rendered();
                }
                Ok(())
            }
            (MessageType::Send, "StopStream") => {
                let matched = if let Ok(map) = self.sessions.lock() {
                    if let Some(sess) = map
                        .get(key)
                        .filter(|s| expected_session_id.is_none_or(|eid| s.id == eid))
                    {
                        sess.stream_paused.store(true, Ordering::Release);
                        true
                    } else {
                        false
                    }
                } else {
                    false
                };
                if matched {
                    info!("[{key}] Client requested StopStream — pausing video transmission");
                    self.sync_capture_pause_states();
                }
                Ok(())
            }
            (MessageType::Send, "StartStream") => {
                let matched = if let Ok(map) = self.sessions.lock() {
                    if let Some(sess) = map
                        .get(key)
                        .filter(|s| expected_session_id.is_none_or(|eid| s.id == eid))
                    {
                        // Clear pause BEFORE waking streamer so it never observes stale paused=true!
                        sess.stream_paused.store(false, Ordering::Release);
                        sess.flow.reset_in_flight();
                        true
                    } else {
                        false
                    }
                } else {
                    false
                };
                if matched {
                    info!("[{key}] Client requested StartStream — resuming video transmission");
                    self.sync_capture_pause_states();
                }
                Ok(())
            }
            (MessageType::Send, "DisableUDPCursor") => {
                if let Ok(map) = self.sessions.lock() {
                    if let Some(sess) = map
                        .get(key)
                        .filter(|s| expected_session_id.is_none_or(|eid| s.id == eid))
                    {
                        sess.udp_cursor_enabled.store(false, Ordering::Release);
                    }
                }
                debug!("[{key}] Client requested DisableUDPCursor — falling back to Telemetry cursor");
                Ok(())
            }
            (MessageType::Request, other) => {
                debug!("[{key}] Unhandled telemetry request: {other}");
                Ok(())
            }
            _ => {
                // Compatibility: if an authorized client sends an input event wrapped inside an
                // `MSMMessagePacket` on Telemetry, forward it into the standard input pipeline.
                if authorized
                    && crate::protocol::messages::decode_input_value(&pkt.param).is_some()
                {
                    return self.handle_data_bytes_for_session(key, expected_session_id, None, bytes);
                }
                debug!("[{key}] Ignoring telemetry method: {}", pkt.name_method);
                Ok(())
            }
        }
    }

    fn authorize_client(
        &self,
        session_id: u64,
        key: &str,
        fingerprint: &str,
        is_usb: bool,
        hs: &ClientHandshake,
    ) -> bool {
        if self.config.auto_accept {
            crate::debug_trace::record(
                "auth",
                "decision",
                serde_json::json!({ "allowed": true, "reason": "auto_accept", "is_usb": is_usb }),
            );
            return true;
        }
        if is_usb && self.config.is_usb_auto_trusted() {
            info!(
                "[{key}] USB device auto-approved via --trust-usb (name={:?}, fp={fingerprint})",
                hs.name
            );
            crate::debug_trace::record(
                "auth",
                "decision",
                serde_json::json!({ "allowed": true, "reason": "trust_usb", "is_usb": true }),
            );
            return true;
        }
        if self
            .config
            .allow_fingerprints
            .iter()
            .filter_map(|fp| normalize_fingerprint(fp))
            .any(|fp| fp == fingerprint)
        {
            info!(
                "[{key}] Device matched --allow-fingerprint whitelist (name={:?}, fp={fingerprint})",
                hs.name
            );
            crate::debug_trace::record(
                "auth",
                "decision",
                serde_json::json!({ "allowed": true, "reason": "allow_fingerprint", "is_usb": is_usb }),
            );
            return true;
        }
        if self.trust_store.is_trusted(Some(fingerprint)) {
            info!(
                "[{key}] Trusted device recognized by fingerprint (name={:?}, fp={fingerprint})",
                hs.name
            );
            crate::debug_trace::record(
                "auth",
                "decision",
                serde_json::json!({ "allowed": true, "reason": "trust_store", "is_usb": is_usb }),
            );
            return true;
        }
        if self.config.no_confirm || self.is_low_power() {
            crate::debug_trace::record(
                "auth",
                "decision",
                serde_json::json!({ "allowed": false, "reason": if self.is_low_power() { "low_power_trusted_only" } else { "no_confirm" }, "is_usb": is_usb }),
            );
            return false;
        }

        let pending = PendingDevice {
            session_id,
            addr: key.to_string(),
            fingerprint: fingerprint.to_string(),
            uid: hs.uid.clone(),
            name: hs.name.clone(),
            model: hs.model.clone(),
            is_usb,
            is_web: false,
        };

        let custom = self.confirm_handler.lock().unwrap().clone();
        let decision = if let Some(cb) = custom {
            // Custom confirm handlers (e.g. Web Admin approval queue) manage their own concurrency
            // so one unauthenticated peer cannot stall other connections for 60s on `confirm_lock`.
            cb(&pending)
        } else {
            let _guard = self.confirm_lock.lock().unwrap();
            if io::stdin().is_terminal() {
                // Spawn at most one reusable background stdin reader thread so disconnected clients
                // or 60s timeouts can immediately release `confirm_lock` instead of hanging forever.
                if !self.tty_reader_started.swap(true, Ordering::AcqRel) {
                    let prompt_slot = self.tty_prompt_tx.clone();
                    let _ = thread::Builder::new()
                        .name("tty-confirm-stdin".to_string())
                        .spawn(move || {
                            let stdin = io::stdin();
                            let mut line = String::new();
                            loop {
                                line.clear();
                                match stdin.read_line(&mut line) {
                                    Ok(0) | Err(_) => break,
                                    Ok(_) => {
                                        let tx_opt = prompt_slot.lock().ok().and_then(|g| g.clone());
                                        if let Some(tx) = tx_opt {
                                            let _ = tx.send(line.clone());
                                        }
                                    }
                                }
                            }
                        });
                }
                let (tx, rx) = std::sync::mpsc::channel::<String>();
                *self.tty_prompt_tx.lock().unwrap() = Some(tx);
                print!(
                    "\n[TRUST] Untrusted device wants to connect (60s timeout):\n  Name:        {:?} ({})\n  Addr:        {}\n  Fingerprint: {}\nAllow connection? [y = allow & trust / o = once / N = deny]: ",
                    pending.name,
                    pending.model,
                    pending.addr,
                    pending.fingerprint
                );
                let _ = io::stdout().flush();
                let deadline = Instant::now() + Duration::from_secs(60);
                let mut decided = ConfirmDecision::Deny;
                loop {
                    let rem = deadline.saturating_duration_since(Instant::now());
                    if rem.is_zero() {
                        println!("\n[TRUST] Approval timed out (60s) — denied.");
                        break;
                    }
                    // Abort immediately if the session was replaced/removed or the peer closed its socket.
                    let peer_alive = self
                        .sessions
                        .lock()
                        .ok()
                        .and_then(|m| {
                            m.get(key)
                                .filter(|s| s.id == session_id)
                                .map(|s| !s.telemetry_writer.is_peer_closed())
                        })
                        .unwrap_or(false);
                    if !peer_alive {
                        println!("\n[TRUST] Client disconnected — approval cancelled.");
                        break;
                    }
                    match rx.recv_timeout(rem.min(Duration::from_millis(250))) {
                        Ok(line) => {
                            decided = match line.trim().to_ascii_lowercase().as_str() {
                                "y" | "yes" => ConfirmDecision::AllowAndTrust,
                                "o" | "once" => ConfirmDecision::AllowOnce,
                                _ => ConfirmDecision::Deny,
                            };
                            break;
                        }
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }
                *self.tty_prompt_tx.lock().unwrap() = None;
                decided
            } else {
                warn!(
                    "[{key}] Untrusted device (name={:?}, fp={}) denied because stdin is not interactive. Run interactively once to trust by fingerprint, or pass `--allow-fingerprint` / `--auto-accept`.",
                    pending.name,
                    pending.fingerprint
                );
                ConfirmDecision::Deny
            }
        };

        match decision {
            ConfirmDecision::AllowAndTrust => {
                // Guard against ghost trust if the iPad disconnected (FIN/RST) or was replaced
                // while waiting for Web Admin approval (matches TTY & Web viewer liveness checks).
                let peer_still_alive = {
                    let map = self.sessions.lock().unwrap();
                    map.get(key)
                        .is_some_and(|s| s.id == session_id && !s.telemetry_writer.is_peer_closed())
                };
                if !peer_still_alive {
                    info!("[{key}] Client disconnected before AllowAndTrust completed; skipping trust persistence");
                    return false;
                }
                if let Err(e) =
                    self.trust_device_and_save(fingerprint, &hs.uid, &hs.name, &hs.model)
                {
                    warn!("[{key}] Failed to persist trusted device: {e:#}");
                }
                true
            }
            ConfirmDecision::AllowOnce => {
                let peer_still_alive = {
                    let map = self.sessions.lock().unwrap();
                    map.get(key)
                        .is_some_and(|s| s.id == session_id && !s.telemetry_writer.is_peer_closed())
                };
                if !peer_still_alive {
                    info!("[{key}] Client disconnected before AllowOnce completed; aborting session");
                    return false;
                }
                info!("[{key}] Allowed once (not persisted to trusted store)");
                true
            }
            ConfirmDecision::Deny => false,
        }
    }

    fn on_handshake(
        &self,
        key: &str,
        expected_session_id: Option<u64>,
        param: &ArchivedValue,
    ) -> Result<()> {
        let hs = ClientHandshake::from_archived(param)?;
        let fingerprint = compute_device_fingerprint(&hs);
        let (eff_w, eff_h) = hs.effective_resolution();
        let (sess_id, is_usb) = {
            let mut map = self.sessions.lock().unwrap();
            let sess = map
                .get_mut(key)
                .filter(|s| expected_session_id.is_none_or(|eid| s.id == eid))
                .ok_or_else(|| anyhow!("unknown or displaced session {key}"))?;
            sess.fingerprint = Some(fingerprint.clone());
            sess.awaiting_confirm = true;
            sess.last_activity = Instant::now();
            (sess.id, sess.is_usb)
        };
        info!(
            "[{key}] Handshake from name={:?} (fp={}, uid={:?}, {}, iOS {}, app v{}), proto={}, res={}x{} (effective {}x{}), telemetryCursor={}",
            hs.name,
            fingerprint,
            hs.uid,
            hs.model,
            hs.system_version,
            hs.client_version,
            hs.data_protocol_version,
            hs.screen_width,
            hs.screen_height,
            eff_w,
            eff_h,
            hs.supports_telemetry_cursor
        );
        crate::debug_trace::record(
            "session",
            "handshake",
            serde_json::json!({
                "key": key,
                "is_usb": is_usb,
                "fingerprint": fingerprint,
                "model": hs.model,
                "system_version": hs.system_version,
                "client_version": hs.client_version,
                "proto": hs.data_protocol_version,
                "orientation": hs.orientation,
                "reported_width": hs.screen_width,
                "reported_height": hs.screen_height,
                "effective_width": eff_w,
                "effective_height": eff_h,
                "udp_port": hs.udp_port,
                "telemetry_cursor": hs.supports_telemetry_cursor,
                "max_compression": hs.max_compression,
                "preferred_compression": hs.preferred_compression,
                "preferred_fps": hs.preferred_fps,
            }),
        );

        // Refresh live OS lock state before admission so unlock clears prior lockouts immediately
        // and an already-locked idle host never leaks a fresh grace-delay window, while rejecting
        // new incoming handshakes while locked with `ipad=disconnect` without prematurely aborting
        // an active authorized session's grace countdown.
        self.refresh_host_lock_state_now(true);
        if self.is_ipad_lock_disconnect_blocking()
            || (self.is_host_screen_locked()
                && self.lock_action_ipad() == crate::config::LockAction::Disconnect)
        {
            warn!(
                "[{key}] Rejecting incoming handshake while host screen is locked (on_lock_ipad=disconnect)"
            );
            // IMPORTANT: Do NOT send `build_access_declined_packet(4)` here! Legacy iDisplay maps
            // reason=4 to "This device is blacklisted". Closing the socket cleanly reports a
            // temporary disconnect until the host is unlocked.
            self.close_session_if_id(key, sess_id);
            return Ok(());
        }

        // Pre-check `max_extended_screens` before prompting/persisting trust so a distinct device
        // hitting the screen cap never triggers a futile approval prompt or gets persisted only to
        // be declined immediately after. Same-fingerprint reconnects still proceed so they can
        // supersede their own stale session once authorized.
        {
            let standalone_web_n = usize::from(
                self.is_web_independent_screen()
                    && self.standalone_web_capture.lock().unwrap().is_some(),
            );
            let map = self.sessions.lock().unwrap();
            let max_ext = self.max_extended_screens();
            let auth_others = map
                .iter()
                .filter(|(k, s)| {
                    *k != key
                        && s.authorized
                        && s.fingerprint.as_deref() != Some(fingerprint.as_str())
                })
                .count();
            if max_ext > 0 && (auth_others + standalone_web_n + 1) > max_ext {
                warn!(
                    "[{key}] Handshake declined: max_extended_screens={max_ext} reached (authorized={auth_others}, standalone_web={standalone_web_n})"
                );
                let tw = map
                    .get(key)
                    .filter(|s| s.id == sess_id)
                    .map(|s| s.telemetry_writer.clone());
                drop(map);
                if let Some(tw) = tw {
                    let _ = tw.send_frame(&build_access_declined_packet(4).encode()?);
                }
                self.close_session_if_id(key, sess_id);
                return Ok(());
            }
        }

        let allowed = self.authorize_client(sess_id, key, &fingerprint, is_usb, &hs);
        if let Ok(mut map) = self.sessions.lock() {
            if let Some(sess) = map.get_mut(key) {
                if sess.id == sess_id {
                    sess.awaiting_confirm = false;
                    sess.last_activity = Instant::now();
                }
            }
        }
        if !allowed {
            warn!(
                "[{key}] Connection declined by access policy (name={:?}, fp={}, uid={}).",
                hs.name,
                fingerprint,
                hs.uid
            );
            let tel_writer = {
                let map = self.sessions.lock().unwrap();
                map.get(key)
                    .filter(|s| s.id == sess_id)
                    .map(|s| s.telemetry_writer.clone())
            };
            if let Some(tw) = tel_writer {
                // reason = 4 matches legacy securityRule rejection
                let _ = tw.send_frame(&build_access_declined_packet(4).encode()?);
            }
            self.close_session_if_id(key, sess_id);
            return Ok(());
        }

        // Re-check live OS lock state AFTER blocking `authorize_client` (up to 60s) so an approval
        // clicked after the host locked never admits a new iPad under `on_lock_ipad=disconnect` (P1-A2).
        self.refresh_host_lock_state_now(true);
        if self.is_ipad_lock_disconnect_blocking()
            || (self.is_host_screen_locked()
                && self.lock_action_ipad() == crate::config::LockAction::Disconnect)
        {
            warn!(
                "[{key}] Aborting post-approval admission: host screen locked during approval (on_lock_ipad=disconnect)"
            );
            self.close_session_if_id(key, sess_id);
            return Ok(());
        }
        self.record_external_activity();

        let sys = self.backend.host_system_info(&self.config.host_name);
        // Enforce `max_extended_screens` on authorized sessions (allowing the same device to
        // supersede its own previous session across Wi-Fi/USB or DHCP IP changes).
        let (tel_writer, data_port, superseded) = {
            // Consistent lock order: `standalone_web_capture` -> `sessions`.
            let standalone_web_n = usize::from(
                self.is_web_independent_screen()
                    && self.standalone_web_capture.lock().unwrap().is_some(),
            );
            let mut map = self.sessions.lock().unwrap();
            let max_ext = self.max_extended_screens();
            // Match same device across Wi-Fi <-> Wi-Fi, USB <-> Wi-Fi, and USB <-> USB via
            // deterministic SHA-256 handshake fingerprint (orientation- and transport-invariant).
            let same_device_keys: Vec<String> = map
                .iter()
                .filter(|(k, s)| {
                    *k != key
                        && s.authorized
                        && s.fingerprint.as_deref() == Some(fingerprint.as_str())
                })
                .map(|(k, _)| k.clone())
                .collect();
            // Check quota BEFORE removing any existing session so a declined connection NEVER kills
            // an unrelated or existing authorized session.
            let auth_others = map
                .iter()
                .filter(|(k, s)| *k != key && s.authorized && !same_device_keys.contains(k))
                .count();
            if max_ext > 0 && (auth_others + standalone_web_n + 1) > max_ext {
                warn!(
                    "[{key}] Handshake declined: max_extended_screens={max_ext} reached (authorized={auth_others}, standalone_web={standalone_web_n})"
                );
                let tw = map
                    .get(key)
                    .filter(|s| s.id == sess_id)
                    .map(|s| s.telemetry_writer.clone());
                drop(map);
                if let Some(tw) = tw {
                    let _ = tw.send_frame(&build_access_declined_packet(4).encode()?);
                }
                self.close_session_if_id(key, sess_id);
                return Ok(());
            }
            // Verify the incoming session itself is still alive BEFORE superseding any existing session
            // so a stale/replaced handshake thread can never evict an active session and then error out.
            if map.get(key).map(|s| s.id) != Some(sess_id) {
                return Err(anyhow!(
                    "session {key} (id={sess_id}) replaced during handshake"
                ));
            }
            let mut superseded_list: Vec<(String, ClientSession)> = Vec::new();
            for old_k in same_device_keys {
                if let Some(old_sess) = map.remove(&old_k) {
                    superseded_list.push((old_k, old_sess));
                }
            }
            let sess = map
                .get_mut(key)
                .filter(|s| s.id == sess_id)
                .ok_or_else(|| anyhow!("session {key} (id={sess_id}) replaced during handshake"))?;
            let dp = sess.data_port;
            let tw = sess.telemetry_writer.clone();
            let now = Instant::now();
            sess.handshake = Some(hs.clone());
            sess.authorized = true;
            sess.authorized_at = Some(now);
            sess.data_detached_at = None;
            sess.last_activity = now;
            (tw, dp, superseded_list)
        };
        for (old_k, old_sess) in superseded {
            self.teardown_session(&old_k, Some(old_sess));
        }

        let ac_pkt = build_access_confirmed_packet(
            &sys.user_name,
            &sys.host_name,
            &sys.os_version,
            sys.physical_memory,
            sys.cpu_count,
            self.config.mode.legacy_type_capture(),
            hs.data_protocol_version,
        );
        tel_writer.send_frame(&ac_pkt.encode()?)?;

        let port_pkt = build_video_port_packet(data_port);
        tel_writer.send_frame(&port_pkt.encode()?)?;

        info!("[{key}] Sent AccessConfirmed + VideoServiceAccessibleOnPort({data_port})");
        Ok(())
    }

    fn on_ping(
        &self,
        key: &str,
        expected_session_id: Option<u64>,
        pkt: &MessagePacket,
    ) -> Result<()> {
        let (tel_writer, maybe_usb_start) = {
            let mut map = self.sessions.lock().unwrap();
            let Some(sess) = map
                .get_mut(key)
                .filter(|s| expected_session_id.is_none_or(|eid| s.id == eid))
            else {
                return Ok(());
            };
            if sess.authorized {
                sess.last_activity = Instant::now();
            }
            let is_start = sess.is_usb
                && sess.authorized
                && pkt.param.as_str() == Some("START")
                && sess.capture.is_none();
            let usb_dw = if is_start {
                sess.pending_usb_data_writer.clone().map(|dw| (sess.id, dw))
            } else {
                None
            };
            (sess.telemetry_writer.clone(), usb_dw)
        };

        // On USB, Ping("START") triggers opening the Data channel (PT type 101).
        if let Some((sid, dw)) = maybe_usb_start {
            info!("[{key}] USB Ping(\"START\") received — activating PeerTalk data channel (type 101)");
            let _ = self.attach_data_channel_checked(key, Some(sid), dw)?;
        }

        let resp = pkt.into_response(ArchivedValue::Date(now_apple_secs()));
        tel_writer.send_frame(&resp.encode()?)?;
        Ok(())
    }

    fn on_orientation_change(
        &self,
        key: &str,
        expected_session_id: Option<u64>,
        param: &ArchivedValue,
    ) -> Result<()> {
        let Some(orientation) = parse_archived_i32(param) else {
            warn!("[{key}] OrientationChange had unparseable param: {param:?}");
            return Ok(());
        };
        let (new_w, new_h, eff_vs, eff_edge, handle_opt) = {
            let mut map = self.sessions.lock().unwrap();
            let Some(sess) = map
                .get_mut(key)
                .filter(|s| expected_session_id.is_none_or(|eid| s.id == eid))
            else {
                return Ok(());
            };
            let Some(hs) = sess.handshake.as_mut() else {
                return Ok(());
            };
            hs.orientation = orientation;
            let eff_vs = self.effective_video_for_fingerprint(sess.fingerprint.as_deref());
            let (w, h) = Self::resolve_dimensions_for_settings(hs, &eff_vs, self.backend.supports_hidpi());
            let edge = Self::effective_ipad_max_pixel_edge(hs, &eff_vs);
            let hdl = sess.capture.as_ref().map(|c| c.handle.clone());
            (w, h, eff_vs, edge, hdl)
        };
        let eff_hidpi = if self.backend.supports_hidpi() { eff_vs.hidpi } else { 1 };
        info!(
            "[{key}] OrientationChange -> {orientation} ({}) -> reconfiguring display to {new_w}x{new_h} (max_edge={eff_edge})",
            if matches!(orientation, 1 | 3 | 4) { "landscape" } else { "portrait" }
        );
        self.ipad_video_settings_gen.fetch_add(1, Ordering::AcqRel);
        if let Ok(mut lf) = self.last_ipad_web_frame.lock() {
            *lf = None;
        }
        if let Some(hdl) = handle_opt {
            if let Ok(mut g) = hdl.lock() {
                if let Err(e) = g.reconfigure(
                    new_w,
                    new_h,
                    eff_vs.fps,
                    eff_vs.bitrate_mbps,
                    eff_hidpi,
                    eff_edge,
                ) {
                    warn!("[{key}] OrientationChange reconfigure to {new_w}x{new_h} failed: {e:#}");
                }
            }
            self.notify_lifecycle_wakeup();
        }
        Ok(())
    }

    fn on_resolution_change(
        &self,
        key: &str,
        expected_session_id: Option<u64>,
        param: &ArchivedValue,
    ) -> Result<()> {
        let Some(dict) = param.as_dict() else {
            return Ok(());
        };
        let w = dict
            .get("screenWidth")
            .and_then(parse_archived_u32)
            .unwrap_or(0);
        let h = dict
            .get("screenHeight")
            .and_then(parse_archived_u32)
            .unwrap_or(0);
        if w < 320 || h < 240 {
            return Ok(());
        }
        let (new_w, new_h, eff_vs, eff_edge, handle_opt) = {
            let mut map = self.sessions.lock().unwrap();
            let Some(sess) = map
                .get_mut(key)
                .filter(|s| expected_session_id.is_none_or(|eid| s.id == eid))
            else {
                return Ok(());
            };
            let Some(hs) = sess.handshake.as_mut() else {
                return Ok(());
            };
            hs.screen_width = w.min(8192) & !1;
            hs.screen_height = h.min(8192) & !1;
            // Wire orientation convention: width > height => landscape (1).
            hs.orientation = if w > h { 1 } else { 0 };
            let eff_vs = self.effective_video_for_fingerprint(sess.fingerprint.as_deref());
            let (rw, rh) = Self::resolve_dimensions_for_settings(hs, &eff_vs, self.backend.supports_hidpi());
            let edge = Self::effective_ipad_max_pixel_edge(hs, &eff_vs);
            let hdl = sess.capture.as_ref().map(|c| c.handle.clone());
            (rw, rh, eff_vs, edge, hdl)
        };
        let eff_hidpi = if self.backend.supports_hidpi() { eff_vs.hidpi } else { 1 };
        info!("[{key}] ResolutionChange -> {new_w}x{new_h} (max_edge={eff_edge})");
        self.ipad_video_settings_gen.fetch_add(1, Ordering::AcqRel);
        if let Ok(mut lf) = self.last_ipad_web_frame.lock() {
            *lf = None;
        }
        if let Some(hdl) = handle_opt {
            if let Ok(mut g) = hdl.lock() {
                if let Err(e) = g.reconfigure(
                    new_w,
                    new_h,
                    eff_vs.fps,
                    eff_vs.bitrate_mbps,
                    eff_hidpi,
                    eff_edge,
                ) {
                    warn!("[{key}] ResolutionChange reconfigure to {new_w}x{new_h} failed: {e:#}");
                }
            }
            self.notify_lifecycle_wakeup();
        }
        Ok(())
    }

    pub(super) fn resolve_dimensions_for_settings(
        hs: &ClientHandshake,
        vs: &VideoSettings,
        supports_hidpi: bool,
    ) -> (u32, u32) {
        let (phys_w, phys_h) = hs.effective_resolution();
        let explicit = if vs.width >= 320 && vs.height >= 240 {
            Some(hs.orient_dimensions(vs.width, vs.height))
        } else {
            None
        };
        let eff_hidpi = if supports_hidpi { vs.hidpi } else { 1 };
        let eff_edge = Self::effective_ipad_max_pixel_edge(hs, vs);
        if vs.integer_scale {
            // Legacy 1x-point Retina iPads (e.g. 1024x768) have `phys_w.max(phys_h) < 1600`;
            // scale their logical point dimensions to native 2x backing pixels BEFORE dividing
            // by `eff_hidpi` so 1024x768 @ 2x stays 1024x768 logical (2048x1536 backing), not 512x384.
            let (panel_w, panel_h) = if eff_hidpi >= 2 && phys_w.max(phys_h) < 1600 {
                (phys_w.saturating_mul(eff_hidpi), phys_h.saturating_mul(eff_hidpi))
            } else {
                (phys_w, phys_h)
            };
            compute_integer_scaled_logical(panel_w, panel_h, explicit, eff_hidpi, eff_edge)
        } else if let Some(exp) = explicit {
            exp
        } else if eff_hidpi >= 2 && phys_w.max(phys_h) >= 1600 {
            // In auto-resolution 2x HiDPI mode on Retina iPads (e.g. 2048x1536 panel), divide
            // physical panel pixels by 2 so logical UI is 1024x768 @ 2x = 2048x1536 exact 1:1
            // instead of an unreadable 4096x3072 backing framebuffer downscaled 2x.
            (
                ((phys_w / eff_hidpi).max(320)) & !1,
                ((phys_h / eff_hidpi).max(240)) & !1,
            )
        } else {
            (phys_w, phys_h)
        }
    }

    pub(super) fn overlay_device_prefs(
        mut vs: VideoSettings,
        prefs: Option<&DevicePreferences>,
        low_power: bool,
    ) -> VideoSettings {
        if low_power {
            return vs;
        }
        if let Some(p) = prefs.filter(|p| !p.is_empty()) {
            if let (Some(dw), Some(dh)) = (p.width, p.height) {
                vs.width = dw;
                vs.height = dh;
            }
            if let Some(dfps) = p.fps {
                vs.fps = dfps.clamp(5, 120);
            }
            if let Some(dbr) = p.bitrate_mbps {
                vs.bitrate_mbps = dbr.clamp(2, 60);
            }
            if let Some(dhidpi) = p.hidpi {
                vs.hidpi = if dhidpi >= 2 { 2 } else { 1 };
            }
            if let Some(dedge) = p.max_pixel_edge {
                vs.max_pixel_edge = dedge;
            }
            if let Some(dabr) = p.adaptive_quality {
                vs.adaptive_quality = dabr;
            }
            vs.quality = QualityPreset::from_fps_bitrate(vs.fps, vs.bitrate_mbps);
        }
        vs
    }

    pub(super) fn effective_video_for_fingerprint(&self, fingerprint: Option<&str>) -> VideoSettings {
        let base = self.video_settings();
        let prefs = fingerprint
            .and_then(|fp| self.trust_store.get_device(fp))
            .map(|d| d.prefs);
        Self::overlay_device_prefs(base, prefs.as_ref(), self.is_low_power())
    }

    pub fn close_session(&self, key: &str) {
        let removed = {
            let mut map = self.sessions.lock().unwrap();
            map.remove(key)
        };
        let was_authorized = removed.as_ref().is_some_and(|s| s.authorized);
        if was_authorized {
            self.record_external_activity();
        } else if removed.is_some() {
            self.notify_lifecycle_wakeup();
        }
        self.teardown_session(key, removed);
        if was_authorized && self.web_screen_mode() == crate::config::WebScreenMode::FollowIpad {
            self.schedule_standalone_web_resume_after(Duration::from_secs(5));
        } else {
            self.resume_standalone_web_capture_if_needed();
        }
    }

    /// Close a session only if its unique registration `id` still matches, preventing a stale
    /// socket thread's EOF from accidentally closing a newer reconnected session for the same IP.
    pub fn close_session_if_id(&self, key: &str, id: u64) {
        let removed = {
            let mut map = self.sessions.lock().unwrap();
            if map.get(key).map(|s| s.id) == Some(id) {
                map.remove(key)
            } else {
                None
            }
        };
        let was_authorized = removed.as_ref().is_some_and(|s| s.authorized);
        if was_authorized {
            self.record_external_activity();
        } else if removed.is_some() {
            self.notify_lifecycle_wakeup();
        }
        self.teardown_session(key, removed);
        if was_authorized && self.web_screen_mode() == crate::config::WebScreenMode::FollowIpad {
            self.schedule_standalone_web_resume_after(Duration::from_secs(5));
        } else {
            self.resume_standalone_web_capture_if_needed();
        }
    }

    /// Schedule standalone Web virtual display fallback after a brief reconnect grace window so
    /// transient iPad Wi-Fi drops do not thrash macOS displays or flash Web viewers twice.
    pub(super) fn schedule_standalone_web_resume_after(&self, grace: Duration) {
        if self.is_host_lock_paused_web() || self.is_web_lock_disconnect_blocking() {
            if let Ok(mut g) = self.standalone_web_resume_after.lock() {
                *g = None;
            }
            return;
        }
        if self.web_screen_mode() != crate::config::WebScreenMode::FollowIpad {
            self.resume_standalone_web_capture_if_needed();
            return;
        }
        let has_viewers = !self.web_subscribers.lock().unwrap().is_empty();
        let has_ipad_capture = self
            .sessions
            .lock()
            .unwrap()
            .values()
            .any(|s| s.capture.is_some());
        if !has_viewers || has_ipad_capture {
            if let Ok(mut g) = self.standalone_web_resume_after.lock() {
                *g = None;
            }
            return;
        }
        let deadline = Instant::now() + grace;
        if let Ok(mut g) = self.standalone_web_resume_after.lock() {
            if g.is_none_or(|cur| deadline < cur) {
                *g = Some(deadline);
            }
        }
        info!(
            "Deferring standalone Web virtual display fallback for {}s while awaiting iPad reconnect",
            grace.as_secs()
        );
        self.notify_lifecycle_wakeup();
    }

    /// Check whether a deferred follow-iPad standalone Web fallback grace timer has expired.
    pub fn tick_pending_standalone_web_resume(&self) {
        let due = {
            let mut g = self.standalone_web_resume_after.lock().unwrap();
            if g.is_some_and(|deadline| Instant::now() >= deadline) {
                *g = None;
                true
            } else {
                false
            }
        };
        if due {
            self.resume_standalone_web_capture_if_needed();
        }
    }

    pub(super) fn resume_standalone_web_capture_if_needed(&self) {
        if let Ok(mut g) = self.standalone_web_resume_after.lock() {
            *g = None;
        }
        if self.is_host_lock_paused_web() || self.is_web_lock_disconnect_blocking() {
            return;
        }
        let screen_mode = self.web_screen_mode();
        let (has_ipad, need_standalone) = {
            let map = self.sessions.lock().unwrap();
            let subs = self.web_subscribers.lock().unwrap();
            let has_ipad = map.values().any(|s| s.capture.is_some());
            (
                has_ipad,
                !subs.is_empty()
                    && (screen_mode != crate::config::WebScreenMode::FollowIpad || !has_ipad),
            )
        };
        if !has_ipad {
            if let Ok(mut lf) = self.last_ipad_web_frame.lock() {
                *lf = None;
            }
        }
        if need_standalone {
            if let Err(e) = self.ensure_standalone_web_capture() {
                warn!("Failed to resume standalone Web capture after iPad disconnect: {e:#}");
            }
        }
    }

    fn teardown_session(&self, key: &str, removed: Option<ClientSession>) {
        if let Some(mut sess) = removed {
            let sid = sess.id;
            if !sess.is_usb {
                self.record_wifi_activity();
            }
            info!("[{key}] Closing session");
            self.notify_cancel_pending(Some(sid), Some(key));
            // Close sockets and join capture threads FIRST so any blocked writer unblocks and
            // the dying iPad stream thread can NEVER re-claim `web_follow_ipad_session_id` or
            // poison `last_ipad_web_frame` under the bumped epoch (Iter-8 P1-B2).
            if let Some(dw) = sess.data_writer.take() {
                dw.close();
            }
            sess.telemetry_writer.close();
            if let Some(mut cap) = sess.capture.take() {
                cap.shutdown();
            }
            let was_follow_owner = self
                .web_follow_ipad_session_id
                .compare_exchange(sid, 0, Ordering::AcqRel, Ordering::Acquire)
                .is_ok();
            if was_follow_owner {
                if self.web_screen_mode() == crate::config::WebScreenMode::FollowIpad {
                    self.bump_web_source_epoch();
                }
                if let Ok(mut lf) = self.last_ipad_web_frame.lock() {
                    *lf = None;
                }
                // Immediately elect and unpause any remaining iPad in FollowIpad mode and request an IDR.
                self.sync_capture_pause_states();
                self.request_active_keyframes();
            }
        }
    }

    pub fn has_active_wifi_sessions(&self) -> bool {
        self.sessions
            .lock()
            .unwrap()
            .values()
            .any(|s| !s.is_usb)
    }

    pub fn close_wifi_sessions(&self) {
        let keys: Vec<String> = self
            .sessions
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, s)| !s.is_usb)
            .map(|(k, _)| k.clone())
            .collect();
        for k in keys {
            self.close_session(&k);
        }
    }

    pub fn close_all_ipad_sessions(&self) {
        self.notify_cancel_pending(None, None);
        let keys: Vec<String> = self.sessions.lock().unwrap().keys().cloned().collect();
        for k in keys {
            self.close_session(&k);
        }
    }

    pub fn close_all(&self) {
        // Kick Web viewers FIRST so closing iPad sessions never spuriously spawns and immediately
        // tears down a standalone virtual display during Ctrl-C / "disconnect all".
        self.kick_all_web_viewers();
        self.close_all_ipad_sessions();
        self.stop_standalone_web_capture_if_no_viewers();
        self.shutdown_all_virtual_displays();
    }
}
