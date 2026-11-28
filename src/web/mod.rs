//! Built-in secure Web Admin Console & Passcode-Protected Extended Screen Viewer.
//!
//! Security posture (Secure by Default):
//! - Disabled unless `--web` is explicitly passed.
//! - Admin Console binds `127.0.0.1:8787` (localhost-only) unless `--web-bind` is explicitly changed,
//!   and only serves Admin routes (`/`, `/admin`, `/api/admin/*`).
//! - Web extended-screen viewer runs on a separate dynamic random port listening on `0.0.0.0:0`
//!   that is opened ONLY while Web viewing is enabled (`max_web_viewers > 0` and a view passcode is
//!   configured) and immediately closed when Web viewing is disabled.
//! - Admin password defaults to empty (no login required from loopback) when bound to a loopback address;
//!   when bound to a non-loopback address without `--web-admin-token`, auto-generates a cryptographically
//!   random 32-hex-char Admin token.
//! - Constant-time token verification, per-IP login brute-force rate limiting, `HttpOnly; SameSite=Strict`
//!   session cookies, `Origin` CSRF validation, connection limits, and bounded frame/request sizes.

mod http;
mod log_buffer;
mod p2p;
mod routes;
mod ws_stream;

use crate::session::{ConfirmDecision, PendingDevice, SessionRegistry};
use anyhow::{Context, Result};
pub use http::{generate_random_hex, percent_encode_query_val};
pub use log_buffer::{LogBuffer, LogBufferLayer, LogEntry};
use p2p::P2pRelayHub;
pub use p2p::SharedWebMuxer;

/// Internal parser & topology hooks exposed strictly for deterministic Tier-0/Tier-2 fuzz tests.
#[doc(hidden)]
pub mod fuzz_hooks {
    pub use super::p2p::P2pRelayHub;
    use super::http;
    use std::collections::HashMap;
    use std::io::Cursor;
    use std::time::{Duration, Instant};

    pub type ParsedHttpRequest = (String, String, HashMap<String, String>, Vec<u8>);

    pub fn parse_http_bytes(raw: &[u8]) -> anyhow::Result<Option<ParsedHttpRequest>> {
        let mut cursor = Cursor::new(raw);
        let dl = Instant::now() + Duration::from_secs(1);
        let req = http::read_http_request_from(&mut cursor, dl, |_| Ok(()))?;
        Ok(req.map(|r| (r.method, r.path, r.headers, r.body)))
    }

    pub fn origin_matches_host(headers: &HashMap<String, String>) -> bool {
        http::origin_matches_host(headers)
    }

    pub fn parse_ws_client_frame(raw: &[u8]) -> std::io::Result<Option<(u8, Vec<u8>)>> {
        let mut cursor = Cursor::new(raw);
        http::read_ws_control_frame(&mut cursor)
    }

    pub fn read_http_request_with_deadline(
        stream: &std::net::TcpStream,
        deadline: Instant,
    ) -> anyhow::Result<Option<ParsedHttpRequest>> {
        let req = http::read_http_request_with_deadline(stream, deadline)?;
        Ok(req.map(|r| (r.method, r.path, r.headers, r.body)))
    }

    pub fn read_ws_control_frame_with_deadline(
        stream: &mut std::net::TcpStream,
        idle_timeout: Duration,
        frame_deadline: Duration,
    ) -> std::io::Result<Option<(u8, Vec<u8>)>> {
        http::read_ws_control_frame_deadline(stream, idle_timeout, frame_deadline)
    }

    pub fn write_ws_frame_with_deadline<W: std::io::Write>(
        writer: &mut W,
        opcode: u8,
        payload: &[u8],
        deadline: Instant,
    ) -> std::io::Result<()> {
        http::write_ws_frame_with_deadline(writer, opcode, payload, deadline)
    }

    pub fn write_ws_frame_tcp_with_deadline(
        stream: &mut std::net::TcpStream,
        opcode: u8,
        payload: &[u8],
        deadline: Instant,
    ) -> std::io::Result<()> {
        http::write_ws_frame_tcp_deadline(stream, opcode, payload, deadline)
    }
}
use routes::handle_connection;
use serde::Serialize;
use std::collections::HashMap;
use std::io::{IsTerminal, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

pub(super) const MAX_HTTP_REQUEST_BYTES: usize = 64 * 1024;
const MAX_WEB_CONNECTIONS: usize = 64;
const MAX_WEB_CONNS_PER_IP: usize = 24;
const MAX_PENDING_APPROVALS: usize = 8;
const MAX_RATE_LIMIT_IPS: usize = 1024;
const MAX_ACTIVE_SESSIONS: usize = 256;
pub(super) const MAX_WS_CONTROL_PAYLOAD: u64 = 125;
pub(super) const HTTP_REQUEST_DEADLINE: Duration = Duration::from_secs(10);
pub(super) const SESSION_TTL: Duration = Duration::from_secs(12 * 3600);
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const RATE_LIMIT_MAX_FAILS: usize = 8;
const PENDING_APPROVAL_TIMEOUT: Duration = Duration::from_secs(60);
const LAN_IP_CACHE_TTL: Duration = Duration::from_secs(15);

/// Public view of a pending untrusted connection awaiting Web Admin approval.
#[derive(Debug, Clone, Serialize)]
pub struct PendingApprovalView {
    pub id: u64,
    pub addr: String,
    pub fingerprint: String,
    pub uid: String,
    pub name: String,
    pub model: String,
    pub is_usb: bool,
    pub is_web: bool,
    pub waiting_secs: u64,
}

struct PendingApprovalSlot {
    id: u64,
    device: PendingDevice,
    created_at: Instant,
    tty_prompted: bool,
    decision: Arc<(Mutex<Option<ConfirmDecision>>, Condvar)>,
}

fn decision_label_zh(decision: ConfirmDecision) -> &'static str {
    match decision {
        ConfirmDecision::AllowAndTrust => "允许并信任",
        ConfirmDecision::AllowOnce => "仅本次允许",
        ConfirmDecision::Deny => "拒绝",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ListenerScope {
    Admin,
    Viewer,
}

struct ViewerListenerRuntime {
    addr: SocketAddr,
    opened_at: Instant,
    stop: Arc<AtomicBool>,
    wake: Arc<crate::transport::WakePipe>,
    thread: Option<thread::JoinHandle<()>>,
}

struct WebState {
    registry: Arc<SessionRegistry>,
    logs: LogBuffer,
    started_at: Instant,
    web_addr: SocketAddr,
    stopping: Arc<AtomicBool>,
    global_stop: Arc<AtomicBool>,
    viewer_listener_op_lock: Mutex<()>,
    viewer_listener: Mutex<Option<ViewerListenerRuntime>>,
    wifi_controller: Arc<crate::transport::wifi::WifiServerController>,
    wifi_addrs: Mutex<Option<(SocketAddr, SocketAddr)>>,
    admin_token: Option<String>,
    admin_token_explicit: bool,
    view_token: Mutex<Option<String>>,
    /// Monotonic generation bumped on every `set_view_token` rotation/disable so in-flight
    /// `?token=` WebSockets and logins can never survive token rotation.
    view_token_gen: AtomicU64,
    admin_sessions: Mutex<HashMap<String, u64>>,
    viewer_sessions: Mutex<HashMap<String, u64>>,
    web_once_approved: Mutex<HashMap<String, u64>>,
    login_failures: Mutex<HashMap<(IpAddr, bool), Vec<Instant>>>,
    debug_event_rates: Mutex<HashMap<IpAddr, (Instant, u32)>>,
    lan_ip_cache: Mutex<Option<(Instant, Vec<String>)>>,
    next_approval_id: AtomicU64,
    pending_approvals: Mutex<Vec<PendingApprovalSlot>>,
    active_conns: AtomicUsize,
    per_ip_conns: Mutex<HashMap<IpAddr, usize>>,
    mux_cache: Arc<SharedWebMuxer>,
    p2p: Arc<P2pRelayHub>,
}

/// Wall-clock Unix epoch seconds (used for 12h session cookie TTLs so multi-day host sleep
/// cannot freeze monotonic clocks and extend expired sessions).
fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl WebState {
    fn check_debug_event_rate(&self, ip: IpAddr) -> bool {
        let mut map = self.debug_event_rates.lock().unwrap();
        let now = Instant::now();
        if map.len() >= MAX_RATE_LIMIT_IPS && !map.contains_key(&ip) {
            map.retain(|_, (ts, _)| ts.elapsed() < Duration::from_secs(2));
            if map.len() >= MAX_RATE_LIMIT_IPS {
                return false;
            }
        }
        let entry = map.entry(ip).or_insert((now, 0));
        if entry.0.elapsed() >= Duration::from_secs(1) {
            *entry = (now, 1);
            true
        } else if entry.1 < 25 {
            entry.1 += 1;
            true
        } else {
            false
        }
    }

    fn cached_lan_ipv4s(&self) -> Vec<String> {
        {
            let guard = self.lan_ip_cache.lock().unwrap();
            if let Some((ts, ref ips)) = *guard {
                if ts.elapsed() < LAN_IP_CACHE_TTL {
                    return ips.clone();
                }
            }
        }
        let fresh = crate::netinfo::detect_lan_ipv4s();
        *self.lan_ip_cache.lock().unwrap() = Some((Instant::now(), fresh.clone()));
        fresh
    }

    fn check_rate_limit(&self, ip: IpAddr, is_admin_scope: bool) -> bool {
        let mut map = self.login_failures.lock().unwrap();
        let key = (ip, is_admin_scope);
        let Some(list) = map.get_mut(&key) else {
            return true;
        };
        list.retain(|t| t.elapsed() < RATE_LIMIT_WINDOW);
        let allowed = list.len() < RATE_LIMIT_MAX_FAILS;
        if list.is_empty() {
            map.remove(&key);
        }
        allowed
    }

    fn record_login_failure(&self, ip: IpAddr, is_admin_scope: bool) {
        let mut map = self.login_failures.lock().unwrap();
        let key = (ip, is_admin_scope);
        if map.len() >= MAX_RATE_LIMIT_IPS && !map.contains_key(&key) {
            map.retain(|_, list| {
                list.retain(|t| t.elapsed() < RATE_LIMIT_WINDOW);
                !list.is_empty()
            });
            if map.len() >= MAX_RATE_LIMIT_IPS {
                // Evict the entry whose newest failure is oldest.
                if let Some(oldest_key) = map
                    .iter()
                    .min_by_key(|(_, list)| list.last().copied())
                    .map(|(k, _)| *k)
                {
                    map.remove(&oldest_key);
                }
            }
        }
        let list = map.entry(key).or_default();
        list.retain(|t| t.elapsed() < RATE_LIMIT_WINDOW);
        list.push(Instant::now());
    }

    fn clear_login_failures(&self, ip: IpAddr, is_admin_scope: bool) {
        let mut map = self.login_failures.lock().unwrap();
        map.remove(&(ip, is_admin_scope));
    }

    fn create_admin_session(&self) -> String {
        let sid = generate_random_hex(24);
        let now = unix_now_secs();
        let ttl = SESSION_TTL.as_secs();
        let mut map = self.admin_sessions.lock().unwrap();
        map.retain(|_, created| now.saturating_sub(*created) < ttl);
        while map.len() >= MAX_ACTIVE_SESSIONS {
            if let Some(oldest) = map.iter().min_by_key(|(_, t)| **t).map(|(k, _)| k.clone()) {
                map.remove(&oldest);
            } else {
                break;
            }
        }
        map.insert(sid.clone(), now);
        sid
    }

    #[cfg(test)]
    fn create_viewer_session(&self) -> String {
        let sid = generate_random_hex(24);
        let now = unix_now_secs();
        let ttl = SESSION_TTL.as_secs();
        let mut map = self.viewer_sessions.lock().unwrap();
        map.retain(|_, created| now.saturating_sub(*created) < ttl);
        while map.len() >= MAX_ACTIVE_SESSIONS {
            if let Some(oldest) = map.iter().min_by_key(|(_, t)| **t).map(|(k, _)| k.clone()) {
                map.remove(&oldest);
            } else {
                break;
            }
        }
        map.insert(sid.clone(), now);
        sid
    }

    fn verify_admin_cookie(&self, token: Option<&str>) -> bool {
        let Some(tok) = token else {
            return false;
        };
        let now = unix_now_secs();
        let ttl = SESSION_TTL.as_secs();
        let mut map = self.admin_sessions.lock().unwrap();
        map.retain(|_, created| now.saturating_sub(*created) < ttl);
        map.contains_key(tok)
    }

    fn verify_viewer_cookie(&self, token: Option<&str>) -> bool {
        // Viewer cookies are only valid while a view passcode is enabled.
        if self.view_token.lock().unwrap().is_none() {
            return false;
        }
        let Some(tok) = token else {
            return false;
        };
        let now = unix_now_secs();
        let ttl = SESSION_TTL.as_secs();
        let mut map = self.viewer_sessions.lock().unwrap();
        map.retain(|_, created| now.saturating_sub(*created) < ttl);
        map.contains_key(tok)
    }

    fn revoke_admin_cookie(&self, token: Option<&str>) {
        if let Some(tok) = token {
            self.admin_sessions.lock().unwrap().remove(tok);
        }
    }

    fn revoke_viewer_cookie(&self, token: Option<&str>) {
        if let Some(tok) = token {
            self.viewer_sessions.lock().unwrap().remove(tok);
        }
    }

    /// Atomically verify `candidate` against `view_token` and mint a viewer session cookie
    /// under `view_token.lock()` so a concurrent `set_view_token` rotation can never let a stale
    /// passcode insert a surviving session after `viewer_sessions.clear()`.
    pub(super) fn login_viewer_with_token(
        &self,
        candidate: &str,
        old_cookie: Option<&str>,
    ) -> Option<String> {
        let tok_guard = self.view_token.lock().unwrap();
        let expected = tok_guard.as_deref()?;
        if !http::ct_eq(candidate, expected) {
            return None;
        }
        let sid = generate_random_hex(24);
        let now = unix_now_secs();
        let ttl = SESSION_TTL.as_secs();
        let mut map = self.viewer_sessions.lock().unwrap();
        if let Some(old) = old_cookie {
            map.remove(old);
        }
        map.retain(|_, created| now.saturating_sub(*created) < ttl);
        if map.len() >= MAX_ACTIVE_SESSIONS {
            if let Some(oldest_key) = map
                .iter()
                .min_by_key(|(_, ts)| **ts)
                .map(|(k, _)| k.clone())
            {
                map.remove(&oldest_key);
            }
        }
        map.insert(sid.clone(), now);
        Some(sid)
    }

    /// Verify a `?token=` candidate under `view_token.lock()` and return the matched `view_token_gen`.
    pub(super) fn verify_view_token_with_gen(&self, candidate: &str) -> Option<u64> {
        let tok_guard = self.view_token.lock().unwrap();
        let expected = tok_guard.as_deref()?;
        if http::ct_eq(candidate, expected) {
            Some(self.view_token_gen.load(Ordering::Acquire))
        } else {
            None
        }
    }

    fn set_view_token(self: &Arc<Self>, new_token: Option<String>) {
        let cleaned = new_token
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        {
            let mut tok_guard = self.view_token.lock().unwrap();
            *tok_guard = cleaned;
            self.view_token_gen.fetch_add(1, Ordering::AcqRel);
            // Invalidate viewer sessions & one-time approvals BEFORE releasing `view_token` lock
            // so `login_viewer_with_token` is totally ordered against rotation!
            self.viewer_sessions.lock().unwrap().clear();
            self.web_once_approved.lock().unwrap().clear();
        }
        self.cancel_pending_web_approvals(None);
        self.registry.kick_all_web_viewers();
        self.sync_viewer_listener();
    }

    pub(super) fn viewer_addr(&self) -> Option<SocketAddr> {
        self.viewer_listener
            .lock()
            .unwrap()
            .as_ref()
            .map(|rt| rt.addr)
    }

    pub(super) fn effective_wifi_addrs(&self) -> Option<(SocketAddr, SocketAddr)> {
        self.wifi_controller
            .addrs()
            .or_else(|| *self.wifi_addrs.lock().unwrap())
    }

    pub(super) fn has_pending_web_approval(&self) -> bool {
        self.pending_approvals
            .lock()
            .unwrap()
            .iter()
            .any(|s| s.device.is_web)
    }

    pub(super) fn has_pending_wifi_approval(&self) -> bool {
        self.pending_approvals
            .lock()
            .unwrap()
            .iter()
            .any(|s| !s.device.is_web && !s.device.is_usb)
    }

    pub(super) fn viewer_idle_duration(&self) -> Option<Duration> {
        let opened_at = self
            .viewer_listener
            .lock()
            .unwrap()
            .as_ref()
            .map(|rt| rt.opened_at)?;
        if self.registry.active_web_viewers() > 0 || self.has_pending_web_approval() {
            self.registry.record_web_activity();
            return None;
        }
        let last = opened_at.max(self.registry.last_web_activity());
        Some(last.elapsed())
    }

    pub(super) fn viewer_remaining_idle_close(&self) -> Option<Duration> {
        let limit = self.registry.port_idle_close_secs();
        if limit == 0 {
            return None;
        }
        let idle = self.viewer_idle_duration()?;
        Some(Duration::from_secs(limit).saturating_sub(idle))
    }

    pub(super) fn wifi_remaining_idle_close(&self) -> Option<Duration> {
        let limit = self.registry.port_idle_close_secs();
        if limit == 0 {
            return None;
        }
        if self.has_pending_wifi_approval() {
            self.registry.record_wifi_activity();
            return None;
        }
        self.wifi_controller.remaining_idle_close(limit)
    }

    /// Reconcile the dedicated `0.0.0.0:<random_port>` Web Viewer listener with live runtime state:
    /// open while Web viewing is enabled (`max_web_viewers > 0` and a view passcode is set) and
    /// immediately closed when Web viewing is turned off or the server shuts down.
    pub(super) fn sync_viewer_listener(self: &Arc<Self>) {
        let _op_guard = self.viewer_listener_op_lock.lock().unwrap();
        let want_open = !self.stopping.load(Ordering::SeqCst)
            && !self.global_stop.load(Ordering::SeqCst)
            && !self.registry.is_low_power()
            && self.registry.max_web_viewers() > 0
            && self.view_token.lock().unwrap().is_some();

        if want_open {
            let already_open = self.viewer_listener.lock().unwrap().is_some();
            if already_open {
                return;
            }
            let bind_addr = SocketAddr::from(([0, 0, 0, 0], 0));
            let listener = match TcpListener::bind(bind_addr) {
                Ok(l) => l,
                Err(e) => {
                    warn!("Failed to bind dynamic Web Viewer listener on {bind_addr}: {e}");
                    return;
                }
            };
            #[cfg(unix)]
            if let Err(e) = listener.set_nonblocking(true) {
                warn!("Failed to set dynamic Web Viewer listener nonblocking: {e}");
                return;
            }
            #[cfg(not(unix))]
            if let Err(e) = listener.set_nonblocking(false) {
                warn!("Failed to configure dynamic Web Viewer listener blocking mode: {e}");
                return;
            }
            let vaddr = match listener.local_addr() {
                Ok(a) => a,
                Err(e) => {
                    warn!("Failed to read dynamic Web Viewer local_addr: {e}");
                    return;
                }
            };
            let wake = match crate::transport::WakePipe::new() {
                Ok(w) => Arc::new(w),
                Err(e) => {
                    warn!("Failed to create dynamic Web Viewer wake pipe: {e}");
                    return;
                }
            };
            let local_stop = Arc::new(AtomicBool::new(false));
            let stop_a = local_stop.clone();
            let stop_g = self.global_stop.clone();
            let wake_loop = wake.clone();
            let st_loop = self.clone();
            let thread = match thread::Builder::new()
                .name("web-viewer-accept".to_string())
                .spawn(move || {
                    run_web_accept_loop(
                        listener,
                        wake_loop,
                        st_loop,
                        stop_a,
                        stop_g,
                        ListenerScope::Viewer,
                    );
                }) {
                Ok(t) => t,
                Err(e) => {
                    warn!("Failed to spawn dynamic Web Viewer accept thread: {e}");
                    return;
                }
            };
            *self.viewer_listener.lock().unwrap() = Some(ViewerListenerRuntime {
                addr: vaddr,
                opened_at: Instant::now(),
                stop: local_stop,
                wake,
                thread: Some(thread),
            });
            self.registry.record_web_activity();
            self.registry.notify_lifecycle_wakeup();
            info!(
                "Web extended-screen viewer listener opened on http://{vaddr}/view (0.0.0.0 random port)"
            );
            crate::debug_trace::record(
                "lifecycle",
                "web_viewer_listener_opened",
                serde_json::json!({ "addr": vaddr.to_string(), "port": vaddr.port() }),
            );
        } else {
            let old = self.viewer_listener.lock().unwrap().take();
            if let Some(mut rt) = old {
                let closed_addr = rt.addr;
                rt.stop.store(true, Ordering::SeqCst);
                rt.wake.wake();
                #[cfg(not(unix))]
                crate::transport::wake_blocking_listener_addr(closed_addr);
                self.cancel_pending_web_approvals(None);
                if let Some(t) = rt.thread.take() {
                    let _ = t.join();
                }
                self.registry.notify_lifecycle_wakeup();
                info!("Web extended-screen viewer listener closed ({closed_addr})");
                crate::debug_trace::record(
                    "lifecycle",
                    "web_viewer_listener_closed",
                    serde_json::json!({ "addr": closed_addr.to_string(), "port": closed_addr.port() }),
                );
            }
        }
    }

    pub(super) fn cancel_pending_web_approvals(&self, fingerprint: Option<&str>) {
        let norm_fp = fingerprint.and_then(crate::trust::normalize_fingerprint);
        let to_wake: Vec<Arc<(Mutex<Option<ConfirmDecision>>, Condvar)>> = {
            let mut list = self.pending_approvals.lock().unwrap();
            let mut waking = Vec::new();
            list.retain(|slot| {
                let matches = slot.device.is_web
                    && match &norm_fp {
                        Some(fp) => slot.device.fingerprint.eq_ignore_ascii_case(fp),
                        None => true,
                    };
                if matches {
                    waking.push(slot.decision.clone());
                    false
                } else {
                    true
                }
            });
            waking
        };
        for pair in to_wake {
            let (lock, cvar) = &*pair;
            let mut guard = lock.lock().unwrap();
            if guard.is_none() {
                *guard = Some(ConfirmDecision::Deny);
                cvar.notify_all();
            }
        }
    }

    fn is_web_viewer_approved(&self, is_admin: bool, fingerprint: Option<&str>) -> bool {
        if !self.registry.is_web_require_approval() || is_admin {
            return true;
        }
        let Some(fp) = fingerprint.and_then(crate::trust::normalize_fingerprint) else {
            return false;
        };
        if self.registry.trust_store().is_trusted(Some(&fp)) {
            return true;
        }
        let now = unix_now_secs();
        let ttl = SESSION_TTL.as_secs();
        let mut map = self.web_once_approved.lock().unwrap();
        map.retain(|_, created| now.saturating_sub(*created) < ttl);
        map.contains_key(&fp)
    }

    fn approve_web_viewer_once(&self, fingerprint: &str) {
        let Some(fp) = crate::trust::normalize_fingerprint(fingerprint) else {
            return;
        };
        let now = unix_now_secs();
        let ttl = SESSION_TTL.as_secs();
        let mut map = self.web_once_approved.lock().unwrap();
        map.retain(|_, created| now.saturating_sub(*created) < ttl);
        while map.len() >= MAX_ACTIVE_SESSIONS {
            if let Some(oldest) = map.iter().min_by_key(|(_, t)| **t).map(|(k, _)| k.clone()) {
                map.remove(&oldest);
            } else {
                break;
            }
        }
        map.insert(fp, now);
    }

    fn revoke_web_viewer_once(&self, fingerprint: &str) {
        if let Some(fp) = crate::trust::normalize_fingerprint(fingerprint) {
            self.web_once_approved.lock().unwrap().remove(&fp);
        }
    }

    pub(super) fn clear_web_once_approvals(&self) {
        self.web_once_approved.lock().unwrap().clear();
    }

    pub(super) fn kick_unapproved_web_viewers(&self) -> usize {
        if !self.registry.is_web_require_approval() {
            return 0;
        }
        self.registry
            .kick_web_viewers_unless(|is_admin, fp| self.is_web_viewer_approved(is_admin, fp))
    }

    fn enqueue_pending_approval(&self, device: &PendingDevice) -> ConfirmDecision {
        self.enqueue_pending_approval_with_liveness(device, || {
            !device.is_web
                && device.session_id != 0
                && self
                    .registry
                    .is_session_peer_closed(&device.addr, device.session_id)
        })
    }

    /// Enqueue a pending connection approval and wait until the admin decides, the 60s timeout
    /// elapses, or `is_peer_closed()` reports that the waiting client has disconnected (evicts
    /// closed-tab zombie slots within <=250ms instead of lingering for 60s).
    pub(super) fn enqueue_pending_approval_with_liveness(
        &self,
        device: &PendingDevice,
        is_peer_closed: impl Fn() -> bool,
    ) -> ConfirmDecision {
        if self.stopping.load(Ordering::Acquire) || self.global_stop.load(Ordering::Acquire) {
            return ConfirmDecision::Deny;
        }
        let id = self.next_approval_id.fetch_add(1, Ordering::Relaxed);
        let pair = Arc::new((Mutex::new(None), Condvar::new()));
        let tty_prompted = std::io::stdin().is_terminal();
        // Supersede any stale pending slots for the same peer address & channel so retries or
        // rotating browser cookies from a single IP can never pile up zombies or exhaust all 8 slots.
        let mut superseded = Vec::new();
        {
            let mut list = self.pending_approvals.lock().unwrap();
            list.retain(|slot| {
                let same_peer = slot.device.addr == device.addr
                    && slot.device.is_web == device.is_web;
                if same_peer {
                    superseded.push((slot.id, slot.tty_prompted, slot.decision.clone()));
                    false
                } else {
                    true
                }
            });
            if list.len() >= MAX_PENDING_APPROVALS {
                warn!(
                    "[TRUST] Pending approval queue full ({MAX_PENDING_APPROVALS}); denying device from {}",
                    device.addr
                );
                return ConfirmDecision::Deny;
            }
            list.push(PendingApprovalSlot {
                id,
                device: device.clone(),
                created_at: Instant::now(),
                tty_prompted,
                decision: pair.clone(),
            });
        }
        for (old_id, old_tty, old_pair) in superseded {
            let (lock, cvar) = &*old_pair;
            let mut guard = lock.lock().unwrap();
            if guard.is_none() {
                *guard = Some(ConfirmDecision::Deny);
                cvar.notify_all();
                if old_tty {
                    println!("\n[TRUST] 审批 #{old_id} 已被新连接替换。");
                    let _ = std::io::stdout().flush();
                }
            }
        }
        info!(
            "[TRUST] Pending approval #{id} in Web Admin Console: name={:?}, addr={}, fp={}, uid={:?}",
            device.name,
            device.addr,
            device.fingerprint,
            device.uid
        );
        crate::debug_trace::record(
            "auth",
            "pending_enqueued",
            serde_json::json!({
                "approval_id": id,
                "is_usb": device.is_usb,
                "is_web": device.is_web,
                "fingerprint": device.fingerprint,
            }),
        );
        if tty_prompted {
            print!(
                "\n[TRUST] 待审批连接 #{id}: {:?} ({}) | {} | addr={} | fp={}\n  可在网页管理后台点击审批，或直接在此输入 [y=允许并信任 / o=仅本次 / n=拒绝] 后回车: ",
                device.name,
                device.model,
                if device.is_web { "Web" } else if device.is_usb { "USB" } else { "Wi-Fi" },
                device.addr,
                device.fingerprint
            );
            let _ = std::io::stdout().flush();
        }

        let started = Instant::now();
        let (lock, cvar) = &*pair;
        let mut guard = lock.lock().unwrap();
        let mut peer_gone = false;
        while guard.is_none() {
            let elapsed = started.elapsed();
            if elapsed >= PENDING_APPROVAL_TIMEOUT {
                break;
            }
            if self.stopping.load(Ordering::Acquire)
                || self.global_stop.load(Ordering::Acquire)
                || is_peer_closed()
            {
                peer_gone = true;
                break;
            }
            let wait = (PENDING_APPROVAL_TIMEOUT - elapsed).min(Duration::from_millis(250));
            let (g, _) = cvar.wait_timeout(guard, wait).unwrap();
            guard = g;
        }
        let timed_out = guard.is_none() && !peer_gone;
        let decision = guard.unwrap_or(ConfirmDecision::Deny);

        {
            let mut list = self.pending_approvals.lock().unwrap();
            list.retain(|slot| slot.id != id);
        }
        if timed_out {
            warn!(
                "[TRUST] Pending approval #{id} timed out after {}s — denying {}",
                PENDING_APPROVAL_TIMEOUT.as_secs(),
                device.addr
            );
            if tty_prompted {
                println!(
                    "\n[TRUST] 审批 #{id} 已超时（{}s），自动拒绝（{}）。",
                    PENDING_APPROVAL_TIMEOUT.as_secs(),
                    device.name
                );
                let _ = std::io::stdout().flush();
            }
        }
        crate::debug_trace::record(
            "auth",
            "pending_resolved",
            serde_json::json!({
                "approval_id": id,
                "decision": format!("{decision:?}"),
                "timed_out": timed_out,
                "wait_ms": started.elapsed().as_millis() as u64,
            }),
        );
        decision
    }

    fn cancel_pending_approvals(&self, session_id: Option<u64>, addr: Option<&str>) {
        let mut to_cancel = Vec::new();
        {
            let mut list = self.pending_approvals.lock().unwrap();
            list.retain(|slot| {
                let matches = match (session_id, addr) {
                    (Some(sid), _) => slot.device.session_id == sid,
                    (None, Some(a)) => slot.device.addr == a,
                    (None, None) => true,
                };
                if matches {
                    to_cancel.push((
                        slot.id,
                        slot.device.name.clone(),
                        slot.tty_prompted,
                        slot.decision.clone(),
                    ));
                    false
                } else {
                    true
                }
            });
        }
        for (id, name, tty_prompted, pair) in to_cancel {
            let (lock, cvar) = &*pair;
            let mut guard = lock.lock().unwrap();
            if guard.is_none() {
                *guard = Some(ConfirmDecision::Deny);
                cvar.notify_all();
                if tty_prompted {
                    println!("\n[TRUST] 审批 #{id} 已取消（{name}）。");
                    let _ = std::io::stdout().flush();
                }
            }
        }
    }

    fn list_pending_approvals(&self) -> Vec<PendingApprovalView> {
        let list = self.pending_approvals.lock().unwrap();
        list.iter()
            .map(|s| PendingApprovalView {
                id: s.id,
                addr: s.device.addr.clone(),
                fingerprint: s.device.fingerprint.clone(),
                uid: s.device.uid.clone(),
                name: s.device.name.clone(),
                model: s.device.model.clone(),
                is_usb: s.device.is_usb,
                is_web: s.device.is_web,
                waiting_secs: s.created_at.elapsed().as_secs(),
            })
            .collect()
    }

    fn resolve_pending_approval(
        &self,
        id: u64,
        decision: ConfirmDecision,
        from_web: bool,
    ) -> Result<bool, &'static str> {
        // Atomically remove the slot BEFORE notifying so immediate UI refreshes never see stale
        // entries and rapid double-clicks / double TTY inputs cannot resolve the same slot twice.
        let removed_opt = {
            let mut list = self.pending_approvals.lock().unwrap();
            list.iter()
                .position(|s| s.id == id)
                .map(|idx| list.remove(idx))
        };
        if let Some(slot) = removed_opt {
            let (lock, cvar) = &*slot.decision;
            let mut guard = lock.lock().unwrap();
            *guard = Some(decision);
            cvar.notify_all();
            drop(guard);
            if slot.tty_prompted {
                let label = decision_label_zh(decision);
                if from_web {
                    // Break the waiting prompt line in terminal so Web and CLI stay visually synchronized.
                    println!(
                        "\n[TRUST] 审批 #{} 已在网页端处理：{}（{}）。",
                        slot.id, label, slot.device.name
                    );
                } else {
                    println!(
                        "[TRUST] 审批 #{} 已在终端处理：{}（{}）。",
                        slot.id, label, slot.device.name
                    );
                }
                let _ = std::io::stdout().flush();
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

/// Handle to the running Web control & viewer server.
pub struct WebServerHandle {
    pub addr: SocketAddr,
    pub admin_token: Option<String>,
    pub admin_token_generated: bool,
    state: Arc<WebState>,
    stop: Arc<AtomicBool>,
    wake: Arc<crate::transport::WakePipe>,
    thread: Option<thread::JoinHandle<()>>,
    idle_thread: Option<thread::JoinHandle<()>>,
}

impl WebServerHandle {
    pub fn set_wifi_addrs(&self, telemetry_addr: SocketAddr, data_addr: SocketAddr) {
        *self.state.wifi_addrs.lock().unwrap() = Some((telemetry_addr, data_addr));
    }

    /// Shared runtime controller for dynamically starting/stopping the iPad Wi-Fi listener.
    pub fn wifi_controller(&self) -> Arc<crate::transport::wifi::WifiServerController> {
        self.state.wifi_controller.clone()
    }

    /// Live `0.0.0.0:<random_port>` address of the dedicated Web Viewer listener, or `None` when closed.
    pub fn viewer_addr(&self) -> Option<SocketAddr> {
        self.state.viewer_addr()
    }

    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.state.registry.notify_lifecycle_wakeup();
        // 1) Wake & join Admin accept thread FIRST so no new Admin HTTP settings requests can
        //    re-open Wi-Fi or Viewer listeners after we stop them.
        self.wake.wake();
        #[cfg(not(unix))]
        crate::transport::wake_blocking_listener_addr(self.addr);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        if let Some(t) = self.idle_thread.take() {
            let _ = t.join();
        }
        // 2) Close Viewer & Wi-Fi listeners and abort any in-flight approvals / Web viewers.
        self.state.sync_viewer_listener();
        self.state.wifi_controller.stop();
        self.state.cancel_pending_approvals(None, None);
        self.state.registry.kick_all_web_viewers();
    }
}

impl Drop for WebServerHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Start the Web Admin Console & Extended-Screen Viewer server.
pub fn start_web_server(
    bind_addr: &str,
    admin_token_opt: Option<String>,
    view_token_opt: Option<String>,
    registry: Arc<SessionRegistry>,
    logs: LogBuffer,
    global_stop: Arc<AtomicBool>,
) -> Result<WebServerHandle> {
    start_web_server_with_listener(
        bind_addr,
        admin_token_opt,
        view_token_opt,
        registry,
        logs,
        global_stop,
        None,
    )
}

/// Start the Web Admin Console & Extended-Screen Viewer server, optionally adopting a
/// pre-bound OS socket-activated listener (`launchd` / `systemd`).
pub fn start_web_server_with_listener(
    bind_addr: &str,
    admin_token_opt: Option<String>,
    view_token_opt: Option<String>,
    registry: Arc<SessionRegistry>,
    logs: LogBuffer,
    global_stop: Arc<AtomicBool>,
    prebound_listener: Option<TcpListener>,
) -> Result<WebServerHandle> {
    let listener = match prebound_listener {
        Some(l) => l,
        None => {
            let resolved_bind = crate::netinfo::resolve_bind_socket_addr(bind_addr, None)
                .with_context(|| format!("failed to resolve Web bind address {bind_addr:?}"))?;
            TcpListener::bind(resolved_bind).with_context(|| {
                format!(
                    "failed to bind Web control server on {resolved_bind} (from {bind_addr:?})"
                )
            })?
        }
    };
    #[cfg(unix)]
    listener.set_nonblocking(true)?;
    #[cfg(not(unix))]
    listener.set_nonblocking(false)?;
    let addr = listener.local_addr()?;

    let (admin_token, admin_token_generated) = match admin_token_opt
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        Some(t) => (Some(t), false),
        None if addr.ip().is_loopback() => (None, false),
        None => (Some(generate_random_hex(16)), true),
    };
    let view_token = view_token_opt
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let local_stop = Arc::new(AtomicBool::new(false));
    let wifi_controller = Arc::new(crate::transport::wifi::WifiServerController::new(
        registry.config().clone(),
        registry.backend(),
        registry.clone(),
        global_stop.clone(),
    ));
    let state = Arc::new(WebState {
        registry: registry.clone(),
        logs,
        started_at: Instant::now(),
        web_addr: addr,
        stopping: local_stop.clone(),
        global_stop: global_stop.clone(),
        viewer_listener_op_lock: Mutex::new(()),
        viewer_listener: Mutex::new(None),
        wifi_controller,
        wifi_addrs: Mutex::new(None),
        admin_token: admin_token.clone(),
        admin_token_explicit: admin_token.is_some() && !admin_token_generated,
        view_token: Mutex::new(view_token),
        view_token_gen: AtomicU64::new(1),
        admin_sessions: Mutex::new(HashMap::new()),
        viewer_sessions: Mutex::new(HashMap::new()),
        web_once_approved: Mutex::new(HashMap::new()),
        login_failures: Mutex::new(HashMap::new()),
        debug_event_rates: Mutex::new(HashMap::new()),
        per_ip_conns: Mutex::new(HashMap::new()),
        lan_ip_cache: Mutex::new(None),
        next_approval_id: AtomicU64::new(1),
        pending_approvals: Mutex::new(Vec::new()),
        active_conns: AtomicUsize::new(0),
        mux_cache: Arc::new(SharedWebMuxer::new()),
        p2p: Arc::new(P2pRelayHub::new(registry.is_p2p_relay_enabled())),
    });

    // Wire Web Admin approval queue, cancellation hook & dynamic Viewer listener lifecycle hook into SessionRegistry
    // using Weak references so `SessionRegistry <-> WebState` never forms a permanent Arc cycle.
    {
        let st_weak = Arc::downgrade(&state);
        registry.set_confirm_handler(Arc::new(move |dev| {
            st_weak
                .upgrade()
                .map(|st| st.enqueue_pending_approval(dev))
                .unwrap_or(ConfirmDecision::Deny)
        }));
        let st_cancel_weak = Arc::downgrade(&state);
        registry.set_cancel_pending_handler(Arc::new(move |sid, addr| {
            if let Some(st) = st_cancel_weak.upgrade() {
                st.cancel_pending_approvals(sid, addr);
            }
        }));
        let st_viewer_weak = Arc::downgrade(&state);
        registry.set_web_viewer_limit_handler(Arc::new(move |_max_viewers| {
            if let Some(st) = st_viewer_weak.upgrade() {
                st.sync_viewer_listener();
            }
        }));
        let st_close_web_weak = Arc::downgrade(&state);
        registry.set_close_web_sharing_handler(Arc::new(move || {
            if let Some(st) = st_close_web_weak.upgrade() {
                let was_open =
                    st.view_token.lock().unwrap().is_some() || st.viewer_addr().is_some();
                st.set_view_token(None);
                was_open
            } else {
                false
            }
        }));
    }
    // Open the dedicated 0.0.0.0 random-port Web Viewer listener immediately if startup already
    // enables Web viewing (`max_web_viewers > 0` and a view passcode is configured).
    state.sync_viewer_listener();
    // Also allow interactive terminal input (y/o/n + Enter) to resolve pending Web approvals
    // simultaneously so users watching the terminal can approve without switching to the browser.
    if std::io::stdin().is_terminal() {
        let st_tty = state.clone();
        let stop_tty = global_stop.clone();
        let _ = thread::Builder::new()
            .name("web-tty-approval".to_string())
            .spawn(move || {
                let stdin = std::io::stdin();
                let mut line = String::new();
                while !stop_tty.load(Ordering::SeqCst) {
                    line.clear();
                    match stdin.read_line(&mut line) {
                        Ok(0) => break,
                        Ok(_) => {
                            let decision = match line.trim().to_ascii_lowercase().as_str() {
                                "y" | "yes" => Some(ConfirmDecision::AllowAndTrust),
                                "o" | "once" => Some(ConfirmDecision::AllowOnce),
                                "n" | "no" | "d" | "deny" => Some(ConfirmDecision::Deny),
                                _ => None,
                            };
                            let Some(dec) = decision else {
                                continue;
                            };
                            let latest_id = {
                                let list = st_tty.pending_approvals.lock().unwrap();
                                list.last().map(|s| s.id)
                            };
                            if let Some(id) = latest_id {
                                match st_tty.resolve_pending_approval(id, dec, false) {
                                    Ok(true) => {
                                        info!("[TRUST] Terminal resolved pending approval #{id} => {dec:?}");
                                    }
                                    Err(msg) => {
                                        println!("[TRUST] {msg}");
                                        let _ = std::io::stdout().flush();
                                        warn!("[TRUST] {msg}");
                                    }
                                    Ok(false) => {}
                                }
                            } else {
                                println!("[TRUST] 当前没有待审批的连接（可能已在网页端处理）。");
                                let _ = std::io::stdout().flush();
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
    }

    let wake = Arc::new(
        crate::transport::WakePipe::new().context("failed to create Web accept wake pipe")?,
    );
    let stop_a = local_stop.clone();
    let stop_g = global_stop.clone();
    let wake_loop = wake.clone();
    let st_loop = state.clone();

    let thread = thread::spawn(move || {
        run_web_accept_loop(
            listener,
            wake_loop,
            st_loop,
            stop_a,
            stop_g,
            ListenerScope::Admin,
        );
    });

    let st_watch = state.clone();
    let stop_wa = local_stop.clone();
    let stop_wg = global_stop.clone();
    let idle_thread = thread::Builder::new()
        .name("web-port-idle-watchdog".to_string())
        .spawn(move || {
            while !stop_wa.load(Ordering::SeqCst) && !stop_wg.load(Ordering::SeqCst) {
                let seq = st_watch.registry.lifecycle_seq();
                let limit = st_watch.registry.port_idle_close_secs();
                let mut next_wait: Option<Duration> = None;
                if limit > 0 {
                    let limit_dur = Duration::from_secs(limit);
                    if let Some(v_idle) = st_watch.viewer_idle_duration() {
                        if v_idle >= limit_dur {
                            info!(
                                "Web extended-screen viewer port idle for {}s (limit={}s) — auto-closing.",
                                v_idle.as_secs(),
                                limit
                            );
                            st_watch.registry.set_max_web_viewers_runtime(0);
                        } else {
                            let rem = limit_dur.saturating_sub(v_idle);
                            next_wait = Some(next_wait.map_or(rem, |cur| cur.min(rem)));
                        }
                    }
                    if !st_watch.has_pending_wifi_approval() {
                        if let Some(w_idle) = st_watch.wifi_controller.idle_duration() {
                            if w_idle >= limit_dur {
                                info!(
                                    "iPad Wi-Fi port idle for {}s (limit={}s) — auto-closing.",
                                    w_idle.as_secs(),
                                    limit
                                );
                                st_watch.wifi_controller.stop();
                            } else {
                                let rem = limit_dur.saturating_sub(w_idle);
                                next_wait = Some(next_wait.map_or(rem, |cur| cur.min(rem)));
                            }
                        }
                    }
                }
                st_watch
                    .registry
                    .wait_lifecycle_since(seq, &stop_wa, &stop_wg, next_wait);
            }
        })
        .ok();

    Ok(WebServerHandle {
        addr,
        admin_token,
        admin_token_generated,
        state,
        stop: local_stop,
        wake,
        thread: Some(thread),
        idle_thread,
    })
}

fn run_web_accept_loop(
    listener: TcpListener,
    wake_loop: Arc<crate::transport::WakePipe>,
    st_loop: Arc<WebState>,
    stop_a: Arc<AtomicBool>,
    stop_g: Arc<AtomicBool>,
    scope: ListenerScope,
) {
    while !stop_a.load(Ordering::SeqCst) && !stop_g.load(Ordering::SeqCst) {
        match crate::transport::accept_interruptible(&listener, &wake_loop) {
            Ok(Some((stream, peer))) => {
                let cur = st_loop.active_conns.fetch_add(1, Ordering::AcqRel);
                if cur >= MAX_WEB_CONNECTIONS {
                    st_loop.active_conns.fetch_sub(1, Ordering::AcqRel);
                    warn!("Web server max connection limit ({MAX_WEB_CONNECTIONS}) reached; rejecting {peer}");
                    let _ = stream.shutdown(Shutdown::Both);
                    continue;
                }
                let ip_allowed = {
                    let mut ip_map = st_loop.per_ip_conns.lock().unwrap();
                    let count = ip_map.entry(peer.ip()).or_insert(0);
                    if *count >= MAX_WEB_CONNS_PER_IP {
                        false
                    } else {
                        *count += 1;
                        true
                    }
                };
                if !ip_allowed {
                    st_loop.active_conns.fetch_sub(1, Ordering::AcqRel);
                    warn!("Web server per-IP connection limit ({MAX_WEB_CONNS_PER_IP}) reached for {peer}");
                    let _ = stream.shutdown(Shutdown::Both);
                    continue;
                }
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_nodelay(true);
                let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                crate::transport::enable_tcp_keepalive(&stream);
                let st_c = st_loop.clone();
                let stop_c = stop_a.clone();
                let stop_gc = stop_g.clone();
                thread::spawn(move || {
                    struct ConnGuard(Arc<WebState>, IpAddr);
                    impl Drop for ConnGuard {
                        fn drop(&mut self) {
                            self.0.active_conns.fetch_sub(1, Ordering::AcqRel);
                            if let Ok(mut ip_map) = self.0.per_ip_conns.lock() {
                                if let Some(c) = ip_map.get_mut(&self.1) {
                                    *c = c.saturating_sub(1);
                                    if *c == 0 {
                                        ip_map.remove(&self.1);
                                    }
                                }
                            }
                        }
                    }
                    let _guard = ConnGuard(st_c.clone(), peer.ip());
                    if let Err(e) = handle_connection(stream, peer, st_c, stop_c, stop_gc, scope) {
                        debug!("[web {peer}] connection ended: {e:#}");
                    }
                });
            }
            Ok(None) => break,
            Err(e) => {
                warn!("Web accept error ({scope:?}): {e}");
                if wake_loop.wait_timeout(Duration::from_millis(100))
                    == crate::transport::PollOutcome::Woken
                {
                    break;
                }
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use super::http::{compute_ws_accept, ct_eq};

    #[test]
    fn rfc6455_websocket_accept_vector() {
        // Official RFC 6455 Section 4.2.2 test vector
        assert_eq!(
            compute_ws_accept("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn constant_time_eq_works() {
        assert!(ct_eq("secret-token-123", "secret-token-123"));
        assert!(!ct_eq("secret-token-123", "secret-token-124"));
        assert!(!ct_eq("short", "longer"));
    }

    #[test]
    fn session_cookies_and_once_approvals_expire_after_ttl() {
        use super::*;
        use clap::Parser;
        let mut cfg = crate::config::AppConfig::try_parse_from(["idis"]).unwrap();
        cfg.config_file = Some("none".to_string());
        cfg.web_require_approval = true;
        let reg = Arc::new(SessionRegistry::new(
            cfg,
            Arc::new(crate::platform::mock::MockBackend::new()),
        ));
        let stop = Arc::new(AtomicBool::new(false));
        let mut web = start_web_server(
            "127.0.0.1:0",
            Some("adm".to_string()),
            Some("vw".to_string()),
            reg,
            LogBuffer::new(),
            stop.clone(),
        )
        .unwrap();
        let st = web.state.clone();
        let a_tok = st.create_admin_session();
        let v_tok = st.create_viewer_session();
        let fp = "fp:11223344556677889900aabb";
        st.approve_web_viewer_once(fp);
        assert!(st.verify_admin_cookie(Some(&a_tok)));
        assert!(st.verify_viewer_cookie(Some(&v_tok)));
        assert!(st.is_web_viewer_approved(false, Some(fp)));

        // Backdate timestamps past SESSION_TTL (12h + 1s)
        let expired = unix_now_secs().saturating_sub(SESSION_TTL.as_secs() + 2);
        st.admin_sessions.lock().unwrap().insert(a_tok.clone(), expired);
        st.viewer_sessions.lock().unwrap().insert(v_tok.clone(), expired);
        st.web_once_approved.lock().unwrap().insert(fp.to_string(), expired);

        assert!(!st.verify_admin_cookie(Some(&a_tok)), "expired admin cookie must fail");
        assert!(!st.verify_viewer_cookie(Some(&v_tok)), "expired viewer cookie must fail");
        assert!(!st.is_web_viewer_approved(false, Some(fp)), "expired allow_once must fail");
        assert!(st.admin_sessions.lock().unwrap().is_empty(), "expired admin cookie must be pruned");
        assert!(st.viewer_sessions.lock().unwrap().is_empty(), "expired viewer cookie must be pruned");
        assert!(st.web_once_approved.lock().unwrap().is_empty(), "expired allow_once must be pruned");
        stop.store(true, Ordering::SeqCst);
        web.stop();
    }
}
