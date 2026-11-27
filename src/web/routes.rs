use super::http::{
    ct_eq, generate_random_hex, is_json_content_type, is_loopback_peer, is_safe_loopback_host,
    origin_matches_host, parse_cookies, parse_query_param, percent_encode_query_val,
    read_http_request, send_json, send_response, send_viewer_html_response,
};
use super::ws_stream::{handle_ws_stream, WsAuth};
use super::{unix_now_secs, ListenerScope, WebState, SESSION_TTL};
use crate::config::{AbrSensitivity, LockAction, QualityPreset, WebScreenMode};
use crate::platform::WindowMoveLayout;
use crate::session::{ConfirmDecision, PendingDevice, PollingPatch, VideoSettingsPatch};
use crate::trust::{compute_web_viewer_fingerprint, parse_web_client_label};
use crate::user_config::{EdgeGesturesConfig, WindowRule};
use anyhow::Result;
use serde::Deserialize;
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{info, warn};

const ADMIN_HTML: &str = include_str!("admin.html");
const VIEWER_HTML: &str = include_str!("viewer.html");

#[derive(Deserialize)]
struct LoginReq {
    token: String,
}

#[derive(Deserialize)]
struct DisconnectReq {
    key: String,
}

#[derive(Deserialize)]
struct KickViewerReq {
    id: Option<u64>,
}

#[derive(Deserialize)]
struct DecidePendingReq {
    id: u64,
    decision: String,
}

#[derive(Deserialize)]
struct TrustedAddReq {
    #[serde(alias = "mac")]
    fingerprint: Option<String>,
    name: Option<String>,
    model: Option<String>,
}

#[derive(Deserialize)]
struct TrustedRevokeReq {
    #[serde(alias = "mac")]
    fingerprint: Option<String>,
}

#[derive(Deserialize)]
struct SaveConfigYamlReq {
    yaml: String,
}

#[derive(Deserialize)]
struct ResetConfigReq {
    #[serde(default = "default_true_opt")]
    keep_trusted: bool,
}

#[derive(Deserialize)]
struct PresetNameReq {
    name: String,
}

#[derive(Deserialize)]
struct CreateVirtualDisplayReq {
    #[serde(default)]
    name: String,
    #[serde(default = "default_vd_width")]
    width: u32,
    #[serde(default = "default_vd_height")]
    height: u32,
}

fn default_vd_width() -> u32 {
    1280
}

fn default_vd_height() -> u32 {
    720
}

#[derive(Deserialize)]
struct RemoveVirtualDisplayReq {
    id: u64,
}

#[derive(Deserialize)]
struct MoveWindowReq {
    window_id: u32,
    #[serde(default)]
    pid: i32,
    target_display_id: u32,
    #[serde(default)]
    layout: WindowMoveLayout,
}

#[derive(Deserialize)]
struct DeleteWindowRuleReq {
    id: String,
}

fn default_true_opt() -> bool {
    true
}

#[derive(Deserialize)]
struct UpdateSettingsReq {
    allow_input: Option<bool>,
    client_cursor: Option<bool>,
    #[serde(alias = "max_screen_connections", alias = "max_connections")]
    max_extended_screens: Option<usize>,
    max_web_viewers: Option<usize>,
    view_token: Option<String>,
    disable_view_token: Option<bool>,
    rotate_view_token: Option<bool>,
    quality: Option<QualityPreset>,
    width: Option<u32>,
    height: Option<u32>,
    fps: Option<u32>,
    bitrate_mbps: Option<u32>,
    hidpi: Option<u32>,
    integer_scale: Option<bool>,
    max_pixel_edge: Option<u32>,
    adaptive_quality: Option<bool>,
    abr_sensitivity: Option<AbrSensitivity>,
    half_fps_when_unfocused: Option<bool>,
    auto_max_in_flight: Option<bool>,
    max_in_flight: Option<u32>,
    reset_video: Option<bool>,
    web_quality: Option<QualityPreset>,
    web_width: Option<u32>,
    web_height: Option<u32>,
    web_fps: Option<u32>,
    web_bitrate_mbps: Option<u32>,
    web_hidpi: Option<u32>,
    web_max_pixel_edge: Option<u32>,
    reset_web_video: Option<bool>,
    web_independent_screen: Option<bool>,
    web_screen_mode: Option<WebScreenMode>,
    web_require_approval: Option<bool>,
    lock_action: Option<LockAction>,
    lock_action_ipad: Option<LockAction>,
    lock_action_web: Option<LockAction>,
    lock_delay_secs: Option<u64>,
    port_idle_close_secs: Option<u64>,
    wifi_enabled: Option<bool>,
    p2p_relay_enabled: Option<bool>,
    low_power: Option<bool>,
    main_loop_ms: Option<u64>,
    cursor_poll_ms: Option<u64>,
    usb_retry_ms: Option<u64>,
    admin_poll_ms: Option<u64>,
    reset_polling: Option<bool>,
    gestures: Option<EdgeGesturesConfig>,
}

pub(super) fn handle_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    state: Arc<WebState>,
    stop_a: Arc<AtomicBool>,
    stop_g: Arc<AtomicBool>,
    scope: ListenerScope,
) -> Result<()> {
    if stop_a.load(Ordering::Acquire)
        || stop_g.load(Ordering::Acquire)
        || state.stopping.load(Ordering::Acquire)
    {
        let _ = stream.shutdown(Shutdown::Both);
        return Ok(());
    }
    let Some(req) = read_http_request(&stream)? else {
        return Ok(());
    };
    let cookies = parse_cookies(&req.headers);
    let admin_cookie = cookies.get("idis_admin").map(String::as_str);
    let viewer_cookie = cookies.get("idis_view").map(String::as_str);
    let existing_vid = cookies
        .get("idis_vid")
        .map(String::as_str)
        .filter(|s| s.len() >= 16 && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_hexdigit()));
    let (viewer_id, vid_set_cookie) = match existing_vid {
        Some(v) => (v.to_string(), None),
        None => {
            let v = generate_random_hex(16);
            let hdr = format!(
                "Set-Cookie: idis_vid={v}; HttpOnly; SameSite=Strict; Path=/; Max-Age=31536000"
            );
            (v, Some(hdr))
        }
    };
    let viewer_label = parse_web_client_label(
        req.headers
            .get("user-agent")
            .map(String::as_str)
            .unwrap_or(""),
    );
    let viewer_fp = compute_web_viewer_fingerprint(&viewer_id, &viewer_label);
    // Strictly isolate Admin vs Viewer privileges by listener port:
    // - Admin port (`ListenerScope::Admin`) serves Admin Console & `/api/admin/*` only.
    // - Viewer port (`ListenerScope::Viewer`, dynamic `0.0.0.0:<random_port>`) serves `/view`,
    //   `/api/view/*`, and `/ws/stream` only and NEVER grants Admin privileges (even on loopback).
    // Localhost convenience contract:
    // - On `0.0.0.0` Admin bind, direct `127.0.0.1` access with safe loopback `Host` stays passwordless
    //   while LAN / proxied / non-loopback `Host` requests require the Admin token.
    // - On `127.0.0.1` Admin bind, passing explicit `--web-admin-token` enforces password login even locally.
    let loopback_auto_admin = scope == ListenerScope::Admin
        && (!state.admin_token_explicit || !state.web_addr.ip().is_loopback())
        && is_loopback_peer(peer.ip())
        && is_safe_loopback_host(&req.headers, state.web_addr.port());
    let is_admin =
        scope == ListenerScope::Admin && (loopback_auto_admin || state.verify_admin_cookie(admin_cookie));
    let is_viewer =
        scope == ListenerScope::Viewer && state.verify_viewer_cookie(viewer_cookie);

    // Gate idle activity refresh on authenticated requests so unauthenticated LAN scanners
    // cannot perpetually defeat `--idle-exit-secs` or `--port-idle-close-secs`.
    if is_admin || is_viewer {
        state.registry.record_external_activity();
        if scope == ListenerScope::Viewer {
            state.registry.record_web_activity();
        }
    }

    if req.method == "POST"
        && (!origin_matches_host(&req.headers) || !is_json_content_type(&req.headers))
    {
        return send_json(
            &mut stream,
            "403 Forbidden",
            &[],
            &serde_json::json!({ "error": "origin or content-type rejected" }),
        );
    }

    let path = req.path.as_str();
    let route_allowed_on_scope = match scope {
        ListenerScope::Admin => {
            !matches!(path, "/view" | "/ws/stream") && !path.starts_with("/api/view/")
        }
        ListenerScope::Viewer => {
            path != "/admin" && !path.starts_with("/api/admin/")
        }
    };
    if !route_allowed_on_scope {
        return send_json(
            &mut stream,
            "404 Not Found",
            &[],
            &serde_json::json!({ "error": "not found" }),
        );
    }

    match (req.method.as_str(), path) {
        ("GET", "/view") => {
            // Standalone viewer authentication via URL parameter `/view?token=xxx`:
            // Strictly validates against `view_token` only (never accepts `admin_token`),
            // enforces per-IP rate limiting, sets an HttpOnly session cookie, and redirects
            // to `/view` so the secret token is stripped from the browser URL bar.
            // Only process `?token=` on top-level document navigations (`Sec-Fetch-Mode: navigate`
            // and `Sec-Fetch-Dest: document`, when sent by modern browsers) so `<img>`/`<iframe>`/
            // `fetch` subresource tags cannot trigger login-CSRF or rate-limit lockouts, while
            // shared direct links from chat/email/QR scanners (`Sec-Fetch-Site: cross-site`) still work.
            let sfm_ok = req
                .headers
                .get("sec-fetch-mode")
                .map(|v| v.trim().eq_ignore_ascii_case("navigate"))
                .unwrap_or(true);
            let sfd_ok = req
                .headers
                .get("sec-fetch-dest")
                .map(|v| v.trim().eq_ignore_ascii_case("document"))
                .unwrap_or(true);
            if sfm_ok && sfd_ok {
                if let Some(raw_tok) = parse_query_param(req.query.as_deref(), "token") {
                    let candidate = raw_tok.trim();
                    if !candidate.is_empty() {
                        if !state.check_rate_limit(peer.ip(), false) {
                            warn!("[web {peer}] Rate-limited /view?token= authentication attempt");
                            return send_response(
                                &mut stream,
                                "429 Too Many Requests",
                                "text/plain; charset=utf-8",
                                &[],
                                "尝试次数过多，请 1 分钟后再试".as_bytes(),
                            );
                        }
                        if let Some(sid) = state.login_viewer_with_token(candidate, viewer_cookie) {
                            state.clear_login_failures(peer.ip(), false);
                            state.registry.record_external_activity();
                            state.registry.record_web_activity();
                            info!("[web {peer}] Extended-screen viewer authenticated via URL ?token=");
                            let mut hdrs = vec![
                                format!(
                                    "Set-Cookie: idis_view={sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}",
                                    SESSION_TTL.as_secs()
                                ),
                                "Location: /view".to_string(),
                            ];
                            if let Some(vc) = vid_set_cookie {
                                hdrs.push(vc);
                            }
                            return send_response(
                                &mut stream,
                                "302 Found",
                                "text/plain; charset=utf-8",
                                &hdrs,
                                b"Redirecting to /view",
                            );
                        }
                        state.record_login_failure(peer.ip(), false);
                        warn!("[web {peer}] Failed /view?token= authentication attempt");
                    }
                }
            }
            let extra: Vec<String> = if is_viewer || is_admin {
                vid_set_cookie.into_iter().collect()
            } else {
                Vec::new()
            };
            send_viewer_html_response(&mut stream, &extra, VIEWER_HTML.as_bytes())
        }
        ("GET", "/") if scope == ListenerScope::Viewer => {
            let loc = match req.query.as_deref().filter(|q| !q.is_empty()) {
                Some(q) => format!("Location: /view?{q}"),
                None => "Location: /view".to_string(),
            };
            send_response(
                &mut stream,
                "302 Found",
                "text/plain; charset=utf-8",
                &[loc],
                b"Redirecting to /view",
            )
        }
        ("GET", "/") | ("GET", "/admin") => {
            send_response(
                &mut stream,
                "200 OK",
                "text/html; charset=utf-8",
                &[],
                ADMIN_HTML.as_bytes(),
            )
        }
        ("GET", "/api/auth/status") => {
            let viewer_enabled = state.view_token.lock().unwrap().is_some();
            let authed = is_viewer || is_admin;
            let mut body = serde_json::json!({
                "admin_logged_in": is_admin,
                "admin_auth_required": scope == ListenerScope::Admin && !loopback_auto_admin && state.admin_token.is_some(),
                "viewer_logged_in": if scope == ListenerScope::Viewer { is_viewer } else { is_admin },
                "viewer_enabled": viewer_enabled,
            });
            if authed {
                // Refresh OS lock state on demand (without cutting active sessions' grace windows)
                // so a viewer recovering after zero-wakeup idle standby sees the live unlock state
                // instead of a stale `host_lock_disconnect_blocked: true` lockout (Iter-6 P1-C1).
                state.registry.refresh_host_lock_state_now(false);
                body["total_screen_connections"] =
                    serde_json::json!(state.registry.total_screen_connections());
                body["max_extended_screens"] =
                    serde_json::json!(state.registry.max_extended_screens());
                body["max_web_viewers"] =
                    serde_json::json!(state.registry.max_web_viewers());
                body["active_web_viewers"] =
                    serde_json::json!(state.registry.active_web_viewers());
                body["max_screen_connections"] =
                    serde_json::json!(state.registry.max_extended_screens());
                body["web_independent_screen"] =
                    serde_json::json!(state.registry.is_web_independent_screen());
                body["web_screen_mode"] = serde_json::json!(state.registry.web_screen_mode());
                body["web_require_approval"] =
                    serde_json::json!(state.registry.is_web_require_approval());
                body["viewer_approved"] =
                    serde_json::json!(state.is_web_viewer_approved(is_admin, Some(&viewer_fp)));
                body["viewer_fingerprint"] = serde_json::json!(viewer_fp);
                body["viewer_label"] = serde_json::json!(viewer_label);
                body["supports_independent_web_screen"] =
                    serde_json::json!(state.registry.supports_independent_web_screen());
                body["host_lock_disconnect_blocked"] =
                    serde_json::json!(state.registry.is_web_lock_disconnect_admit_blocked());
                body["debug_enabled"] = serde_json::json!(crate::debug_trace::is_enabled());
                body["debug_trace_active"] = serde_json::json!(crate::debug_trace::is_enabled());
                body["debug_logging_enabled"] =
                    serde_json::json!(crate::debug_trace::is_debug_logging_enabled());
                // Only expose host filesystem path of debug log to authenticated admins.
                if is_admin {
                    if let Some(p) = crate::debug_trace::active_path() {
                        body["debug_log_path"] = serde_json::json!(p.display().to_string());
                    }
                }
            }
            let extra: Vec<String> = vid_set_cookie.into_iter().collect();
            send_json(&mut stream, "200 OK", &extra, &body)
        }
        ("POST", "/api/debug/event") => {
            if !is_admin && !is_viewer {
                return send_json(
                    &mut stream,
                    "401 Unauthorized",
                    &[],
                    &serde_json::json!({ "error": "unauthorized" }),
                );
            }
            if !crate::debug_trace::is_enabled() {
                return send_json(&mut stream, "200 OK", &[], &serde_json::json!({ "ok": false }));
            }
            if !state.check_debug_event_rate(peer.ip()) {
                return send_json(
                    &mut stream,
                    "429 Too Many Requests",
                    &[],
                    &serde_json::json!({ "error": "debug event rate limit exceeded" }),
                );
            }
            let max_debug_body = if is_admin { 4096 } else { 512 };
            if req.body.len() > max_debug_body {
                return send_json(
                    &mut stream,
                    "413 Payload Too Large",
                    &[],
                    &serde_json::json!({ "error": "debug event too large" }),
                );
            }
            if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&req.body) {
                let raw_name = val
                    .get("event")
                    .and_then(|v| v.as_str())
                    .unwrap_or("ui_event");
                let ev_name: String = raw_name
                    .chars()
                    .filter(|c| !c.is_control())
                    .take(64)
                    .collect();
                let data = val
                    .get("data")
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!({}));
                let clean_payload = crate::debug_trace::sanitize_json_value(serde_json::json!({
                    "peer": peer.ip().to_string(),
                    "role": if is_admin { "admin" } else { "viewer" },
                    "detail": data,
                }));
                // Only admin events go into `tracing::debug!` / main LogBuffer; viewer telemetry
                // uses `"log"` category (writes only to optional `--debug-log` file) so low-privilege
                // viewers can never flood the admin audit log buffer or host terminal.
                if is_admin {
                    crate::debug_trace::record(
                        "web_ui",
                        if ev_name.is_empty() { "ui_event" } else { &ev_name },
                        clean_payload,
                    );
                } else {
                    crate::debug_trace::record(
                        "log",
                        if ev_name.is_empty() { "viewer_ui_event" } else { &ev_name },
                        clean_payload,
                    );
                }
            }
            send_json(&mut stream, "200 OK", &[], &serde_json::json!({ "ok": true }))
        }
        ("POST", "/api/admin/login") => {
            if loopback_auto_admin {
                return send_json(&mut stream, "200 OK", &[], &serde_json::json!({ "ok": true }));
            }
            let Some(expected) = state.admin_token.as_deref() else {
                return send_json(
                    &mut stream,
                    "403 Forbidden",
                    &[],
                    &serde_json::json!({ "error": "forbidden" }),
                );
            };
            if !state.check_rate_limit(peer.ip(), true) {
                return send_json(
                    &mut stream,
                    "429 Too Many Requests",
                    &[],
                    &serde_json::json!({ "error": "登录失败次数过多，请 1 分钟后再试" }),
                );
            }
            let Ok(payload) = serde_json::from_slice::<LoginReq>(&req.body) else {
                return send_json(
                    &mut stream,
                    "400 Bad Request",
                    &[],
                    &serde_json::json!({ "error": "invalid json" }),
                );
            };
            if ct_eq(payload.token.trim(), expected) {
                state.clear_login_failures(peer.ip(), true);
                state.registry.record_external_activity();
                let sid = state.create_admin_session();
                info!("[web {peer}] Admin logged in");
                let cookie = format!(
                    "Set-Cookie: idis_admin={sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}",
                    SESSION_TTL.as_secs()
                );
                send_json(
                    &mut stream,
                    "200 OK",
                    &[cookie],
                    &serde_json::json!({ "ok": true }),
                )
            } else {
                state.record_login_failure(peer.ip(), true);
                warn!("[web {peer}] Failed admin login attempt");
                send_json(
                    &mut stream,
                    "401 Unauthorized",
                    &[],
                    &serde_json::json!({ "error": "管理员口令错误" }),
                )
            }
        }
        ("POST", "/api/admin/logout") => {
            if let Some(tok) = admin_cookie {
                state.registry.kick_web_viewers_by_tag(tok);
            }
            state.revoke_admin_cookie(admin_cookie);
            let clear = "Set-Cookie: idis_admin=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"
                .to_string();
            send_json(
                &mut stream,
                "200 OK",
                &[clear],
                &serde_json::json!({ "ok": true }),
            )
        }
        ("POST", "/api/view/login") => {
            if state.view_token.lock().unwrap().is_none() {
                return send_json(
                    &mut stream,
                    "403 Forbidden",
                    &[],
                    &serde_json::json!({ "error": "管理员尚未开启网页扩展屏观看口令" }),
                );
            }
            if !state.check_rate_limit(peer.ip(), false) {
                return send_json(
                    &mut stream,
                    "429 Too Many Requests",
                    &[],
                    &serde_json::json!({ "error": "尝试次数过多，请 1 分钟后再试" }),
                );
            }
            let Ok(payload) = serde_json::from_slice::<LoginReq>(&req.body) else {
                return send_json(
                    &mut stream,
                    "400 Bad Request",
                    &[],
                    &serde_json::json!({ "error": "invalid json" }),
                );
            };
            if let Some(sid) = state.login_viewer_with_token(payload.token.trim(), viewer_cookie) {
                state.clear_login_failures(peer.ip(), false);
                state.registry.record_external_activity();
                state.registry.record_web_activity();
                info!("[web {peer}] Extended-screen viewer authenticated");
                let mut hdrs = vec![format!(
                    "Set-Cookie: idis_view={sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}",
                    SESSION_TTL.as_secs()
                )];
                if let Some(vc) = vid_set_cookie {
                    hdrs.push(vc);
                }
                send_json(
                    &mut stream,
                    "200 OK",
                    &hdrs,
                    &serde_json::json!({ "ok": true }),
                )
            } else {
                state.record_login_failure(peer.ip(), false);
                warn!("[web {peer}] Failed viewer passcode attempt");
                send_json(
                    &mut stream,
                    "401 Unauthorized",
                    &[],
                    &serde_json::json!({ "error": "观看口令错误" }),
                )
            }
        }
        ("POST", "/api/view/request-approval") => {
            if !is_viewer && !is_admin {
                return send_json(
                    &mut stream,
                    "401 Unauthorized",
                    &[],
                    &serde_json::json!({ "error": "viewer authentication required" }),
                );
            }
            let extra: Vec<String> = vid_set_cookie.into_iter().collect();
            if state.is_web_viewer_approved(is_admin, Some(&viewer_fp)) {
                return send_json(
                    &mut stream,
                    "200 OK",
                    &extra,
                    &serde_json::json!({
                        "ok": true,
                        "approved": true,
                        "decision": "trusted",
                        "fingerprint": viewer_fp,
                    }),
                );
            }
            if state.registry.is_low_power() || state.registry.config().no_confirm {
                return send_json(
                    &mut stream,
                    "403 Forbidden",
                    &extra,
                    &serde_json::json!({
                        "ok": false,
                        "approved": false,
                        "decision": "deny",
                        "error": "当前处于严格/低电量模式，仅允许已受信设备观看",
                    }),
                );
            }
            let pending = PendingDevice {
                session_id: 0,
                addr: peer.ip().to_string(),
                fingerprint: viewer_fp.clone(),
                uid: String::new(),
                name: viewer_label.clone(),
                model: "Web Browser".to_string(),
                is_usb: false,
                is_web: true,
            };
            let decision = state.enqueue_pending_approval_with_liveness(&pending, || {
                crate::transport::is_tcp_peer_closed(&stream)
            });
            // Final guard against ghost approval/trust if the browser tab closed (FIN/RST),
            // logged out, or the admin rotated/disabled `view_token` while waiting (P1-C1).
            let peer_closed = crate::transport::is_tcp_peer_closed(&stream);
            let still_authed = is_admin || state.verify_viewer_cookie(viewer_cookie);
            match decision {
                ConfirmDecision::AllowAndTrust => {
                    if peer_closed || !still_authed {
                        info!("[web {peer}] Web viewer disconnected or session invalidated before AllowAndTrust completed; skipping trust persistence");
                        if !peer_closed {
                            return send_json(
                                &mut stream,
                                "401 Unauthorized",
                                &extra,
                                &serde_json::json!({
                                    "ok": false,
                                    "approved": false,
                                    "error": "会话已失效，请重新登录",
                                }),
                            );
                        }
                        return Ok(());
                    }
                    if let Err(e) = state.registry.trust_device_and_save(
                        &viewer_fp,
                        "",
                        &viewer_label,
                        "Web Browser",
                    ) {
                        warn!("[web {peer}] Failed to persist trusted web viewer: {e:#}");
                        state.approve_web_viewer_once(&viewer_fp);
                    }
                    send_json(
                        &mut stream,
                        "200 OK",
                        &extra,
                        &serde_json::json!({
                            "ok": true,
                            "approved": true,
                            "decision": "allow_and_trust",
                            "fingerprint": viewer_fp,
                        }),
                    )
                }
                ConfirmDecision::AllowOnce => {
                    if peer_closed || !still_authed {
                        info!("[web {peer}] Web viewer disconnected or session invalidated before AllowOnce completed; skipping one-time approval");
                        if !peer_closed {
                            return send_json(
                                &mut stream,
                                "401 Unauthorized",
                                &extra,
                                &serde_json::json!({
                                    "ok": false,
                                    "approved": false,
                                    "error": "会话已失效，请重新登录",
                                }),
                            );
                        }
                        return Ok(());
                    }
                    state.approve_web_viewer_once(&viewer_fp);
                    send_json(
                        &mut stream,
                        "200 OK",
                        &extra,
                        &serde_json::json!({
                            "ok": true,
                            "approved": true,
                            "decision": "allow_once",
                            "fingerprint": viewer_fp,
                        }),
                    )
                }
                ConfirmDecision::Deny => {
                    if !still_authed && !peer_closed {
                        return send_json(
                            &mut stream,
                            "401 Unauthorized",
                            &extra,
                            &serde_json::json!({
                                "ok": false,
                                "approved": false,
                                "error": "会话已失效，请重新登录",
                            }),
                        );
                    }
                    send_json(
                        &mut stream,
                        "403 Forbidden",
                        &extra,
                        &serde_json::json!({
                            "ok": false,
                            "approved": false,
                            "decision": "deny",
                            "error": "管理员拒绝了本次观看请求或审批超时",
                        }),
                    )
                }
            }
        }
        ("POST", "/api/view/logout") => {
            // Revoke the viewer session cookie FIRST so any concurrent waking `request-approval`
            // handler sees `still_authed == false` and skips ghost trust / AllowOnce (Iter-6 P1-C3).
            state.revoke_viewer_cookie(viewer_cookie);
            if let Some(tok) = viewer_cookie {
                state.registry.kick_web_viewers_by_tag(tok);
            }
            state.cancel_pending_web_approvals(Some(&viewer_fp));
            state.revoke_web_viewer_once(&viewer_fp);
            state.registry.kick_web_viewers_by_fingerprint(&viewer_fp);
            let clear = "Set-Cookie: idis_view=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"
                .to_string();
            send_json(
                &mut stream,
                "200 OK",
                &[clear],
                &serde_json::json!({ "ok": true }),
            )
        }
        ("GET", "/ws/stream") => {
            if !origin_matches_host(&req.headers) {
                return send_response(&mut stream, "403 Forbidden", "text/plain", &[], b"forbidden");
            }
            let mut ws_authed = is_viewer || is_admin;
            let mut matched_query_token_gen: Option<u64> = None;
            if !ws_authed {
                if let Some(raw_tok) = parse_query_param(req.query.as_deref(), "token") {
                    let candidate = raw_tok.trim();
                    if !candidate.is_empty() {
                        if !state.check_rate_limit(peer.ip(), false) {
                            warn!("[web {peer}] Rate-limited /ws/stream?token= authentication attempt");
                            return send_response(
                                &mut stream,
                                "429 Too Many Requests",
                                "text/plain",
                                &[],
                                b"too many authentication attempts",
                            );
                        }
                        if let Some(tok_gen) = state.verify_view_token_with_gen(candidate) {
                            state.clear_login_failures(peer.ip(), false);
                            state.registry.record_external_activity();
                            state.registry.record_web_activity();
                            info!("[web {peer}] WebSocket viewer authenticated via URL ?token=");
                            ws_authed = true;
                            matched_query_token_gen = Some(tok_gen);
                        } else {
                            state.record_login_failure(peer.ip(), false);
                            warn!("[web {peer}] Failed /ws/stream?token= authentication attempt");
                        }
                    }
                }
            }
            if !ws_authed {
                return send_response(
                    &mut stream,
                    "401 Unauthorized",
                    "text/plain",
                    &[],
                    b"viewer authentication required",
                );
            }
            state.registry.refresh_host_lock_state_now(true);
            if state.registry.is_web_lock_disconnect_admit_blocked() {
                return send_json(
                    &mut stream,
                    "423 Locked",
                    &[],
                    &serde_json::json!({ "error": "主机已锁屏（当前网页端锁屏策略为自动断开），请先解锁主机" }),
                );
            }
            if state.registry.max_web_viewers() == 0 {
                return send_json(
                    &mut stream,
                    "403 Forbidden",
                    &[],
                    &serde_json::json!({ "error": "网页观看已关闭（当前网页观看上限为 0，请在管理后台调大观看上限）" }),
                );
            }
            if !state.is_web_viewer_approved(is_admin, Some(&viewer_fp)) {
                return send_json(
                    &mut stream,
                    "403 Forbidden",
                    &[],
                    &serde_json::json!({
                        "error": "需要管理员审批通过后才能观看",
                        "approval_required": true,
                        "fingerprint": viewer_fp,
                    }),
                );
            }
            let ws_auth = if is_admin {
                if loopback_auto_admin {
                    WsAuth::LoopbackAdmin
                } else if let Some(tok) = admin_cookie {
                    WsAuth::AdminCookie(tok.to_string())
                } else {
                    WsAuth::LoopbackAdmin
                }
            } else if is_viewer {
                match viewer_cookie {
                    Some(tok) => WsAuth::ViewerCookie(tok.to_string()),
                    None => WsAuth::QueryViewToken(matched_query_token_gen.unwrap_or(0)),
                }
            } else {
                WsAuth::QueryViewToken(matched_query_token_gen.unwrap_or(0))
            };
            handle_ws_stream(
                stream,
                peer,
                &req.headers,
                ws_auth,
                Some(viewer_fp),
                Some(viewer_label),
                state,
                stop_a,
                stop_g,
            )
        }
        // Admin-only APIs below
        ("GET", "/api/admin/state") => {
            if !is_admin {
                return send_json(
                    &mut stream,
                    "401 Unauthorized",
                    &[],
                    &serde_json::json!({ "error": "unauthorized" }),
                );
            }
            handle_admin_state(&mut stream, &state)
        }
        ("POST", "/api/admin/sessions/disconnect") => {
            if !is_admin {
                return send_json(
                    &mut stream,
                    "401 Unauthorized",
                    &[],
                    &serde_json::json!({ "error": "unauthorized" }),
                );
            }
            let Ok(payload) = serde_json::from_slice::<DisconnectReq>(&req.body) else {
                return send_json(
                    &mut stream,
                    "400 Bad Request",
                    &[],
                    &serde_json::json!({ "error": "invalid json" }),
                );
            };
            if payload.key == "*" {
                info!("[web {peer}] Admin disconnected ALL sessions");
                state.registry.close_all();
            } else {
                info!("[web {peer}] Admin disconnected session {:?}", payload.key);
                state.registry.close_session(&payload.key);
            }
            send_json(&mut stream, "200 OK", &[], &serde_json::json!({ "ok": true }))
        }
        ("POST", "/api/admin/viewers/disconnect") => {
            if !is_admin {
                return send_json(
                    &mut stream,
                    "401 Unauthorized",
                    &[],
                    &serde_json::json!({ "error": "unauthorized" }),
                );
            }
            let payload = if req.body.is_empty() {
                KickViewerReq { id: None }
            } else {
                match serde_json::from_slice::<KickViewerReq>(&req.body) {
                    Ok(p) => p,
                    Err(_) => {
                        return send_json(
                            &mut stream,
                            "400 Bad Request",
                            &[],
                            &serde_json::json!({ "error": "invalid json" }),
                        );
                    }
                }
            };
            if let Some(id) = payload.id {
                if let Some(Some(fp)) = state.registry.kick_web_viewer(id) {
                    state.revoke_web_viewer_once(&fp);
                }
            } else {
                for fp in state.registry.kick_all_web_viewers_with_fingerprints() {
                    state.revoke_web_viewer_once(&fp);
                }
                state.clear_web_once_approvals();
            }
            send_json(&mut stream, "200 OK", &[], &serde_json::json!({ "ok": true }))
        }
        ("POST", "/api/admin/pending/decide") => {
            if !is_admin {
                return send_json(
                    &mut stream,
                    "401 Unauthorized",
                    &[],
                    &serde_json::json!({ "error": "unauthorized" }),
                );
            }
            let Ok(payload) = serde_json::from_slice::<DecidePendingReq>(&req.body) else {
                return send_json(
                    &mut stream,
                    "400 Bad Request",
                    &[],
                    &serde_json::json!({ "error": "invalid json" }),
                );
            };
            let decision = match payload.decision.as_str() {
                "allow_and_trust" => ConfirmDecision::AllowAndTrust,
                "allow_once" => ConfirmDecision::AllowOnce,
                "deny" => ConfirmDecision::Deny,
                _ => {
                    return send_json(
                        &mut stream,
                        "400 Bad Request",
                        &[],
                        &serde_json::json!({ "error": "invalid decision" }),
                    );
                }
            };
            match state.resolve_pending_approval(payload.id, decision, true) {
                Ok(resolved) => {
                    info!(
                        "[web {peer}] Admin pending approval #{} => {:?} (resolved={resolved})",
                        payload.id, decision
                    );
                    send_json(
                        &mut stream,
                        "200 OK",
                        &[],
                        &serde_json::json!({ "ok": resolved }),
                    )
                }
                Err(err_msg) => send_json(
                    &mut stream,
                    "400 Bad Request",
                    &[],
                    &serde_json::json!({ "error": err_msg }),
                ),
            }
        }
        ("POST", "/api/admin/trusted/add") => {
            if !is_admin {
                return send_json(
                    &mut stream,
                    "401 Unauthorized",
                    &[],
                    &serde_json::json!({ "error": "unauthorized" }),
                );
            }
            let Ok(payload) = serde_json::from_slice::<TrustedAddReq>(&req.body) else {
                return send_json(
                    &mut stream,
                    "400 Bad Request",
                    &[],
                    &serde_json::json!({ "error": "invalid json" }),
                );
            };
            let Some(fp_clean) = payload
                .fingerprint
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            else {
                return send_json(
                    &mut stream,
                    "400 Bad Request",
                    &[],
                    &serde_json::json!({ "error": "请填写设备指纹（格式 fp:<24位十六进制>）" }),
                );
            };
            if crate::trust::normalize_fingerprint(fp_clean).is_none() {
                return send_json(
                    &mut stream,
                    "400 Bad Request",
                    &[],
                    &serde_json::json!({ "error": "设备指纹格式无效（示例 fp:a1b2c3d4e5f60718293a4b5c）" }),
                );
            }
            let name = payload.name.as_deref().unwrap_or("Manual Device");
            let model = payload.model.as_deref().unwrap_or("iPad");
            match state
                .registry
                .trust_device_and_save(fp_clean, "", name, model)
            {
                Ok(rec) => send_json(
                    &mut stream,
                    "200 OK",
                    &[],
                    &serde_json::json!({ "ok": true, "device": rec }),
                ),
                Err(e) => send_json(
                    &mut stream,
                    "500 Internal Server Error",
                    &[],
                    &serde_json::json!({ "error": format!("{e:#}") }),
                ),
            }
        }
        ("POST", "/api/admin/trusted/revoke") => {
            if !is_admin {
                return send_json(
                    &mut stream,
                    "401 Unauthorized",
                    &[],
                    &serde_json::json!({ "error": "unauthorized" }),
                );
            }
            let Ok(payload) = serde_json::from_slice::<TrustedRevokeReq>(&req.body) else {
                return send_json(
                    &mut stream,
                    "400 Bad Request",
                    &[],
                    &serde_json::json!({ "error": "invalid json" }),
                );
            };
            let Some(fp_clean) = payload
                .fingerprint
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            else {
                return send_json(
                    &mut stream,
                    "400 Bad Request",
                    &[],
                    &serde_json::json!({ "error": "缺少设备指纹" }),
                );
            };
            match state.registry.revoke_trusted_device_and_save(fp_clean) {
                Ok(removed) => {
                    state.revoke_web_viewer_once(fp_clean);
                    state.registry.kick_web_viewers_by_fingerprint(fp_clean);
                    send_json(
                        &mut stream,
                        "200 OK",
                        &[],
                        &serde_json::json!({ "ok": removed }),
                    )
                }
                Err(e) => send_json(
                    &mut stream,
                    "500 Internal Server Error",
                    &[],
                    &serde_json::json!({ "error": format!("{e:#}") }),
                ),
            }
        }
        ("POST", "/api/admin/trusted/clear-prefs") => {
            if !is_admin {
                return send_json(
                    &mut stream,
                    "401 Unauthorized",
                    &[],
                    &serde_json::json!({ "error": "unauthorized" }),
                );
            }
            let Ok(payload) = serde_json::from_slice::<TrustedRevokeReq>(&req.body) else {
                return send_json(
                    &mut stream,
                    "400 Bad Request",
                    &[],
                    &serde_json::json!({ "error": "invalid json" }),
                );
            };
            let Some(fp_clean) = payload
                .fingerprint
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            else {
                return send_json(
                    &mut stream,
                    "400 Bad Request",
                    &[],
                    &serde_json::json!({ "error": "缺少设备指纹" }),
                );
            };
            match state.registry.clear_trusted_device_prefs_and_save(fp_clean) {
                Ok(cleared) => send_json(
                    &mut stream,
                    "200 OK",
                    &[],
                    &serde_json::json!({ "ok": cleared }),
                ),
                Err(e) => send_json(
                    &mut stream,
                    "500 Internal Server Error",
                    &[],
                    &serde_json::json!({ "error": format!("{e:#}") }),
                ),
            }
        }
        ("POST", "/api/admin/settings") => {
            if !is_admin {
                return send_json(
                    &mut stream,
                    "401 Unauthorized",
                    &[],
                    &serde_json::json!({ "error": "unauthorized" }),
                );
            }
            handle_admin_settings(&mut stream, peer, &state, &req.body)
        }
        ("GET", "/api/admin/config") => {
            if !is_admin {
                return send_json(
                    &mut stream,
                    "401 Unauthorized",
                    &[],
                    &serde_json::json!({ "error": "unauthorized" }),
                );
            }
            handle_admin_config_get(&mut stream, &state)
        }
        ("POST", "/api/admin/debug") => {
            if !is_admin {
                return send_json(
                    &mut stream,
                    "401 Unauthorized",
                    &[],
                    &serde_json::json!({ "error": "unauthorized" }),
                );
            }
            #[derive(Deserialize)]
            struct DebugToggleReq {
                enabled: bool,
            }
            let Ok(payload) = serde_json::from_slice::<DebugToggleReq>(&req.body) else {
                return send_json(
                    &mut stream,
                    "400 Bad Request",
                    &[],
                    &serde_json::json!({ "error": "invalid json" }),
                );
            };
            crate::debug_trace::set_runtime_debug_enabled(payload.enabled);
            info!("[web {peer}] Admin set runtime debug logging={}", payload.enabled);
            send_json(
                &mut stream,
                "200 OK",
                &[],
                &serde_json::json!({
                    "ok": true,
                    "debug_enabled": crate::debug_trace::is_debug_logging_enabled(),
                    "debug_logging_enabled": crate::debug_trace::is_debug_logging_enabled(),
                    "debug_trace_active": crate::debug_trace::is_enabled(),
                }),
            )
        }
        ("GET", "/api/admin/debug/bundle") => {
            if !is_admin {
                return send_json(
                    &mut stream,
                    "401 Unauthorized",
                    &[],
                    &serde_json::json!({ "error": "unauthorized" }),
                );
            }
            handle_admin_debug_bundle(&mut stream, &state)
        }
        ("POST", "/api/admin/config") => {
            if !is_admin {
                return send_json(
                    &mut stream,
                    "401 Unauthorized",
                    &[],
                    &serde_json::json!({ "error": "unauthorized" }),
                );
            }
            handle_admin_config_save(&mut stream, peer, &state, &req.body)
        }
        ("POST", "/api/admin/config/reload") => {
            if !is_admin {
                return send_json(
                    &mut stream,
                    "401 Unauthorized",
                    &[],
                    &serde_json::json!({ "error": "unauthorized" }),
                );
            }
            handle_admin_config_reload(&mut stream, peer, &state)
        }
        ("POST", "/api/admin/config/reset") => {
            if !is_admin {
                return send_json(
                    &mut stream,
                    "401 Unauthorized",
                    &[],
                    &serde_json::json!({ "error": "unauthorized" }),
                );
            }
            handle_admin_config_reset(&mut stream, peer, &state, &req.body)
        }
        ("POST", "/api/admin/presets/apply") => {
            if !is_admin {
                return send_json(
                    &mut stream,
                    "401 Unauthorized",
                    &[],
                    &serde_json::json!({ "error": "unauthorized" }),
                );
            }
            handle_admin_preset_apply(&mut stream, peer, &state, &req.body)
        }
        ("POST", "/api/admin/presets/save") => {
            if !is_admin {
                return send_json(
                    &mut stream,
                    "401 Unauthorized",
                    &[],
                    &serde_json::json!({ "error": "unauthorized" }),
                );
            }
            handle_admin_preset_save(&mut stream, peer, &state, &req.body)
        }
        ("POST", "/api/admin/presets/delete") => {
            if !is_admin {
                return send_json(
                    &mut stream,
                    "401 Unauthorized",
                    &[],
                    &serde_json::json!({ "error": "unauthorized" }),
                );
            }
            handle_admin_preset_delete(&mut stream, peer, &state, &req.body)
        }
        ("GET", "/api/admin/screens") => {
            if !is_admin {
                return send_json(
                    &mut stream,
                    "401 Unauthorized",
                    &[],
                    &serde_json::json!({ "error": "unauthorized" }),
                );
            }
            handle_admin_screens(&mut stream, &state)
        }
        ("POST", "/api/admin/virtual-displays") => {
            if !is_admin {
                return send_json(
                    &mut stream,
                    "401 Unauthorized",
                    &[],
                    &serde_json::json!({ "error": "unauthorized" }),
                );
            }
            handle_admin_virtual_display_create(&mut stream, peer, &state, &req.body)
        }
        ("POST", "/api/admin/virtual-displays/remove") => {
            if !is_admin {
                return send_json(
                    &mut stream,
                    "401 Unauthorized",
                    &[],
                    &serde_json::json!({ "error": "unauthorized" }),
                );
            }
            handle_admin_virtual_display_remove(&mut stream, peer, &state, &req.body)
        }
        ("GET", "/api/admin/windows") => {
            if !is_admin {
                return send_json(
                    &mut stream,
                    "401 Unauthorized",
                    &[],
                    &serde_json::json!({ "error": "unauthorized" }),
                );
            }
            handle_admin_windows_list(&mut stream, &state)
        }
        ("POST", "/api/admin/windows/move") => {
            if !is_admin {
                return send_json(
                    &mut stream,
                    "401 Unauthorized",
                    &[],
                    &serde_json::json!({ "error": "unauthorized" }),
                );
            }
            handle_admin_window_move(&mut stream, peer, &state, &req.body)
        }
        ("POST", "/api/admin/window-rules/upsert") => {
            if !is_admin {
                return send_json(
                    &mut stream,
                    "401 Unauthorized",
                    &[],
                    &serde_json::json!({ "error": "unauthorized" }),
                );
            }
            handle_admin_window_rule_upsert(&mut stream, peer, &state, &req.body)
        }
        ("POST", "/api/admin/window-rules/delete") => {
            if !is_admin {
                return send_json(
                    &mut stream,
                    "401 Unauthorized",
                    &[],
                    &serde_json::json!({ "error": "unauthorized" }),
                );
            }
            handle_admin_window_rule_delete(&mut stream, peer, &state, &req.body)
        }
        ("POST", "/api/admin/window-rules/apply") => {
            if !is_admin {
                return send_json(
                    &mut stream,
                    "401 Unauthorized",
                    &[],
                    &serde_json::json!({ "error": "unauthorized" }),
                );
            }
            handle_admin_window_rules_apply(&mut stream, peer, &state)
        }
        ("POST", "/api/admin/permissions/request") => {
            if !is_admin {
                return send_json(
                    &mut stream,
                    "401 Unauthorized",
                    &[],
                    &serde_json::json!({ "error": "unauthorized" }),
                );
            }
            handle_admin_permissions_request(&mut stream, peer, &state, &req.body)
        }
        _ => send_json(
            &mut stream,
            "404 Not Found",
            &[],
            &serde_json::json!({ "error": "not found" }),
        ),
    }
}

fn handle_admin_state(stream: &mut TcpStream, state: &WebState) -> Result<()> {
    state.registry.refresh_host_lock_state_now(false);
    let cfg = state.registry.config();
    let host = state.registry.host_info();
    let video = state.registry.video_settings();
    let view_token_opt = state.view_token.lock().unwrap().clone();
    let view_token_enabled = view_token_opt.is_some();
    let lan_ips = state.cached_lan_ipv4s();
    let wifi_addrs = state.effective_wifi_addrs();
    let conn = crate::netinfo::HostConnectionInfo::build_with_viewer(
        lan_ips,
        wifi_addrs.map(|(t, _)| t.ip()),
        wifi_addrs.map(|(t, d)| (t.port(), d.port())),
        Some(state.web_addr),
        state.viewer_addr(),
    );
    let wifi_idle_remaining_secs = state.wifi_remaining_idle_close().map(|d| d.as_secs());
    let web_viewer_idle_remaining_secs = state.viewer_remaining_idle_close().map(|d| d.as_secs());
    let wifi_qr_svg = conn
        .primary_wifi_endpoint()
        .and_then(|s| crate::qr::QrCode::encode(s).ok())
        .map(|q| q.to_svg());
    let web_viewer_qr_svg = conn
        .primary_web_viewer_url()
        .and_then(|s| crate::qr::QrCode::encode(s).ok())
        .map(|q| q.to_svg());
    let (web_viewer_token_urls, web_viewer_token_qr_svg) = if let Some(ref vt) = view_token_opt {
        let encoded = percent_encode_query_val(vt);
        let urls: Vec<String> = conn
            .web_viewer_urls
            .iter()
            .map(|u| format!("{u}?token={encoded}"))
            .collect();
        let qr = urls
            .first()
            .and_then(|u| crate::qr::QrCode::encode(u).ok())
            .map(|q| q.to_svg());
        (urls, qr)
    } else {
        (Vec::new(), None)
    };
    let (mux_hits, mux_misses) = state.mux_cache.stats();
    let web_p2p = state.p2p.summary(mux_hits, mux_misses);
    let web_viewers: Vec<serde_json::Value> = state
        .registry
        .list_web_viewers()
        .into_iter()
        .map(|v| {
            let p2p_snap = state.p2p.viewer_snapshot(v.id);
            serde_json::json!({
                "id": v.id,
                "peer": v.peer,
                "fingerprint": v.fingerprint,
                "label": v.label,
                "connected_secs": v.connected_secs,
                "p2p_role": p2p_snap.p2p_role,
                "p2p_parent_id": p2p_snap.p2p_parent_id,
                "p2p_children": p2p_snap.p2p_children,
                "p2p_active": p2p_snap.p2p_active,
                "p2p_depth": p2p_snap.p2p_depth,
                "p2p_supported": p2p_snap.p2p_supported,
                "p2p_can_relay": p2p_snap.p2p_can_relay,
                "p2p_relay_priority": p2p_snap.p2p_relay_priority,
                "p2p_fallback_count": p2p_snap.p2p_fallback_count,
                "p2p_fallback_reason": p2p_snap.p2p_fallback_reason,
            })
        })
        .collect();
    let (active_preset, custom_presets) = state.registry.list_presets();
    let host_json = serde_json::json!({
        "host_name": host.host_name,
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "supports_hidpi": state.registry.supports_hidpi(),
        "supports_independent_web_screen": state.registry.supports_independent_web_screen(),
        "capabilities": state.registry.capabilities(),
        "executable_path": std::env::current_exe().ok().map(|p| p.display().to_string()),
        "last_capture_error": state.registry.last_capture_error(),
        "config_corrupt": state.registry.is_config_corrupt(),
        "debug_enabled": crate::debug_trace::is_debug_logging_enabled(),
        "debug_logging_enabled": crate::debug_trace::is_debug_logging_enabled(),
        "debug_trace_active": crate::debug_trace::is_enabled(),
        "version": env!("CARGO_PKG_VERSION"),
        "mode": format!("{:?}", cfg.mode),
        "fps": video.fps,
        "bitrate_mbps": video.bitrate_mbps,
        "wifi": wifi_addrs.is_some(),
        "usb": !cfg.no_usb,
        "idle_exit_secs": cfg.idle_exit_secs,
        "uptime_secs": state.started_at.elapsed().as_secs(),
        "config_path": state.registry.config_path().map(|p| p.display().to_string()),
        "trusted_store": state
            .registry
            .config_path()
            .map(|p| p.display().to_string())
            .or_else(|| {
                state
                    .registry
                    .trust_store()
                    .path()
                    .map(|p| p.display().to_string())
            }),
    });
    let connection_json = serde_json::json!({
        "lan_ips": conn.lan_ips,
        "primary_ip": conn.primary_ip,
        "wifi_enabled": conn.wifi_enabled,
        "wifi_telemetry_port": conn.wifi_telemetry_port,
        "wifi_data_port": conn.wifi_data_port,
        "wifi_endpoints": conn.wifi_endpoints,
        "wifi_qr_svg": wifi_qr_svg,
        "web_bind": conn.web_bind,
        "web_localhost_only": conn.web_localhost_only,
        "web_admin_urls": conn.web_admin_urls,
        "web_viewer_bind": conn.web_viewer_bind,
        "web_viewer_port": conn.web_viewer_port,
        "web_viewer_listening": conn.web_viewer_listening,
        "web_viewer_urls": conn.web_viewer_urls,
        "web_viewer_qr_svg": web_viewer_qr_svg,
        "web_viewer_token_urls": web_viewer_token_urls,
        "web_viewer_token_qr_svg": web_viewer_token_qr_svg,
        "port_idle_close_secs": state.registry.port_idle_close_secs(),
        "wifi_idle_remaining_secs": wifi_idle_remaining_secs,
        "web_viewer_idle_remaining_secs": web_viewer_idle_remaining_secs,
    });
    let settings_json = serde_json::json!({
        "allow_input": state.registry.is_input_allowed(),
        "client_cursor": state.registry.is_client_cursor(),
        "input_stats": state.registry.input_stats(),
        "gestures": state.registry.gestures_config(),
        "default_screenshot_dir": crate::user_config::default_screenshot_base_dir().to_string_lossy().into_owned(),
        "last_gesture": state.registry.last_gesture(),
        "wifi_enabled": wifi_addrs.is_some(),
        "port_idle_close_secs": state.registry.port_idle_close_secs(),
        "max_extended_screens": state.registry.max_extended_screens(),
        "active_extended_screens": state.registry.active_extended_screens(),
        "max_web_viewers": state.registry.max_web_viewers(),
        "active_web_viewers": state.registry.active_web_viewers(),
        "max_connections": state.registry.max_extended_screens(),
        "max_screen_connections": state.registry.max_extended_screens(),
        "auto_max_in_flight": state.registry.is_auto_max_in_flight(),
        "max_in_flight": state.registry.max_in_flight(),
        "total_screen_connections": state.registry.total_screen_connections(),
        "view_token_enabled": view_token_enabled,
        "view_token": view_token_opt,
        "web_independent_screen": state.registry.is_web_independent_screen(),
        "web_screen_mode": state.registry.web_screen_mode(),
        "web_require_approval": state.registry.is_web_require_approval(),
        "lock_action": state.registry.lock_action_ipad(),
        "lock_action_ipad": state.registry.lock_action_ipad(),
        "lock_action_web": state.registry.lock_action_web(),
        "lock_delay_secs": state.registry.lock_delay_secs(),
        "host_screen_locked": state.registry.is_host_screen_locked(),
        "host_lock_enforced": state.registry.is_host_lock_enforced(),
        "host_lock_paused_ipad": state.registry.is_host_lock_paused_ipad(),
        "host_lock_paused_web": state.registry.is_host_lock_paused_web(),
        "p2p_relay_enabled": state.p2p.is_enabled(),
        "low_power": state.registry.is_low_power(),
        "polling": state.registry.polling_config(),
    });
    let cli_config_json = serde_json::json!({
        "mode": format!("{:?}", cfg.mode).to_lowercase(),
        "wifi": wifi_addrs.is_some(),
        "no_usb": cfg.no_usb,
        "no_bonjour": cfg.no_bonjour,
        "bind_addr": cfg.bind_addr,
        "telemetry_port": cfg.telemetry_port,
        "data_port": cfg.data_port,
        "host_name": cfg.host_name,
        "display_id": cfg.display_id,
        "client_cursor": state.registry.is_client_cursor(),
        "abr_sensitivity": video.abr_sensitivity,
        "half_fps_when_unfocused": video.half_fps_when_unfocused,
        "web_screen_mode": state.registry.web_screen_mode(),
        "web_require_approval": state.registry.is_web_require_approval(),
        "ping_timeout_secs": cfg.ping_timeout_secs,
        "idle_exit_secs": cfg.idle_exit_secs,
        "port_idle_close_secs": state.registry.port_idle_close_secs(),
        "trust_usb": cfg.trust_usb,
        "require_usb_confirm": cfg.require_usb_confirm,
        "low_power": state.registry.is_low_power(),
        "auto_accept": cfg.auto_accept,
        "no_confirm": cfg.no_confirm,
        "web_bind": cfg.web_bind,
        "web_width": video.web_width,
        "web_height": video.web_height,
        "web_fps": video.web_fps,
        "web_bitrate_mbps": video.web_bitrate_mbps,
        "web_hidpi": video.web_hidpi,
        "web_max_pixel_edge": video.web_max_pixel_edge,
        "qr": cfg.qr,
        "debug": crate::debug_trace::is_debug_logging_enabled(),
        "all_intra": cfg.all_intra,
        "allow_ips": cfg.allow_ips,
        "allow_fingerprints": cfg.allow_fingerprints,
        "use_system_proxy": cfg.use_system_proxy,
        "has_explicit_admin_token": state.admin_token_explicit,
    });
    send_json(
        stream,
        "200 OK",
        &[],
        &serde_json::json!({
            "host": host_json,
            "connection": connection_json,
            "video": video,
            "settings": settings_json,
            "polling": state.registry.polling_config(),
            "web_screen": state.registry.web_screen_info(),
            "web_p2p": web_p2p,
            "cli_config": cli_config_json,
            "sessions": state.registry.list_sessions(),
            "web_viewers": web_viewers,
            "pending_approvals": state.list_pending_approvals(),
            "trusted_devices": state.registry.trust_store().list(),
            "active_preset": active_preset,
            "presets": custom_presets,
            "builtin_presets": crate::user_config::ConfigPreset::builtin_presets(),
            "virtual_displays": state.registry.list_standalone_virtual_displays(),
            "screens": state.registry.list_target_screens(),
            "window_rules": state.registry.list_window_rules(),
            "logs": state.logs.snapshot(),
        }),
    )
}

fn handle_admin_settings(
    stream: &mut TcpStream,
    peer: SocketAddr,
    state: &Arc<WebState>,
    body: &[u8],
) -> Result<()> {
    let Ok(payload) = serde_json::from_slice::<UpdateSettingsReq>(body) else {
        return send_json(
            stream,
            "400 Bad Request",
            &[],
            &serde_json::json!({ "error": "invalid json" }),
        );
    };
    // Pre-validate `view_token` length and `web_screen_mode` support/quota BEFORE mutating any
    // runtime or persisted settings so rejected 400 requests never leave partial side-effects (Iter-7 P2-C3).
    if payload.disable_view_token != Some(true) && payload.rotate_view_token != Some(true) {
        if let Some(ref tok) = payload.view_token {
            if tok.trim().len() < 4 {
                return send_json(
                    stream,
                    "400 Bad Request",
                    &[],
                    &serde_json::json!({ "error": "观看口令长度至少 4 位" }),
                );
            }
        }
    }
    let req_screen_mode = payload.web_screen_mode.or_else(|| {
        payload.web_independent_screen.map(|indep| {
            if indep {
                WebScreenMode::Independent
            } else {
                WebScreenMode::FollowIpad
            }
        })
    });
    if let Some(mode) = req_screen_mode {
        if let Err(e) = state.registry.validate_web_screen_mode_switch(
            mode,
            payload.max_extended_screens,
            payload.max_web_viewers,
        ) {
            return send_json(
                stream,
                "400 Bad Request",
                &[],
                &serde_json::json!({ "error": format!("{e:#}") }),
            );
        }
    }
    if payload.reset_video == Some(true) && state.registry.is_config_corrupt() {
        return send_json(
            stream,
            "409 Conflict",
            &[],
            &serde_json::json!({
                "error": "配置文件存在语法错误，当前处于只读保护模式；请先在「配置文件」修复并保存有效 YAML 后再重置视频设置"
            }),
        );
    }

    if let Some(allow) = payload.allow_input {
        state.registry.set_input_allowed(allow);
    }
    if let Some(gestures) = payload.gestures {
        if let Err(e) = state.registry.set_gestures_config(gestures) {
            return send_json(
                stream,
                "400 Bad Request",
                &[],
                &serde_json::json!({ "error": format!("{e:#}") }),
            );
        }
    }
    if let Some(cc) = payload.client_cursor {
        state.registry.set_client_cursor(cc);
    }
    if let Some(wra) = payload.web_require_approval {
        let prev_wra = state.registry.is_web_require_approval();
        state.registry.set_web_require_approval(wra);
        if wra {
            if !prev_wra {
                state.clear_web_once_approvals();
            }
            state.kick_unapproved_web_viewers();
        }
    }
    if let Some(max_ext) = payload.max_extended_screens {
        state.registry.set_max_extended_screens(max_ext);
    }
    if let Some(max_web) = payload.max_web_viewers {
        state.registry.set_max_web_viewers(max_web);
    }
    if let Some(auto_mif) = payload.auto_max_in_flight {
        if auto_mif {
            state.registry.set_auto_max_in_flight(true);
        } else if let Some(mif) = payload.max_in_flight {
            state.registry.set_max_in_flight(mif);
        } else {
            state.registry.set_auto_max_in_flight(false);
        }
    } else if let Some(mif) = payload.max_in_flight {
        state.registry.set_max_in_flight(mif);
    }
    if let Some(la) = payload.lock_action {
        state.registry.set_lock_action(la);
    }
    if let Some(la_ipad) = payload.lock_action_ipad {
        state.registry.set_lock_action_ipad(la_ipad);
    }
    if let Some(la_web) = payload.lock_action_web {
        state.registry.set_lock_action_web(la_web);
    }
    if let Some(delay) = payload.lock_delay_secs {
        state.registry.set_lock_delay_secs(delay);
    }
    if let Some(lp) = payload.low_power {
        state.registry.set_low_power(lp);
        state.p2p.set_enabled(state.registry.is_p2p_relay_enabled());
    }
    if payload.reset_polling == Some(true) {
        state.registry.reset_polling_config();
    } else if payload.main_loop_ms.is_some()
        || payload.cursor_poll_ms.is_some()
        || payload.usb_retry_ms.is_some()
        || payload.admin_poll_ms.is_some()
    {
        state.registry.update_polling_config(PollingPatch {
            main_loop_ms: payload.main_loop_ms,
            cursor_poll_ms: payload.cursor_poll_ms,
            usb_retry_ms: payload.usb_retry_ms,
            admin_poll_ms: payload.admin_poll_ms,
        });
    }
    if let Some(p2p_en) = payload.p2p_relay_enabled {
        state.registry.set_p2p_relay_enabled(p2p_en);
        state.p2p.set_enabled(state.registry.is_p2p_relay_enabled());
    }
    if let Some(secs) = payload.port_idle_close_secs {
        state.registry.set_port_idle_close_secs(secs);
    }
    if let Some(wifi_en) = payload.wifi_enabled {
        if wifi_en {
            if state.stopping.load(Ordering::Acquire)
                || state.global_stop.load(Ordering::Acquire)
            {
                return send_json(
                    stream,
                    "503 Service Unavailable",
                    &[],
                    &serde_json::json!({ "error": "server is shutting down" }),
                );
            }
            if let Err(e) = state.wifi_controller.start() {
                return send_json(
                    stream,
                    "400 Bad Request",
                    &[],
                    &serde_json::json!({ "error": format!("开启 iPad Wi-Fi 端口失败: {e:#}") }),
                );
            }
            info!("[web {peer}] Admin enabled iPad Wi-Fi listener");
        } else {
            state.wifi_controller.stop();
            info!("[web {peer}] Admin disabled iPad Wi-Fi listener");
        }
    }
    if let Some(mode) = payload.web_screen_mode {
        if let Err(e) = state.registry.set_web_screen_mode(mode) {
            return send_json(
                stream,
                "400 Bad Request",
                &[],
                &serde_json::json!({ "error": format!("{e:#}") }),
            );
        }
    } else if let Some(indep) = payload.web_independent_screen {
        if let Err(e) = state.registry.set_web_independent_screen(indep) {
            return send_json(
                stream,
                "400 Bad Request",
                &[],
                &serde_json::json!({ "error": format!("{e:#}") }),
            );
        }
    }
    if payload.reset_video == Some(true) {
        if let Err(e) = state.registry.reset_video_settings() {
            let status = if state.registry.is_config_corrupt() {
                "409 Conflict"
            } else {
                "500 Internal Server Error"
            };
            return send_json(
                stream,
                status,
                &[],
                &serde_json::json!({ "error": format!("{e:#}") }),
            );
        }
        state.registry.set_client_cursor(false);
    }
    if payload.reset_web_video == Some(true) {
        let _ = state.registry.reset_web_video_settings();
        state.registry.set_p2p_relay_enabled(true);
        state.p2p.set_enabled(state.registry.is_p2p_relay_enabled());
        let _ = state.registry.set_web_screen_mode(WebScreenMode::FollowIpad);
        state.registry.set_max_web_viewers(0);
    }
    if payload.reset_video != Some(true)
        && payload.reset_web_video != Some(true)
        && (payload.quality.is_some()
            || payload.width.is_some()
            || payload.height.is_some()
            || payload.fps.is_some()
            || payload.bitrate_mbps.is_some()
            || payload.hidpi.is_some()
            || payload.integer_scale.is_some()
            || payload.max_pixel_edge.is_some()
            || payload.adaptive_quality.is_some()
            || payload.abr_sensitivity.is_some()
            || payload.half_fps_when_unfocused.is_some()
            || payload.web_quality.is_some()
            || payload.web_width.is_some()
            || payload.web_height.is_some()
            || payload.web_fps.is_some()
            || payload.web_bitrate_mbps.is_some()
            || payload.web_hidpi.is_some()
            || payload.web_max_pixel_edge.is_some())
    {
        let _ = state.registry.update_video_settings(VideoSettingsPatch {
            quality: payload.quality,
            width: payload.width,
            height: payload.height,
            fps: payload.fps,
            bitrate_mbps: payload.bitrate_mbps,
            hidpi: payload.hidpi,
            integer_scale: payload.integer_scale,
            max_pixel_edge: payload.max_pixel_edge,
            adaptive_quality: payload.adaptive_quality,
            abr_sensitivity: payload.abr_sensitivity,
            half_fps_when_unfocused: payload.half_fps_when_unfocused,
            web_quality: payload.web_quality,
            web_width: payload.web_width,
            web_height: payload.web_height,
            web_fps: payload.web_fps,
            web_bitrate_mbps: payload.web_bitrate_mbps,
            web_hidpi: payload.web_hidpi,
            web_max_pixel_edge: payload.web_max_pixel_edge,
        });
    }
    let mut generated_token: Option<String> = None;
    if payload.disable_view_token == Some(true) {
        state.set_view_token(None);
        info!("[web {peer}] Admin disabled web extended-screen viewer passcode");
    } else if payload.rotate_view_token == Some(true) {
        let tok = generate_random_hex(8);
        state.set_view_token(Some(tok.clone()));
        generated_token = Some(tok);
        info!("[web {peer}] Admin generated a new web extended-screen viewer passcode");
    } else if let Some(tok) = payload.view_token {
        let trimmed = tok.trim().to_string();
        if trimmed.len() < 4 {
            return send_json(
                stream,
                "400 Bad Request",
                &[],
                &serde_json::json!({ "error": "观看口令长度至少 4 位" }),
            );
        }
        state.set_view_token(Some(trimmed));
        info!("[web {peer}] Admin updated web extended-screen viewer passcode");
    }
    let active_view_token = state.view_token.lock().unwrap().clone();
    let viewer_addr = state.viewer_addr();
    send_json(
        stream,
        "200 OK",
        &[],
        &serde_json::json!({
            "ok": true,
            "generated_view_token": generated_token,
            "view_token": active_view_token,
            "view_token_enabled": active_view_token.is_some(),
            "web_viewer_bind": viewer_addr.map(|a| a.to_string()),
            "web_viewer_port": viewer_addr.map(|a| a.port()),
            "web_viewer_listening": viewer_addr.is_some(),
            "wifi_enabled": state.effective_wifi_addrs().is_some(),
            "port_idle_close_secs": state.registry.port_idle_close_secs(),
            "max_extended_screens": state.registry.max_extended_screens(),
            "max_web_viewers": state.registry.max_web_viewers(),
            "client_cursor": state.registry.is_client_cursor(),
            "web_independent_screen": state.registry.is_web_independent_screen(),
            "web_screen_mode": state.registry.web_screen_mode(),
            "web_require_approval": state.registry.is_web_require_approval(),
            "lock_action": state.registry.lock_action_ipad(),
            "lock_action_ipad": state.registry.lock_action_ipad(),
            "lock_action_web": state.registry.lock_action_web(),
            "lock_delay_secs": state.registry.lock_delay_secs(),
            "p2p_relay_enabled": state.p2p.is_enabled(),
            "low_power": state.registry.is_low_power(),
            "polling": state.registry.polling_config(),
            "auto_max_in_flight": state.registry.is_auto_max_in_flight(),
            "max_in_flight": state.registry.max_in_flight(),
            "web_screen": state.registry.web_screen_info(),
            "video": state.registry.video_settings(),
        }),
    )
}

fn handle_admin_config_get(stream: &mut TcpStream, state: &WebState) -> Result<()> {
    let cfg = state.registry.export_persisted_config();
    let yaml = match cfg.to_yaml_string() {
        Ok(y) => y,
        Err(e) => {
            return send_json(
                stream,
                "500 Internal Server Error",
                &[],
                &serde_json::json!({ "error": format!("{e:#}") }),
            );
        }
    };
    let corrupt = state.registry.is_config_corrupt();
    let raw_disk_yaml = if corrupt {
        state.registry.read_raw_config_file()
    } else {
        None
    };
    let parse_error = if corrupt {
        state.registry.config_parse_error()
    } else {
        None
    };
    send_json(
        stream,
        "200 OK",
        &[],
        &serde_json::json!({
            "path": state.registry.config_path().map(|p| p.display().to_string()),
            "persisted": state.registry.config_path().is_some(),
            "config_corrupt": corrupt,
            "raw_disk_yaml": raw_disk_yaml,
            "parse_error": parse_error,
            "yaml": yaml,
            "config": cfg,
        }),
    )
}

fn handle_admin_debug_bundle(stream: &mut TcpStream, state: &WebState) -> Result<()> {
    let cfg = state.registry.config();
    let (mux_hits, mux_misses) = state.mux_cache.stats();
    let web_p2p = state.p2p.summary(mux_hits, mux_misses);
    let web_viewers: Vec<serde_json::Value> = state
        .registry
        .list_web_viewers()
        .into_iter()
        .map(|v| {
            let p2p_snap = state.p2p.viewer_snapshot(v.id);
            serde_json::json!({
                "id": v.id,
                "connected_secs": v.connected_secs,
                "p2p_role": p2p_snap.p2p_role,
                "p2p_parent_id": p2p_snap.p2p_parent_id,
                "p2p_children": p2p_snap.p2p_children,
                "p2p_active": p2p_snap.p2p_active,
                "p2p_depth": p2p_snap.p2p_depth,
                "p2p_supported": p2p_snap.p2p_supported,
                "p2p_can_relay": p2p_snap.p2p_can_relay,
                "p2p_relay_priority": p2p_snap.p2p_relay_priority,
                "p2p_fallback_count": p2p_snap.p2p_fallback_count,
                "p2p_fallback_reason": p2p_snap.p2p_fallback_reason,
            })
        })
        .collect();
    let bundle = crate::debug_trace::sanitize_json_value(serde_json::json!({
        "schema_version": 1,
        "generated_unix_secs": unix_now_secs(),
        "version": env!("CARGO_PKG_VERSION"),
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "mode": format!("{:?}", cfg.mode),
        "all_intra": cfg.all_intra,
        "uptime_secs": state.started_at.elapsed().as_secs(),
        "debug_enabled": crate::debug_trace::is_enabled(),
        "debug_logging_enabled": crate::debug_trace::is_debug_logging_enabled(),
        "debug_trace_active": crate::debug_trace::is_enabled(),
        "capabilities": state.registry.capabilities(),
        "config_corrupt": state.registry.is_config_corrupt(),
        "config_parse_error": state.registry.config_parse_error(),
        "effective_config": state.registry.export_user_config(),
        "persisted_config": state.registry.export_persisted_config(),
        "video": state.registry.video_settings(),
        "polling": state.registry.polling_config(),
        "web_screen": state.registry.web_screen_info(),
        "web_p2p": web_p2p,
        "sessions": state.registry.list_sessions(),
        "web_viewers": web_viewers,
        "recent_logs": state.logs.snapshot(),
        "recent_trace_events": crate::debug_trace::recent_events(),
    }));
    send_json(stream, "200 OK", &[], &bundle)
}

fn handle_admin_config_save(
    stream: &mut TcpStream,
    peer: SocketAddr,
    state: &WebState,
    body: &[u8],
) -> Result<()> {
    let Ok(payload) = serde_json::from_slice::<SaveConfigYamlReq>(body) else {
        return send_json(
            stream,
            "400 Bad Request",
            &[],
            &serde_json::json!({ "error": "invalid json" }),
        );
    };
    let parsed = match crate::user_config::UserConfigFile::from_yaml_str(&payload.yaml) {
        Ok(c) => c,
        Err(e) => {
            return send_json(
                stream,
                "400 Bad Request",
                &[],
                &serde_json::json!({ "error": format!("{e:#}") }),
            );
        }
    };
    let prev_wra = state.registry.is_web_require_approval();
    let prev_fps: std::collections::HashSet<String> = state
        .registry
        .trust_store()
        .list()
        .into_iter()
        .map(|d| d.fingerprint)
        .collect();
    match state.registry.apply_user_config(parsed, true) {
        Ok(applied) => {
            state.p2p.set_enabled(applied.p2p_relay_enabled);
            let next_fps: std::collections::HashSet<String> = applied
                .trusted_devices
                .iter()
                .map(|d| d.fingerprint.clone())
                .collect();
            for removed_fp in prev_fps.difference(&next_fps) {
                state.revoke_web_viewer_once(removed_fp);
            }
            if applied.web_require_approval {
                if !prev_wra {
                    state.clear_web_once_approvals();
                }
                state.kick_unapproved_web_viewers();
            }
            let yaml = state
                .registry
                .export_persisted_config()
                .to_yaml_string()
                .unwrap_or_default();
            info!(
                "[web {peer}] Admin saved & applied YAML config ({} trusted device(s))",
                applied.trusted_devices.len()
            );
            send_json(
                stream,
                "200 OK",
                &[],
                &serde_json::json!({
                    "ok": true,
                    "path": state.registry.config_path().map(|p| p.display().to_string()),
                    "yaml": yaml,
                    "config": applied,
                }),
            )
        }
        Err(e) => send_json(
            stream,
            "500 Internal Server Error",
            &[],
            &serde_json::json!({ "error": format!("{e:#}") }),
        ),
    }
}

fn handle_admin_config_reload(
    stream: &mut TcpStream,
    peer: SocketAddr,
    state: &WebState,
) -> Result<()> {
    let prev_wra = state.registry.is_web_require_approval();
    let prev_fps: std::collections::HashSet<String> = state
        .registry
        .trust_store()
        .list()
        .into_iter()
        .map(|d| d.fingerprint)
        .collect();
    match state.registry.reload_user_config_from_disk() {
        Ok(applied) => {
            state.p2p.set_enabled(applied.p2p_relay_enabled);
            let next_fps: std::collections::HashSet<String> = applied
                .trusted_devices
                .iter()
                .map(|d| d.fingerprint.clone())
                .collect();
            for removed_fp in prev_fps.difference(&next_fps) {
                state.revoke_web_viewer_once(removed_fp);
            }
            if applied.web_require_approval {
                if !prev_wra {
                    state.clear_web_once_approvals();
                }
                state.kick_unapproved_web_viewers();
            }
            let yaml = state
                .registry
                .export_persisted_config()
                .to_yaml_string()
                .unwrap_or_default();
            info!("[web {peer}] Admin reloaded YAML config from disk");
            send_json(
                stream,
                "200 OK",
                &[],
                &serde_json::json!({
                    "ok": true,
                    "path": state.registry.config_path().map(|p| p.display().to_string()),
                    "yaml": yaml,
                    "config": applied,
                }),
            )
        }
        Err(e) => send_json(
            stream,
            "400 Bad Request",
            &[],
            &serde_json::json!({ "error": format!("{e:#}") }),
        ),
    }
}

fn handle_admin_config_reset(
    stream: &mut TcpStream,
    peer: SocketAddr,
    state: &WebState,
    body: &[u8],
) -> Result<()> {
    let payload = if body.is_empty() {
        ResetConfigReq { keep_trusted: true }
    } else {
        match serde_json::from_slice::<ResetConfigReq>(body) {
            Ok(p) => p,
            Err(_) => {
                return send_json(
                    stream,
                    "400 Bad Request",
                    &[],
                    &serde_json::json!({ "error": "invalid json" }),
                );
            }
        }
    };
    if state.registry.is_config_corrupt() && payload.keep_trusted {
        return send_json(
            stream,
            "409 Conflict",
            &[],
            &serde_json::json!({
                "error": "当前磁盘 YAML 配置存在语法错误，内存中的受信设备列表为空；为防止清空原有受信设备，请先修复 YAML 或选择不保留受信设备重置"
            }),
        );
    }
    let mut fresh = crate::user_config::UserConfigFile::default();
    if payload.keep_trusted {
        fresh.trusted_devices = state.registry.trust_store().list();
        fresh.presets = state.registry.list_presets().1;
    }
    let prev_wra = state.registry.is_web_require_approval();
    match state.registry.apply_user_config(fresh, true) {
        Ok(applied) => {
            state.p2p.set_enabled(applied.p2p_relay_enabled);
            if !payload.keep_trusted || (!prev_wra && applied.web_require_approval) {
                state.clear_web_once_approvals();
            }
            if applied.web_require_approval {
                state.kick_unapproved_web_viewers();
            }
            let yaml = applied.to_yaml_string().unwrap_or_default();
            info!(
                "[web {peer}] Admin reset YAML config (keep_trusted={})",
                payload.keep_trusted
            );
            send_json(
                stream,
                "200 OK",
                &[],
                &serde_json::json!({
                    "ok": true,
                    "path": state.registry.config_path().map(|p| p.display().to_string()),
                    "yaml": yaml,
                    "config": applied,
                }),
            )
        }
        Err(e) => send_json(
            stream,
            "500 Internal Server Error",
            &[],
            &serde_json::json!({ "error": format!("{e:#}") }),
        ),
    }
}

fn handle_admin_preset_apply(
    stream: &mut TcpStream,
    peer: SocketAddr,
    state: &WebState,
    body: &[u8],
) -> Result<()> {
    let Ok(payload) = serde_json::from_slice::<PresetNameReq>(body) else {
        return send_json(
            stream,
            "400 Bad Request",
            &[],
            &serde_json::json!({ "error": "invalid json" }),
        );
    };
    let prev_wra = state.registry.is_web_require_approval();
    match state.registry.apply_preset(&payload.name) {
        Ok(applied) => {
            state.p2p.set_enabled(applied.p2p_relay_enabled);
            if applied.web_require_approval {
                if !prev_wra {
                    state.clear_web_once_approvals();
                }
                state.kick_unapproved_web_viewers();
            }
            info!("[web {peer}] Admin applied config preset {:?}", payload.name);
            send_json(
                stream,
                "200 OK",
                &[],
                &serde_json::json!({
                    "ok": true,
                    "active_preset": applied.active_preset,
                    "config": applied,
                }),
            )
        }
        Err(e) => send_json(
            stream,
            "400 Bad Request",
            &[],
            &serde_json::json!({ "error": format!("{e:#}") }),
        ),
    }
}

fn handle_admin_preset_save(
    stream: &mut TcpStream,
    peer: SocketAddr,
    state: &WebState,
    body: &[u8],
) -> Result<()> {
    let Ok(payload) = serde_json::from_slice::<PresetNameReq>(body) else {
        return send_json(
            stream,
            "400 Bad Request",
            &[],
            &serde_json::json!({ "error": "invalid json" }),
        );
    };
    match state.registry.save_current_as_preset(&payload.name) {
        Ok(preset) => {
            let (active_preset, presets) = state.registry.list_presets();
            info!("[web {peer}] Admin saved config preset {:?}", preset.name);
            send_json(
                stream,
                "200 OK",
                &[],
                &serde_json::json!({
                    "ok": true,
                    "preset": preset,
                    "active_preset": active_preset,
                    "presets": presets,
                }),
            )
        }
        Err(e) => send_json(
            stream,
            "400 Bad Request",
            &[],
            &serde_json::json!({ "error": format!("{e:#}") }),
        ),
    }
}

fn handle_admin_preset_delete(
    stream: &mut TcpStream,
    peer: SocketAddr,
    state: &WebState,
    body: &[u8],
) -> Result<()> {
    let Ok(payload) = serde_json::from_slice::<PresetNameReq>(body) else {
        return send_json(
            stream,
            "400 Bad Request",
            &[],
            &serde_json::json!({ "error": "invalid json" }),
        );
    };
    match state.registry.delete_preset(&payload.name) {
        Ok(removed) => {
            let (active_preset, presets) = state.registry.list_presets();
            info!(
                "[web {peer}] Admin deleted config preset {:?} (removed={removed})",
                payload.name
            );
            send_json(
                stream,
                "200 OK",
                &[],
                &serde_json::json!({
                    "ok": removed,
                    "active_preset": active_preset,
                    "presets": presets,
                }),
            )
        }
        Err(e) => send_json(
            stream,
            "400 Bad Request",
            &[],
            &serde_json::json!({ "error": format!("{e:#}") }),
        ),
    }
}

fn handle_admin_screens(stream: &mut TcpStream, state: &WebState) -> Result<()> {
    send_json(
        stream,
        "200 OK",
        &[],
        &serde_json::json!({
            "screens": state.registry.list_target_screens(),
            "virtual_displays": state.registry.list_standalone_virtual_displays(),
            "window_rules": state.registry.list_window_rules(),
        }),
    )
}

fn handle_admin_virtual_display_create(
    stream: &mut TcpStream,
    peer: SocketAddr,
    state: &WebState,
    body: &[u8],
) -> Result<()> {
    let Ok(payload) = serde_json::from_slice::<CreateVirtualDisplayReq>(body) else {
        return send_json(
            stream,
            "400 Bad Request",
            &[],
            &serde_json::json!({ "error": "invalid json" }),
        );
    };
    match state
        .registry
        .create_standalone_virtual_display(&payload.name, payload.width, payload.height)
    {
        Ok(vd) => {
            info!(
                "[web {peer}] Admin created standalone virtual display #{} {:?} ({}x{}, display_id={})",
                vd.id, vd.name, vd.width, vd.height, vd.display_id
            );
            send_json(
                stream,
                "200 OK",
                &[],
                &serde_json::json!({
                    "ok": true,
                    "virtual_display": vd,
                    "virtual_displays": state.registry.list_standalone_virtual_displays(),
                    "screens": state.registry.list_target_screens(),
                }),
            )
        }
        Err(e) => send_json(
            stream,
            "400 Bad Request",
            &[],
            &serde_json::json!({ "error": format!("{e:#}") }),
        ),
    }
}

fn handle_admin_virtual_display_remove(
    stream: &mut TcpStream,
    peer: SocketAddr,
    state: &WebState,
    body: &[u8],
) -> Result<()> {
    let Ok(payload) = serde_json::from_slice::<RemoveVirtualDisplayReq>(body) else {
        return send_json(
            stream,
            "400 Bad Request",
            &[],
            &serde_json::json!({ "error": "invalid json" }),
        );
    };
    let removed = state.registry.remove_standalone_virtual_display(payload.id);
    info!(
        "[web {peer}] Admin removed standalone virtual display #{} (removed={removed})",
        payload.id
    );
    send_json(
        stream,
        "200 OK",
        &[],
        &serde_json::json!({
            "ok": removed,
            "virtual_displays": state.registry.list_standalone_virtual_displays(),
            "screens": state.registry.list_target_screens(),
        }),
    )
}

fn handle_admin_windows_list(stream: &mut TcpStream, state: &WebState) -> Result<()> {
    match state.registry.list_desktop_windows() {
        Ok(windows) => send_json(
            stream,
            "200 OK",
            &[],
            &serde_json::json!({
                "ok": true,
                "windows": windows,
                "screens": state.registry.list_target_screens(),
            }),
        ),
        Err(e) => send_json(
            stream,
            "400 Bad Request",
            &[],
            &serde_json::json!({ "error": format!("{e:#}") }),
        ),
    }
}

fn handle_admin_window_move(
    stream: &mut TcpStream,
    peer: SocketAddr,
    state: &WebState,
    body: &[u8],
) -> Result<()> {
    let Ok(payload) = serde_json::from_slice::<MoveWindowReq>(body) else {
        return send_json(
            stream,
            "400 Bad Request",
            &[],
            &serde_json::json!({ "error": "invalid json" }),
        );
    };
    match state.registry.move_desktop_window(
        payload.window_id,
        payload.pid,
        payload.target_display_id,
        payload.layout,
    ) {
        Ok(()) => {
            info!(
                "[web {peer}] Admin moved window {} (pid={}) -> display {} ({:?})",
                payload.window_id, payload.pid, payload.target_display_id, payload.layout
            );
            send_json(stream, "200 OK", &[], &serde_json::json!({ "ok": true }))
        }
        Err(e) => send_json(
            stream,
            "400 Bad Request",
            &[],
            &serde_json::json!({ "error": format!("{e:#}") }),
        ),
    }
}

fn handle_admin_window_rule_upsert(
    stream: &mut TcpStream,
    peer: SocketAddr,
    state: &WebState,
    body: &[u8],
) -> Result<()> {
    let Ok(rule) = serde_json::from_slice::<WindowRule>(body) else {
        return send_json(
            stream,
            "400 Bad Request",
            &[],
            &serde_json::json!({ "error": "invalid json" }),
        );
    };
    match state.registry.upsert_window_rule(rule) {
        Ok(saved) => {
            info!(
                "[web {peer}] Admin upserted window rule {:?} (app={:?}, floating_only={})",
                saved.id, saved.app_name, saved.floating_only
            );
            send_json(
                stream,
                "200 OK",
                &[],
                &serde_json::json!({
                    "ok": true,
                    "rule": saved,
                    "window_rules": state.registry.list_window_rules(),
                }),
            )
        }
        Err(e) => send_json(
            stream,
            "400 Bad Request",
            &[],
            &serde_json::json!({ "error": format!("{e:#}") }),
        ),
    }
}

fn handle_admin_window_rule_delete(
    stream: &mut TcpStream,
    peer: SocketAddr,
    state: &WebState,
    body: &[u8],
) -> Result<()> {
    let Ok(payload) = serde_json::from_slice::<DeleteWindowRuleReq>(body) else {
        return send_json(
            stream,
            "400 Bad Request",
            &[],
            &serde_json::json!({ "error": "invalid json" }),
        );
    };
    let removed = state.registry.delete_window_rule(&payload.id);
    info!(
        "[web {peer}] Admin deleted window rule {:?} (removed={removed})",
        payload.id
    );
    send_json(
        stream,
        "200 OK",
        &[],
        &serde_json::json!({
            "ok": removed,
            "window_rules": state.registry.list_window_rules(),
        }),
    )
}

fn handle_admin_window_rules_apply(
    stream: &mut TcpStream,
    peer: SocketAddr,
    state: &WebState,
) -> Result<()> {
    match state.registry.apply_window_rules_now() {
        Ok(report) => {
            info!(
                "[web {peer}] Admin triggered apply window rules: moved={}, skipped={}, failed={}",
                report.moved, report.skipped, report.failed
            );
            send_json(
                stream,
                "200 OK",
                &[],
                &serde_json::json!({
                    "ok": true,
                    "report": report,
                }),
            )
        }
        Err(e) => send_json(
            stream,
            "400 Bad Request",
            &[],
            &serde_json::json!({ "error": format!("{e:#}") }),
        ),
    }
}

fn handle_admin_permissions_request(
    stream: &mut TcpStream,
    peer: SocketAddr,
    state: &WebState,
    body: &[u8],
) -> Result<()> {
    #[derive(Deserialize)]
    struct PermissionReq {
        kind: String,
    }
    let Ok(payload) = serde_json::from_slice::<PermissionReq>(body) else {
        return send_json(
            stream,
            "400 Bad Request",
            &[],
            &serde_json::json!({ "error": "invalid json" }),
        );
    };
    match state.registry.request_os_permission(&payload.kind) {
        Ok(msg) => {
            info!(
                "[web {peer}] Admin permission action kind={:?} -> {msg}",
                payload.kind
            );
            send_json(
                stream,
                "200 OK",
                &[],
                &serde_json::json!({
                    "ok": true,
                    "message": msg,
                    "capabilities": state.registry.capabilities(),
                    "last_capture_error": state.registry.last_capture_error(),
                }),
            )
        }
        Err(e) => send_json(
            stream,
            "400 Bad Request",
            &[],
            &serde_json::json!({ "error": format!("{e:#}") }),
        ),
    }
}
