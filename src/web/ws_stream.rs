use super::http::{compute_ws_accept, read_ws_control_frame, send_json, send_response, write_ws_frame};
use super::p2p::{self, MAX_SIGNAL_PAYLOAD_BYTES};
use super::{unix_now_secs, WebState, SESSION_TTL};
use crate::platform::RecvFrameError;
use anyhow::Result;
use std::collections::HashMap;
use std::io::Write;
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// Explicit WebSocket authentication provenance so 15s keepalive TTL checks validate
/// against the exact session store that authorized the connection (preventing dual Admin+Viewer
/// loopback browsers from validating `idis_view` against `admin_sessions`).
pub(super) enum WsAuth {
    AdminCookie(String),
    ViewerCookie(String),
    LoopbackAdmin,
    QueryViewToken,
}

/// Upgrade HTTP/1.1 connection to RFC 6455 WebSocket and stream extended display fMP4 frames.
#[allow(clippy::too_many_arguments)]
pub(super) fn handle_ws_stream(
    mut stream: TcpStream,
    peer: SocketAddr,
    headers: &HashMap<String, String>,
    ws_auth: WsAuth,
    viewer_fingerprint: Option<String>,
    viewer_label: Option<String>,
    state: Arc<WebState>,
    stop_a: Arc<AtomicBool>,
    stop_g: Arc<AtomicBool>,
) -> Result<()> {
    let Some(ws_key) = headers.get("sec-websocket-key") else {
        return send_response(
            &mut stream,
            "400 Bad Request",
            "text/plain",
            &[],
            b"missing Sec-WebSocket-Key",
        );
    };
    let session_tag = match &ws_auth {
        WsAuth::AdminCookie(tok) | WsAuth::ViewerCookie(tok) => Some(tok.clone()),
        WsAuth::LoopbackAdmin | WsAuth::QueryViewToken => None,
    };
    let is_admin_ws = matches!(ws_auth, WsAuth::AdminCookie(_) | WsAuth::LoopbackAdmin);
    let sub = match state.registry.subscribe_web_stream_with_identity(
        peer.to_string(),
        session_tag,
        viewer_fingerprint.clone(),
        viewer_label,
        is_admin_ws,
    ) {
        Ok(s) => s,
        Err(e) => {
            warn!("[web {peer}] Rejected WebSocket viewer stream: {e:#}");
            return send_json(
                &mut stream,
                "429 Too Many Requests",
                &[],
                &serde_json::json!({ "error": format!("{e:#}") }),
            );
        }
    };
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let accept = compute_ws_accept(ws_key);
    let upgrade_resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    stream.write_all(upgrade_resp.as_bytes())?;
    stream.flush()?;

    info!(
        "[web {peer}] Extended-screen WebSocket stream started (viewer_id={})",
        sub.id
    );

    let closed = Arc::new(AtomicBool::new(false));
    let shared_writer = Arc::new(Mutex::new(stream.try_clone()?));
    let ws_started_at = Instant::now();
    let ws_started_wall = unix_now_secs();
    let last_pong_ms = Arc::new(AtomicU64::new(0));

    // Register viewer with the LAN P2P relay hub (signaling piggybacks on this authenticated WS).
    let (sig_tx, sig_rx) = std::sync::mpsc::sync_channel::<String>(64);
    let viewer_id = sub.id;
    let ws_direct_paused = state
        .p2p
        .register(viewer_id, sig_tx, sub.rx.waker());

    // Reader thread handles client Ping/Pong/Close frames AND P2P/stream JSON control frames with a
    // short 2s read timeout so shutdown is prompt and frozen tabs are evicted within 45s.
    let tab_hidden = Arc::new(AtomicBool::new(false));
    let viewer_needs_idr = Arc::new(AtomicBool::new(true));
    let reader_closed = closed.clone();
    let reader_writer = shared_writer.clone();
    let reader_pong = last_pong_ms.clone();
    let reader_p2p = state.p2p.clone();
    let reader_registry = state.registry.clone();
    let reader_tab_hidden = tab_hidden.clone();
    let reader_needs_idr = viewer_needs_idr.clone();
    let mut ws_reader = stream;
    let _ = ws_reader.set_read_timeout(Some(Duration::from_secs(2)));
    let reader_handle = thread::spawn(move || {
        let mut ctrl_win_start = Instant::now();
        let mut ctrl_win_count: u32 = 0;
        let mut sig_win_count: u32 = 0;
        let mut ping_sec: u64 = 0;
        let mut ping_count: u32 = 0;
        let mut last_idr_req = Instant::now() - Duration::from_secs(1);
        let mut last_vis_req = Instant::now() - Duration::from_secs(1);
        while !reader_closed.load(Ordering::Relaxed) {
            match read_ws_control_frame(&mut ws_reader) {
                Ok(Some((opcode, payload))) => {
                    let now_ms = ws_started_at.elapsed().as_millis() as u64;
                    match opcode {
                        0x1 => {
                            reader_pong.store(now_ms, Ordering::Release);
                            if payload.len() <= MAX_SIGNAL_PAYLOAD_BYTES {
                                if ctrl_win_start.elapsed() >= Duration::from_secs(1) {
                                    ctrl_win_start = Instant::now();
                                    ctrl_win_count = 0;
                                    sig_win_count = 0;
                                }
                                if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&payload)
                                {
                                    let msg_type = val.get("type").and_then(|v| v.as_str());
                                    if msg_type == Some("p2p_signal") {
                                        sig_win_count = sig_win_count.saturating_add(1);
                                        if sig_win_count > 200 {
                                            continue;
                                        }
                                    } else {
                                        ctrl_win_count = ctrl_win_count.saturating_add(1);
                                        if ctrl_win_count > 40 {
                                            continue;
                                        }
                                    }
                                    match msg_type {
                                        Some("p2p_hello") => {
                                            let supported = val
                                                .get("supported")
                                                .and_then(|v| v.as_bool())
                                                .unwrap_or(false);
                                            let can_relay = val
                                                .get("can_relay")
                                                .and_then(|v| v.as_bool())
                                                .unwrap_or(false);
                                            let relay_priority = val
                                                .get("relay_priority")
                                                .and_then(|v| v.as_u64())
                                                .map(|v| v.min(2) as u8)
                                                .unwrap_or(if can_relay { 2 } else { 0 });
                                            reader_p2p.on_hello_with_priority(
                                                viewer_id,
                                                supported,
                                                relay_priority,
                                            );
                                        }
                                        Some("p2p_caps") => {
                                            let can_relay = val
                                                .get("can_relay")
                                                .and_then(|v| v.as_bool())
                                                .unwrap_or(false);
                                            let relay_priority = val
                                                .get("relay_priority")
                                                .and_then(|v| v.as_u64())
                                                .map(|v| v.min(2) as u8)
                                                .unwrap_or(if can_relay { 2 } else { 0 });
                                            reader_p2p.on_caps_update_with_priority(
                                                viewer_id,
                                                relay_priority,
                                            );
                                        }
                                        Some("p2p_active") => {
                                            if let Some(pid) =
                                                val.get("parent_id").and_then(|v| v.as_u64())
                                            {
                                                reader_needs_idr.store(true, Ordering::Release);
                                                reader_p2p.on_p2p_active(viewer_id, pid);
                                            }
                                        }
                                        Some("p2p_fallback") => {
                                            reader_needs_idr.store(true, Ordering::Release);
                                            let raw_reason = val
                                                .get("reason")
                                                .and_then(|v| v.as_str())
                                                .unwrap_or("client_fallback");
                                            let clean_reason: String = raw_reason
                                                .chars()
                                                .filter(|c| !c.is_control())
                                                .take(64)
                                                .collect();
                                            reader_p2p.on_p2p_fallback(
                                                viewer_id,
                                                if clean_reason.is_empty() {
                                                    "client_fallback"
                                                } else {
                                                    &clean_reason
                                                },
                                            );
                                        }
                                        Some("p2p_signal") => {
                                            if let (Some(to_id), Some(sig)) = (
                                                val.get("to").and_then(|v| v.as_u64()),
                                                val.get("signal").cloned(),
                                            ) {
                                                let _ = reader_p2p
                                                    .route_signal(viewer_id, to_id, sig);
                                            }
                                        }
                                        Some("need_idr") => {
                                            if last_idr_req.elapsed() >= Duration::from_millis(300)
                                            {
                                                last_idr_req = Instant::now();
                                                reader_registry.request_active_keyframes();
                                            }
                                        }
                                        Some("viewer_visibility") => {
                                            let visible = val
                                                .get("visible")
                                                .and_then(|v| v.as_bool())
                                                .unwrap_or(true);
                                            // NEVER drop `visible == true` (foreground resume must be instant);
                                            // only rate-limit `visible == false` pause flips to >=500ms.
                                            if visible
                                                || last_vis_req.elapsed()
                                                    >= Duration::from_millis(500)
                                            {
                                                if !visible {
                                                    last_vis_req = Instant::now();
                                                }
                                                reader_tab_hidden
                                                    .store(!visible, Ordering::Release);
                                                reader_needs_idr.store(true, Ordering::Release);
                                                reader_registry
                                                    .set_web_viewer_visible(viewer_id, visible);
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                        0x8 => {
                            if let Ok(mut w) = reader_writer.lock() {
                                let _ = write_ws_frame(&mut *w, 0x8, &[]);
                            }
                            break;
                        }
                        0x9 => {
                            reader_pong.store(now_ms, Ordering::Release);
                            let now_s = now_ms / 1000;
                            if now_s != ping_sec {
                                ping_sec = now_s;
                                ping_count = 0;
                            }
                            ping_count = ping_count.saturating_add(1);
                            if ping_count <= 30 {
                                if let Ok(mut w) = reader_writer.lock() {
                                    if write_ws_frame(&mut *w, 0xA, &payload).is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                        0xA => {
                            reader_pong.store(now_ms, Ordering::Release);
                        }
                        _ => {
                            reader_pong.store(now_ms, Ordering::Release);
                        }
                    }
                }
                Ok(None) => break,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    continue;
                }
                Err(_) => break,
            }
        }
        reader_closed.store(true, Ordering::SeqCst);
    });

    let mut last_ping = Instant::now();
    let mut last_sent_source: Option<(&'static str, bool)> = None;
    let mut last_sent_epoch: u64 = 0;
    let mut last_sent_init_gen: u64 = 0;
    let mut last_sent_lock_paused = false;
    let mut last_lock_epoch = state.registry.lock_state_epoch();
    let mut was_ws_paused = false;
    let mut initial_seed_done = false;
    let mut viewer_awaiting_idr = true;
    let mut last_kf_req = Instant::now() - Duration::from_secs(1);
    let mut kicked_by_admin = false;
    let mut kicked_by_lock = false;
    let mut write_failed = false;

    let write_shared_pkt = |writer: &mut TcpStream,
                            pkt: &p2p::MuxedWsPacket,
                            cur_source: &'static str,
                            is_indep: bool,
                            last_src: &mut Option<(&'static str, bool)>,
                            last_epoch: &mut u64,
                            last_init_gen: &mut u64,
                            force_init: bool|
     -> std::io::Result<()> {
        let first_init = last_src.is_none();
        let epoch_changed = !first_init && *last_epoch != pkt.epoch;
        let need_init =
            first_init || epoch_changed || *last_init_gen != pkt.init_gen || force_init;
        if need_init {
            let meta = serde_json::json!({
                "type": "init",
                "codec": pkt.codec,
                "width": pkt.width,
                "height": pkt.height,
                "fps": pkt.fps,
                "source": cur_source,
                "independent": is_indep,
                "epoch": pkt.epoch,
                "reset": first_init || epoch_changed,
            })
            .to_string();
            *last_src = Some((cur_source, is_indep));
            *last_epoch = pkt.epoch;
            *last_init_gen = pkt.init_gen;
            write_ws_frame(writer, 0x1, meta.as_bytes())?;
            writer.write_all(&pkt.init_ws_frame)?;
        } else if *last_src != Some((cur_source, is_indep)) {
            let meta = serde_json::json!({
                "type": "source",
                "source": cur_source,
                "independent": is_indep,
            })
            .to_string();
            *last_src = Some((cur_source, is_indep));
            write_ws_frame(writer, 0x1, meta.as_bytes())?;
        }
        writer.write_all(&pkt.media_ws_frame)?;
        writer.flush()
    };

    while !closed.load(Ordering::Relaxed)
        && !stop_a.load(Ordering::SeqCst)
        && !stop_g.load(Ordering::SeqCst)
    {
        // 1) Drain outbound P2P signaling messages promptly.
        while let Ok(sig_msg) = sig_rx.try_recv() {
            let mut w = shared_writer.lock().unwrap();
            if write_ws_frame(&mut *w, 0x1, sig_msg.as_bytes()).is_err() {
                write_failed = true;
                break;
            }
        }
        if write_failed {
            break;
        }

        // 2) Push host screen-lock status transitions immediately (Web-specific policy).
        let cur_lock_paused = state.registry.is_host_lock_paused_web();
        if cur_lock_paused != last_sent_lock_paused {
            let meta = serde_json::json!({
                "type": "host_lock",
                "locked": cur_lock_paused,
            })
            .to_string();
            let mut w = shared_writer.lock().unwrap();
            if write_ws_frame(&mut *w, 0x1, meta.as_bytes()).is_err() {
                write_failed = true;
                break;
            }
            last_sent_lock_paused = cur_lock_paused;
        }

        // 3) Seed a static cached IDR on initial connect or P2P->WS fallback for instant display,
        //    WITHOUT clearing `viewer_awaiting_idr` (so no stale mid-GOP P-frame can ever pass
        //    before a real live IDR arrives!). Never seed while locked or after a lock-pause transition (P1-A2/P2-B2).
        let cur_ws_paused = ws_direct_paused.load(Ordering::Acquire);
        let cur_tab_hidden = tab_hidden.load(Ordering::Acquire);
        let cur_lock_blocking = state.registry.is_web_lock_disconnect_blocking();
        let cur_lock_epoch = state.registry.lock_state_epoch();
        if cur_lock_epoch != last_lock_epoch {
            last_lock_epoch = cur_lock_epoch;
            viewer_awaiting_idr = true;
            // Suppress pre-lock static cache seeding across lock transitions (wait for live post-unlock IDR).
            initial_seed_done = true;
        }
        if cur_lock_paused
            || cur_lock_blocking
            || cur_tab_hidden
            || viewer_needs_idr.swap(false, Ordering::AcqRel)
        {
            viewer_awaiting_idr = true;
            if cur_lock_paused || cur_lock_blocking {
                initial_seed_done = true;
            }
        }
        let need_static_seed = (!initial_seed_done || (was_ws_paused && !cur_ws_paused))
            && !cur_lock_paused
            && !cur_lock_blocking
            && !cur_tab_hidden
            && !cur_ws_paused;
        if need_static_seed {
            initial_seed_done = true;
            was_ws_paused = false;
            viewer_awaiting_idr = true;
            let cur_source = state.registry.current_web_stream_source();
            let cur_source_epoch = state.registry.web_source_epoch();
            let seed_pkt = state
                .mux_cache
                .latest_packet_for_source(cur_source, cur_source_epoch)
                .or_else(|| {
                    state
                        .registry
                        .cached_web_idr_frame()
                        .filter(|(src, ep, _, _)| *src == cur_source && *ep == cur_source_epoch)
                        .and_then(|(src, ep, fps, f)| {
                            state.mux_cache.seed_if_empty(src, ep, fps, &f)
                        })
                });
            if let Some(pkt) = seed_pkt {
                let is_indep = state.registry.is_web_independent_screen();
                let mut w = shared_writer.lock().unwrap();
                if write_shared_pkt(
                    &mut w,
                    &pkt,
                    cur_source,
                    is_indep,
                    &mut last_sent_source,
                    &mut last_sent_epoch,
                    &mut last_sent_init_gen,
                    true,
                )
                .is_err()
                {
                    write_failed = true;
                    break;
                }
            }
            state.registry.request_active_keyframes();
        }

        match sub.rx.recv_timeout_shared_tagged(Duration::from_millis(120)) {
            Ok((frame_seq, frame_source_epoch, frame, ov)) => {
                if ov > 0 {
                    viewer_awaiting_idr = true;
                    if matches!(
                        state.registry.current_web_stream_source(),
                        "standalone" | "main"
                    ) {
                        state.registry.record_web_viewer_write_sample(0, ov);
                    }
                }
                // Drop stale frames emitted before the latest source/mode/owner transition (P1-B1).
                let active_source_epoch = state.registry.web_source_epoch();
                if frame_source_epoch != 0 && frame_source_epoch != active_source_epoch {
                    viewer_awaiting_idr = true;
                    if last_kf_req.elapsed() >= Duration::from_millis(300) {
                        last_kf_req = Instant::now();
                        state.registry.request_active_keyframes();
                    }
                    continue;
                }
                let post_lock_epoch = state.registry.lock_state_epoch();
                if post_lock_epoch != last_lock_epoch {
                    last_lock_epoch = post_lock_epoch;
                    viewer_awaiting_idr = true;
                }
                if viewer_needs_idr.swap(false, Ordering::AcqRel) {
                    viewer_awaiting_idr = true;
                }
                if state.registry.is_host_lock_paused_web()
                    || state.registry.is_web_lock_disconnect_blocking()
                {
                    viewer_awaiting_idr = true;
                    continue;
                }
                if tab_hidden.load(Ordering::Acquire) {
                    viewer_awaiting_idr = true;
                    continue;
                }
                if ws_direct_paused.load(Ordering::Acquire) {
                    was_ws_paused = true;
                    viewer_awaiting_idr = true;
                    continue;
                }
                if viewer_awaiting_idr && !frame.is_keyframe {
                    if last_kf_req.elapsed() >= Duration::from_millis(300) {
                        last_kf_req = Instant::now();
                        state.registry.request_active_keyframes();
                    }
                    continue;
                }
                let force_init = was_ws_paused;
                was_ws_paused = false;
                let cur_source = state.registry.current_web_stream_source();
                if cur_source == "idle" {
                    viewer_awaiting_idr = true;
                    continue;
                }
                let vs = state.registry.video_settings();
                let cur_fps = if matches!(cur_source, "standalone" | "main") {
                    vs.web_fps.max(1)
                } else {
                    vs.fps.max(1)
                };
                let is_indep = state.registry.is_web_independent_screen();
                if last_sent_source.is_some_and(|(s, _)| s != cur_source) {
                    viewer_awaiting_idr = true;
                }
                // Drop non-IDR P-frames BEFORE invoking `mux_or_get` so a stale old-source P-frame
                // never resets `SharedWebMuxer` on a live source switch (BUG-B2-3).
                if viewer_awaiting_idr && !frame.is_keyframe {
                    if last_kf_req.elapsed() >= Duration::from_millis(300) {
                        last_kf_req = Instant::now();
                        state.registry.request_active_keyframes();
                    }
                    continue;
                }
                let post_source_epoch = state.registry.web_source_epoch();
                if frame_source_epoch != 0 && frame_source_epoch != post_source_epoch {
                    viewer_awaiting_idr = true;
                    continue;
                }
                let eff_source_epoch = if frame_source_epoch != 0 {
                    frame_source_epoch
                } else {
                    post_source_epoch
                };
                if let Some(pkt) = state.mux_cache.mux_or_get(
                    frame_seq,
                    cur_source,
                    eff_source_epoch,
                    cur_fps,
                    &frame,
                ) {
                    if last_sent_epoch != 0 && last_sent_epoch != pkt.epoch {
                        viewer_awaiting_idr = true;
                    }
                    if viewer_awaiting_idr && !pkt.is_keyframe {
                        if last_kf_req.elapsed() >= Duration::from_millis(300) {
                            last_kf_req = Instant::now();
                            state.registry.request_active_keyframes();
                        }
                        continue;
                    }
                    let send_t0 = Instant::now();
                    let mut w = shared_writer.lock().unwrap();
                    if write_shared_pkt(
                        &mut w,
                        &pkt,
                        cur_source,
                        is_indep,
                        &mut last_sent_source,
                        &mut last_sent_epoch,
                        &mut last_sent_init_gen,
                        force_init,
                    )
                    .is_err()
                    {
                        write_failed = true;
                        break;
                    }
                    drop(w);
                    if pkt.is_keyframe {
                        viewer_awaiting_idr = false;
                    }
                    if matches!(cur_source, "standalone" | "main") {
                        let write_ms = send_t0.elapsed().as_millis() as u64;
                        state.registry.record_web_viewer_write_sample(write_ms, 0);
                    }
                } else {
                    viewer_awaiting_idr = true;
                }
            }
            Err(RecvFrameError::Timeout) => {
                let cur_ws_p = ws_direct_paused.load(Ordering::Acquire);
                if cur_ws_p {
                    was_ws_paused = true;
                } else if viewer_awaiting_idr
                    && !tab_hidden.load(Ordering::Acquire)
                    && !state.registry.is_host_lock_paused_web()
                    && !state.registry.is_web_lock_disconnect_blocking()
                    && last_kf_req.elapsed() >= Duration::from_millis(500)
                {
                    // Retry keyframe request on static screens so a missed <80ms edge never stalls.
                    last_kf_req = Instant::now();
                    state.registry.request_active_keyframes();
                }
                let cur_source = state.registry.current_web_stream_source();
                let is_indep = state.registry.is_web_independent_screen();
                if last_sent_source.is_some() && last_sent_source != Some((cur_source, is_indep)) {
                    viewer_awaiting_idr = true;
                    let meta = serde_json::json!({
                        "type": "source",
                        "source": cur_source,
                        "independent": is_indep,
                    })
                    .to_string();
                    last_sent_source = Some((cur_source, is_indep));
                    let mut w = shared_writer.lock().unwrap();
                    if write_ws_frame(&mut *w, 0x1, meta.as_bytes()).is_err() {
                        write_failed = true;
                        break;
                    }
                }
            }
            Err(RecvFrameError::Disconnected) => {
                if state.registry.is_web_lock_disconnect_blocking() {
                    info!(
                        "[web {peer}] Viewer stream disconnected because host screen locked (viewer_id={})",
                        sub.id
                    );
                    kicked_by_lock = true;
                } else {
                    info!(
                        "[web {peer}] Viewer stream kicked/disconnected (viewer_id={})",
                        sub.id
                    );
                    kicked_by_admin = true;
                }
                break;
            }
        }

        // Run periodic Ping + Pong liveness + SESSION_TTL enforcement on EVERY loop tick (even at
        // 60fps when `recv_timeout` never times out!), including 12h wall-clock TTL for `?token=`.
        if last_ping.elapsed() >= Duration::from_secs(15) {
            let now_ms = ws_started_at.elapsed().as_millis() as u64;
            let last_p = last_pong_ms.load(Ordering::Acquire);
            if now_ms.saturating_sub(last_p) > 45_000 {
                warn!(
                    "[web {peer}] Closing half-open/frozen WebSocket (viewer_id={}): no Pong received for >45s",
                    sub.id
                );
                write_failed = true;
                break;
            }
            let ttl_valid = match &ws_auth {
                WsAuth::AdminCookie(tok) => state.verify_admin_cookie(Some(tok)),
                WsAuth::ViewerCookie(tok) => state.verify_viewer_cookie(Some(tok)),
                WsAuth::LoopbackAdmin => true,
                WsAuth::QueryViewToken => {
                    unix_now_secs().saturating_sub(ws_started_wall) < SESSION_TTL.as_secs()
                        && state.view_token.lock().unwrap().is_some()
                }
            };
            let approval_valid = matches!(ws_auth, WsAuth::AdminCookie(_) | WsAuth::LoopbackAdmin)
                || state.is_web_viewer_approved(false, viewer_fingerprint.as_deref());
            if !ttl_valid || !approval_valid {
                info!(
                    "[web {peer}] Closing WebSocket: session expired or approval/trust revoked (ttl_valid={ttl_valid}, approval_valid={approval_valid})"
                );
                if !approval_valid {
                    kicked_by_admin = true;
                }
                break;
            }
            let mut w = shared_writer.lock().unwrap();
            // Send RFC 6455 Ping (checked by server Pong watchdog) AND a lightweight JSON heartbeat
            // so the browser's JS watchdog can detect silent host sleep/network drops on static screens.
            if write_ws_frame(&mut *w, 0x9, b"ping").is_err()
                || write_ws_frame(&mut *w, 0x1, br#"{"type":"hb"}"#).is_err()
            {
                write_failed = true;
                break;
            }
            state.p2p.maybe_rebalance_periodic();
            last_ping = Instant::now();
        }
    }

    closed.store(true, Ordering::SeqCst);
    let _remaining_viewers = state
        .p2p
        .unregister_and_maybe_reset(viewer_id, || state.mux_cache.reset());
    if let Ok(mut w) = shared_writer.lock() {
        if !write_failed {
            let close_payload: &[u8] = if kicked_by_lock {
                // Custom RFC 6455 close code 4002 ("host screen locked") so viewer stops auto-reconnecting.
                &4002u16.to_be_bytes()
            } else if kicked_by_admin {
                // Custom RFC 6455 close code 4001 ("kicked by admin") so viewer stops auto-reconnecting.
                &4001u16.to_be_bytes()
            } else {
                &[]
            };
            let _ = write_ws_frame(&mut *w, 0x8, close_payload);
        }
        let _ = w.shutdown(Shutdown::Both);
    }
    let _ = reader_handle.join();
    drop(sub);
    Ok(())
}
