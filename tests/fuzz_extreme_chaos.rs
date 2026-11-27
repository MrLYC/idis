//! Extreme-scenario chaos & fuzzing suite targeting brutal client kills (`SO_LINGER(0)` TCP RST,
//! half-open sockets), brutal server/subprocess kills (`SIGKILL`), extreme network faults
//! (zero-window slow reader, Slowloris trickle, asymmetric channel drops), legacy iPad v6.2.0
//! edge cases, and cross-subsystem intermediate-state / zombie detection.

#[path = "common/chaos.rs"]
mod chaos;
#[path = "common/fuzz.rs"]
mod fuzz;

use chaos::{force_tcp_rst, shrink_rcvbuf, shrink_sndbuf, wait_until, DeadlockWatchdog};
use fuzz::{fuzz_seeds, FuzzRng};
use idis::config::{AppConfig, CaptureMode, LockAction, MaxInFlight, WebScreenMode};
use idis::platform::mock::{MockBackend, SYNTHETIC_H264_ANNEX_B};
use idis::platform::EncodedFrame;
use idis::protocol::framing::{
    read_canal_block, read_canal_block_limited_deadline, write_canal_block, write_pt_frame,
    PT_FRAME_TYPE_DATA, PT_FRAME_TYPE_TELEMETRY,
};
use idis::protocol::keyed_archive::{archive, ArchivedValue};
use idis::protocol::messages::{
    decode_input_event, InputEvent, MessagePacket, KEY_MOD_CTRL, KEY_MOD_META, KEY_MOD_SHIFT,
};
use idis::session::SessionRegistry;
use idis::transport::wifi::{start_wifi_server, TcpCanalWriter};
use idis::transport::{is_tcp_peer_closed, FrameWriter};
use idis::web::{start_web_server, LogBuffer};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

fn base_config() -> AppConfig {
    AppConfig {
        mode: CaptureMode::Extend,
        quality: None,
        fps: 30,
        bitrate_mbps: 16,
        all_intra: false,
        width: 0,
        height: 0,
        hidpi: 1,
        integer_scale: false,
        max_pixel_edge: 0,
        no_adaptive_quality: false,
        abr_sensitivity: None,
        on_lock: LockAction::Pause,
        on_lock_ipad: None,
        on_lock_web: None,
        on_lock_delay_secs: 0,
        display_id: 0,
        capture_rect: None,
        encoder: "libx264".to_string(),
        ffmpeg_path: "ffmpeg".to_string(),
        bind_addr: "127.0.0.1".to_string(),
        telemetry_port: 0,
        data_port: 0,
        host_name: "ChaosHost".to_string(),
        wifi: true,
        no_bonjour: true,
        no_usb: true,
        allow_input: true,
        no_allow_input: false,
        usbmuxd_addr: "127.0.0.1:0".to_string(),
        client_cursor: false,
        no_client_cursor: false,
        half_fps_unfocused: false,
        no_half_fps_unfocused: false,
        allow_fingerprints: Vec::new(),
        allow_ips: Vec::new(),
        config_file: Some("none".to_string()),
        trusted_devices_file: Some("none".to_string()),
        max_extended_screens: 2,
        max_web_viewers: 4,
        idle_exit_secs: 300,
        port_idle_close_secs: 300,
        auto_accept: true,
        no_confirm: false,
        trust_usb: false,
        require_usb_confirm: false,
        low_power: false,
        no_low_power: false,
        ping_timeout_secs: 20,
        max_in_flight: MaxInFlight::Fixed(4),
        sentry_dsn: None,
        sentry_env: "test".to_string(),
        proxy: None,
        use_system_proxy: false,
        web: false,
        web_bind: "127.0.0.1:0".to_string(),
        web_admin_token: None,
        web_view_token: None,
        web_width: 1280,
        web_height: 720,
        web_fps: 30,
        web_bitrate_mbps: 16,
        web_hidpi: 1,
        web_max_pixel_edge: 0,
        web_independent_screen: false,
        web_screen_mode: None,
        web_require_approval: false,
        no_web_require_approval: false,
        qr: false,
        debug: false,
        debug_log: None,
        mock: true,
    }
}

fn make_handshake_packet(uid: &str, name: &str, w: i64, h: i64, proto: &str) -> Vec<u8> {
    let mut dict = BTreeMap::new();
    dict.insert(
        "uniqueIdentifier".to_string(),
        ArchivedValue::String(uid.to_string()),
    );
    dict.insert("name".to_string(), ArchivedValue::String(name.to_string()));
    dict.insert(
        "model".to_string(),
        ArchivedValue::String("iPad".to_string()),
    );
    dict.insert(
        "systemVersion".to_string(),
        ArchivedValue::String("12.5.8".to_string()),
    );
    dict.insert(
        "clientVersion".to_string(),
        ArchivedValue::String("6.2.0".to_string()),
    );
    dict.insert(
        "clientDataProtocolVersionKey".to_string(),
        ArchivedValue::String(proto.to_string()),
    );
    dict.insert("screenWidth".to_string(), ArchivedValue::Int(w));
    dict.insert("screenHeight".to_string(), ArchivedValue::Int(h));
    dict.insert(
        "clientOrientationKey".to_string(),
        ArchivedValue::Int(if w > h { 1 } else { 0 }),
    );
    dict.insert(
        "MSMClientTelemetryCursorSupportedKey".to_string(),
        ArchivedValue::Bool(proto != "1.0"),
    );
    MessagePacket::new_send("Handshake", ArchivedValue::Dict(dict))
        .encode()
        .unwrap()
}

fn make_touch_bplist(phase: i64, subtype: i64, x: f64, y: f64) -> Vec<u8> {
    let mut t_fields = BTreeMap::new();
    t_fields.insert("_phase".to_string(), ArchivedValue::Int(phase));
    t_fields.insert("_tapCount".to_string(), ArchivedValue::Int(1));
    t_fields.insert("_location.x".to_string(), ArchivedValue::Real(x));
    t_fields.insert("_location.y".to_string(), ArchivedValue::Real(y));
    let touch = ArchivedValue::Object {
        class_name: "MSMTouch".to_string(),
        classes: vec!["MSMTouch".to_string(), "NSObject".to_string()],
        fields: t_fields,
    };
    let mut fields = BTreeMap::new();
    fields.insert("_subtype".to_string(), ArchivedValue::Int(subtype));
    fields.insert("_allTouches".to_string(), ArchivedValue::Set(vec![touch]));
    archive(&ArchivedValue::Object {
        class_name: "MSMTouchEvent".to_string(),
        classes: vec!["MSMTouchEvent".to_string(), "NSObject".to_string()],
        fields,
    })
    .unwrap()
}

fn make_keyboard_bplist(value: ArchivedValue, special: i64, modifiers: i64) -> Vec<u8> {
    let mut fields = BTreeMap::new();
    fields.insert("value".to_string(), value);
    fields.insert("specialValue".to_string(), ArchivedValue::Int(special));
    if modifiers != 0 {
        fields.insert("modifiers".to_string(), ArchivedValue::Int(modifiers));
    }
    archive(&ArchivedValue::Object {
        class_name: "MSMKeyboardEvent".to_string(),
        classes: vec!["MSMKeyboardEvent".to_string(), "NSObject".to_string()],
        fields,
    })
    .unwrap()
}

fn http_req(
    addr: SocketAddr,
    method: &str,
    path: &str,
    extra_headers: &str,
    body: Option<&str>,
) -> (u16, String, String) {
    // Windows Winsock rejects `connect(0.0.0.0:port)` with WSAEADDRNOTAVAIL (10049); normalize
    // unspecified wildcard listener addresses to loopback before connecting.
    let connect_addr = if addr.ip().is_unspecified() {
        SocketAddr::new(
            if addr.is_ipv6() {
                std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
            } else {
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
            },
            addr.port(),
        )
    } else {
        addr
    };
    let mut s = TcpStream::connect_timeout(&connect_addr, Duration::from_secs(2)).unwrap();
    let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
    let _ = s.set_write_timeout(Some(Duration::from_secs(2)));
    let b = body.unwrap_or("");
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {connect_addr}\r\nOrigin: http://{connect_addr}\r\n{extra_headers}Content-Length: {}\r\nConnection: close\r\n\r\n{b}",
        b.len()
    );
    s.write_all(req.as_bytes()).unwrap();
    let mut resp = Vec::new();
    let _ = s.read_to_end(&mut resp);
    let txt = String::from_utf8_lossy(&resp).to_string();
    let (head, rest) = txt.split_once("\r\n\r\n").unwrap_or((&txt, ""));
    let code = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .unwrap_or(0);
    (code, head.to_string(), rest.to_string())
}

fn extract_set_cookie(headers: &str) -> String {
    for line in headers.lines() {
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("set-cookie:") {
            let start = line.len() - rest.len();
            let raw = line[start..].trim();
            if let Some((kv, _)) = raw.split_once(';') {
                return kv.trim().to_string();
            }
            return raw.to_string();
        }
    }
    String::new()
}

fn send_ws_masked_frame(s: &mut TcpStream, opcode: u8, payload: &[u8]) -> std::io::Result<()> {
    let mask = [0x12u8, 0x34, 0x56, 0x78];
    let mut hdr = Vec::with_capacity(14 + payload.len());
    hdr.push(0x80 | (opcode & 0x0F));
    if payload.len() < 126 {
        hdr.push(0x80 | (payload.len() as u8));
    } else {
        hdr.push(0x80 | 126);
        hdr.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    }
    hdr.extend_from_slice(&mask);
    for (i, &b) in payload.iter().enumerate() {
        hdr.push(b ^ mask[i & 3]);
    }
    s.write_all(&hdr)
}

fn read_ws_frame(s: &mut TcpStream) -> std::io::Result<(u8, Vec<u8>)> {
    let mut h2 = [0u8; 2];
    s.read_exact(&mut h2)?;
    let opcode = h2[0] & 0x0F;
    let masked = (h2[1] & 0x80) != 0;
    let mut len = (h2[1] & 0x7F) as usize;
    if len == 126 {
        let mut b = [0u8; 2];
        s.read_exact(&mut b)?;
        len = u16::from_be_bytes(b) as usize;
    } else if len == 127 {
        let mut b = [0u8; 8];
        s.read_exact(&mut b)?;
        len = u64::from_be_bytes(b) as usize;
    }
    let mut mask = [0u8; 4];
    if masked {
        s.read_exact(&mut mask)?;
    }
    let mut payload = vec![0u8; len];
    s.read_exact(&mut payload)?;
    if masked {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask[i & 3];
        }
    }
    Ok((opcode, payload))
}

fn connect_ws_viewer(addr: SocketAddr, cookie: Option<&str>) -> TcpStream {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap();
    let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
    let _ = s.set_write_timeout(Some(Duration::from_secs(2)));
    let c_hdr = cookie
        .map(|c| format!("Cookie: {c}\r\n"))
        .unwrap_or_default();
    let req = format!(
        "GET /ws/stream HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n{c_hdr}\r\n"
    );
    s.write_all(req.as_bytes()).unwrap();
    let mut resp = Vec::new();
    let mut byte = [0u8; 1];
    while !resp.ends_with(b"\r\n\r\n") {
        s.read_exact(&mut byte).unwrap();
        resp.push(byte[0]);
        assert!(resp.len() < 4096, "WS upgrade response too large");
    }
    let head = String::from_utf8_lossy(&resp);
    assert!(
        head.starts_with("HTTP/1.1 101"),
        "expected 101 Switching Protocols, got: {head}"
    );
    s
}

// ============================================================================
// Iteration 1 Test 1: Legacy iPad v6.2.0 Compatibility Polish & Safety Oracles
// ============================================================================
#[test]
fn chaos_legacy_ipad_input_cursor_orientation_and_stuck_mouse_safety() {
    let _wd = DeadlockWatchdog::arm(
        "chaos_legacy_ipad_input_cursor_orientation_and_stuck_mouse_safety",
        Duration::from_secs(12),
    );

    // 1) Keyboard decoding: Apple PUA arrows/nav, modifiers (Cmd+C, Shift+Up), multi-char QuickType & emoji.
    let up_ev = decode_input_event(&make_keyboard_bplist(
        ArchivedValue::Int(0xF700),
        0,
        0,
    ))
    .unwrap();
    assert_eq!(up_ev, Some(InputEvent::KeySpecial { key_code: 0x7E }));

    let shift_left = decode_input_event(&make_keyboard_bplist(
        ArchivedValue::Int(0xF702),
        0,
        1 << 17, // UIKeyModifierShift
    ))
    .unwrap();
    assert_eq!(
        shift_left,
        Some(InputEvent::KeyModified {
            key_code: Some(0x7B),
            ch: None,
            modifiers: KEY_MOD_SHIFT,
        })
    );

    let cmd_c = decode_input_event(&make_keyboard_bplist(
        ArchivedValue::String("c".to_string()),
        0,
        1 << 20, // UIKeyModifierCommand
    ))
    .unwrap();
    assert_eq!(
        cmd_c,
        Some(InputEvent::KeyModified {
            key_code: None,
            ch: Some(b'c' as u16),
            modifiers: KEY_MOD_META,
        })
    );

    let ctrl_shift_a = decode_input_event(&make_keyboard_bplist(
        ArchivedValue::String("a".to_string()),
        0,
        (1 << 18) | (1 << 17),
    ))
    .unwrap();
    assert_eq!(
        ctrl_shift_a,
        Some(InputEvent::KeyModified {
            key_code: None,
            ch: Some(b'a' as u16),
            modifiers: KEY_MOD_CTRL | KEY_MOD_SHIFT,
        })
    );

    let quicktype = decode_input_event(&make_keyboard_bplist(
        ArchivedValue::String("你好😀".to_string()),
        0,
        0,
    ))
    .unwrap();
    assert_eq!(
        quicktype,
        Some(InputEvent::KeyText {
            text: "你好😀".to_string()
        })
    );

    // 2) Live Wi-Fi session: right-click tail suppression, stuck mouse-up release on RST / view-only / lock,
    //    coalesced trailing truncation prefix preservation, FaceUp(5)/FaceDown(6) & 180° orientation no-op,
    //    and cursor PNG suppression when supports_tel_cursor == false.
    let mut cfg = base_config();
    cfg.client_cursor = true;
    cfg.on_lock_ipad = Some(LockAction::Pause);
    cfg.on_lock_delay_secs = 0;

    let mock = Arc::new(MockBackend::new());
    mock.manual_frame_mode.store(true, Ordering::Release);
    *mock.cursor_png.lock().unwrap() = Some(vec![0x89, b'P', b'N', b'G', 1, 2, 3, 4]);
    let registry = Arc::new(SessionRegistry::new(cfg.clone(), mock.clone()));
    let stop = Arc::new(AtomicBool::new(false));
    let mut wifi = start_wifi_server(cfg, mock.clone(), registry.clone(), stop.clone()).unwrap();

    // Connect Telemetry with proto "1.0" (supports_tel_cursor == false) to verify ChangeCursorImage is gated!
    let mut tel = TcpStream::connect(wifi.telemetry_addr).unwrap();
    let _ = tel.set_read_timeout(Some(Duration::from_secs(2)));
    let hs_pkt = make_handshake_packet("ipad-legacy-1", "iPad Air 1", 1024, 768, "1.0");
    write_canal_block(&mut tel, &hs_pkt).unwrap();
    let _ = read_canal_block(&mut tel).unwrap(); // AccessConfirmed
    let mut data = TcpStream::connect(wifi.data_addr).unwrap();
    let _ = data.set_read_timeout(Some(Duration::from_secs(2)));

    wait_until(
        Duration::from_secs(2),
        || !mock.frame_senders.lock().unwrap().is_empty(),
        "capture started for legacy iPad",
    );

    // Push a frame so cursor thread runs a few ticks; verify NO ChangeCursorImage arrives on proto "1.0".
    let _ = mock.push_frame(EncodedFrame {
        width: 1024,
        height: 768,
        bytes_per_row: 1024 * 4,
        annex_b: SYNTHETIC_H264_ANNEX_B.to_vec(),
        is_keyframe: true,
    });
    let _ = tel.set_read_timeout(Some(Duration::from_millis(150)));
    while let Ok(Some(raw)) = read_canal_block(&mut tel) {
        if let Ok(pkt) = MessagePacket::decode(&raw) {
            assert!(
                !matches!(
                    pkt.name_method.as_str(),
                    "ChangeCursorImage" | "ChangeCursorPosition" | "ChangeCursorVisible"
                ),
                "proto 1.0 (supports_tel_cursor=false) must NOT receive cursor packet over Telemetry, got {}",
                pkt.name_method
            );
        }
    }
    let _ = tel.set_read_timeout(Some(Duration::from_secs(2)));

    // 2a) Right-click tail suppression across all OSes: RightClick Down -> Drag -> Up should inject ONLY MouseDown(right_click=true).
    write_canal_block(&mut data, &make_touch_bplist(0, 1, 50.0, 60.0)).unwrap();
    write_canal_block(&mut data, &make_touch_bplist(1, 0, 51.0, 61.0)).unwrap();
    write_canal_block(&mut data, &make_touch_bplist(3, 0, 51.0, 61.0)).unwrap();
    // 2b) Coalesced batch with valid leading MouseDown + truncated trailing chunk must preserve leading event!
    let valid_down = make_touch_bplist(0, 0, 120.0, 240.0);
    let mut coalesced = Vec::new();
    coalesced.extend_from_slice(&(valid_down.len() as u32).to_le_bytes());
    coalesced.extend_from_slice(&valid_down);
    coalesced.extend_from_slice(&500u32.to_le_bytes()); // truncated trailing chunk
    coalesced.extend_from_slice(b"bplist00trunc");
    write_canal_block(&mut data, &coalesced).unwrap();

    wait_until(
        Duration::from_secs(2),
        || mock.recorded_inputs.lock().unwrap().len() >= 2,
        "right-click + coalesced leading left MouseDown injected",
    );
    {
        let inputs = mock.recorded_inputs.lock().unwrap();
        assert_eq!(inputs.len(), 2, "right-click tail Drag/Up must be suppressed: {inputs:?}");
        assert!(matches!(
            inputs[0],
            InputEvent::MouseDown {
                right_click: true,
                ..
            }
        ));
        assert!(matches!(
            inputs[1],
            InputEvent::MouseDown {
                x,
                y,
                right_click: false,
                ..
            } if (x - 120.0).abs() < 0.1 && (y - 240.0).abs() < 0.1
        ));
    }

    // 2c) Toggling view-only (allow_input=false) mid-drag MUST synthesize safety MouseUp at (120, 240)!
    registry.set_input_allowed(false);
    wait_until(
        Duration::from_secs(1),
        || {
            mock.recorded_inputs.lock().unwrap().iter().any(|e| {
                matches!(e, InputEvent::MouseUp { x, y, double_click: false } if (*x - 120.0).abs() < 0.1 && (*y - 240.0).abs() < 0.1)
            })
        },
        "view-only toggle mid-drag must synthesize safety MouseUp",
    );

    // 2d) Re-enable input, start drag at (300, 400), then trigger Host Lock (Pause) -> MUST synthesize MouseUp!
    registry.set_input_allowed(true);
    mock.recorded_inputs.lock().unwrap().clear();
    write_canal_block(&mut data, &make_touch_bplist(0, 0, 300.0, 400.0)).unwrap();
    wait_until(
        Duration::from_secs(1),
        || mock.recorded_inputs.lock().unwrap().len() == 1,
        "left MouseDown before lock",
    );
    registry.on_host_screen_lock_changed(true);
    wait_until(
        Duration::from_secs(1),
        || {
            mock.recorded_inputs.lock().unwrap().iter().any(|e| {
                matches!(e, InputEvent::MouseUp { x, y, double_click: false } if (*x - 300.0).abs() < 0.1 && (*y - 400.0).abs() < 0.1)
            })
        },
        "host lock pause mid-drag must synthesize safety MouseUp",
    );
    registry.on_host_screen_lock_changed(false);

    // 2e) OrientationChange: FaceUp(5), FaceDown(6), and 180° landscape flip (1 -> 3) must trigger 0 reconfigures!
    mock.recorded_reconfigures.lock().unwrap().clear();
    for ori in [5i64, 6, -1, 3] {
        let pkt = MessagePacket::new_send("OrientationChange", ArchivedValue::Int(ori))
            .encode()
            .unwrap();
        write_canal_block(&mut tel, &pkt).unwrap();
    }
    // Now rotate to Portrait (2) -> MUST trigger exactly 1 reconfigure!
    let port_pkt = MessagePacket::new_send("OrientationChange", ArchivedValue::Int(2))
        .encode()
        .unwrap();
    write_canal_block(&mut tel, &port_pkt).unwrap();
    wait_until(
        Duration::from_secs(2),
        || !mock.recorded_reconfigures.lock().unwrap().is_empty(),
        "real portrait OrientationChange(2) reconfigures display",
    );
    assert_eq!(
        mock.recorded_reconfigures.lock().unwrap().len(),
        1,
        "FaceUp(5)/FaceDown(6)/180-flip(3) must not cause spurious display reconfigures"
    );

    // 2f) Start drag at (410, 520), then brutally RST Data channel -> MUST synthesize MouseUp!
    //     AND immediately reconnecting Telemetry while old Telemetry is still open (data closed) must succeed (no 3s lockout)!
    mock.recorded_inputs.lock().unwrap().clear();
    write_canal_block(&mut data, &make_touch_bplist(0, 0, 410.0, 520.0)).unwrap();
    wait_until(
        Duration::from_secs(1),
        || mock.recorded_inputs.lock().unwrap().len() == 1,
        "left MouseDown before brutal Data RST",
    );
    force_tcp_rst(data);
    wait_until(
        Duration::from_secs(2),
        || {
            mock.recorded_inputs.lock().unwrap().iter().any(|e| {
                matches!(e, InputEvent::MouseUp { x, y, double_click: false } if (*x - 410.0).abs() < 0.1 && (*y - 520.0).abs() < 0.1)
            })
        },
        "brutal Data RST mid-drag must synthesize safety MouseUp",
    );

    // Instant same-IP Telemetry reconnect while old Telemetry is still held open (half-open scenario):
    let mut tel2 = TcpStream::connect(wifi.telemetry_addr).unwrap();
    let _ = tel2.set_read_timeout(Some(Duration::from_secs(2)));
    write_canal_block(&mut tel2, &hs_pkt).unwrap();
    let resp = read_canal_block(&mut tel2)
        .expect("reconnect after Data RST must succeed immediately without 3s lockout");
    assert!(resp.is_some(), "expected AccessConfirmed on reconnect");

    force_tcp_rst(tel);
    force_tcp_rst(tel2);
    wait_until(
        Duration::from_secs(2),
        || registry.active_session_count() == 0 && mock.live_virtual_display_ids().is_empty(),
        "clean session & VD teardown after RST",
    );
    stop.store(true, Ordering::SeqCst);
    wifi.stop();
}

// ============================================================================
// Iteration 1 Test 2: Trailing-Byte FIN/RST Ghost-Approval & Ghost-Trust Killer
// (Directly targets Role B P0 #1 & P0 #2!)
// ============================================================================
#[test]
fn chaos_trailing_byte_rst_and_fin_ghost_approval_and_trust_killer() {
    let _wd = DeadlockWatchdog::arm(
        "chaos_trailing_byte_rst_and_fin_ghost_approval_and_trust_killer",
        Duration::from_secs(15),
    );
    let mut cfg = base_config();
    cfg.auto_accept = false;
    cfg.web_require_approval = true;
    cfg.max_web_viewers = 4;

    let mock = Arc::new(MockBackend::new());
    let registry = Arc::new(SessionRegistry::new(cfg.clone(), mock.clone()));
    let stop = Arc::new(AtomicBool::new(false));
    let mut wifi = start_wifi_server(cfg, mock.clone(), registry.clone(), stop.clone()).unwrap();
    let mut web = start_web_server(
        "127.0.0.1:0",
        None,
        Some("123456".to_string()),
        registry.clone(),
        LogBuffer::new(),
        stop.clone(),
    )
    .unwrap();
    let admin_addr = web.addr;
    let viewer_addr = web.viewer_addr().expect("viewer listener active");

    // Authenticate viewer cookie
    let (code, hdrs, _) = http_req(
        viewer_addr,
        "POST",
        "/api/view/login",
        "Content-Type: application/json\r\n",
        Some(r#"{"token":"123456"}"#),
    );
    assert_eq!(code, 200);
    let v_cookie = extract_set_cookie(&hdrs);
    assert!(!v_cookie.is_empty());

    // Phase A: Web `/api/view/request-approval` with 1 trailing unread byte `X` + FIN, then + SO_LINGER(0) RST!
    for use_rst in [false, true] {
        let mut s = TcpStream::connect(viewer_addr).unwrap();
        let req = format!(
            "POST /api/view/request-approval HTTP/1.1\r\nHost: {viewer_addr}\r\nOrigin: http://{viewer_addr}\r\nUser-Agent: TrailingByteBot/{use_rst}\r\nCookie: {v_cookie}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}X"
        );
        s.write_all(req.as_bytes()).unwrap();
        // Wait until slot actually appears in pending_approvals
        wait_until(
            Duration::from_secs(2),
            || {
                let (_, _, body) = http_req(admin_addr, "GET", "/api/admin/state", "", None);
                serde_json::from_str::<serde_json::Value>(&body)
                    .ok()
                    .and_then(|v| v["pending_approvals"].as_array().map(|a| !a.is_empty()))
                    .unwrap_or(false)
            },
            "web pending approval appeared",
        );
        if use_rst {
            force_tcp_rst(s);
        } else {
            let _ = s.shutdown(Shutdown::Both);
            drop(s);
        }
        // Must self-evict within <= 1.2s (NOT linger 60s due to unread trailing byte 'X'!).
        wait_until(
            Duration::from_millis(1200),
            || {
                let (_, _, body) = http_req(admin_addr, "GET", "/api/admin/state", "", None);
                serde_json::from_str::<serde_json::Value>(&body)
                    .ok()
                    .and_then(|v| v["pending_approvals"].as_array().map(|a| a.is_empty()))
                    .unwrap_or(false)
            },
            &format!("web trailing-byte closed peer (rst={use_rst}) must evict pending approval promptly"),
        );
    }

    // Phase B: Untrusted Wi-Fi iPad sends [Handshake][trailing byte 'X'] then RST/FIN WITHOUT main-loop reaper ticking!
    for use_rst in [false, true] {
        let mut tel = TcpStream::connect(wifi.telemetry_addr).unwrap();
        let hs = make_handshake_packet(
            &format!("ghost-ipad-{use_rst}"),
            "GhostPad",
            1024,
            768,
            "1.2",
        );
        write_canal_block(&mut tel, &hs).unwrap();
        tel.write_all(b"X").unwrap(); // 1 unread trailing byte in kernel recv queue!
        wait_until(
            Duration::from_secs(2),
            || {
                let (_, _, body) = http_req(admin_addr, "GET", "/api/admin/state", "", None);
                body.contains("GhostPad")
            },
            "wifi pending approval appeared",
        );
        if use_rst {
            force_tcp_rst(tel);
        } else {
            let _ = tel.shutdown(Shutdown::Both);
            drop(tel);
        }
        // Must self-evict within <= 1.2s even when main-loop reaper is NOT ticked!
        wait_until(
            Duration::from_millis(1200),
            || {
                let (_, _, body) = http_req(admin_addr, "GET", "/api/admin/state", "", None);
                !body.contains("GhostPad")
            },
            &format!("wifi trailing-byte closed peer (rst={use_rst}) must evict pending approval promptly"),
        );
    }

    assert!(
        registry.trust_store().list().is_empty(),
        "dead trailing-byte peers must NEVER persist ghost trust"
    );
    wait_until(
        Duration::from_secs(2),
        || registry.active_session_count() == 0 && mock.live_virtual_display_ids().is_empty(),
        "zero zombie sessions or ghost virtual displays",
    );

    stop.store(true, Ordering::SeqCst);
    web.stop();
    wifi.stop();
}

// ============================================================================
// Iteration 1 Test 3: Seeded Brutal SO_LINGER(0) RST Storm Across Wi-Fi & Web
// ============================================================================
#[test]
fn chaos_wifi_and_web_brutal_rst_storm_slot_and_display_recovery() {
    let _wd = DeadlockWatchdog::arm(
        "chaos_wifi_and_web_brutal_rst_storm_slot_and_display_recovery",
        Duration::from_secs(15),
    );
    let mut cfg = base_config();
    cfg.auto_accept = true;
    cfg.max_extended_screens = 2;
    cfg.max_web_viewers = 4;
    cfg.web_screen_mode = Some(WebScreenMode::Independent);

    let mock = Arc::new(MockBackend::new());
    mock.manual_frame_mode.store(true, Ordering::Release);
    let registry = Arc::new(SessionRegistry::new(cfg.clone(), mock.clone()));
    let stop = Arc::new(AtomicBool::new(false));
    let mut wifi = start_wifi_server(cfg, mock.clone(), registry.clone(), stop.clone()).unwrap();
    let mut web = start_web_server(
        "127.0.0.1:0",
        None,
        Some("998877".to_string()),
        registry.clone(),
        LogBuffer::new(),
        stop.clone(),
    )
    .unwrap();
    let admin_addr = web.addr;
    let viewer_addr = web.viewer_addr().expect("viewer listener");

    let seeds = fuzz_seeds(0xC4A0_5001, 16);
    for (idx, seed) in seeds.iter().enumerate() {
        let mut rng = FuzzRng::new(*seed);
        // 1) Wi-Fi Telemetry brutal cut at randomized protocol boundary
        if let Ok(mut s) = TcpStream::connect_timeout(&wifi.telemetry_addr, Duration::from_secs(1)) {
            match rng.next_usize(5) {
                0 => {} // 0-byte immediate RST
                1 => {
                    let _ = s.write_all(&[0x10, 0x00]); // partial 2-byte length prefix
                }
                2 => {
                    let _ = s.write_all(&u32::MAX.to_le_bytes()); // oversized preauth frame length
                }
                3 => {
                    let mut bad = vec![0x20, 0, 0, 0];
                    bad.extend_from_slice(&rng.bytes(12)); // truncated mid-bplist
                    let _ = s.write_all(&bad);
                }
                _ => {
                    let hs = make_handshake_packet(
                        &format!("storm-{idx}"),
                        "StormPad",
                        1024,
                        768,
                        "1.2",
                    );
                    let _ = write_canal_block(&mut s, &hs);
                }
            }
            if rng.next_bool() {
                force_tcp_rst(s);
            } else {
                let _ = s.shutdown(Shutdown::Write);
                drop(s);
            }
        }
        // 2) Wi-Fi Data brutal cut
        if let Ok(mut d) = TcpStream::connect_timeout(&wifi.data_addr, Duration::from_secs(1)) {
            if rng.next_bool() {
                let n = 1 + rng.next_usize(32);
                let _ = d.write_all(&rng.bytes(n));
            }
            force_tcp_rst(d);
        }
        // 3) Web Admin / Viewer HTTP + WS mid-upgrade RST
        let target = if rng.next_bool() { admin_addr } else { viewer_addr };
        if let Ok(mut w) = TcpStream::connect_timeout(&target, Duration::from_secs(1)) {
            match rng.next_usize(4) {
                0 => {}
                1 => {
                    let _ = w.write_all(b"GET /api/admin/st");
                }
                2 => {
                    let _ = w.write_all(
                        b"POST /api/view/login HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 500\r\n\r\n{\"tok",
                    );
                }
                _ => {
                    let _ = w.write_all(
                        b"GET /ws/stream HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
                    );
                }
            }
            force_tcp_rst(w);
        }
    }

    // Also test read_canal_block_limited_deadline(120ms) on a real loopback Slowloris peer
    {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).unwrap();
        let (mut server, _) = l.accept().unwrap();
        let _ = server.set_read_timeout(Some(Duration::from_millis(50)));
        client.write_all(&[0x20, 0x00, 0x00, 0x00, b'b']).unwrap();
        let t0 = Instant::now();
        let res = read_canal_block_limited_deadline(
            &mut server,
            1024,
            Instant::now() + Duration::from_millis(120),
        );
        assert!(res.is_err(), "Slowloris partial Canal block must fail by deadline");
        assert!(
            t0.elapsed() < Duration::from_millis(800),
            "Slowloris deadline took too long: {:?}",
            t0.elapsed()
        );
        force_tcp_rst(client);
    }

    // Reap any post-handshake no-data sessions from the storm and verify zero leaks
    registry.reap_timed_out_with_limit(Duration::from_millis(1));
    wait_until(
        Duration::from_secs(2),
        || {
            registry.active_session_count() == 0
                && registry.active_extended_screens() == 0
                && registry.active_web_viewers() == 0
                && mock.live_virtual_display_ids().is_empty()
        },
        "all storm sessions, viewers, and virtual displays cleaned up",
    );

    // Golden check: both Wi-Fi & Web must still accept clean connections with zero wedged worker slots!
    let (code, _, body) = http_req(admin_addr, "GET", "/api/admin/state", "", None);
    assert_eq!(code, 200, "admin API must stay healthy after RST storm: {body}");

    let mut tel = TcpStream::connect(wifi.telemetry_addr).unwrap();
    let _ = tel.set_read_timeout(Some(Duration::from_secs(2)));
    write_canal_block(&mut tel, &make_handshake_packet("golden-uid", "GoldenPad", 1024, 768, "1.2")).unwrap();
    assert!(read_canal_block(&mut tel).unwrap().is_some());
    let mut data = TcpStream::connect(wifi.data_addr).unwrap();
    let _ = data.set_read_timeout(Some(Duration::from_secs(2)));
    wait_until(
        Duration::from_secs(2),
        || !mock.live_virtual_display_ids().is_empty(),
        "golden Wi-Fi virtual display created",
    );
    let _ = mock.push_frame(EncodedFrame {
        width: 1024,
        height: 768,
        bytes_per_row: 1024 * 4,
        annex_b: SYNTHETIC_H264_ANNEX_B.to_vec(),
        is_keyframe: true,
    });
    assert!(
        read_canal_block(&mut data).unwrap().is_some(),
        "golden Wi-Fi Data channel must receive H.264 frame"
    );
    force_tcp_rst(data);
    force_tcp_rst(tel);

    let (v_code, v_hdrs, _) = http_req(
        viewer_addr,
        "POST",
        "/api/view/login",
        "Content-Type: application/json\r\n",
        Some(r#"{"token":"998877"}"#),
    );
    assert_eq!(v_code, 200);
    let v_cookie = extract_set_cookie(&v_hdrs);
    let mut ws = connect_ws_viewer(viewer_addr, Some(&v_cookie));
    wait_until(
        Duration::from_secs(2),
        || registry.active_web_viewers() == 1,
        "golden WS viewer connected",
    );
    let _ = mock.push_frame(EncodedFrame {
        width: 1280,
        height: 720,
        bytes_per_row: 1280 * 4,
        annex_b: SYNTHETIC_H264_ANNEX_B.to_vec(),
        is_keyframe: true,
    });
    let (op, _) = read_ws_frame(&mut ws).unwrap();
    assert!(op == 1 || op == 2, "expected init/media WS frame, got op={op}");
    force_tcp_rst(ws);

    wait_until(
        Duration::from_secs(2),
        || {
            registry.active_session_count() == 0
                && registry.active_web_viewers() == 0
                && mock.live_virtual_display_ids().is_empty()
        },
        "final golden cleanup",
    );
    stop.store(true, Ordering::SeqCst);
    web.stop();
    wifi.stop();
}

// ============================================================================
// Iteration 1 Test 4: TcpCanalWriter Slow-Reader Desync Guard, Lock-Free Close,
//                     and Asymmetric Data-RST Reattach Torture
// ============================================================================
#[test]
fn chaos_asymmetric_channel_split_and_tcp_canal_writer_lockfree_close() {
    let _wd = DeadlockWatchdog::arm(
        "chaos_asymmetric_channel_split_and_tcp_canal_writer_lockfree_close",
        Duration::from_secs(12),
    );

    // Part A: Direct TcpCanalWriter slow-reader timeout closes socket immediately + concurrent lock-free close()
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let reader = TcpStream::connect(addr).unwrap();
        shrink_rcvbuf(&reader, 4096);
        let (server, _) = listener.accept().unwrap();
        shrink_sndbuf(&server, 4096);
        server
            .set_write_timeout(Some(Duration::from_millis(150)))
            .unwrap();
        let writer = Arc::new(TcpCanalWriter::new(server));
        let big = vec![0xABu8; 256 * 1024];

        let t0 = Instant::now();
        let mut timed_out = false;
        for _ in 0..32 {
            if writer.send_frame(&big).is_err() {
                timed_out = true;
                break;
            }
        }
        assert!(timed_out, "stalled reader must trigger write timeout");
        assert!(
            t0.elapsed() < Duration::from_secs(2),
            "timeout took too long: {:?}",
            t0.elapsed()
        );
        // Subsequent write MUST fail immediately (socket was shutdown to prevent frame desync).
        assert!(
            writer.send_frame(b"tiny").is_err(),
            "post-timeout TcpCanalWriter must reject further frames to prevent stream desync"
        );
        drop(reader);
    }

    // Part B: Lock-free writer.close() unblocks a thread wedged in send_frame_parts (< 500ms)
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let reader = TcpStream::connect(addr).unwrap();
        shrink_rcvbuf(&reader, 4096);
        let (server, _) = listener.accept().unwrap();
        shrink_sndbuf(&server, 4096);
        server
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let writer = Arc::new(TcpCanalWriter::new(server));
        let w2 = writer.clone();
        let blocked = Arc::new(AtomicBool::new(false));
        let b2 = blocked.clone();
        let handle = thread::spawn(move || {
            let big = vec![0xCDu8; 256 * 1024];
            let hdr = [0u8; 16];
            for _ in 0..64 {
                b2.store(true, Ordering::Release);
                if w2.send_frame_parts(&[&hdr, &big]).is_err() {
                    return;
                }
            }
        });
        wait_until(
            Duration::from_secs(1),
            || blocked.load(Ordering::Acquire),
            "writer thread started",
        );
        thread::sleep(Duration::from_millis(60));
        let t0 = Instant::now();
        writer.close();
        handle.join().unwrap();
        assert!(
            t0.elapsed() < Duration::from_millis(800),
            "lock-free close() must unblock wedged send_frame_parts promptly, took {:?}",
            t0.elapsed()
        );
        drop(reader);
    }

    // Part C: is_tcp_peer_closed detects FIN, RST, AND FIN/RST with unread trailing byte!
    for (with_trailing, use_rst) in [(false, false), (false, true), (true, false), (true, true)] {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let mut c = TcpStream::connect(addr).unwrap();
        let (s, _) = l.accept().unwrap();
        assert!(!is_tcp_peer_closed(&s));
        if with_trailing {
            c.write_all(b"Z").unwrap();
        }
        if use_rst {
            force_tcp_rst(c);
        } else {
            let _ = c.shutdown(Shutdown::Both);
            drop(c);
        }
        wait_until(
            Duration::from_millis(500),
            || is_tcp_peer_closed(&s),
            &format!(
                "is_tcp_peer_closed must detect peer close (trailing={with_trailing}, rst={use_rst})"
            ),
        );
    }

    // Part D: Live asymmetric Data RST + 8x rapid reattach on same Telemetry -> 0 ghost virtual displays
    let cfg = base_config();
    let mock = Arc::new(MockBackend::new());
    mock.manual_frame_mode.store(true, Ordering::Release);
    let registry = Arc::new(SessionRegistry::new(cfg.clone(), mock.clone()));
    let stop = Arc::new(AtomicBool::new(false));
    let mut wifi = start_wifi_server(cfg, mock.clone(), registry.clone(), stop.clone()).unwrap();

    let mut tel = TcpStream::connect(wifi.telemetry_addr).unwrap();
    let _ = tel.set_read_timeout(Some(Duration::from_secs(2)));
    write_canal_block(&mut tel, &make_handshake_packet("asym-uid", "AsymPad", 1024, 768, "1.2")).unwrap();
    assert!(read_canal_block(&mut tel).unwrap().is_some());

    let big_nal = vec![0x55u8; 64 * 1024];
    for cycle in 0..8 {
        let data = TcpStream::connect(wifi.data_addr).unwrap();
        shrink_rcvbuf(&data, 4096);
        wait_until(
            Duration::from_secs(2),
            || mock.live_virtual_display_ids().len() == 1,
            &format!("VD active on reattach cycle {cycle}"),
        );
        let mut frame_bytes = SYNTHETIC_H264_ANNEX_B.to_vec();
        frame_bytes.extend_from_slice(&big_nal);
        for _ in 0..3 {
            let _ = mock.push_frame(EncodedFrame {
                width: 1024,
                height: 768,
                bytes_per_row: 1024 * 4,
                annex_b: frame_bytes.clone(),
                is_keyframe: true,
            });
        }
        force_tcp_rst(data);
        wait_until(
            Duration::from_secs(2),
            || mock.live_virtual_display_ids().is_empty(),
            &format!("VD destroyed promptly after Data RST cycle {cycle}"),
        );
    }

    force_tcp_rst(tel);
    wait_until(
        Duration::from_secs(2),
        || registry.active_session_count() == 0 && mock.live_virtual_display_ids().is_empty(),
        "asymmetric teardown complete",
    );
    stop.store(true, Ordering::SeqCst);
    wifi.stop();
}

// ============================================================================
// Iteration 1 Test 5: USB PeerTalk Brutal Unplug & Pre-Auth Error Recovery
// ============================================================================
#[test]
fn chaos_usbmux_peertalk_brutal_unplug_and_preauth_error_recovery() {
    let _wd = DeadlockWatchdog::arm(
        "chaos_usbmux_peertalk_brutal_unplug_and_preauth_error_recovery",
        Duration::from_secs(12),
    );
    use idis::transport::usbmux::{serve_peertalk_stream, UsbmuxStream};

    let cfg = base_config();
    let mock = Arc::new(MockBackend::new());
    let registry = Arc::new(SessionRegistry::new(cfg, mock.clone()));

    for cycle in 0..10 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        let reg = registry.clone();
        let key = format!("usb:chaos-{cycle}");
        let srv_join = thread::spawn(move || {
            let _ = serve_peertalk_stream(UsbmuxStream::Tcp(server), key, reg);
        });

        match cycle % 3 {
            0 => {
                // Truncated 8-byte PeerTalk header + RST
                let _ = client.write_all(&[0, 0, 0, 1, 0, 0, 0, 100]);
                force_tcp_rst(client);
            }
            1 => {
                // Garbage pre-auth telemetry payload — server must break cleanly on pre-auth error!
                let _ = write_pt_frame(&mut client, PT_FRAME_TYPE_TELEMETRY, 1, b"not-a-bplist");
                // Keep socket briefly open to ensure server breaks on its own rather than looping!
                let t0 = Instant::now();
                srv_join.join().unwrap();
                assert!(
                    t0.elapsed() < Duration::from_secs(1),
                    "USB PeerTalk reader must break promptly on pre-auth telemetry error"
                );
                force_tcp_rst(client);
                continue;
            }
            _ => {
                // Full Handshake + Ping("START") + garbage data + brutal RST unplug
                let hs = make_handshake_packet(
                    &format!("usb-uid-{cycle}"),
                    "UsbPad",
                    1024,
                    768,
                    "1.2",
                );
                let _ = write_pt_frame(&mut client, PT_FRAME_TYPE_TELEMETRY, 1, &hs);
                let ping = MessagePacket::new_request(
                    "Ping",
                    ArchivedValue::String("START".to_string()),
                    5.0,
                )
                .encode()
                .unwrap();
                let _ = write_pt_frame(&mut client, PT_FRAME_TYPE_TELEMETRY, 2, &ping);
                let _ = write_pt_frame(&mut client, PT_FRAME_TYPE_DATA, 3, b"corrupt-touch");
                thread::sleep(Duration::from_millis(25));
                force_tcp_rst(client);
            }
        }
        srv_join.join().unwrap();
    }

    wait_until(
        Duration::from_secs(2),
        || {
            registry.active_session_count() == 0
                && registry.active_extended_screens() == 0
                && mock.live_virtual_display_ids().is_empty()
        },
        "zero USB zombie sessions or ghost virtual displays",
    );
}

// ============================================================================
// Iteration 1 Test 6: WebSocket Zero-Window Backpressure + Admin Kick + RST
// ============================================================================
#[test]
fn chaos_ws_mid_upgrade_and_zero_window_backpressure_kick_rst() {
    let _wd = DeadlockWatchdog::arm(
        "chaos_ws_mid_upgrade_and_zero_window_backpressure_kick_rst",
        Duration::from_secs(15),
    );
    let mut cfg = base_config();
    cfg.max_web_viewers = 4;
    cfg.web_screen_mode = Some(WebScreenMode::Independent);

    let mock = Arc::new(MockBackend::new());
    mock.manual_frame_mode.store(true, Ordering::Release);
    let registry = Arc::new(SessionRegistry::new(cfg, mock.clone()));
    let stop = Arc::new(AtomicBool::new(false));
    let mut web = start_web_server(
        "127.0.0.1:0",
        None,
        Some("776655".to_string()),
        registry.clone(),
        LogBuffer::new(),
        stop.clone(),
    )
    .unwrap();
    let viewer_addr = web.viewer_addr().expect("viewer listener active");
    let (v_code, v_hdrs, _) = http_req(
        viewer_addr,
        "POST",
        "/api/view/login",
        "Content-Type: application/json\r\n",
        Some(r#"{"token":"776655"}"#),
    );
    assert_eq!(v_code, 200);
    let v_cookie = extract_set_cookie(&v_hdrs);

    // 1) Connect one slow/blackholed viewer (tiny SO_RCVBUF, never reads!) + one healthy viewer.
    let mut slow_ws = connect_ws_viewer(viewer_addr, Some(&v_cookie));
    shrink_rcvbuf(&slow_ws, 4096);
    let mut healthy_ws = connect_ws_viewer(viewer_addr, Some(&v_cookie));

    wait_until(
        Duration::from_secs(2),
        || registry.active_web_viewers() == 2 && mock.live_virtual_display_ids().len() == 1,
        "both slow and healthy WS viewers subscribed",
    );

    // Push large frames so slow_ws saturates its kernel receive buffer while spamming Ping frames
    // to trigger shared_writer contention with reader_handle Pong!
    let mut big_idr = SYNTHETIC_H264_ANNEX_B.to_vec();
    big_idr.resize(192 * 1024, 0x33);
    for _ in 0..8 {
        let _ = mock.push_frame(EncodedFrame {
            width: 1280,
            height: 720,
            bytes_per_row: 1280 * 4,
            annex_b: big_idr.clone(),
            is_keyframe: true,
        });
        let _ = send_ws_masked_frame(&mut slow_ws, 0x9, b"ping");
        thread::sleep(Duration::from_millis(10));
    }

    // Verify healthy_ws is completely isolated (receives init + binary media frames promptly!)
    let mut healthy_binary = 0usize;
    let deadline = Instant::now() + Duration::from_secs(2);
    while healthy_binary < 2 && Instant::now() < deadline {
        match read_ws_frame(&mut healthy_ws) {
            Ok((2, payload)) if !payload.is_empty() => healthy_binary += 1,
            Ok(_) => {}
            Err(_) => break,
        }
    }
    assert!(
        healthy_binary >= 2,
        "healthy WS viewer must NOT be head-of-line blocked by slow/zero-window sibling (got {healthy_binary})"
    );

    // Kick all Web viewers via Admin registry API while slow_ws is still wedged in zero-window!
    // Must unblock the wedged writer thread and unregister from P2P hub in <= 1.5s BEFORE RST
    // (NOT stall 5-15s inside shared_writer.lock()!).
    let t_kick = Instant::now();
    registry.kick_all_web_viewers();
    wait_until(
        Duration::from_millis(1500),
        || {
            if registry.active_web_viewers() != 0 || !mock.live_virtual_display_ids().is_empty() {
                return false;
            }
            let Some((200, _, body)) =
                try_http_req(loopback_of(web.addr), "GET", "/api/admin/state", "", None)
            else {
                return false;
            };
            serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v["web_p2p"]["total_viewers"].as_u64())
                == Some(0)
        },
        &format!(
            "kicked zero-window WS viewer must unblock writer, unregister P2P, and release VD promptly (elapsed {:?})",
            t_kick.elapsed()
        ),
    );

    force_tcp_rst(slow_ws);
    force_tcp_rst(healthy_ws);
    stop.store(true, Ordering::SeqCst);
    web.stop();
}

// ============================================================================
// Iteration 1 Test 7: FFmpeg Subprocess SIGKILL Mid-NAL & Stderr Flood
// ============================================================================
#[cfg(any(target_os = "linux", target_os = "windows"))]
#[test]
#[ignore]
fn __chaos_fake_ffmpeg_worker() {
    // Hard 5s self-destruct so this helper can NEVER leak an orphan child process.
    thread::spawn(|| {
        thread::sleep(Duration::from_secs(5));
        std::process::exit(99);
    });
    let mode = std::env::var("IDIS_CHAOS_FFMPEG_MODE").unwrap_or_default();
    let mut out = std::io::stdout().lock();
    let mut err = std::io::stderr().lock();
    match mode.as_str() {
        "valid_then_stall_mid_idr" => {
            let _ = out.write_all(SYNTHETIC_H264_ANNEX_B);
            let _ = out.write_all(SYNTHETIC_H264_ANNEX_B);
            // Emit truncated half of IDR #3, then block until killed by `FfmpegProcess::stop()`.
            let _ = out.write_all(&SYNTHETIC_H264_ANNEX_B[..12]);
            let _ = out.flush();
            thread::sleep(Duration::from_secs(4));
            std::process::exit(0);
        }
        "crash_mid_nal" => {
            // Two complete AUs so AU #1 is flushed by AU #2's boundary before the crash,
            // followed by a truncated mid-write IDR slice that must NOT be flushed on exit(137).
            let _ = out.write_all(SYNTHETIC_H264_ANNEX_B);
            let _ = out.write_all(SYNTHETIC_H264_ANNEX_B);
            let _ = out.write_all(&[0x00, 0x00, 0x00, 0x01, 0x65, 0x88]);
            let _ = out.flush();
            std::process::exit(137);
        }
        "stderr_flood" => {
            let chunk = vec![b'E'; 64 * 1024];
            for _ in 0..32 {
                // 2 MiB on stderr!
                if err.write_all(&chunk).is_err() {
                    break;
                }
            }
            let _ = err.flush();
            let _ = out.write_all(SYNTHETIC_H264_ANNEX_B);
            let _ = out.write_all(SYNTHETIC_H264_ANNEX_B);
            let _ = out.flush();
            std::process::exit(0);
        }
        _ => {
            std::process::exit(1);
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
#[test]
fn chaos_ffmpeg_subprocess_sigkill_mid_nal_and_stderr_flood() {
    use chaos::ChildReaperGuard;
    use idis::platform::ffmpeg_capture::{FfmpegPipelineSpec, FfmpegProcess};
    use idis::platform::{latest_frame_channel, RecvFrameError};

    let _wd = DeadlockWatchdog::arm(
        "chaos_ffmpeg_subprocess_sigkill_mid_nal_and_stderr_flood",
        Duration::from_secs(12),
    );

    let exe = std::env::current_exe().unwrap();
    let nonce = std::process::id();
    let modes = ["valid_then_stall_mid_idr", "crash_mid_nal", "stderr_flood"];
    let mut shim_paths = Vec::new();
    for mode in modes {
        let shim_path = if cfg!(windows) {
            std::env::temp_dir().join(format!("idis_chaos_ffmpeg_{nonce}_{mode}.cmd"))
        } else {
            std::env::temp_dir().join(format!("idis_chaos_ffmpeg_{nonce}_{mode}.sh"))
        };
        let script = if cfg!(windows) {
            format!(
                "@set IDIS_CHAOS_FFMPEG_MODE={mode}\r\n@\"{}\" --exact __chaos_fake_ffmpeg_worker --ignored --nocapture\r\n",
                exe.display()
            )
        } else {
            format!(
                "#!/bin/sh\nIDIS_CHAOS_FFMPEG_MODE={mode} exec \"{}\" --exact __chaos_fake_ffmpeg_worker --ignored --nocapture\n",
                exe.display()
            )
        };
        std::fs::write(&shim_path, script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&shim_path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        shim_paths.push(shim_path);
    }
    let _cleanup = ChildReaperGuard::new(None, shim_paths.clone());

    let make_spec = |idx: usize| FfmpegPipelineSpec {
        ffmpeg_path: shim_paths[idx].to_string_lossy().to_string(),
        input_args: vec!["-f".into(), "lavfi".into(), "-i".into(), "nullsrc".into()],
        video_filter_prefix: None,
        out_width: 1280,
        out_height: 720,
        max_pixel_edge: 1920,
        fps: 30,
        bitrate_mbps: 10,
        encoder: "libx264".into(),
        all_intra: false,
    };

    // Case 1: `proc.stop()` SIGKILL mid-IDR must NOT flush truncated tail NAL and must complete < 1s.
    {
        let (tx, rx) = latest_frame_channel();
        let mut proc = FfmpegProcess::spawn(&make_spec(0), tx).unwrap();
        let first = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("must receive first complete Annex-B AU");
        assert!(first.is_keyframe, "first AU must be self-contained IDR");
        let t0 = Instant::now();
        proc.stop();
        // On Windows, the `.cmd` batch test shim spawns the worker as a grandchild of `cmd.exe`
        // (no POSIX `exec`), so killing `cmd.exe` waits up to the worker's 4s self-exit before
        // stdout closes; real `ffmpeg.exe` has no batch wrapper and exits immediately.
        let stop_budget = if cfg!(windows) {
            Duration::from_secs(6)
        } else {
            Duration::from_secs(1)
        };
        assert!(
            t0.elapsed() < stop_budget,
            "FfmpegProcess::stop() took too long: {:?}",
            t0.elapsed()
        );
    }

    // Case 2: External crash mid-NAL -> rx must receive Disconnected promptly and MUST NOT emit
    // a tiny truncated IDR tail!
    {
        let (tx, rx) = latest_frame_channel();
        let mut proc = FfmpegProcess::spawn(&make_spec(1), tx).unwrap();
        let mut received = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut disconnected = false;
        while Instant::now() < deadline {
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(f) => received.push(f),
                Err(RecvFrameError::Disconnected) => {
                    disconnected = true;
                    break;
                }
                Err(RecvFrameError::Timeout) => {}
            }
        }
        proc.stop();
        assert!(disconnected, "rx must receive Disconnected promptly on FFmpeg crash");
        assert!(
            !received.is_empty(),
            "must receive valid frame before crash"
        );
        for f in &received {
            assert!(
                f.annex_b.len() >= SYNTHETIC_H264_ANNEX_B.len(),
                "external crash mid-NAL must NOT flush truncated tail NAL (len={})",
                f.annex_b.len()
            );
        }
    }

    // Case 3: 2 MiB stderr flood must complete promptly without wedging child or OOMing stderr reader.
    {
        let (tx, rx) = latest_frame_channel();
        let mut proc = FfmpegProcess::spawn(&make_spec(2), tx).unwrap();
        let f = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("must still receive video frame during 2 MiB stderr flood");
        assert!(f.is_keyframe);
        proc.stop();
    }
}

// ============================================================================
// Iteration 2: Server Brutal Kill (SIGKILL / SIGTERM), Crash Persistence &
//              Port Rebind / Shutdown Race Chaos Tests
// ============================================================================

fn spawn_idis_mock_subprocess(
    tel_port: u16,
    data_port: u16,
    web_port: u16,
    cfg_path: &std::path::Path,
    stderr_log: &std::path::Path,
    extra_args: &[&str],
) -> std::process::Child {
    let stderr_file = std::fs::File::create(stderr_log).expect("create stderr log");
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_idis"));
    for var in [
        "SENTRY_DSN",
        "IDIS_CONFIG",
        "IDIS_TRUSTED_DEVICES",
        "IDIS_WEB_ADMIN_TOKEN",
        "IDIS_WEB_VIEW_TOKEN",
        "LISTEN_FDS",
        "LISTEN_PID",
        "LISTEN_FDNAMES",
    ] {
        cmd.env_remove(var);
    }
    cmd.args([
        "--mock",
        "--wifi",
        "--bind-addr",
        "127.0.0.1",
        "--telemetry-port",
        &tel_port.to_string(),
        "--data-port",
        &data_port.to_string(),
        "--web",
        "--web-bind",
        &format!("127.0.0.1:{web_port}"),
        "--max-web-viewers",
        "2",
        "--web-view-token",
        "998877",
        "--no-web-require-approval",
        "--no-low-power",
        "--no-bonjour",
        "--no-usb",
        "--auto-accept",
        "--config",
        &cfg_path.to_string_lossy(),
        "--trusted-devices-file",
        "none",
    ]);
    cmd.args(extra_args);
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::from(stderr_file));
    cmd.spawn().expect("spawn idis subprocess")
}

fn wait_idis_subprocess_ready(
    child: &mut std::process::Child,
    admin_addr: SocketAddr,
    stderr_log: &std::path::Path,
    timeout: Duration,
) -> Result<serde_json::Value, String> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            let err_txt = std::fs::read_to_string(stderr_log).unwrap_or_default();
            return Err(format!(
                "idis exited early with {status}; stderr:\n{err_txt}"
            ));
        }
        if let Ok(mut s) = TcpStream::connect_timeout(&admin_addr, Duration::from_millis(100)) {
            let _ = s.set_read_timeout(Some(Duration::from_millis(500)));
            let _ = s.set_write_timeout(Some(Duration::from_millis(500)));
            let req = format!(
                "GET /api/admin/state HTTP/1.1\r\nHost: {admin_addr}\r\nOrigin: http://{admin_addr}\r\nConnection: close\r\n\r\n"
            );
            if s.write_all(req.as_bytes()).is_ok() {
                let mut raw = Vec::new();
                let _ = s.read_to_end(&mut raw);
                let txt = String::from_utf8_lossy(&raw);
                if let Some((head, body)) = txt.split_once("\r\n\r\n") {
                    if head.contains("200 OK") {
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
                            let wifi_ok = v["connection"]["wifi_enabled"].as_bool() == Some(true);
                            let vport = v["connection"]["web_viewer_port"].as_u64().unwrap_or(0);
                            if wifi_ok && vport > 0 {
                                return Ok(v);
                            }
                        }
                    }
                }
            }
        }
        if Instant::now() >= deadline {
            let err_txt = std::fs::read_to_string(stderr_log).unwrap_or_default();
            return Err(format!(
                "timed out waiting for idis readiness on {admin_addr}; stderr:\n{err_txt}"
            ));
        }
        thread::sleep(Duration::from_millis(15));
    }
}

fn spawn_with_initial_bind_retry(
    cfg_path: &std::path::Path,
    stderr_log: &std::path::Path,
    extra_args: &[&str],
) -> (std::process::Child, u16, u16, u16, serde_json::Value) {
    let mut last_err = String::new();
    for _ in 0..3 {
        let ports = chaos::alloc_distinct_loopback_ports(3);
        let (t, d, w) = (ports[0], ports[1], ports[2]);
        let mut child = spawn_idis_mock_subprocess(t, d, w, cfg_path, stderr_log, extra_args);
        let admin_addr: SocketAddr = format!("127.0.0.1:{w}").parse().unwrap();
        match wait_idis_subprocess_ready(&mut child, admin_addr, stderr_log, Duration::from_secs(4))
        {
            Ok(state) => return (child, t, d, w, state),
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                if e.contains("failed to bind")
                    || e.contains("Address already in use")
                    || e.contains("10048")
                {
                    last_err = e;
                    continue;
                }
                panic!("idis failed to start: {e}");
            }
        }
    }
    panic!("idis failed initial bind after 3 attempts: {last_err}");
}

#[test]
fn chaos_subprocess_sigkill_mid_stream_and_config_write_clean_rebind() {
    let _wd = DeadlockWatchdog::arm(
        "chaos_subprocess_sigkill_mid_stream_and_config_write_clean_rebind",
        Duration::from_secs(20),
    );
    let dir = chaos::temp_chaos_dir("sigkill_rebind");
    let cfg_path = dir.join("idis.yaml");
    let stderr1 = dir.join("stderr1.log");
    let stderr2 = dir.join("stderr2.log");
    let mut guard = chaos::ChildReaperGuard::new(None, vec![dir.clone()]);

    let (child1, tel_port, data_port, web_port, state1) =
        spawn_with_initial_bind_retry(&cfg_path, &stderr1, &[]);
    guard.child = Some(child1);

    let admin_addr: SocketAddr = format!("127.0.0.1:{web_port}").parse().unwrap();
    let viewer_port_1 = state1["connection"]["web_viewer_port"].as_u64().unwrap() as u16;
    let viewer_addr_1: SocketAddr = format!("127.0.0.1:{viewer_port_1}").parse().unwrap();
    assert_eq!(
        state1["connection"]["wifi_telemetry_port"].as_u64(),
        Some(tel_port as u64)
    );
    assert_eq!(
        state1["connection"]["wifi_data_port"].as_u64(),
        Some(data_port as u64)
    );
    assert_eq!(state1["host"]["config_corrupt"].as_bool(), Some(false));

    // 1) Active iPad Wi-Fi stream
    let mut tel1 = TcpStream::connect(("127.0.0.1", tel_port)).unwrap();
    let _ = tel1.set_read_timeout(Some(Duration::from_secs(2)));
    write_canal_block(
        &mut tel1,
        &make_handshake_packet("sigkill-ipad-1", "KillPad1", 1024, 768, "1.2"),
    )
    .unwrap();
    assert!(read_canal_block(&mut tel1).unwrap().is_some());
    let mut data1 = TcpStream::connect(("127.0.0.1", data_port)).unwrap();
    let _ = data1.set_read_timeout(Some(Duration::from_secs(2)));
    assert!(
        read_canal_block(&mut data1).unwrap().is_some(),
        "must receive live mock H.264 block before SIGKILL"
    );

    // 2) Active Web Viewer WS stream
    let (vcode, vhdrs, _) = http_req(
        viewer_addr_1,
        "POST",
        "/api/view/login",
        "Content-Type: application/json\r\n",
        Some(r#"{"token":"998877"}"#),
    );
    assert_eq!(vcode, 200);
    let cookie1 = extract_set_cookie(&vhdrs);
    let mut ws1 = connect_ws_viewer(viewer_addr_1, Some(&cookie1));
    let (op1, _) = read_ws_frame(&mut ws1).unwrap();
    assert!(op1 == 1 || op1 == 2, "must receive live WS frame before SIGKILL");

    // 3) Hammer concurrent Admin YAML writes while streaming, then SIGKILL mid-flight!
    let stop_writer = Arc::new(AtomicBool::new(false));
    let saves_ok = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let sw = stop_writer.clone();
    let ok_c = saves_ok.clone();
    let writer_thread = thread::spawn(move || {
        let fps_cycle = [24u32, 30, 48, 60];
        let mut i = 0usize;
        while !sw.load(Ordering::Acquire) {
            let fps = fps_cycle[i % fps_cycle.len()];
            i += 1;
            let mut ucfg = idis::user_config::UserConfigFile {
                max_web_viewers: 2,
                web_require_approval: false,
                low_power: false,
                ..Default::default()
            };
            ucfg.ipad.fps = fps;
            ucfg.trusted_devices.push(idis::trust::TrustedDevice {
                fingerprint: "fp:deadbeef0123456789abcdef".to_string(),
                mac: String::new(),
                uid: "sentinel-uid".to_string(),
                name: "SentinelPad".to_string(),
                model: "iPad".to_string(),
                trusted_at: 1_700_000_000,
                prefs: Default::default(),
            });
            let yaml = ucfg.to_yaml_string().unwrap();
            let payload = serde_json::json!({ "yaml": yaml }).to_string();
            let req = format!(
                "POST /api/admin/config HTTP/1.1\r\nHost: {admin_addr}\r\nOrigin: http://{admin_addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                payload.len()
            );
            if let Ok(mut s) = TcpStream::connect_timeout(&admin_addr, Duration::from_secs(1)) {
                let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
                let _ = s.set_write_timeout(Some(Duration::from_secs(2)));
                if s.write_all(req.as_bytes()).is_ok() {
                    let mut resp = Vec::new();
                    let _ = s.read_to_end(&mut resp);
                    if String::from_utf8_lossy(&resp).contains("200 OK") {
                        ok_c.fetch_add(1, Ordering::Release);
                    }
                }
            }
        }
    });

    wait_until(
        Duration::from_secs(6),
        || saves_ok.load(Ordering::Acquire) >= 2,
        "at least 2 admin config YAML saves succeeded before SIGKILL",
    );
    thread::sleep(Duration::from_millis(5));

    // Brutal SIGKILL (`kill -9` / `TerminateProcess`) + mandatory waitpid!
    let mut c1 = guard.child.take().unwrap();
    let old_pid = c1.id();
    c1.kill().unwrap();
    let status1 = c1.wait().unwrap();
    assert!(!status1.success(), "killed child must not report exit 0");
    stop_writer.store(true, Ordering::Release);
    let _ = writer_thread.join();

    // Verify old client sockets detect EOF/RST promptly (no hang!)
    let _ = data1.set_read_timeout(Some(Duration::from_secs(1)));
    let mut saw_data_eof = false;
    for _ in 0..32 {
        match read_canal_block(&mut data1) {
            Ok(Some(_)) => continue,
            Ok(None) | Err(_) => {
                saw_data_eof = true;
                break;
            }
        }
    }
    assert!(saw_data_eof, "iPad Data client must detect EOF/RST after server SIGKILL");
    let _ = ws1.set_read_timeout(Some(Duration::from_secs(1)));
    let mut saw_ws_eof = false;
    for _ in 0..32 {
        match read_ws_frame(&mut ws1) {
            Ok((8, _)) | Err(_) => {
                saw_ws_eof = true;
                break;
            }
            Ok(_) => continue,
        }
    }
    assert!(saw_ws_eof, "WS viewer must detect EOF/RST after server SIGKILL");
    drop(data1);
    drop(tel1);
    drop(ws1);

    // Verify zero YAML corruption on disk after SIGKILL
    let raw_yaml = std::fs::read_to_string(&cfg_path).expect("idis.yaml must exist after SIGKILL");
    assert!(!raw_yaml.trim().is_empty(), "idis.yaml must never be 0 bytes after SIGKILL");
    let parsed = idis::user_config::load_yaml_file(&cfg_path)
        .expect("idis.yaml must parse cleanly after SIGKILL");
    assert!(
        [24, 30, 48, 60].contains(&parsed.ipad.fps),
        "unexpected torn fps={}",
        parsed.ipad.fps
    );
    assert!(
        parsed
            .trusted_devices
            .iter()
            .any(|d| d.fingerprint == "fp:deadbeef0123456789abcdef"),
        "sentinel trusted device lost across SIGKILL"
    );

    // Deterministically plant an orphan `.tmp` from the dead PID to verify restart sweeps/tolerates it
    let orphan_tmp = dir.join(format!("idis.yaml.{old_pid}.9999.tmp"));
    std::fs::write(&orphan_tmp, b"ipad:\n  fps: [truncated").unwrap();

    // 4) Immediate restart on the EXACT SAME (tel_port, data_port, web_port) — NO port change!
    let mut child2 = spawn_idis_mock_subprocess(tel_port, data_port, web_port, &cfg_path, &stderr2, &[]);
    let state2 = wait_idis_subprocess_ready(
        &mut child2,
        admin_addr,
        &stderr2,
        Duration::from_secs(4),
    )
    .expect("restarted idis must immediately rebind identical ports after SIGKILL");
    let new_pid = child2.id();
    guard.child = Some(child2);

    assert_eq!(state2["host"]["config_corrupt"].as_bool(), Some(false));
    assert_eq!(
        state2["connection"]["wifi_telemetry_port"].as_u64(),
        Some(tel_port as u64)
    );
    assert_eq!(
        state2["connection"]["wifi_data_port"].as_u64(),
        Some(data_port as u64)
    );
    let viewer_port_2 = state2["connection"]["web_viewer_port"].as_u64().unwrap() as u16;
    assert!(viewer_port_2 > 0);
    // Verify stale orphan `.tmp` was swept cleanly on restart!
    assert!(
        !orphan_tmp.exists(),
        "startup should sweep stale orphan .tmp files left behind by SIGKILL"
    );

    // Fresh config write on restarted server must succeed cleanly with zero `.tmp` left behind
    let mut ucfg2 = parsed.clone();
    ucfg2.ipad.fps = 45;
    let body2 = serde_json::json!({ "yaml": ucfg2.to_yaml_string().unwrap() }).to_string();
    let (sc, _, sbody) = http_req(
        admin_addr,
        "POST",
        "/api/admin/config",
        "Content-Type: application/json\r\n",
        Some(&body2),
    );
    assert_eq!(sc, 200, "post-restart config save failed: {sbody}");
    let reloaded = idis::user_config::load_yaml_file(&cfg_path).unwrap();
    assert_eq!(reloaded.ipad.fps, 45);
    for entry in std::fs::read_dir(&dir).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        assert!(
            !name.contains(&format!(".{new_pid}.")) || !name.ends_with(".tmp"),
            "leaked tmp file after clean save: {name}"
        );
    }

    // Fresh iPad + Web Viewer streams work on restarted server
    let mut tel2 = TcpStream::connect(("127.0.0.1", tel_port)).unwrap();
    let _ = tel2.set_read_timeout(Some(Duration::from_secs(2)));
    write_canal_block(
        &mut tel2,
        &make_handshake_packet("sigkill-ipad-2", "KillPad2", 1024, 768, "1.2"),
    )
    .unwrap();
    assert!(read_canal_block(&mut tel2).unwrap().is_some());
    let mut data2 = TcpStream::connect(("127.0.0.1", data_port)).unwrap();
    let _ = data2.set_read_timeout(Some(Duration::from_secs(2)));
    assert!(read_canal_block(&mut data2).unwrap().is_some());

    let viewer_addr_2: SocketAddr = format!("127.0.0.1:{viewer_port_2}").parse().unwrap();
    let (vc2, vh2, _) = http_req(
        viewer_addr_2,
        "POST",
        "/api/view/login",
        "Content-Type: application/json\r\n",
        Some(r#"{"token":"998877"}"#),
    );
    assert_eq!(vc2, 200);
    let cookie2 = extract_set_cookie(&vh2);
    let mut ws2 = connect_ws_viewer(viewer_addr_2, Some(&cookie2));
    let (op2, _) = read_ws_frame(&mut ws2).unwrap();
    assert!(op2 == 1 || op2 == 2);

    drop(ws2);
    drop(data2);
    drop(tel2);
}

#[test]
fn chaos_subprocess_sigterm_graceful_shutdown_under_active_streams() {
    let _wd = DeadlockWatchdog::arm(
        "chaos_subprocess_sigterm_graceful_shutdown_under_active_streams",
        Duration::from_secs(15),
    );
    let dir = chaos::temp_chaos_dir("sigterm_graceful");
    let cfg_path = dir.join("idis.yaml");
    let stderr_log = dir.join("stderr.log");
    let mut guard = chaos::ChildReaperGuard::new(None, vec![dir.clone()]);

    #[cfg(unix)]
    let extra: &[&str] = &["--idle-exit-secs", "300"];
    #[cfg(windows)]
    let extra: &[&str] = &["--idle-exit-secs", "1"];

    let (child, tel_port, data_port, web_port, state) =
        spawn_with_initial_bind_retry(&cfg_path, &stderr_log, extra);
    guard.child = Some(child);

    let admin_addr: SocketAddr = format!("127.0.0.1:{web_port}").parse().unwrap();
    let viewer_port = state["connection"]["web_viewer_port"].as_u64().unwrap() as u16;
    let viewer_addr: SocketAddr = format!("127.0.0.1:{viewer_port}").parse().unwrap();

    // Connect active iPad + active Web Viewer
    let mut tel = TcpStream::connect(("127.0.0.1", tel_port)).unwrap();
    let _ = tel.set_read_timeout(Some(Duration::from_secs(2)));
    write_canal_block(
        &mut tel,
        &make_handshake_packet("sigterm-ipad", "TermPad", 1024, 768, "1.2"),
    )
    .unwrap();
    assert!(read_canal_block(&mut tel).unwrap().is_some());
    let mut data = TcpStream::connect(("127.0.0.1", data_port)).unwrap();
    let _ = data.set_read_timeout(Some(Duration::from_secs(2)));
    assert!(read_canal_block(&mut data).unwrap().is_some());

    let (vc, vh, _) = http_req(
        viewer_addr,
        "POST",
        "/api/view/login",
        "Content-Type: application/json\r\n",
        Some(r#"{"token":"998877"}"#),
    );
    assert_eq!(vc, 200);
    let cookie = extract_set_cookie(&vh);
    let mut ws = connect_ws_viewer(viewer_addr, Some(&cookie));
    let (op, _) = read_ws_frame(&mut ws).unwrap();
    assert!(op == 1 || op == 2);

    wait_until(
        Duration::from_secs(2),
        || {
            let (code, _, body) = http_req(admin_addr, "GET", "/api/admin/state", "", None);
            code == 200
                && serde_json::from_str::<serde_json::Value>(&body)
                    .ok()
                    .map(|v| {
                        v["settings"]["active_extended_screens"].as_u64().unwrap_or(0) >= 1
                            && v["settings"]["active_web_viewers"].as_u64().unwrap_or(0) == 1
                    })
                    .unwrap_or(false)
        },
        "both iPad and Web viewer active before graceful shutdown",
    );

    #[cfg(unix)]
    {
        let c = guard.child.as_mut().unwrap();
        let t0 = Instant::now();
        chaos::send_sigterm(c.id()).expect("send SIGTERM");
        let mut exit_status = None;
        wait_until(
            Duration::from_secs(2),
            || {
                if let Ok(Some(st)) = c.try_wait() {
                    exit_status = Some(st);
                    true
                } else {
                    false
                }
            },
            "idis must exit cleanly within 2s of SIGTERM under active streams",
        );
        let st = exit_status.unwrap();
        assert_eq!(
            st.code(),
            Some(0),
            "SIGTERM must trigger graceful exit code 0 (took {:?}), got {st:?}",
            t0.elapsed()
        );
        guard.child = None;

        // Verify connected streams receive EOF/Close promptly
        let _ = data.set_read_timeout(Some(Duration::from_secs(1)));
        let mut data_closed = false;
        for _ in 0..32 {
            match read_canal_block(&mut data) {
                Ok(Some(_)) => continue,
                Ok(None) | Err(_) => {
                    data_closed = true;
                    break;
                }
            }
        }
        assert!(data_closed, "iPad Data socket must close on SIGTERM");
        let _ = ws.set_read_timeout(Some(Duration::from_secs(1)));
        let mut ws_closed = false;
        for _ in 0..32 {
            match read_ws_frame(&mut ws) {
                Ok((8, _)) | Err(_) => {
                    ws_closed = true;
                    break;
                }
                Ok(_) => continue,
            }
        }
        assert!(ws_closed, "WS viewer socket must close on SIGTERM");
        drop(data);
        drop(tel);
        drop(ws);
    }

    #[cfg(windows)]
    {
        let c = guard.child.as_mut().unwrap();
        assert!(c.try_wait().unwrap().is_none(), "must stay alive while streaming");
        drop(data);
        drop(tel);
        drop(ws);
        let mut exit_status = None;
        wait_until(
            Duration::from_secs(4),
            || {
                if let Ok(Some(st)) = c.try_wait() {
                    exit_status = Some(st);
                    true
                } else {
                    false
                }
            },
            "idis --idle-exit-secs 1 must exit cleanly on Windows",
        );
        assert_eq!(exit_status.unwrap().code(), Some(0));
        guard.child = None;
    }

    // All 3 explicit ports must be immediately rebindable
    let l1 = TcpListener::bind(("127.0.0.1", tel_port)).expect("rebind tel_port");
    let l2 = TcpListener::bind(("127.0.0.1", data_port)).expect("rebind data_port");
    let l3 = TcpListener::bind(("127.0.0.1", web_port)).expect("rebind web_port");
    drop((l1, l2, l3));
}

#[test]
fn chaos_concurrent_atomic_persistence_and_truncation_recovery() {
    use idis::trust::{DevicePreferences, TrustStore, TrustedDevice};
    use idis::user_config::{load_yaml_file, save_yaml_file, UserConfigFile};

    let _wd = DeadlockWatchdog::arm(
        "chaos_concurrent_atomic_persistence_and_truncation_recovery",
        Duration::from_secs(15),
    );
    let dir = chaos::temp_chaos_dir("atomic_persist");
    let _cleanup = chaos::ChildReaperGuard::new(None, vec![dir.clone()]);
    let yaml_path = dir.join("idis.yaml");
    let tsv_path = dir.join("trusted_devices.txt");
    let sentinel_fp = "fp:aaaa11112222333344445555";

    // Seed YAML and TSV with sentinel trusted device
    let mut seed_cfg = UserConfigFile::default();
    seed_cfg.ipad.fps = 30;
    seed_cfg.trusted_devices.push(TrustedDevice {
        fingerprint: sentinel_fp.to_string(),
        mac: String::new(),
        uid: "sentinel-uid".to_string(),
        name: "SentinelPad".to_string(),
        model: "iPad".to_string(),
        trusted_at: 1_700_000_000,
        prefs: DevicePreferences::default(),
    });
    save_yaml_file(&yaml_path, &seed_cfg).unwrap();

    let trust = Arc::new(TrustStore::load(Some(tsv_path.clone())));
    trust
        .trust_device(sentinel_fp, "sentinel-uid", "SentinelPad", "iPad")
        .unwrap();

    // Phase A: Concurrent multi-thread atomic YAML + TrustStore write/read storm
    let done = Arc::new(AtomicBool::new(false));
    let yaml_reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let tsv_reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let mut writers = Vec::new();
    for tid in 0..4usize {
        let yp = yaml_path.clone();
        writers.push(thread::spawn(move || {
            let fps_vals = [15u32, 24, 30, 48, 60];
            let mut ok_writes = 0usize;
            for i in 0..50usize {
                let mut c = UserConfigFile::default();
                c.ipad.fps = fps_vals[(tid + i) % fps_vals.len()];
                c.trusted_devices.push(TrustedDevice {
                    fingerprint: sentinel_fp.to_string(),
                    mac: String::new(),
                    uid: "sentinel-uid".to_string(),
                    name: "SentinelPad".to_string(),
                    model: "iPad".to_string(),
                    trusted_at: 1_700_000_000,
                    prefs: DevicePreferences::default(),
                });
                if i % 2 == 0 {
                    c.trusted_devices.push(TrustedDevice {
                        fingerprint: format!("fp:{:04x}{:020x}", tid + 1, i + 1),
                        mac: String::new(),
                        uid: format!("uid-{tid}-{i}"),
                        name: format!("Pad-{tid}"),
                        model: "iPad".to_string(),
                        trusted_at: 1_700_000_001,
                        prefs: DevicePreferences::default(),
                    });
                }
                match save_yaml_file(&yp, &c) {
                    Ok(()) => ok_writes += 1,
                    Err(e) => {
                        #[cfg(unix)]
                        panic!("save_yaml_file failed on Unix: {e:#}");
                        #[cfg(windows)]
                        {
                            let _ = e;
                        }
                    }
                }
            }
            assert!(ok_writes > 0, "at least one YAML write must succeed");
        }));
    }
    for tid in 0..3usize {
        let tr = trust.clone();
        writers.push(thread::spawn(move || {
            let fp = format!("fp:bbbb0000000000000000000{tid}");
            for i in 0..30usize {
                let _ = tr.trust_device(&fp, &format!("u{tid}"), &format!("T{tid}"), "iPad");
                if i % 3 == 0 {
                    let _ = tr.revoke_device(&fp);
                }
            }
        }));
    }

    let mut readers = Vec::new();
    for _ in 0..2 {
        let yp = yaml_path.clone();
        let d = done.clone();
        let rc = yaml_reads.clone();
        readers.push(thread::spawn(move || {
            while !d.load(Ordering::Acquire) {
                match std::fs::read_to_string(&yp) {
                    Ok(raw) => {
                        assert!(!raw.trim().is_empty(), "reader observed 0-byte YAML during rename");
                        let c = UserConfigFile::from_yaml_str(&raw)
                            .expect("reader observed torn/corrupt YAML during atomic rename");
                        assert!(
                            c.trusted_devices.iter().any(|dev| dev.fingerprint == sentinel_fp),
                            "sentinel device missing in atomic YAML snapshot"
                        );
                        assert!([15, 24, 30, 48, 60].contains(&c.ipad.fps));
                        rc.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) => {
                        #[cfg(unix)]
                        panic!("concurrent YAML read failed on Unix: {e}");
                        #[cfg(windows)]
                        {
                            let _ = e;
                        }
                    }
                }
            }
        }));
    }
    for _ in 0..2 {
        let tp = tsv_path.clone();
        let d = done.clone();
        let rc = tsv_reads.clone();
        readers.push(thread::spawn(move || {
            while !d.load(Ordering::Acquire) {
                let st = TrustStore::load(Some(tp.clone()));
                assert!(
                    st.is_trusted(Some(sentinel_fp)),
                    "sentinel device missing in concurrent TrustStore reload"
                );
                rc.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }

    for w in writers {
        w.join().unwrap();
    }
    done.store(true, Ordering::Release);
    for r in readers {
        r.join().unwrap();
    }
    assert!(yaml_reads.load(Ordering::Relaxed) > 0);
    assert!(tsv_reads.load(Ordering::Relaxed) > 0);

    // Zero leftover `.tmp` files after concurrent save storm
    for entry in std::fs::read_dir(&dir).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        assert!(!name.ends_with(".tmp"), "leftover tmp file: {name}");
    }

    // Phase B: 0-byte & corrupt existing YAML MUST enter read-only corrupt mode (NEVER silently wipe!)
    for (label, content) in [
        ("empty_zero_bytes", b"".as_slice()),
        ("whitespace_only", b"   \n\t\n".as_slice()),
        ("truncated_syntax", b"ipad:\n  fps: [broken\ntrusted_devices:\n  - fingerprint: fp:".as_slice()),
    ] {
        let corrupt_path = dir.join(format!("corrupt_{label}.yaml"));
        std::fs::write(&corrupt_path, content).unwrap();
        let mut cfg = base_config();
        cfg.config_file = Some(corrupt_path.to_string_lossy().to_string());
        cfg.trusted_devices_file = Some("none".to_string());
        let reg = SessionRegistry::new(cfg, Arc::new(MockBackend::new()));
        assert!(
            reg.is_config_corrupt(),
            "existing {label} YAML must trigger read-only corrupt mode (must NOT silently wipe!)"
        );
        assert!(
            reg.save_config_file().is_err(),
            "corrupt {label} YAML must refuse save_config_file"
        );
        assert_eq!(
            std::fs::read(&corrupt_path).unwrap(),
            content,
            "corrupt {label} YAML bytes on disk must remain untouched"
        );
        // Explicit apply_user_config recovers cleanly
        reg.apply_user_config(UserConfigFile::default(), true).unwrap();
        assert!(!reg.is_config_corrupt());
        let _ = load_yaml_file(&corrupt_path).unwrap();
    }

    // Fuzz prefix truncations on both YAML and TSV: zero panics!
    let valid_yaml = seed_cfg.to_yaml_string().unwrap();
    let valid_tsv = std::fs::read_to_string(&tsv_path).unwrap();
    let mut rng = FuzzRng::new(0xA70C_2026);
    for _ in 0..24 {
        let cut = rng.next_usize(valid_yaml.len() + 1);
        let prefix = String::from_utf8_lossy(&valid_yaml.as_bytes()[..cut]);
        let _ = UserConfigFile::from_yaml_str(&prefix);

        let tcut = rng.next_usize(valid_tsv.len() + 1);
        let scratch = dir.join("tsv_trunc.txt");
        std::fs::write(&scratch, &valid_tsv.as_bytes()[..tcut]).unwrap();
        let st = TrustStore::load(Some(scratch));
        for dev in st.list() {
            assert!(dev.fingerprint.starts_with("fp:"));
        }
    }
}

#[test]
fn chaos_stop_race_with_concurrent_wifi_connect_and_pending_approval() {
    let _wd = DeadlockWatchdog::arm(
        "chaos_stop_race_with_concurrent_wifi_connect_and_pending_approval",
        Duration::from_secs(12),
    );
    let mut cfg = base_config();
    cfg.auto_accept = false;
    cfg.web_require_approval = true;
    cfg.max_web_viewers = 4;

    let mock = Arc::new(MockBackend::new());
    let registry = Arc::new(SessionRegistry::new(cfg.clone(), mock.clone()));
    let stop = Arc::new(AtomicBool::new(false));
    let mut web = start_web_server(
        "127.0.0.1:0",
        None,
        Some("554433".to_string()),
        registry.clone(),
        LogBuffer::new(),
        stop.clone(),
    )
    .unwrap();
    let admin_addr = web.addr;
    let viewer_addr = web.viewer_addr().expect("viewer listener");
    let wifi_ctrl = web.wifi_controller();
    let (tel_addr, data_addr) = wifi_ctrl.start().unwrap();

    // 1) Hold a live pending `/api/view/request-approval` open
    let (code, hdrs, _) = http_req(
        viewer_addr,
        "POST",
        "/api/view/login",
        "Content-Type: application/json\r\n",
        Some(r#"{"token":"554433"}"#),
    );
    assert_eq!(code, 200);
    let v_cookie = extract_set_cookie(&hdrs);
    let mut pending_sock = TcpStream::connect(viewer_addr).unwrap();
    let _ = pending_sock.set_read_timeout(Some(Duration::from_secs(2)));
    let req = format!(
        "POST /api/view/request-approval HTTP/1.1\r\nHost: {viewer_addr}\r\nOrigin: http://{viewer_addr}\r\nCookie: {v_cookie}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
    );
    pending_sock.write_all(req.as_bytes()).unwrap();
    wait_until(
        Duration::from_secs(2),
        || {
            let (_, _, body) = http_req(admin_addr, "GET", "/api/admin/state", "", None);
            serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v["pending_approvals"].as_array().map(|a| !a.is_empty()))
                .unwrap_or(false)
        },
        "pending approval entered before stop()",
    );

    // 2) Hammer Wi-Fi Telemetry connects AND Admin `wifi_enabled: true` concurrently with `stop()`!
    let hammer_stop = Arc::new(AtomicBool::new(false));
    let hs1 = hammer_stop.clone();
    let t_wifi = thread::spawn(move || {
        while !hs1.load(Ordering::Acquire) {
            if let Ok(mut s) = TcpStream::connect_timeout(&tel_addr, Duration::from_millis(50)) {
                let _ = write_canal_block(
                    &mut s,
                    &make_handshake_packet("race-uid", "RacePad", 1024, 768, "1.2"),
                );
                thread::sleep(Duration::from_millis(2));
            }
        }
    });
    let hs2 = hammer_stop.clone();
    let t_admin = thread::spawn(move || {
        while !hs2.load(Ordering::Acquire) {
            let body = r#"{"wifi_enabled":true}"#;
            let req = format!(
                "POST /api/admin/settings HTTP/1.1\r\nHost: {admin_addr}\r\nOrigin: http://{admin_addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            if let Ok(mut s) = TcpStream::connect_timeout(&admin_addr, Duration::from_millis(50)) {
                let _ = s.write_all(req.as_bytes());
            }
        }
    });

    thread::sleep(Duration::from_millis(20));
    let t0 = Instant::now();
    stop.store(true, Ordering::SeqCst);
    web.stop();
    wifi_ctrl.stop();
    let stop_elapsed = t0.elapsed();
    hammer_stop.store(true, Ordering::Release);
    let _ = t_wifi.join();
    let _ = t_admin.join();

    assert!(
        stop_elapsed < Duration::from_secs(2),
        "web.stop() + wifi_ctrl.stop() took too long: {stop_elapsed:?}"
    );

    // Pending approval HTTP client MUST finish promptly (not linger 60s!)
    let mut resp_buf = Vec::new();
    let _ = pending_sock.read_to_end(&mut resp_buf);
    drop(pending_sock);

    // Zero leaked listeners, sessions, viewers, or virtual displays!
    assert!(!wifi_ctrl.is_running(), "wifi_ctrl must remain stopped after stop() race");
    assert!(web.viewer_addr().is_none(), "viewer listener must be closed after stop()");
    wait_until(
        Duration::from_secs(1),
        || !registry.has_any_sessions_or_viewers() && mock.live_virtual_display_ids().is_empty(),
        "zero leaked sessions/viewers/VDs after stop() race",
    );
    // All 4 ports must be immediately rebindable!
    let _l1 = TcpListener::bind(tel_addr).expect("tel_addr must be released");
    let _l2 = TcpListener::bind(data_addr).expect("data_addr must be released");
    let _l3 = TcpListener::bind(admin_addr).expect("admin_addr must be released");
    let _l4 = TcpListener::bind(viewer_addr).expect("viewer_addr must be released");
}

// ============================================================================
// Iteration 3: Extreme Network Anomalies (1-Byte Slowloris Trickle,
//              1-Byte-Window Writer Deadlines, Multi-Client Blackhole Isolation,
//              and Seeded Rapid Network Flap Storm)
// ============================================================================

fn spawn_1byte_trickler(
    bytes: Vec<u8>,
    interval: Duration,
    stop: Arc<AtomicBool>,
) -> (TcpStream, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        if let Ok(mut client) = TcpStream::connect(addr) {
            let _ = client.set_nodelay(true);
            for &b in &bytes {
                if stop.load(Ordering::Acquire) {
                    break;
                }
                if client.write_all(&[b]).is_err() {
                    break;
                }
                let _ = client.flush();
                thread::sleep(interval);
            }
            // Hold open briefly until caller signals stop so reader hits deadline rather than EOF.
            let hold_until = Instant::now() + Duration::from_secs(2);
            while !stop.load(Ordering::Acquire) && Instant::now() < hold_until {
                thread::sleep(Duration::from_millis(10));
            }
            force_tcp_rst(client);
        }
    });
    let (srv, _) = listener.accept().unwrap();
    let _ = srv.set_nodelay(true);
    (srv, handle)
}

#[test]
fn chaos_slowloris_1byte_trickle_deadlines_across_all_framers() {
    use idis::protocol::framing::{
        read_pt_frame_limited_deadline, MAX_PREAUTH_FRAME_SIZE, PT_PROTOCOL_VERSION,
    };
    use idis::web::fuzz_hooks::{
        read_http_request_with_deadline, read_ws_control_frame_with_deadline,
    };

    let _wd = DeadlockWatchdog::arm(
        "chaos_slowloris_1byte_trickle_deadlines_across_all_framers",
        Duration::from_secs(8),
    );
    let dl_dur = Duration::from_millis(200);
    let interval = Duration::from_millis(25);

    thread::scope(|s| {
        // 1) HTTP headers 1-byte trickle
        s.spawn(|| {
            let stop = Arc::new(AtomicBool::new(false));
            let mut req = b"POST /api/view/login HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Pad: ".to_vec();
            req.extend(std::iter::repeat_n(b'a', 256));
            req.extend_from_slice(b"\r\n\r\n");
            let (srv, t) = spawn_1byte_trickler(req, interval, stop.clone());
            let t0 = Instant::now();
            let res = read_http_request_with_deadline(&srv, Instant::now() + dl_dur);
            let elapsed = t0.elapsed();
            stop.store(true, Ordering::Release);
            force_tcp_rst(srv);
            t.join().unwrap();
            assert!(res.is_err(), "HTTP header trickle must fail by deadline");
            assert!(
                elapsed <= Duration::from_millis(1500),
                "HTTP header trickle exceeded bound: {elapsed:?}"
            );
        });

        // 2) HTTP body 1-byte trickle (headers upfront, body trickled)
        s.spawn(|| {
            let stop = Arc::new(AtomicBool::new(false));
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let stop_c = stop.clone();
            let t = thread::spawn(move || {
                if let Ok(mut c) = TcpStream::connect(addr) {
                    let _ = c.set_nodelay(true);
                    let _ = c.write_all(
                        b"POST /api/view/login HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 256\r\n\r\n",
                    );
                    for _ in 0..256 {
                        if stop_c.load(Ordering::Acquire) || c.write_all(b"x").is_err() {
                            break;
                        }
                        thread::sleep(interval);
                    }
                    force_tcp_rst(c);
                }
            });
            let (srv, _) = listener.accept().unwrap();
            let t0 = Instant::now();
            let res = read_http_request_with_deadline(&srv, Instant::now() + dl_dur);
            let elapsed = t0.elapsed();
            stop.store(true, Ordering::Release);
            force_tcp_rst(srv);
            t.join().unwrap();
            assert!(res.is_err(), "HTTP body trickle must fail by deadline");
            assert!(
                elapsed <= Duration::from_millis(1500),
                "HTTP body trickle exceeded bound: {elapsed:?}"
            );
        });

        // 3) Canal frame 1-byte trickle
        s.spawn(|| {
            let stop = Arc::new(AtomicBool::new(false));
            let mut raw = 256u32.to_le_bytes().to_vec();
            raw.extend(std::iter::repeat_n(b'C', 256));
            let (mut srv, t) = spawn_1byte_trickler(raw, interval, stop.clone());
            let t0 = Instant::now();
            let res = read_canal_block_limited_deadline(
                &mut srv,
                MAX_PREAUTH_FRAME_SIZE,
                Instant::now() + dl_dur,
            );
            let elapsed = t0.elapsed();
            stop.store(true, Ordering::Release);
            force_tcp_rst(srv);
            t.join().unwrap();
            assert!(res.is_err(), "Canal trickle must fail by deadline");
            assert!(
                elapsed <= Duration::from_millis(1500),
                "Canal trickle exceeded bound: {elapsed:?}"
            );
        });

        // 4) PeerTalk frame 1-byte trickle
        s.spawn(|| {
            let stop = Arc::new(AtomicBool::new(false));
            let mut raw = Vec::new();
            raw.extend_from_slice(&PT_PROTOCOL_VERSION.to_be_bytes());
            raw.extend_from_slice(&PT_FRAME_TYPE_TELEMETRY.to_be_bytes());
            raw.extend_from_slice(&7u32.to_be_bytes());
            raw.extend_from_slice(&256u32.to_be_bytes());
            raw.extend(std::iter::repeat_n(b'P', 256));
            let (mut srv, t) = spawn_1byte_trickler(raw, interval, stop.clone());
            let t0 = Instant::now();
            let res = read_pt_frame_limited_deadline(
                &mut srv,
                MAX_PREAUTH_FRAME_SIZE,
                Instant::now() + dl_dur,
            );
            let elapsed = t0.elapsed();
            stop.store(true, Ordering::Release);
            force_tcp_rst(srv);
            t.join().unwrap();
            assert!(res.is_err(), "PeerTalk trickle must fail by deadline");
            assert!(
                elapsed <= Duration::from_millis(1500),
                "PeerTalk trickle exceeded bound: {elapsed:?}"
            );
        });

        // 5) WebSocket masked frame 1-byte trickle (+ 0-byte idle timeout preservation)
        s.spawn(|| {
            // 5a: 0-byte idle must return WouldBlock/TimedOut (NOT UnexpectedEof!)
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = l.local_addr().unwrap();
            let c = TcpStream::connect(addr).unwrap();
            let (mut srv, _) = l.accept().unwrap();
            let idle_err = read_ws_control_frame_with_deadline(
                &mut srv,
                Duration::from_millis(50),
                dl_dur,
            )
            .expect_err("0-byte idle WS read must timeout");
            assert!(
                matches!(
                    idle_err.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ),
                "0-byte idle WS timeout must stay WouldBlock/TimedOut, got {:?}",
                idle_err.kind()
            );
            drop((c, srv));

            // 5b: mid-frame 1B/25ms trickle MUST fail with non-TimedOut/WouldBlock error within deadline!
            let stop = Arc::new(AtomicBool::new(false));
            let mut raw = vec![0x81, 0xFE, 0x01, 0x00, 0x11, 0x22, 0x33, 0x44]; // masked 256B text frame
            raw.extend(std::iter::repeat_n(b'W', 256));
            let (mut srv, t) = spawn_1byte_trickler(raw, interval, stop.clone());
            let t0 = Instant::now();
            let err = read_ws_control_frame_with_deadline(
                &mut srv,
                Duration::from_secs(2),
                dl_dur,
            )
            .expect_err("WS mid-frame trickle must fail by deadline");
            let elapsed = t0.elapsed();
            stop.store(true, Ordering::Release);
            force_tcp_rst(srv);
            t.join().unwrap();
            assert!(
                !matches!(
                    err.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ),
                "WS mid-frame deadline must remap to UnexpectedEof (not {:?})",
                err.kind()
            );
            assert!(
                elapsed <= Duration::from_millis(1500),
                "WS trickle exceeded bound: {elapsed:?}"
            );
        });
    });
}

#[test]
fn chaos_writer_deadline_under_slow_draining_reader() {
    use idis::protocol::framing::{
        write_canal_block_with_deadline, write_canal_parts_with_deadline,
        write_tcp_vectored_with_deadline,
    };
    use idis::web::fuzz_hooks::{write_ws_frame_tcp_with_deadline, write_ws_frame_with_deadline};

    let _wd = DeadlockWatchdog::arm(
        "chaos_writer_deadline_under_slow_draining_reader",
        Duration::from_secs(8),
    );

    // Deterministic 1-byte-window writer that sleeps 15ms per 1-byte write (OS-independent).
    struct SlowOneByteWriter {
        calls: usize,
        delay: Duration,
    }
    impl Write for SlowOneByteWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            self.calls += 1;
            thread::sleep(self.delay);
            Ok(1)
        }
        fn write_vectored(&mut self, bufs: &[std::io::IoSlice<'_>]) -> std::io::Result<usize> {
            if bufs.iter().all(|b| b.is_empty()) {
                return Ok(0);
            }
            self.calls += 1;
            thread::sleep(self.delay);
            Ok(1)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let payload = vec![0x42u8; 512];
    let dl_dur = Duration::from_millis(160);

    // Layer A: Deterministic 1-byte-window short-write deadline checks across all 3 writers
    thread::scope(|s| {
        s.spawn(|| {
            let mut w = SlowOneByteWriter {
                calls: 0,
                delay: Duration::from_millis(15),
            };
            let t0 = Instant::now();
            let err = write_canal_block_with_deadline(&mut w, &payload, Instant::now() + dl_dur)
                .expect_err("canal block writer must abort on 1B trickle deadline");
            assert!(format!("{err:#}").contains("deadline"));
            assert!(w.calls >= 2 && w.calls < payload.len(), "calls={}", w.calls);
            assert!(t0.elapsed() <= Duration::from_millis(1500));
        });
        s.spawn(|| {
            let mut w = SlowOneByteWriter {
                calls: 0,
                delay: Duration::from_millis(15),
            };
            let t0 = Instant::now();
            let err = write_canal_parts_with_deadline(
                &mut w,
                &[&[1u8; 16], &payload[..256], &payload[256..]],
                Instant::now() + dl_dur,
            )
            .expect_err("canal parts writer must abort on 1B trickle deadline");
            assert!(format!("{err:#}").contains("deadline"));
            assert!(w.calls >= 2 && w.calls < payload.len(), "calls={}", w.calls);
            assert!(t0.elapsed() <= Duration::from_millis(1500));
        });
        s.spawn(|| {
            let mut w = SlowOneByteWriter {
                calls: 0,
                delay: Duration::from_millis(15),
            };
            let t0 = Instant::now();
            let err = write_ws_frame_with_deadline(&mut w, 0x2, &payload, Instant::now() + dl_dur)
                .expect_err("WS writer must abort on 1B trickle deadline");
            assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
            assert!(w.calls >= 2 && w.calls < payload.len(), "calls={}", w.calls);
            assert!(t0.elapsed() <= Duration::from_millis(1500));
        });
    });

    // Layer B: Real loopback TCP slow-draining reader (4 KiB / 20ms) against write_tcp_vectored_with_deadline & write_ws_frame_tcp_with_deadline
    for use_ws in [false, true] {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let mut reader = TcpStream::connect(addr).unwrap();
        shrink_rcvbuf(&reader, 4096);
        let (mut writer, _) = l.accept().unwrap();
        shrink_sndbuf(&writer, 4096);
        let _ = writer.set_nodelay(true);

        // Pre-fill kernel buffers deterministically until WouldBlock (macOS arm64 loopback can
        // autotune 2-4 MiB even after SO_SNDBUF/SO_RCVBUF hints, so 1 MiB is not always enough).
        let _ = writer.set_nonblocking(true);
        let fill = [0xAAu8; 64 * 1024];
        for _ in 0..256 {
            match writer.write(&fill) {
                Ok(0) => break,
                Ok(_) => continue,
                Err(_) => break,
            }
        }
        let _ = writer.set_nonblocking(false);

        let stop_r = Arc::new(AtomicBool::new(false));
        let sr = stop_r.clone();
        let r_join = thread::spawn(move || {
            let _ = reader.set_read_timeout(Some(Duration::from_millis(100)));
            let mut buf = [0u8; 1024];
            while !sr.load(Ordering::Acquire) {
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(_) => thread::sleep(Duration::from_millis(30)),
                    Err(_) => {}
                }
            }
        });

        let big = vec![0x5Au8; 2 * 1024 * 1024];
        let t0 = Instant::now();
        let res = if use_ws {
            write_ws_frame_tcp_with_deadline(
                &mut writer,
                0x2,
                &big,
                Instant::now() + Duration::from_millis(200),
            )
        } else {
            write_tcp_vectored_with_deadline(
                &mut writer,
                &[&big],
                Instant::now() + Duration::from_millis(200),
            )
        };
        let elapsed = t0.elapsed();
        stop_r.store(true, Ordering::Release);
        drop(writer);
        r_join.join().unwrap();

        assert!(res.is_err(), "slow-draining loopback TCP writer (use_ws={use_ws}) must hit deadline");
        assert!(
            elapsed <= Duration::from_millis(750),
            "slow-draining TCP writer (use_ws={use_ws}) took too long: {elapsed:?}"
        );
    }
}

#[test]
fn chaos_multi_client_blackhole_isolation_and_data_rst_under_tel_blackhole() {
    use idis::transport::usbmux::{serve_peertalk_stream, UsbmuxStream};

    let _wd = DeadlockWatchdog::arm(
        "chaos_multi_client_blackhole_isolation_and_data_rst_under_tel_blackhole",
        Duration::from_secs(12),
    );
    let mut cfg = base_config();
    cfg.max_extended_screens = 3;
    cfg.max_web_viewers = 4;
    cfg.web_screen_mode = Some(WebScreenMode::Independent);
    cfg.auto_accept = true;

    let mock = Arc::new(MockBackend::new());
    mock.manual_frame_mode.store(true, Ordering::Release);
    let registry = Arc::new(SessionRegistry::new(cfg.clone(), mock.clone()));
    let stop = Arc::new(AtomicBool::new(false));
    let mut wifi = start_wifi_server(cfg, mock.clone(), registry.clone(), stop.clone()).unwrap();
    let mut web = start_web_server(
        "127.0.0.1:0",
        None,
        Some("332211".to_string()),
        registry.clone(),
        LogBuffer::new(),
        stop.clone(),
    )
    .unwrap();
    let viewer_addr = web.viewer_addr().expect("viewer listener");
    let (vc, vh, _) = http_req(
        viewer_addr,
        "POST",
        "/api/view/login",
        "Content-Type: application/json\r\n",
        Some(r#"{"token":"332211"}"#),
    );
    assert_eq!(vc, 200);
    let v_cookie = extract_set_cookie(&vh);

    // 1) Blackholed USB PeerTalk iPad (tiny SO_RCVBUF, never reads, never ACKs)
    let usb_l = TcpListener::bind("127.0.0.1:0").unwrap();
    let usb_addr = usb_l.local_addr().unwrap();
    let mut bh_usb = TcpStream::connect(usb_addr).unwrap();
    shrink_rcvbuf(&bh_usb, 4096);
    let (usb_srv, _) = usb_l.accept().unwrap();
    let reg_usb = registry.clone();
    let usb_thread = thread::spawn(move || {
        let _ = serve_peertalk_stream(UsbmuxStream::Tcp(usb_srv), "usb:bh-ipad".to_string(), reg_usb);
    });
    write_pt_frame(
        &mut bh_usb,
        PT_FRAME_TYPE_TELEMETRY,
        1,
        &make_handshake_packet("bh-usb-uid", "BlackholeUsbPad", 1024, 768, "1.2"),
    )
    .unwrap();
    let ping_start = MessagePacket::new_request(
        "Ping",
        ArchivedValue::String("START".to_string()),
        5.0,
    )
    .encode()
    .unwrap();
    write_pt_frame(&mut bh_usb, PT_FRAME_TYPE_TELEMETRY, 2, &ping_start).unwrap();

    // 2) Healthy sibling Wi-Fi iPad
    let mut ok_tel = TcpStream::connect(wifi.telemetry_addr).unwrap();
    let _ = ok_tel.set_read_timeout(Some(Duration::from_secs(2)));
    write_canal_block(
        &mut ok_tel,
        &make_handshake_packet("ok-wifi-uid", "HealthyWifiPad", 1024, 768, "1.2"),
    )
    .unwrap();
    assert!(read_canal_block(&mut ok_tel).unwrap().is_some());
    let mut ok_data = TcpStream::connect(wifi.data_addr).unwrap();
    let _ = ok_data.set_read_timeout(Some(Duration::from_secs(2)));

    // 3) Blackholed Web viewer + Healthy sibling Web viewer
    let bh_ws = connect_ws_viewer(viewer_addr, Some(&v_cookie));
    shrink_rcvbuf(&bh_ws, 4096);
    let mut ok_ws = connect_ws_viewer(viewer_addr, Some(&v_cookie));

    wait_until(
        Duration::from_secs(2),
        || {
            registry.active_session_count() == 2
                && registry.active_web_viewers() == 2
                && mock.live_virtual_display_ids().len() == 3
                && mock.frame_senders.lock().unwrap().len() >= 3
        },
        "all 4 clients (blackholed USB, healthy Wi-Fi, blackholed WS, healthy WS) active",
    );

    // Push 8 large 192 KiB IDRs to all captures
    let mut big_idr = SYNTHETIC_H264_ANNEX_B.to_vec();
    big_idr.resize(192 * 1024, 0x77);
    let n_senders = mock.frame_senders.lock().unwrap().len();
    for _ in 0..8 {
        for idx in 0..n_senders {
            let _ = mock.push_frame_to(
                idx,
                EncodedFrame {
                    width: 1024,
                    height: 768,
                    bytes_per_row: 1024 * 4,
                    annex_b: big_idr.clone(),
                    is_keyframe: true,
                },
            );
        }
        thread::sleep(Duration::from_millis(10));
    }

    // Healthy Wi-Fi iPad and Healthy Web viewer MUST receive frames smoothly (zero head-of-line blocking!)
    let mut ok_ipad_frames = 0usize;
    let _ = ok_data.set_read_timeout(Some(Duration::from_millis(500)));
    for _ in 0..4 {
        if read_canal_block(&mut ok_data).ok().flatten().is_some() {
            ok_ipad_frames += 1;
        }
    }
    assert!(
        ok_ipad_frames >= 3,
        "healthy Wi-Fi iPad must not be stalled by blackholed USB/WS siblings (got {ok_ipad_frames})"
    );
    let mut ok_ws_binary = 0usize;
    let ws_dl = Instant::now() + Duration::from_secs(2);
    while ok_ws_binary < 2 && Instant::now() < ws_dl {
        match read_ws_frame(&mut ok_ws) {
            Ok((2, p)) if !p.is_empty() => ok_ws_binary += 1,
            Ok(_) => {}
            Err(_) => break,
        }
    }
    assert!(
        ok_ws_binary >= 2,
        "healthy WS sibling must not be stalled by blackholed peers (got {ok_ws_binary})"
    );

    // Evict blackholed peers via RST -> healthy siblings stay intact!
    force_tcp_rst(bh_usb);
    usb_thread.join().unwrap();
    force_tcp_rst(bh_ws);
    wait_until(
        Duration::from_secs(2),
        || {
            registry.active_session_count() == 1
                && registry.active_web_viewers() == 1
                && mock.live_virtual_display_ids().len() == 2
        },
        "blackholed siblings evicted while healthy Wi-Fi iPad + healthy WS stay online",
    );

    // Phase B: Blackhole Wi-Fi Telemetry, then RST Wi-Fi Data -> iPad VD freed promptly, Web unaffected!
    shrink_rcvbuf(&ok_tel, 4096);
    force_tcp_rst(ok_data);
    wait_until(
        Duration::from_secs(2),
        || mock.live_virtual_display_ids().len() == 1 && registry.active_session_count() == 1,
        "Wi-Fi Data RST under blackholed Telemetry must destroy iPad VD promptly while keeping Web VD",
    );
    thread::sleep(Duration::from_millis(90));
    let reaped = registry.reap_timed_out_with_limit(Duration::from_millis(60));
    assert_eq!(reaped, 1, "blackholed Telemetry must be reaped promptly");
    force_tcp_rst(ok_tel);
    force_tcp_rst(ok_ws);
    wait_until(
        Duration::from_secs(2),
        || registry.active_session_count() == 0 && registry.active_web_viewers() == 0 && mock.live_virtual_display_ids().is_empty(),
        "full clean teardown",
    );
    stop.store(true, Ordering::SeqCst);
    web.stop();
    wifi.stop();
}

#[test]
fn chaos_seeded_network_flap_storm_flow_abr_inflight_p2p() {
    use idis::abr::{AbrController, AbrTargets, AbrWindowSample, InFlightController};
    use idis::config::AbrSensitivity;
    use idis::platform::latest_frame_channel;
    use idis::session::FlowControl;
    use idis::web::fuzz_hooks::P2pRelayHub;

    let _wd = DeadlockWatchdog::arm(
        "chaos_seeded_network_flap_storm_flow_abr_inflight_p2p",
        Duration::from_secs(8),
    );
    let sensitivities = [
        AbrSensitivity::Conservative,
        AbrSensitivity::Balanced,
        AbrSensitivity::Aggressive,
    ];

    for (idx, seed) in fuzz_seeds(0xC304_F1A9, 24).into_iter().enumerate() {
        let mut rng = FuzzRng::new(seed);
        let sens = sensitivities[idx % sensitivities.len()];
        let t0 = Instant::now();
        let fc = FlowControl::new(2);
        let mut abr = AbrController::with_sensitivity(t0, sens);
        let mut ifc = InFlightController::new(false, t0);
        let hub = P2pRelayHub::new(true);

        // Register 10 viewers: 2 desktop relays (prio 2), 3 mobile relays (prio 1), 5 leaves (prio 0)
        let mut paused_flags = Vec::new();
        let mut sig_rxs = Vec::new();
        for vid in 1u64..=10 {
            let (tx, rx) = std::sync::mpsc::sync_channel::<String>(64);
            let (_ftx, frx) = latest_frame_channel();
            let paused = hub.register(vid, tx, frx.waker());
            let prio = if vid <= 2 { 2 } else if vid <= 5 { 1 } else { 0 };
            hub.on_hello_with_priority(vid, true, prio);
            paused_flags.push((vid, paused));
            sig_rxs.push((vid, rx));
        }
        hub.rebalance_at(t0);
        // Drain signaling & confirm initial P2P children
        for (vid, rx) in &sig_rxs {
            while let Ok(msg) = rx.try_recv() {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&msg) {
                    if v["type"] == "p2p_assign_parent" {
                        if let Some(pid) = v["parent_id"].as_u64() {
                            hub.on_p2p_active(*vid, pid);
                        }
                    }
                }
            }
        }

        let mut now_ms: u64 = 0;
        let mut now_inst = t0;
        let mut pending_acks: Vec<(u64, bool)> = Vec::new();
        let mut abr_reversals_flap = 0u32;
        let mut last_abr_dir: i8 = 0;
        let mut ifc_changes_flap = 0u32;

        // 4 phases: Warmup(10s) -> RapidFlap(24s) -> AckBlackhole(18s) -> CleanRecovery(135s)
        for sec in 0u64..187 {
            let phase = if sec < 10 {
                0
            } else if sec < 34 {
                1
            } else if sec < 52 {
                2
            } else {
                3
            };
            let bad_flap = phase == 1 && (sec % 2 == 1);
            let mut sent_sec = 0u64;
            let mut dropped_sec = 0u64;
            let mut blocked_sec = 0u64;
            let mut send_ms_sum = 0u64;
            let mut max_send_ms = 0u64;

            for tick in 0u64..30 {
                now_ms += 33;
                // Deliver due ACKs
                let mut still_pending = Vec::new();
                for (due, is_render) in pending_acks.drain(..) {
                    if due <= now_ms {
                        if is_render {
                            fc.on_picture_rendered_at(now_ms);
                        } else {
                            fc.on_frame_received_at(now_ms);
                        }
                    } else {
                        still_pending.push((due, is_render));
                    }
                }
                pending_acks = still_pending;

                if fc.try_acquire_send_at(now_ms, false) {
                    sent_sec += 1;
                    let sm = match (phase, bad_flap) {
                        (2, _) => rng.range_u64(110, 220),
                        (1, true) => rng.range_u64(90, 200),
                        _ => 2,
                    };
                    send_ms_sum += sm;
                    max_send_ms = max_send_ms.max(sm);
                    let drop_ack = match (phase, bad_flap) {
                        (2, _) => true,
                        (1, true) => rng.chance(6, 10),
                        _ => false,
                    };
                    if !drop_ack {
                        let rtt = match (phase, bad_flap) {
                            (1, true) => rng.range_u64(180, 260),
                            _ => rng.range_u64(10, 18),
                        };
                        let use_render = sec >= 2;
                        pending_acks.push((now_ms + rtt, use_render));
                    }
                } else {
                    blocked_sec += 1;
                    dropped_sec += 1;
                }
                assert!(
                    fc.in_flight() <= fc.max_in_flight().max(InFlightController::WIFI_MAX_WINDOW),
                    "seed=0x{seed:x} in_flight exceeded bound"
                );
                let _ = tick;
            }

            now_inst += Duration::from_secs(1);
            let sample = AbrWindowSample {
                sent_frames: sent_sec,
                dropped_frames: dropped_sec,
                avg_send_ms: if sent_sec > 0 {
                    send_ms_sum as f64 / sent_sec as f64
                } else {
                    0.0
                },
                max_send_ms,
                avg_ack_rtt_ms: fc.ewma_rtt_ms_at(now_ms),
                in_flight_saturated: fc.max_in_flight() > 0 && blocked_sec > 0,
            };

            let prev_tier = abr.tier();
            if let Some(new_tier) = abr.evaluate(&sample, now_inst) {
                let dir = if new_tier > prev_tier { 1 } else { -1 };
                if phase == 1 && last_abr_dir != 0 && dir != last_abr_dir {
                    abr_reversals_flap += 1;
                }
                last_abr_dir = dir;
            }
            let tgt = AbrTargets::compute(abr.tier(), 60, 16, 1920);
            assert_eq!(tgt.scale_pct, 100, "seed=0x{seed:x} ABR must keep constant resolution");

            if let Some(new_lim) = ifc.evaluate(&sample, tgt.fps, now_inst) {
                fc.set_max_in_flight(new_lim);
                if phase == 1 {
                    ifc_changes_flap += 1;
                }
            }
            assert!(
                (1..=InFlightController::WIFI_MAX_WINDOW).contains(&ifc.limit()),
                "seed=0x{seed:x} invalid in_flight limit {}",
                ifc.limit()
            );

            // Blackhole assertions
            if phase == 2 {
                assert!(
                    sent_sec >= 6,
                    "seed=0x{seed:x} sec={sec} FlowControl safety probe stalled (sent_sec={sent_sec})"
                );
                if sec >= 38 {
                    assert!(
                        fc.ewma_rtt_ms_at(now_ms).is_none(),
                        "seed=0x{seed:x} stale RTT must expire during blackhole"
                    );
                }
            }
            // Final 60s of CleanRecovery: zero drops and self-healed in_flight (no phantom token leak!)
            if sec >= 127 {
                assert_eq!(
                    dropped_sec, 0,
                    "seed=0x{seed:x} sec={sec} phantom in_flight leak caused drops during clean recovery"
                );
            }

            // Drive P2P hub chaos in phases 1-3
            if phase == 1 {
                let vid = 1 + (rng.next_u64() % 10);
                if vid <= 2 {
                    hub.on_hello_with_priority(vid, true, if bad_flap { 0 } else { 2 });
                } else if rng.next_bool() {
                    hub.on_p2p_fallback_at(vid, "stall_timeout", now_inst);
                    assert!(
                        !paused_flags[(vid - 1) as usize].1.load(Ordering::Acquire),
                        "seed=0x{seed:x} fallback must immediately unpause direct WS"
                    );
                }
                hub.rebalance_at(now_inst);
            } else if phase == 2 {
                for vid in 1u64..=10 {
                    hub.on_p2p_fallback_at(vid, "stall_timeout", now_inst);
                    assert!(!paused_flags[(vid - 1) as usize].1.load(Ordering::Acquire));
                }
            } else if phase == 3 && (sec == 52 || sec % 10 == 0) {
                if sec == 52 {
                    hub.on_hello_with_priority(1, true, 2);
                    hub.on_hello_with_priority(2, true, 2);
                }
                hub.rebalance_at(now_inst);
            }
            for (vid, rx) in &sig_rxs {
                while let Ok(msg) = rx.try_recv() {
                    if phase == 3 || phase == 1 {
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&msg) {
                            if v["type"] == "p2p_assign_parent" {
                                if let Some(pid) = v["parent_id"].as_u64() {
                                    hub.on_p2p_active(*vid, pid);
                                }
                            }
                        }
                    }
                }
            }
            hub.check_invariants()
                .unwrap_or_else(|e| panic!("seed=0x{seed:x} sec={sec} P2P invariant violated: {e}"));
            let sum = hub.summary(0, 0);
            assert_eq!(sum.direct_viewers + sum.p2p_viewers, sum.total_viewers);

            if sec == 51 {
                assert!(
                    abr.tier() >= 2 && ifc.limit() == 1,
                    "seed=0x{seed:x} must degrade during 18s blackhole (tier={}, lim={})",
                    abr.tier(),
                    ifc.limit()
                );
            }
        }

        assert!(
            abr_reversals_flap <= 2,
            "seed=0x{seed:x} excessive ABR oscillation during flap storm: {abr_reversals_flap}"
        );
        assert!(
            ifc_changes_flap <= 6,
            "seed=0x{seed:x} excessive InFlight thrashing during flap storm: {ifc_changes_flap}"
        );
        assert_eq!(
            abr.tier(),
            0,
            "seed=0x{seed:x} ABR must recover to Tier 0 after 135s clean link (stuck at {})",
            abr.tier()
        );
        assert!(
            ifc.limit() >= 2,
            "seed=0x{seed:x} InFlight must recover to >= 2 after clean link (stuck at {})",
            ifc.limit()
        );
        assert!(
            hub.summary(0, 0).p2p_viewers >= 4,
            "seed=0x{seed:x} P2P tree must heal after avoid_parents TTL expires (got {})",
            hub.summary(0, 0).p2p_viewers
        );
    }
}

// ============================================================================
// Iteration 4: Cross-Subsystem Zombie & Intermediate-State Chaos Tests
// ============================================================================

fn loopback_of(addr: SocketAddr) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], addr.port()))
}

fn try_http_req(
    addr: SocketAddr,
    method: &str,
    path: &str,
    extra_headers: &str,
    body: Option<&str>,
) -> Option<(u16, String, String)> {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).ok()?;
    let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = s.set_write_timeout(Some(Duration::from_secs(2)));
    let b = body.unwrap_or("");
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\n{extra_headers}Content-Length: {}\r\nConnection: close\r\n\r\n{b}",
        b.len()
    );
    s.write_all(req.as_bytes()).ok()?;
    let mut resp = Vec::new();
    let _ = s.read_to_end(&mut resp);
    if resp.is_empty() {
        return None;
    }
    let txt = String::from_utf8_lossy(&resp).to_string();
    let (head, rest) = txt.split_once("\r\n\r\n").unwrap_or((&txt, ""));
    let code = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .unwrap_or(0);
    Some((code, head.to_string(), rest.to_string()))
}

fn try_connect_ws_viewer(addr: SocketAddr, cookie: Option<&str>) -> Option<TcpStream> {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_millis(400)).ok()?;
    let _ = s.set_read_timeout(Some(Duration::from_millis(400)));
    let _ = s.set_write_timeout(Some(Duration::from_millis(400)));
    let c_hdr = cookie
        .map(|c| format!("Cookie: {c}\r\n"))
        .unwrap_or_default();
    let req = format!(
        "GET /ws/stream HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n{c_hdr}\r\n"
    );
    s.write_all(req.as_bytes()).ok()?;
    let mut resp = Vec::new();
    let mut byte = [0u8; 1];
    while !resp.ends_with(b"\r\n\r\n") {
        s.read_exact(&mut byte).ok()?;
        resp.push(byte[0]);
        if resp.len() >= 4096 {
            return None;
        }
    }
    if String::from_utf8_lossy(&resp).starts_with("HTTP/1.1 101") {
        Some(s)
    } else {
        None
    }
}

#[test]
fn chaos_lock_policy_mode_switch_capture_fault_and_rst_storm() {
    let _wd = DeadlockWatchdog::arm(
        "chaos_lock_policy_mode_switch_capture_fault_and_rst_storm",
        Duration::from_secs(14),
    );
    let mut cfg = base_config();
    cfg.auto_accept = true;
    cfg.max_extended_screens = 3;
    cfg.max_web_viewers = 4;
    cfg.on_lock = LockAction::Pause;
    cfg.on_lock_delay_secs = 0;
    cfg.fps = 60;
    cfg.web_fps = 60;
    cfg.web_screen_mode = Some(WebScreenMode::FollowIpad);

    let mock = Arc::new(MockBackend::new());
    let registry = Arc::new(SessionRegistry::new(cfg.clone(), mock.clone()));
    let stop = Arc::new(AtomicBool::new(false));
    let mut wifi = start_wifi_server(cfg, mock.clone(), registry.clone(), stop.clone()).unwrap();
    let mut web = start_web_server(
        "127.0.0.1:0",
        None,
        Some("lock1234".to_string()),
        registry.clone(),
        LogBuffer::new(),
        stop.clone(),
    )
    .unwrap();
    let admin_addr = web.addr;
    let viewer_addr = loopback_of(web.viewer_addr().expect("viewer listener"));
    let (code, hdrs, _) = http_req(
        viewer_addr,
        "POST",
        "/api/view/login",
        "Content-Type: application/json\r\n",
        Some(r#"{"token":"lock1234"}"#),
    );
    assert_eq!(code, 200);
    let v_cookie = extract_set_cookie(&hdrs);

    let seed = fuzz_seeds(0xC4A0_10C4, 1)[0];
    let barrier = Arc::new(std::sync::Barrier::new(4));

    // W0: Lock & Policy mutator
    let w0 = {
        let reg = registry.clone();
        let m = mock.clone();
        let b = barrier.clone();
        thread::spawn(move || {
            let mut rng = FuzzRng::new(seed ^ 0x9E37_79B9_7F4A_7C15);
            let actions = [LockAction::Keep, LockAction::Pause, LockAction::Disconnect];
            b.wait();
            for _ in 0..48 {
                let locked = rng.next_bool();
                m.screen_locked.store(locked, Ordering::Release);
                match rng.next_usize(4) {
                    0 => reg.on_host_screen_lock_changed(locked),
                    1 => reg.refresh_host_lock_state_now(rng.next_bool()),
                    2 => {
                        reg.set_lock_action_ipad(*rng.pick(&actions));
                        reg.set_lock_action_web(*rng.pick(&actions));
                    }
                    _ => reg.tick_host_lock_policy(),
                }
                thread::sleep(Duration::from_millis(3));
            }
        })
    };

    // W1: Mode switch & fail_next_start_capture fault injector
    let w1 = {
        let reg = registry.clone();
        let m = mock.clone();
        let b = barrier.clone();
        thread::spawn(move || {
            let mut rng = FuzzRng::new(seed ^ 0x3C6E_F372_FE94_F82B);
            let modes = [
                WebScreenMode::FollowIpad,
                WebScreenMode::Independent,
                WebScreenMode::Main,
            ];
            b.wait();
            for _ in 0..48 {
                if rng.chance(35, 100) {
                    m.fail_next_start_capture.store(true, Ordering::Release);
                }
                let _ = reg.set_web_screen_mode(*rng.pick(&modes));
                let _ = reg.web_screen_info();
                let _ = reg.current_web_stream_source();
                thread::sleep(Duration::from_millis(3));
            }
        })
    };

    // W2: iPad Wi-Fi Connect/RST storm
    let w2 = {
        let tel_addr = wifi.telemetry_addr;
        let data_addr = wifi.data_addr;
        let b = barrier.clone();
        thread::spawn(move || {
            let mut rng = FuzzRng::new(seed ^ 0x517C_C1B7_2722_0A95);
            b.wait();
            for i in 0..24 {
                if let Ok(mut tel) = TcpStream::connect_timeout(&tel_addr, Duration::from_millis(300))
                {
                    let _ = tel.set_read_timeout(Some(Duration::from_millis(120)));
                    let hs = make_handshake_packet(
                        &format!("lp-uid-{i}"),
                        "LockPad",
                        1024,
                        768,
                        "1.2",
                    );
                    let _ = write_canal_block(&mut tel, &hs);
                    let _ = read_canal_block(&mut tel);
                    let data_opt = TcpStream::connect_timeout(&data_addr, Duration::from_millis(200)).ok();
                    if let Some(mut d) = data_opt {
                        let _ = d.set_read_timeout(Some(Duration::from_millis(40)));
                        let _ = read_canal_block(&mut d);
                        if rng.next_bool() {
                            force_tcp_rst(d);
                            force_tcp_rst(tel);
                        } else {
                            force_tcp_rst(tel);
                            force_tcp_rst(d);
                        }
                    } else {
                        force_tcp_rst(tel);
                    }
                }
            }
        })
    };

    // W3: Web WS Viewer Connect/RST storm
    let w3 = {
        let vc = v_cookie.clone();
        let b = barrier.clone();
        thread::spawn(move || {
            let mut rng = FuzzRng::new(seed ^ 0x94D0_49BB_1331_11EB);
            b.wait();
            for i in 0..24 {
                if let Some(mut ws) = try_connect_ws_viewer(viewer_addr, Some(&vc)) {
                    let _ = ws.set_read_timeout(Some(Duration::from_millis(40)));
                    if rng.next_bool() {
                        let _ = send_ws_masked_frame(&mut ws, 0x9, b"p");
                    } else {
                        let _ = read_ws_frame(&mut ws);
                    }
                    force_tcp_rst(ws);
                }
                if i % 6 == 0 {
                    let (code, _, _) = http_req(admin_addr, "GET", "/api/admin/state", "", None);
                    assert_eq!(code, 200, "admin state must remain 200 OK");
                }
            }
        })
    };

    w0.join().unwrap();
    w1.join().unwrap();
    w2.join().unwrap();
    w3.join().unwrap();

    // Quiesce & clear faults
    mock.fail_next_start_capture.store(false, Ordering::Release);
    mock.screen_locked.store(false, Ordering::Release);
    registry.set_lock_action_ipad(LockAction::Pause);
    registry.set_lock_action_web(LockAction::Pause);
    registry.on_host_screen_lock_changed(false);
    registry.refresh_host_lock_state_now(false);
    registry.reap_timed_out_with_limit(Duration::from_millis(1));

    // Zero stuck lock flags!
    assert!(!registry.is_host_screen_locked());
    assert!(!registry.is_host_lock_enforced());
    assert!(!registry.is_host_lock_paused_ipad());
    assert!(!registry.is_host_lock_paused_web());
    assert!(!registry.is_ipad_lock_disconnect_blocking());
    assert!(!registry.is_web_lock_disconnect_blocking());
    assert!(!registry.is_web_lock_disconnect_admit_blocked());

    // Zero ghost VDs & zero zombies!
    wait_until(
        Duration::from_secs(2),
        || {
            registry.active_session_count() == 0
                && registry.list_sessions().is_empty()
                && registry.active_web_viewers() == 0
                && registry.list_web_viewers().is_empty()
                && registry.active_extended_screens() == 0
                && registry.current_web_stream_source() == "idle"
                && mock.live_virtual_display_ids().is_empty()
        },
        "zero ghost VDs, zero zombie sessions/viewers after lock+mode+fault+RST storm",
    );

    // Golden post-storm recovery: Independent mode + 1 iPad + 1 Web viewer = 2 live VDs!
    registry
        .set_web_screen_mode(WebScreenMode::Independent)
        .unwrap();
    let mut tel = TcpStream::connect(wifi.telemetry_addr).unwrap();
    let _ = tel.set_read_timeout(Some(Duration::from_secs(2)));
    write_canal_block(
        &mut tel,
        &make_handshake_packet("gold-lock-uid", "GoldLockPad", 1024, 768, "1.2"),
    )
    .unwrap();
    assert!(read_canal_block(&mut tel).unwrap().is_some());
    let mut data = TcpStream::connect(wifi.data_addr).unwrap();
    let _ = data.set_read_timeout(Some(Duration::from_secs(2)));
    assert!(read_canal_block(&mut data).unwrap().is_some());

    let mut ws = connect_ws_viewer(viewer_addr, Some(&v_cookie));
    let (op, _) = read_ws_frame(&mut ws).unwrap();
    assert!(op == 1 || op == 2);
    wait_until(
        Duration::from_secs(2),
        || mock.live_virtual_display_ids().len() == 2 && registry.active_web_viewers() == 1,
        "golden post-storm iPad + Independent Web active",
    );

    force_tcp_rst(ws);
    force_tcp_rst(data);
    force_tcp_rst(tel);
    wait_until(
        Duration::from_secs(2),
        || {
            registry.active_session_count() == 0
                && registry.active_web_viewers() == 0
                && mock.live_virtual_display_ids().is_empty()
        },
        "clean final teardown after golden check",
    );
    stop.store(true, Ordering::SeqCst);
    web.stop();
    wifi.stop();
}

#[test]
fn chaos_auth_rotation_dynamic_listener_low_power_preset_wifi_storm() {
    let _wd = DeadlockWatchdog::arm(
        "chaos_auth_rotation_dynamic_listener_low_power_preset_wifi_storm",
        Duration::from_secs(14),
    );
    let mut cfg = base_config();
    cfg.auto_accept = true;
    cfg.max_extended_screens = 2;
    cfg.max_web_viewers = 4;
    cfg.low_power = false;
    cfg.fps = 60;
    cfg.web_fps = 60;
    cfg.port_idle_close_secs = 0;
    cfg.web_screen_mode = Some(WebScreenMode::Independent);

    let mock = Arc::new(MockBackend::new());
    let registry = Arc::new(SessionRegistry::new(cfg, mock.clone()));
    let stop = Arc::new(AtomicBool::new(false));
    let mut web = start_web_server(
        "127.0.0.1:0",
        None,
        Some("init1234".to_string()),
        registry.clone(),
        LogBuffer::new(),
        stop.clone(),
    )
    .unwrap();
    let admin_addr = web.addr;
    let wifi_ctrl = web.wifi_controller();
    let _ = wifi_ctrl.start().unwrap();

    let latest_token = Arc::new(std::sync::Mutex::new(Some("init1234".to_string())));
    let login_fails = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seed = fuzz_seeds(0xC4A0_A074, 1)[0];
    let barrier = Arc::new(std::sync::Barrier::new(4));

    // W0: Auth token rotation / disable & max_web_viewers toggle via Admin HTTP
    let w0 = {
        let lt = latest_token.clone();
        let b = barrier.clone();
        thread::spawn(move || {
            let mut rng = FuzzRng::new(seed ^ 0x1111_2222_3333_4444);
            b.wait();
            for i in 0..32 {
                let body = match i % 4 {
                    0 => {
                        let tok = format!("tokA{i:04}");
                        serde_json::json!({ "view_token": tok, "max_web_viewers": 4 }).to_string()
                    }
                    1 => serde_json::json!({ "rotate_view_token": true }).to_string(),
                    2 => serde_json::json!({ "disable_view_token": true }).to_string(),
                    _ => {
                        let mv = if rng.next_bool() { 0 } else { 4 };
                        serde_json::json!({ "view_token": format!("tokB{i:04}"), "max_web_viewers": mv }).to_string()
                    }
                };
                let (code, _, resp) = http_req(
                    admin_addr,
                    "POST",
                    "/api/admin/settings",
                    "Content-Type: application/json\r\n",
                    Some(&body),
                );
                assert_eq!(code, 200, "admin settings mutation failed: {resp}");
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&resp) {
                    let tok = v["generated_view_token"]
                        .as_str()
                        .or_else(|| v["view_token"].as_str())
                        .map(str::to_string);
                    if v["view_token_enabled"].as_bool() == Some(false) {
                        *lt.lock().unwrap() = None;
                    } else if let Some(t) = tok {
                        *lt.lock().unwrap() = Some(t);
                    }
                }
                thread::sleep(Duration::from_millis(4));
            }
        })
    };

    // W1: low_power + Preset + direct max_web_viewers mutator
    let w1 = {
        let reg = registry.clone();
        let b = barrier.clone();
        thread::spawn(move || {
            let mut rng = FuzzRng::new(seed ^ 0x5555_6666_7777_8888);
            let presets = ["日常均衡", "高清副屏", "极简省电", "网页共享"];
            b.wait();
            for _ in 0..32 {
                match rng.next_usize(3) {
                    0 => reg.set_low_power(rng.next_bool()),
                    1 => reg.set_max_web_viewers(if rng.next_bool() { 4 } else { 0 }),
                    _ => {
                        let name = *rng.pick(&presets);
                        let _ = reg.apply_preset(name);
                    }
                }
                thread::sleep(Duration::from_millis(4));
            }
        })
    };

    // W2: WifiServerController start/stop toggle + iPad RST churn
    let w2 = {
        let wc = wifi_ctrl.clone();
        let b = barrier.clone();
        thread::spawn(move || {
            let mut rng = FuzzRng::new(seed ^ 0x9999_AAAA_BBBB_CCCC);
            b.wait();
            for i in 0..20 {
                if rng.next_bool() {
                    let _ = wc.start();
                } else {
                    wc.stop();
                }
                if let Some((tel_addr, _)) = wc.addrs() {
                    if let Ok(mut s) = TcpStream::connect_timeout(&tel_addr, Duration::from_millis(60))
                    {
                        let _ = write_canal_block(
                            &mut s,
                            &make_handshake_packet(&format!("w2-{i}"), "TogglePad", 1024, 768, "1.2"),
                        );
                        force_tcp_rst(s);
                    }
                }
                thread::sleep(Duration::from_millis(4));
            }
        })
    };

    // W3: Viewer HTTP/WS churn against dynamic viewer port
    let w3 = {
        let lt = latest_token.clone();
        let lf = login_fails.clone();
        let b = barrier.clone();
        thread::spawn(move || {
            b.wait();
            let mut cached_cookie: Option<String> = None;
            for i in 0..24 {
                if let Some((200, _, body)) = try_http_req(admin_addr, "GET", "/api/admin/state", "", None)
                {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                        if let Some(vp) = v["connection"]["web_viewer_port"].as_u64() {
                            if vp > 0 {
                                let vaddr = SocketAddr::from(([127, 0, 0, 1], vp as u16));
                                let _ = try_http_req(vaddr, "GET", "/api/view/status", "", None);
                                if lf.load(Ordering::Acquire) < 3 {
                                    let tok_opt = lt.lock().unwrap().clone();
                                    if let Some(tok) = tok_opt {
                                        let payload = serde_json::json!({ "token": tok }).to_string();
                                        if let Some((c, h, _)) = try_http_req(
                                            vaddr,
                                            "POST",
                                            "/api/view/login",
                                            "Content-Type: application/json\r\n",
                                            Some(&payload),
                                        ) {
                                            if c == 200 {
                                                let ck = extract_set_cookie(&h);
                                                if !ck.is_empty() {
                                                    cached_cookie = Some(ck);
                                                }
                                            } else if c == 401 {
                                                lf.fetch_add(1, Ordering::AcqRel);
                                            }
                                        }
                                    }
                                }
                                if let Some(ref ck) = cached_cookie {
                                    if let Some(ws) = try_connect_ws_viewer(vaddr, Some(ck)) {
                                        force_tcp_rst(ws);
                                    }
                                }
                            }
                        }
                    }
                }
                if i % 4 == 0 {
                    thread::sleep(Duration::from_millis(5));
                }
            }
        })
    };

    w0.join().unwrap();
    w1.join().unwrap();
    w2.join().unwrap();
    w3.join().unwrap();

    // Post-storm strict listener oracle!
    let (code, _, body) = http_req(admin_addr, "GET", "/api/admin/state", "", None);
    assert_eq!(code, 200);
    let st: serde_json::Value = serde_json::from_str(&body).unwrap();
    let tok_enabled = st["settings"]["view_token_enabled"].as_bool().unwrap();
    let listener_reported = st["connection"]["web_viewer_listening"].as_bool().unwrap();
    let want_open = registry.max_web_viewers() > 0 && tok_enabled && !registry.is_low_power();
    assert_eq!(
        web.viewer_addr().is_some(),
        want_open,
        "viewer_addr() must strictly match (max_web_viewers>0 && view_token_enabled && !low_power); max_web={} tok={} low_power={}",
        registry.max_web_viewers(),
        tok_enabled,
        registry.is_low_power()
    );
    assert_eq!(listener_reported, want_open);
    if registry.is_low_power() {
        assert_eq!(registry.max_web_viewers(), 0);
        assert!(web.viewer_addr().is_none());
        assert!(!registry.is_p2p_relay_enabled());
    }

    // Full 2x2 truth table + low_power reversibility
    registry.set_low_power(false);
    let _ = http_req(
        admin_addr,
        "POST",
        "/api/admin/settings",
        "Content-Type: application/json\r\n",
        Some(r#"{"disable_view_token":true,"max_web_viewers":0}"#),
    );
    assert!(web.viewer_addr().is_none(), "(0, None) must close viewer");

    let _ = http_req(
        admin_addr,
        "POST",
        "/api/admin/settings",
        "Content-Type: application/json\r\n",
        Some(r#"{"max_web_viewers":4}"#),
    );
    assert!(web.viewer_addr().is_none(), "(4, None) must keep viewer closed");

    let _ = http_req(
        admin_addr,
        "POST",
        "/api/admin/settings",
        "Content-Type: application/json\r\n",
        Some(r#"{"view_token":"gold5678","max_web_viewers":0}"#),
    );
    assert!(web.viewer_addr().is_none(), "(0, Some) must keep viewer closed");

    let _ = http_req(
        admin_addr,
        "POST",
        "/api/admin/settings",
        "Content-Type: application/json\r\n",
        Some(r#"{"view_token":"gold5678","max_web_viewers":4}"#),
    );
    assert!(web.viewer_addr().is_some(), "(4, Some) must open viewer");

    registry.set_low_power(true);
    assert_eq!(registry.max_web_viewers(), 0);
    assert!(web.viewer_addr().is_none(), "low_power=true must close viewer listener");
    registry.set_low_power(false);
    assert_eq!(registry.max_web_viewers(), 4);
    assert!(web.viewer_addr().is_some(), "low_power=false must restore viewer listener");

    // Zero leaks + golden recovery
    registry.reap_timed_out_with_limit(Duration::from_millis(1));
    wait_until(
        Duration::from_secs(2),
        || {
            registry.active_session_count() == 0
                && registry.active_web_viewers() == 0
                && mock.live_virtual_display_ids().is_empty()
        },
        "zero leaks after auth/listener/low_power/preset/wifi storm",
    );

    let (tel_addr, data_addr) = wifi_ctrl.start().unwrap();
    let vaddr = loopback_of(web.viewer_addr().unwrap());
    let (vc, vh, _) = http_req(
        vaddr,
        "POST",
        "/api/view/login",
        "Content-Type: application/json\r\n",
        Some(r#"{"token":"gold5678"}"#),
    );
    assert_eq!(vc, 200);
    let gold_cookie = extract_set_cookie(&vh);
    let mut ws = connect_ws_viewer(vaddr, Some(&gold_cookie));
    let (op, _) = read_ws_frame(&mut ws).unwrap();
    assert!(op == 1 || op == 2);

    let mut tel = TcpStream::connect(tel_addr).unwrap();
    let _ = tel.set_read_timeout(Some(Duration::from_secs(2)));
    write_canal_block(
        &mut tel,
        &make_handshake_packet("gold-auth-uid", "GoldAuthPad", 1024, 768, "1.2"),
    )
    .unwrap();
    assert!(read_canal_block(&mut tel).unwrap().is_some());
    let mut data = TcpStream::connect(data_addr).unwrap();
    let _ = data.set_read_timeout(Some(Duration::from_secs(2)));
    assert!(read_canal_block(&mut data).unwrap().is_some());

    force_tcp_rst(ws);
    force_tcp_rst(data);
    force_tcp_rst(tel);
    wait_until(
        Duration::from_secs(2),
        || {
            registry.active_session_count() == 0
                && registry.active_web_viewers() == 0
                && mock.live_virtual_display_ids().is_empty()
        },
        "clean post-golden teardown",
    );

    let last_vaddr = web.viewer_addr().unwrap();
    let last_wifi = wifi_ctrl.addrs().unwrap();
    stop.store(true, Ordering::SeqCst);
    web.stop();
    assert!(web.viewer_addr().is_none());
    assert!(!wifi_ctrl.is_running());
    assert!(wifi_ctrl.addrs().is_none());
    let _lv = TcpListener::bind(loopback_of(last_vaddr)).expect("viewer port released");
    let _lt = TcpListener::bind(last_wifi.0).expect("wifi tel port released");
    let _ld = TcpListener::bind(last_wifi.1).expect("wifi data port released");
}

#[test]
fn chaos_standalone_virtual_display_window_routing_and_close_all_race() {
    use idis::platform::{DesktopWindowInfo, WindowMoveLayout};
    use idis::session::MAX_STANDALONE_VIRTUAL_DISPLAYS;
    use idis::user_config::{WindowRouteTarget, WindowRule};

    let _wd = DeadlockWatchdog::arm(
        "chaos_standalone_virtual_display_window_routing_and_close_all_race",
        Duration::from_secs(12),
    );
    for seed in fuzz_seeds(0xC4A0_5D03, 2) {
        let mut cfg = base_config();
        cfg.on_lock_delay_secs = 0;
        let mock = Arc::new(MockBackend::new());
        *mock.mock_windows.lock().unwrap() = vec![
            DesktopWindowInfo {
                window_id: 101,
                pid: 1001,
                app_name: "Safari".into(),
                bundle_id: "com.apple.Safari".into(),
                title: "Docs".into(),
                x: 100,
                y: 100,
                width: 900,
                height: 600,
                layer: 0,
                is_floating: false,
                display_id: 1,
            },
            DesktopWindowInfo {
                window_id: 102,
                pid: 1002,
                app_name: "Notion".into(),
                bundle_id: "notion.id".into(),
                title: "Notes".into(),
                x: 150,
                y: 120,
                width: 800,
                height: 500,
                layer: 3,
                is_floating: true,
                display_id: 1,
            },
            DesktopWindowInfo {
                window_id: 103,
                pid: 1003,
                app_name: "Terminal".into(),
                bundle_id: "com.apple.Terminal".into(),
                title: "bash".into(),
                x: 200,
                y: 140,
                width: 700,
                height: 450,
                layer: 0,
                is_floating: false,
                display_id: 1,
            },
        ];
        let registry = Arc::new(SessionRegistry::new(cfg, mock.clone()));
        let barrier = Arc::new(std::sync::Barrier::new(4));

        // W0: Standalone VD create/remove storm
        let w0 = {
            let reg = registry.clone();
            let b = barrier.clone();
            thread::spawn(move || {
                let mut rng = FuzzRng::new(seed ^ 0xA1A1_B2B2_C3C3_D4D4);
                let names = ["Work", "Aux", "", "Tab\nBad"];
                let sizes = [(0u32, 0u32), (320, 240), (1280, 720), (1920, 1080)];
                b.wait();
                for _ in 0..80 {
                    if rng.next_bool() {
                        let name = *rng.pick(&names);
                        let (w, h) = *rng.pick(&sizes);
                        let _ = reg.create_standalone_virtual_display(name, w, h);
                    } else {
                        let list = reg.list_standalone_virtual_displays();
                        if let Some(vd) = list.first() {
                            let _ = reg.remove_standalone_virtual_display(vd.id);
                        }
                    }
                    assert!(
                        reg.list_standalone_virtual_displays().len() <= MAX_STANDALONE_VIRTUAL_DISPLAYS
                    );
                }
            })
        };

        // W1: Window rules & target screens storm
        let w1 = {
            let reg = registry.clone();
            let b = barrier.clone();
            thread::spawn(move || {
                let mut rng = FuzzRng::new(seed ^ 0xE5E5_F6F6_1717_2828);
                b.wait();
                for i in 0..80 {
                    let rule_id = format!("r-{}", i % 3);
                    if rng.chance(2, 3) {
                        let target = match rng.next_usize(3) {
                            0 => WindowRouteTarget::AnyVirtual,
                            1 => WindowRouteTarget::VirtualName {
                                name: "Work".to_string(),
                            },
                            _ => WindowRouteTarget::MainDisplay,
                        };
                        let _ = reg.upsert_window_rule(WindowRule {
                            id: rule_id,
                            enabled: true,
                            app_name: if rng.next_bool() { "Notion".into() } else { "Safari".into() },
                            bundle_id: String::new(),
                            title_contains: String::new(),
                            floating_only: rng.next_bool(),
                            target,
                            layout: if rng.next_bool() {
                                WindowMoveLayout::FillScreen
                            } else {
                                WindowMoveLayout::KeepSize
                            },
                        });
                    } else {
                        let _ = reg.delete_window_rule(&rule_id);
                    }
                    let _ = reg.apply_window_rules_now();
                    let _ = reg.tick_window_rules();
                    let _ = reg.has_active_window_routing_work();
                    let targets = reg.list_target_screens();
                    let mut seen = std::collections::HashSet::new();
                    for t in &targets {
                        assert!(seen.insert(t.display_id), "duplicate display_id in list_target_screens");
                    }
                }
            })
        };

        // W2: Accessibility & Lock mutator + window reset
        let w2 = {
            let reg = registry.clone();
            let m = mock.clone();
            let b = barrier.clone();
            thread::spawn(move || {
                let mut rng = FuzzRng::new(seed ^ 0x3939_4A4A_5B5B_6C6C);
                b.wait();
                for _ in 0..80 {
                    m.accessibility_granted
                        .store(rng.next_bool(), Ordering::Release);
                    let locked = rng.next_bool();
                    m.screen_locked.store(locked, Ordering::Release);
                    reg.on_host_screen_lock_changed(locked);
                    if let Ok(mut ws) = m.mock_windows.lock() {
                        for win in ws.iter_mut() {
                            win.display_id = 1;
                        }
                    }
                }
            })
        };

        // W3: close_all() & shutdown_all_virtual_displays() race hammer!
        let w3 = {
            let reg = registry.clone();
            let b = barrier.clone();
            thread::spawn(move || {
                b.wait();
                for i in 0..80 {
                    if i % 2 == 0 {
                        reg.close_all();
                    } else {
                        reg.shutdown_all_virtual_displays();
                    }
                }
            })
        };

        w0.join().unwrap();
        w1.join().unwrap();
        w2.join().unwrap();
        w3.join().unwrap();

        // Final close_all MUST leave 0 standalone VDs & 0 ghost VDs in backend!
        registry.close_all();
        assert!(
            registry.list_standalone_virtual_displays().is_empty(),
            "seed=0x{seed:x} standalone VDs leaked after close_all"
        );
        assert!(!registry.has_standalone_virtual_displays());
        assert!(
            mock.live_virtual_display_ids().is_empty(),
            "seed=0x{seed:x} ghost virtual displays leaked in MockBackend after close_all: {:?}",
            mock.live_virtual_display_ids()
        );

        // Golden post-storm routing recovery & lock/accessibility gate checks
        for old_id in ["r-0", "r-1", "r-2"] {
            let _ = registry.delete_window_rule(old_id);
        }
        mock.screen_locked.store(false, Ordering::Release);
        registry.on_host_screen_lock_changed(false);
        mock.accessibility_granted.store(true, Ordering::Release);
        for w in mock.mock_windows.lock().unwrap().iter_mut() {
            w.display_id = 1;
        }
        let vd = registry
            .create_standalone_virtual_display("GoldenVD", 1280, 720)
            .unwrap();
        assert!(mock.live_virtual_display_ids().contains(&vd.display_id));
        registry
            .upsert_window_rule(WindowRule {
                id: "golden-rule".into(),
                enabled: true,
                app_name: "Notion".into(),
                bundle_id: String::new(),
                title_contains: String::new(),
                floating_only: true,
                target: WindowRouteTarget::VirtualName {
                    name: "GoldenVD".into(),
                },
                layout: WindowMoveLayout::FillScreen,
            })
            .unwrap();

        // Locked host skips tick_window_rules cleanly
        for w in mock.mock_windows.lock().unwrap().iter_mut() {
            w.display_id = 1;
        }
        mock.screen_locked.store(true, Ordering::Release);
        registry.on_host_screen_lock_changed(true);
        let lock_rep = registry.tick_window_rules().unwrap();
        assert_eq!(lock_rep.moved, 0);
        assert_eq!(lock_rep.failed, 0);

        // Missing accessibility fails cleanly
        for w in mock.mock_windows.lock().unwrap().iter_mut() {
            w.display_id = 1;
        }
        mock.screen_locked.store(false, Ordering::Release);
        registry.on_host_screen_lock_changed(false);
        mock.accessibility_granted.store(false, Ordering::Release);
        let no_ax_rep = registry.apply_window_rules_now().unwrap();
        assert_eq!(no_ax_rep.moved, 0);
        assert!(no_ax_rep.failed >= 1);

        // Restored accessibility routes floating Notion window onto GoldenVD at 1280x720
        mock.accessibility_granted.store(true, Ordering::Release);
        let ok_rep = registry.apply_window_rules_now().unwrap();
        assert!(ok_rep.moved >= 1 && ok_rep.failed == 0);
        {
            let ws = mock.mock_windows.lock().unwrap();
            let notion = ws.iter().find(|w| w.window_id == 102).unwrap();
            assert_eq!(notion.display_id, vd.display_id);
            assert_eq!(notion.width, 1280);
            assert_eq!(notion.height, 720);
        }

        registry.close_all();
        assert!(registry.list_standalone_virtual_displays().is_empty());
        assert!(mock.live_virtual_display_ids().is_empty());
    }
}
