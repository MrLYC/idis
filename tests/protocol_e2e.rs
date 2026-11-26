use idis::config::{AppConfig, CaptureMode};
use idis::platform::mock::{MockBackend, SYNTHETIC_H264_ANNEX_B};
use idis::protocol::framing::{
    read_canal_block, read_pt_frame, write_canal_block, write_pt_frame, PT_FRAME_TYPE_DATA,
    PT_FRAME_TYPE_TELEMETRY,
};
use idis::protocol::keyed_archive::{archive, ArchivedValue};
use idis::protocol::messages::{InputEvent, MessagePacket, MessageType};
use idis::protocol::video::{parse_video_header, COMPRESSION_H264};
use idis::session::{ConfirmDecision, SessionRegistry};
use idis::transport::usbmux::{serve_peertalk_stream, UsbmuxStream};
use idis::transport::wifi::start_wifi_server;
use std::collections::BTreeMap;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn test_config() -> AppConfig {
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
        on_lock: idis::config::LockAction::Pause,
        on_lock_ipad: None,
        on_lock_web: None,
        on_lock_delay_secs: 10,
        display_id: 0,
        capture_rect: None,
        encoder: "libx264".to_string(),
        ffmpeg_path: "ffmpeg".to_string(),
        bind_addr: "127.0.0.1".to_string(),
        telemetry_port: 0,
        data_port: 0,
        host_name: "TestHost".to_string(),
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
        max_web_viewers: 0,
        idle_exit_secs: 300,
        port_idle_close_secs: 300,
        auto_accept: true,
        no_confirm: false,
        trust_usb: false,
        require_usb_confirm: false,
        low_power: false,
        no_low_power: false,
        ping_timeout_secs: 20,
        max_in_flight: idis::config::MaxInFlight::Fixed(3),
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

fn make_handshake_packet(w: i64, h: i64, proto: &str) -> Vec<u8> {
    make_handshake_packet_custom("ipad-air-test-uid", "iPad Air", w, h, proto)
}

fn make_handshake_packet_custom(
    uid: &str,
    name: &str,
    w: i64,
    h: i64,
    proto: &str,
) -> Vec<u8> {
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
        ArchivedValue::String("12.5.7".to_string()),
    );
    dict.insert(
        "clientVersion".to_string(),
        ArchivedValue::String("3.3.0".to_string()),
    );
    dict.insert(
        "clientDataProtocolVersionKey".to_string(),
        ArchivedValue::String(proto.to_string()),
    );
    dict.insert(
        "clientOrientationKey".to_string(),
        ArchivedValue::Int(if w > h { 1 } else { 0 }),
    );
    dict.insert("screenWidth".to_string(), ArchivedValue::Int(w));
    dict.insert("screenHeight".to_string(), ArchivedValue::Int(h));
    dict.insert(
        "MSMClientTelemetryCursorSupportedKey".to_string(),
        ArchivedValue::Bool(false),
    );
    MessagePacket::new_send("Handshake", ArchivedValue::Dict(dict))
        .encode()
        .unwrap()
}

fn make_touch_event_bytes(phase: i64, x: f64, y: f64) -> Vec<u8> {
    let mut tf = BTreeMap::new();
    tf.insert("_phase".to_string(), ArchivedValue::Int(phase));
    tf.insert("_tapCount".to_string(), ArchivedValue::Int(1));
    tf.insert("_location.x".to_string(), ArchivedValue::Real(x));
    tf.insert("_location.y".to_string(), ArchivedValue::Real(y));
    let touch = ArchivedValue::Object {
        class_name: "MSMTouch".to_string(),
        classes: vec!["MSMTouch".to_string(), "NSObject".to_string()],
        fields: tf,
    };
    let mut ef = BTreeMap::new();
    ef.insert("_subtype".to_string(), ArchivedValue::Int(0));
    ef.insert("_allTouches".to_string(), ArchivedValue::Set(vec![touch]));
    let ev = ArchivedValue::Object {
        class_name: "MSMTouchEvent".to_string(),
        classes: vec![
            "MSMTouchEvent".to_string(),
            "MSMEvent".to_string(),
            "NSObject".to_string(),
        ],
        fields: ef,
    };
    archive(&ev).unwrap()
}

#[test]
fn wifi_full_session_handshake_stream_ping_and_input() {
    let cfg = test_config();
    let backend = Arc::new(MockBackend::new());
    let registry = Arc::new(SessionRegistry::new(cfg.clone(), backend.clone()));
    let stop = Arc::new(AtomicBool::new(false));

    let mut srv = start_wifi_server(cfg, backend.clone(), registry.clone(), stop.clone()).unwrap();

    let mut tel = TcpStream::connect(srv.telemetry_addr).unwrap();
    tel.set_read_timeout(Some(Duration::from_secs(3))).unwrap();

    write_canal_block(&mut tel, &make_handshake_packet(1024, 768, "5")).unwrap();

    let ac_bytes = read_canal_block(&mut tel).unwrap().unwrap();
    let ac = MessagePacket::decode(&ac_bytes).unwrap();
    assert_eq!(ac.msg_type, MessageType::Send);
    assert_eq!(ac.name_method, "AccessConfirmed");
    let ac_dict = ac.param.as_dict().unwrap();
    assert_eq!(ac_dict.get("isAccess").and_then(|v| v.as_bool()), Some(true));
    let srv_info = ac_dict.get("serverInfo").unwrap().as_dict().unwrap();
    assert_eq!(
        srv_info
            .get("hostDataProtocolVersionKey")
            .and_then(|v| v.as_str()),
        Some("5")
    );

    let port_bytes = read_canal_block(&mut tel).unwrap().unwrap();
    let port_pkt = MessagePacket::decode(&port_bytes).unwrap();
    assert_eq!(port_pkt.name_method, "VideoServiceAccessibleOnPort");
    let data_port = port_pkt.param.as_u64().unwrap() as u16;
    assert_eq!(data_port, srv.data_addr.port());

    let mut data = TcpStream::connect(("127.0.0.1", data_port)).unwrap();
    data.set_read_timeout(Some(Duration::from_secs(3))).unwrap();

    let frame_bytes = read_canal_block(&mut data).unwrap().unwrap();
    let hdr = parse_video_header(&frame_bytes).unwrap();
    assert_eq!(hdr.header_len, 17);
    assert_eq!(hdr.width, 1024);
    assert_eq!(hdr.height, 768);
    assert_eq!(hdr.compression, COMPRESSION_H264);
    assert_eq!(hdr.bytes_per_row, Some(4096));
    assert_eq!(&frame_bytes[hdr.payload_offset..], SYNTHETIC_H264_ANNEX_B);

    let ping = MessagePacket::new_request("Ping", ArchivedValue::Null, 5.0);
    write_canal_block(&mut tel, &ping.encode().unwrap()).unwrap();
    let pong_bytes = read_canal_block(&mut tel).unwrap().unwrap();
    let pong = MessagePacket::decode(&pong_bytes).unwrap();
    assert_eq!(pong.msg_type, MessageType::Response);
    assert_eq!(pong.name_method, "Ping");
    assert!(matches!(pong.result, ArchivedValue::Date(_)));

    let touch_bytes = make_touch_event_bytes(0, 512.0, 384.0);
    write_canal_block(&mut data, &touch_bytes).unwrap();

    // Rotate Landscape (1) -> Portrait (0) -> back to Landscape ("1" string form)
    let orient_portrait = MessagePacket::new_send("OrientationChange", ArchivedValue::Int(0));
    write_canal_block(&mut tel, &orient_portrait.encode().unwrap()).unwrap();
    thread::sleep(Duration::from_millis(80));

    let orient_landscape =
        MessagePacket::new_send("OrientationChange", ArchivedValue::String("1".to_string()));
    write_canal_block(&mut tel, &orient_landscape.encode().unwrap()).unwrap();

    thread::sleep(Duration::from_millis(150));
    let inputs = backend.recorded_inputs.lock().unwrap().clone();
    assert!(
        inputs.contains(&InputEvent::MouseDown {
            x: 512.0,
            y: 384.0,
            right_click: false,
            tap_count: 1,
        }),
        "expected touch event, got {inputs:?}"
    );
    let resizes = backend.recorded_resizes.lock().unwrap().clone();
    assert!(
        resizes.contains(&(768, 1024)),
        "expected portrait orientation resize to 768x1024, got {resizes:?}"
    );
    assert!(
        resizes.contains(&(1024, 768)),
        "expected landscape orientation resize back to 1024x768, got {resizes:?}"
    );

    drop(data);
    drop(tel);
    stop.store(true, Ordering::SeqCst);
    registry.close_all();
    srv.stop();
}

#[test]
fn usb_peertalk_multiplexed_handshake_ping_start_and_stream() {
    let cfg = test_config();
    let backend = Arc::new(MockBackend::new());
    let registry = Arc::new(SessionRegistry::new(cfg, backend.clone()));

    // Cross-platform loopback TCP pair (works on macOS, Linux, and Windows!)
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let mut client_sock = TcpStream::connect(addr).unwrap();
    let (server_sock, _) = listener.accept().unwrap();
    client_sock
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();

    let reg_bg = registry.clone();
    let srv_thread = thread::spawn(move || {
        let _ = serve_peertalk_stream(
            UsbmuxStream::Tcp(server_sock),
            "127.0.0.1:usb-test".to_string(),
            reg_bg,
        );
    });

    write_pt_frame(
        &mut client_sock,
        PT_FRAME_TYPE_TELEMETRY,
        1,
        &make_handshake_packet(1024, 768, "5"),
    )
    .unwrap();

    let f1 = read_pt_frame(&mut client_sock).unwrap().unwrap();
    assert_eq!(f1.frame_type, PT_FRAME_TYPE_TELEMETRY);
    assert_eq!(
        MessagePacket::decode(&f1.payload).unwrap().name_method,
        "AccessConfirmed"
    );

    let f2 = read_pt_frame(&mut client_sock).unwrap().unwrap();
    assert_eq!(f2.frame_type, PT_FRAME_TYPE_TELEMETRY);
    assert_eq!(
        MessagePacket::decode(&f2.payload).unwrap().name_method,
        "VideoServiceAccessibleOnPort"
    );

    let ping_start = MessagePacket::new_request(
        "Ping",
        ArchivedValue::String("START".to_string()),
        5.0,
    );
    write_pt_frame(
        &mut client_sock,
        PT_FRAME_TYPE_TELEMETRY,
        2,
        &ping_start.encode().unwrap(),
    )
    .unwrap();

    let mut got_pong = false;
    let mut got_video = false;
    for _ in 0..10 {
        let f = read_pt_frame(&mut client_sock).unwrap().unwrap();
        if f.frame_type == PT_FRAME_TYPE_TELEMETRY {
            let p = MessagePacket::decode(&f.payload).unwrap();
            if p.name_method == "Ping" && p.msg_type == MessageType::Response {
                got_pong = true;
            }
        } else if f.frame_type == PT_FRAME_TYPE_DATA {
            let h = parse_video_header(&f.payload).unwrap();
            assert_eq!(h.compression, COMPRESSION_H264);
            assert_eq!(h.width, 1024);
            assert_eq!(h.height, 768);
            got_video = true;
        }
        if got_pong && got_video {
            break;
        }
    }
    assert!(got_pong, "did not receive USB Ping response");
    assert!(got_video, "did not receive USB H.264 frame on PT type 101");

    write_pt_frame(
        &mut client_sock,
        PT_FRAME_TYPE_DATA,
        3,
        &make_touch_event_bytes(1, 200.0, 150.0),
    )
    .unwrap();
    thread::sleep(Duration::from_millis(120));

    let inputs = backend.recorded_inputs.lock().unwrap().clone();
    assert!(inputs.contains(&InputEvent::MouseDragged { x: 200.0, y: 150.0 }));

    drop(client_sock);
    let _ = srv_thread.join();
    registry.close_all();
}

#[test]
fn wifi_access_control_declines_non_whitelisted_fingerprint_and_reaps_timeout() {
    let mut cfg = test_config();
    cfg.auto_accept = false;
    cfg.no_confirm = true;
    cfg.allow_fingerprints = vec!["fp:000000000000000000000001".to_string()];
    let backend = Arc::new(MockBackend::new());
    let registry = Arc::new(SessionRegistry::new(cfg.clone(), backend.clone()));
    let stop = Arc::new(AtomicBool::new(false));
    let mut srv = start_wifi_server(cfg, backend, registry.clone(), stop.clone()).unwrap();

    // Client whose handshake fingerprint is not in --allow-fingerprint should be declined with isAccess=false, reason=4
    let mut tel = TcpStream::connect(srv.telemetry_addr).unwrap();
    tel.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    write_canal_block(&mut tel, &make_handshake_packet(1024, 768, "5")).unwrap();
    let resp_bytes = read_canal_block(&mut tel).unwrap().unwrap();
    let resp = MessagePacket::decode(&resp_bytes).unwrap();
    assert_eq!(resp.name_method, "AccessConfirmed");
    let d = resp.param.as_dict().unwrap();
    assert_eq!(d.get("isAccess").and_then(|v| v.as_bool()), Some(false));
    assert_eq!(d.get("reason").and_then(|v| v.as_i64()), Some(4));

    // Verify timeout reaper cleans up an idle session
    let mut cfg2 = test_config();
    cfg2.ping_timeout_secs = 1;
    let backend2 = Arc::new(MockBackend::new());
    let reg2 = Arc::new(SessionRegistry::new(cfg2.clone(), backend2.clone()));
    let mut srv2 = start_wifi_server(cfg2, backend2, reg2.clone(), stop.clone()).unwrap();
    let mut tel2 = TcpStream::connect(srv2.telemetry_addr).unwrap();
    tel2.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    write_canal_block(&mut tel2, &make_handshake_packet(1024, 768, "5")).unwrap();
    let _ = read_canal_block(&mut tel2).unwrap().unwrap();
    assert_eq!(reg2.active_session_count(), 1);
    thread::sleep(Duration::from_millis(60));
    assert_eq!(reg2.reap_timed_out_with_limit(Duration::from_millis(50)), 1);
    assert_eq!(reg2.active_session_count(), 0);

    stop.store(true, Ordering::SeqCst);
    registry.close_all();
    reg2.close_all();
    srv.stop();
    srv2.stop();
}

#[test]
fn wifi_trust_confirm_persist_fingerprint_rename_and_connection_limit() {
    use idis::transport::FrameWriter;
    use std::sync::atomic::AtomicUsize;

    struct DummyWriter;
    impl FrameWriter for DummyWriter {
        fn send_frame(&self, _payload: &[u8]) -> anyhow::Result<()> {
            Ok(())
        }
        fn close(&self) {}
    }

    let trust_file = std::env::temp_dir().join(format!(
        "idis_e2e_trust_{}.txt",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&trust_file);

    // 1) First connection triggers confirmation with deterministic SHA-256 fingerprint -> AllowAndTrust persists it
    let mut cfg = test_config();
    cfg.auto_accept = false;
    cfg.max_extended_screens = 1;
    cfg.trusted_devices_file = Some(trust_file.to_string_lossy().to_string());

    let backend = Arc::new(MockBackend::new());
    let reg1 = Arc::new(SessionRegistry::new(cfg.clone(), backend.clone()));
    let prompt_count = Arc::new(AtomicUsize::new(0));
    let seen_fp = Arc::new(std::sync::Mutex::new(String::new()));
    let pc = prompt_count.clone();
    let sfp = seen_fp.clone();
    reg1.set_confirm_handler(Arc::new(move |dev| {
        pc.fetch_add(1, Ordering::SeqCst);
        assert!(dev.fingerprint.starts_with("fp:"));
        assert_eq!(dev.fingerprint.len(), 27);
        *sfp.lock().unwrap() = dev.fingerprint.clone();
        ConfirmDecision::AllowAndTrust
    }));

    let w1: Arc<dyn FrameWriter> = Arc::new(DummyWriter);
    let sid1 = reg1
        .register_telemetry("192.168.1.42".to_string(), w1.clone(), 5027, false)
        .expect("first session should register");

    reg1.handle_telemetry_bytes("192.168.1.42", &make_handshake_packet(1024, 768, "5"))
        .unwrap();
    assert!(reg1.is_authorized("192.168.1.42"));
    assert_eq!(prompt_count.load(Ordering::SeqCst), 1);
    let trusted_fp = seen_fp.lock().unwrap().clone();
    assert!(reg1.trust_store().is_trusted(Some(&trusted_fp)));

    // 2) Once an authorized session occupies max_extended_screens=1, a second distinct device is declined at handshake
    let sid_other = reg1
        .register_telemetry("192.168.1.99".to_string(), w1.clone(), 5027, false)
        .expect("pre-auth slot allows handshake inspection");
    reg1.handle_telemetry_bytes_for_session(
        "192.168.1.99",
        Some(sid_other),
        &make_handshake_packet_custom("other-ipad-uid", "Other iPad", 1024, 768, "5"),
    )
    .unwrap();
    assert!(
        !reg1.is_authorized("192.168.1.99"),
        "second distinct device must be declined when max_extended_screens=1 is occupied"
    );
    assert!(
        reg1.is_authorized("192.168.1.42"),
        "existing authorized session must remain untouched"
    );
    assert_eq!(
        prompt_count.load(Ordering::SeqCst),
        1,
        "quota-declined second device must not trigger a futile approval prompt or persist trust"
    );
    reg1.close_session_if_id("192.168.1.42", sid1);

    // 2c) --allow-ip gate rejects non-whitelisted source IPs before handshake
    let mut ip_cfg = test_config();
    ip_cfg.allow_ips = vec!["192.168.1.42".to_string()];
    let reg_ip = Arc::new(SessionRegistry::new(ip_cfg, backend.clone()));
    assert!(
        reg_ip
            .register_telemetry("192.168.1.99".to_string(), w1.clone(), 5027, false)
            .is_none(),
        "source IP outside --allow-ip must be rejected"
    );
    assert!(reg_ip
        .register_telemetry("192.168.1.42".to_string(), w1.clone(), 5027, false)
        .is_some());
    reg_ip.close_all();

    // 3) Restart with a fresh SessionRegistry loading the same trust file:
    //    same device on a new IP AND rotated orientation (portrait 768x1024) must auto-pass WITHOUT prompting!
    let reg2 = Arc::new(SessionRegistry::new(cfg.clone(), backend.clone()));
    let prompt_count2 = Arc::new(AtomicUsize::new(0));
    let pc2 = prompt_count2.clone();
    reg2.set_confirm_handler(Arc::new(move |_| {
        pc2.fetch_add(1, Ordering::SeqCst);
        ConfirmDecision::Deny
    }));

    assert!(reg2
        .register_telemetry("192.168.1.88".to_string(), w1.clone(), 5027, false)
        .is_some());
    reg2.handle_telemetry_bytes("192.168.1.88", &make_handshake_packet(768, 1024, "5"))
        .unwrap();
    assert!(
        reg2.is_authorized("192.168.1.88"),
        "persisted trusted fingerprint must auto-approve across IP change, restart, and rotation"
    );
    assert_eq!(prompt_count2.load(Ordering::SeqCst), 0);
    reg2.close_all();

    // 4) Renaming the device changes its fingerprint -> must NOT auto-pass -> triggers prompt -> Denied
    assert!(reg2
        .register_telemetry("192.168.1.77".to_string(), w1.clone(), 5027, false)
        .is_some());
    reg2.handle_telemetry_bytes(
        "192.168.1.77",
        &make_handshake_packet_custom("ipad-air-test-uid", "iPad Air Renamed", 1024, 768, "5"),
    )
    .unwrap();
    assert!(
        !reg2.is_authorized("192.168.1.77"),
        "renamed device produces a new fingerprint and must require re-trust"
    );
    assert_eq!(prompt_count2.load(Ordering::SeqCst), 1);

    // 5) Explicit interactive AllowOnce authorizes THAT session without persisting to trust store
    let reg4 = Arc::new(SessionRegistry::new(cfg.clone(), backend));
    reg4.set_confirm_handler(Arc::new(|_| ConfirmDecision::AllowOnce));
    let sid4 = reg4
        .register_telemetry("192.168.1.67".to_string(), w1.clone(), 5027, false)
        .unwrap();
    reg4.handle_telemetry_bytes_for_session(
        "192.168.1.67",
        Some(sid4),
        &make_handshake_packet_custom("temp-ipad-uid", "Guest iPad", 1024, 768, "5"),
    )
    .unwrap();
    assert!(reg4.is_authorized("192.168.1.67"));
    assert_eq!(
        reg4.trust_store().list().len(),
        1,
        "AllowOnce must not persist guest device to trust store"
    );
    assert!(reg4
        .attach_data_channel_checked("192.168.1.67", Some(sid4), w1)
        .is_ok());
    reg4.close_all();

    let _ = std::fs::remove_file(&trust_file);
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
#[test]
fn ffmpeg_pipeline_produces_valid_h264_annexb_frames() {
    use idis::platform::ffmpeg_capture::{FfmpegPipelineSpec, FfmpegProcess};
    use idis::platform::{latest_frame_channel, IPAD_MAX_PIXEL_EDGE};
    use std::process::Command;

    if Command::new("ffmpeg").arg("-version").output().is_err() {
        return; // skip if ffmpeg not installed in environment
    }

    let (tx, rx) = latest_frame_channel();
    let spec = FfmpegPipelineSpec {
        ffmpeg_path: "ffmpeg".to_string(),
        input_args: vec![
            "-f".to_string(),
            "lavfi".to_string(),
            "-i".to_string(),
            "testsrc=size=320x240:rate=15".to_string(),
            "-t".to_string(),
            "1".to_string(),
        ],
        out_width: 320,
        out_height: 240,
        max_pixel_edge: IPAD_MAX_PIXEL_EDGE,
        fps: 15,
        bitrate_mbps: 2,
        all_intra: false,
        encoder: "libx264".to_string(),
    };
    let mut proc = FfmpegProcess::spawn(&spec, tx).unwrap();
    let frame = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("expected at least one H.264 Annex-B frame from ffmpeg");
    assert_eq!(frame.width, 320);
    assert_eq!(frame.height, 240);
    // Must start with Annex-B start code + SPS NAL (0x67)
    assert!(frame.annex_b.len() > 16);
    assert_eq!(&frame.annex_b[0..4], &[0, 0, 0, 1]);
    assert_eq!(frame.annex_b[4] & 0x1F, 7, "first NAL must be SPS");

    // Verify Fmp4Muxer turns real H.264 Annex-B frames into a spec-compliant MP4 readable by ffprobe
    let mut muxer = idis::fmp4::Fmp4Muxer::new(15);
    let chunk = muxer
        .mux_frame(frame.width, frame.height, &frame.annex_b)
        .expect("Fmp4Muxer must mux real ffmpeg frame");
    let init = chunk.init_segment.expect("first frame must emit fMP4 init segment");
    let mut mp4_bytes = init;
    mp4_bytes.extend_from_slice(&chunk.media_segment);
    if let Ok(frame2) = rx.recv_timeout(Duration::from_secs(2)) {
        if let Some(chunk2) = muxer.mux_frame(frame2.width, frame2.height, &frame2.annex_b) {
            mp4_bytes.extend_from_slice(&chunk2.media_segment);
        }
    }
    proc.stop();

    if Command::new("ffprobe").arg("-version").output().is_ok() {
        let tmp_mp4 = std::env::temp_dir().join(format!("idis_fmp4_test_{}.mp4", std::process::id()));
        std::fs::write(&tmp_mp4, &mp4_bytes).unwrap();
        let probe = Command::new("ffprobe")
            .args([
                "-v",
                "error",
                "-select_streams",
                "v:0",
                "-show_entries",
                "stream=codec_name,width,height",
                "-of",
                "csv=p=0",
            ])
            .arg(&tmp_mp4)
            .output()
            .unwrap();
        let _ = std::fs::remove_file(&tmp_mp4);
        let stdout = String::from_utf8_lossy(&probe.stdout);
        let stderr = String::from_utf8_lossy(&probe.stderr);
        assert!(
            probe.status.success(),
            "ffprobe rejected generated fMP4: stderr={stderr}"
        );
        assert!(
            stdout.trim() == "h264,320,240",
            "expected ffprobe h264,320,240, got {stdout:?}"
        );
    }
}

#[test]
fn web_admin_control_and_passcode_viewer_stream() {
    use idis::web::{start_web_server, LogBuffer};
    use std::io::{Read, Write};
    use std::net::SocketAddr;

    fn http_call(
        addr: SocketAddr,
        method: &str,
        path: &str,
        cookie: Option<&str>,
        body: Option<&str>,
    ) -> (u16, Vec<String>, String) {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let b = body.unwrap_or("");
        let mut req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
            b.len()
        );
        if let Some(c) = cookie {
            req.push_str(&format!("Cookie: {c}\r\n"));
        }
        req.push_str("\r\n");
        req.push_str(b);
        s.write_all(req.as_bytes()).unwrap();
        let mut raw = Vec::new();
        let _ = s.read_to_end(&mut raw);
        let text = String::from_utf8_lossy(&raw).to_string();
        let (head, body_out) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        let mut lines = head.lines();
        let status_line = lines.next().unwrap_or("");
        let status = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|v| v.parse::<u16>().ok())
            .unwrap_or(0);
        let cookies: Vec<String> = lines
            .filter_map(|l| {
                let (k, v) = l.split_once(':')?;
                if k.eq_ignore_ascii_case("set-cookie") {
                    Some(v.trim().split(';').next().unwrap_or("").to_string())
                } else {
                    None
                }
            })
            .collect();
        (status, cookies, body_out.to_string())
    }

    fn read_ws_frame_client(s: &mut TcpStream) -> (u8, Vec<u8>) {
        let mut hdr = [0u8; 2];
        s.read_exact(&mut hdr).unwrap();
        let opcode = hdr[0] & 0x0F;
        let mut len = (hdr[1] & 0x7F) as usize;
        if len == 126 {
            let mut ext = [0u8; 2];
            s.read_exact(&mut ext).unwrap();
            len = u16::from_be_bytes(ext) as usize;
        } else if len == 127 {
            let mut ext = [0u8; 8];
            s.read_exact(&mut ext).unwrap();
            len = u64::from_be_bytes(ext) as usize;
        }
        let mut payload = vec![0u8; len];
        s.read_exact(&mut payload).unwrap();
        (opcode, payload)
    }

    let cfg = test_config();
    let backend = Arc::new(MockBackend::new());
    let registry = Arc::new(SessionRegistry::new(cfg, backend));
    let stop = Arc::new(AtomicBool::new(false));

    // 0) Default admin password policy:
    //    - Loopback bind with no admin token => empty password (passwordless loopback access)
    //    - Non-loopback bind with no admin token => auto-generated random password (401 without login)
    {
        let mut h_loop = start_web_server(
            "127.0.0.1:0",
            None,
            None,
            registry.clone(),
            LogBuffer::new(),
            stop.clone(),
        )
        .unwrap();
        assert!(h_loop.admin_token.is_none());
        assert!(!h_loop.admin_token_generated);
        let (code, _, _) = http_call(h_loop.addr, "GET", "/api/admin/state", None, None);
        assert_eq!(code, 200, "loopback bind with no admin token should default to empty password");

        // DNS Rebinding defense: forged Host header on loopback passwordless server MUST be 401!
        {
            let mut s = TcpStream::connect(h_loop.addr).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let req = format!(
                "GET /api/admin/state HTTP/1.1\r\nHost: evil.rebind.test:{}\r\n\r\n",
                h_loop.addr.port()
            );
            s.write_all(req.as_bytes()).unwrap();
            let mut raw = Vec::new();
            let _ = s.read_to_end(&mut raw);
            let text = String::from_utf8_lossy(&raw);
            assert!(
                text.starts_with("HTTP/1.1 401"),
                "loopback passwordless admin must reject DNS-rebound Host header, got: {text}"
            );
        }
        h_loop.stop();

        let mut h_lan = start_web_server(
            "0.0.0.0:0",
            None,
            None,
            registry.clone(),
            LogBuffer::new(),
            stop.clone(),
        )
        .unwrap();
        let gen_tok = h_lan
            .admin_token
            .clone()
            .expect("non-loopback bind without explicit admin token must generate a random token");
        assert!(gen_tok.len() >= 16);
        assert!(h_lan.admin_token_generated);
        let lan_loop = SocketAddr::from(([127, 0, 0, 1], h_lan.addr.port()));
        // Direct local loopback access without explicit --web-admin-token is passwordless
        let (code, _, _) = http_call(lan_loop, "GET", "/api/admin/state", None, None);
        assert_eq!(
            code, 200,
            "direct loopback access on 0.0.0.0 bind without explicit --web-admin-token should be passwordless"
        );
        let (code, _, status_body) = http_call(lan_loop, "GET", "/api/auth/status", None, None);
        assert_eq!(code, 200);
        let status_json: serde_json::Value = serde_json::from_str(&status_body).unwrap();
        assert_eq!(status_json["admin_logged_in"], true);
        assert_eq!(status_json["admin_auth_required"], false);

        // Non-loopback Host (e.g. LAN IP) or reverse-proxied request MUST still require the random token
        for raw_req in [
            format!(
                "GET /api/admin/state HTTP/1.1\r\nHost: 192.168.1.50:{}\r\nConnection: close\r\n\r\n",
                h_lan.addr.port()
            ),
            format!(
                "GET /api/admin/state HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-Forwarded-For: 192.168.1.50\r\nConnection: close\r\n\r\n",
                h_lan.addr.port()
            ),
            format!(
                "GET /api/admin/state HTTP/1.1\r\nHost: 0.0.0.0:{}\r\nConnection: close\r\n\r\n",
                h_lan.addr.port()
            ),
        ] {
            let mut s = TcpStream::connect(lan_loop).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            s.write_all(raw_req.as_bytes()).unwrap();
            let mut raw = Vec::new();
            let _ = s.read_to_end(&mut raw);
            let text = String::from_utf8_lossy(&raw);
            assert!(
                text.starts_with("HTTP/1.1 401"),
                "LAN/proxied/0.0.0.0 access without token must be 401, got: {text}"
            );
        }

        // LAN/proxied client can still authenticate using the auto-generated random token
        {
            let body = format!(r#"{{"token":"{gen_tok}"}}"#);
            let login_req = format!(
                "POST /api/admin/login HTTP/1.1\r\n\
                 Host: 192.168.1.50:{port}\r\n\
                 Origin: http://192.168.1.50:{port}\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: {len}\r\n\
                 Connection: close\r\n\r\n\
                 {body}",
                port = h_lan.addr.port(),
                len = body.len()
            );
            let mut s = TcpStream::connect(lan_loop).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            s.write_all(login_req.as_bytes()).unwrap();
            let mut raw = Vec::new();
            let _ = s.read_to_end(&mut raw);
            let text = String::from_utf8_lossy(&raw);
            assert!(
                text.starts_with("HTTP/1.1 200") && text.contains("Set-Cookie: idis_admin="),
                "LAN client must be able to log in with generated random token, got: {text}"
            );
        }
        h_lan.stop();

        // Explicit --web-admin-token on non-loopback (0.0.0.0) bind:
        // Direct localhost/127.0.0.1 access MUST stay passwordless while LAN/proxied access requires the explicit token!
        let mut h_lan_explicit = start_web_server(
            "0.0.0.0:0",
            Some("explicit-lan-pass".to_string()),
            None,
            registry.clone(),
            LogBuffer::new(),
            stop.clone(),
        )
        .unwrap();
        let lan_exp_loop = SocketAddr::from(([127, 0, 0, 1], h_lan_explicit.addr.port()));
        let (code, _, _) = http_call(lan_exp_loop, "GET", "/api/admin/state", None, None);
        assert_eq!(
            code, 200,
            "direct loopback access on 0.0.0.0 bind with explicit --web-admin-token must remain passwordless"
        );
        let (code, _, status_body) = http_call(lan_exp_loop, "GET", "/api/auth/status", None, None);
        assert_eq!(code, 200);
        let status_json: serde_json::Value = serde_json::from_str(&status_body).unwrap();
        assert_eq!(status_json["admin_logged_in"], true);
        assert_eq!(status_json["admin_auth_required"], false);
        // Non-loopback Host (e.g. LAN/Tailscale domain) or proxied request must still require explicit token
        {
            let raw_req = format!(
                "GET /api/admin/state HTTP/1.1\r\nHost: host.example.test:{}\r\nConnection: close\r\n\r\n",
                h_lan_explicit.addr.port()
            );
            let mut s = TcpStream::connect(lan_exp_loop).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            s.write_all(raw_req.as_bytes()).unwrap();
            let mut raw = Vec::new();
            let _ = s.read_to_end(&mut raw);
            let text = String::from_utf8_lossy(&raw);
            assert!(
                text.starts_with("HTTP/1.1 401"),
                "remote Host on 0.0.0.0 bind with explicit token must require login, got: {text}"
            );
        }
        h_lan_explicit.stop();
    }

    let mut web = start_web_server(
        "127.0.0.1:0",
        Some("super-admin-secret".to_string()),
        None, // viewer disabled by default
        registry.clone(),
        LogBuffer::new(),
        stop.clone(),
    )
    .unwrap();
    let addr = web.addr;

    // 1) Unauthenticated admin state must be 401
    let (code, _, _) = http_call(addr, "GET", "/api/admin/state", None, None);
    assert_eq!(code, 401);

    // 2) Wrong admin token -> 401, right admin token -> 200 + session cookie
    let (code, _, _) = http_call(addr, "POST", "/api/admin/login", None, Some(r#"{"token":"wrong"}"#));
    assert_eq!(code, 401);
    let (code, cookies, _) = http_call(
        addr,
        "POST",
        "/api/admin/login",
        None,
        Some(r#"{"token":"super-admin-secret"}"#),
    );
    assert_eq!(code, 200);
    let admin_cookie = cookies.into_iter().find(|c| c.starts_with("idis_admin=")).unwrap();

    // 3) Viewer port is closed while disabled & Admin port strictly rejects Viewer routes with 404
    assert!(
        web.viewer_addr().is_none(),
        "dynamic Web Viewer listener must stay closed while max_web_viewers=0"
    );
    let (code, _, _) = http_call(addr, "POST", "/api/view/login", None, Some(r#"{"token":"watch1234"}"#));
    assert_eq!(code, 404, "Admin port must return 404 for /api/view/login");

    // Verify /api/admin/state reports split limits (without process CPU/memory stats)
    let (code, _, state_body) = http_call(addr, "GET", "/api/admin/state", Some(&admin_cookie), None);
    assert_eq!(code, 200);
    let st_json: serde_json::Value = serde_json::from_str(&state_body).unwrap();
    assert!(st_json["host"].get("process").is_none());
    assert_eq!(st_json["settings"]["max_extended_screens"], 2);
    assert_eq!(st_json["settings"]["max_web_viewers"], 0);
    assert_eq!(st_json["connection"]["web_viewer_listening"], false);

    let (code, _, _) = http_call(
        addr,
        "POST",
        "/api/admin/settings",
        Some(&admin_cookie),
        Some(r#"{"allow_input":false,"max_extended_screens":1,"max_web_viewers":1,"max_in_flight":2,"integer_scale":true,"view_token":"watch1234"}"#),
    );
    assert_eq!(code, 200);
    assert!(!registry.is_input_allowed());
    assert_eq!(registry.max_extended_screens(), 1);
    assert_eq!(registry.max_web_viewers(), 1);
    assert_eq!(registry.max_in_flight(), 2);
    assert!(registry.video_settings().integer_scale);
    let raw_vaddr = web
        .viewer_addr()
        .expect("enabling max_web_viewers + view_token must open dynamic 0.0.0.0 viewer port");
    assert!(raw_vaddr.ip().is_unspecified());
    assert_ne!(raw_vaddr.port(), addr.port());
    let vaddr = std::net::SocketAddr::from(([127, 0, 0, 1], raw_vaddr.port()));

    // 4) Admin adds & revokes a trusted device (deterministic handshake fingerprint)
    let (code, _, _) = http_call(
        addr,
        "POST",
        "/api/admin/trusted/add",
        Some(&admin_cookie),
        Some(r#"{"name":"No FP Device"}"#),
    );
    assert_eq!(code, 400, "adding trusted device without fingerprint must fail");
    let (code, _, _) = http_call(
        addr,
        "POST",
        "/api/admin/trusted/add",
        Some(&admin_cookie),
        Some(r#"{"fingerprint":"fp:a1b2c3d4e5f60718293a4b5c","name":"Test iPad"}"#),
    );
    assert_eq!(code, 200);
    assert!(registry
        .trust_store()
        .is_trusted(Some("fp:a1b2c3d4e5f60718293a4b5c")));
    let (code, _, _) = http_call(
        addr,
        "POST",
        "/api/admin/trusted/revoke",
        Some(&admin_cookie),
        Some(r#"{"fingerprint":"fp:a1b2c3d4e5f60718293a4b5c"}"#),
    );
    assert_eq!(code, 200);
    assert!(!registry
        .trust_store()
        .is_trusted(Some("fp:a1b2c3d4e5f60718293a4b5c")));

    // 5) Viewer logs in with passcode (both POST and standalone URL `?token=xxx`) on the dedicated Viewer port and upgrades /ws/stream
    let (code, _, _) = http_call(vaddr, "POST", "/api/view/login", None, Some(r#"{"token":"badpass"}"#));
    assert_eq!(code, 401);

    // Admin token MUST NOT be accepted as standalone viewer `?token=`
    let (code, bad_cookies, _) = http_call(vaddr, "GET", "/view?token=super-admin-secret", None, None);
    assert_eq!(code, 200);
    assert!(bad_cookies.is_empty());

    // Valid standalone viewer `?token=watch1234` sets HttpOnly viewer cookie and redirects to clean `/view`
    let (code, qcookies, _) = http_call(vaddr, "GET", "/view?token=watch1234", None, None);
    assert_eq!(code, 302);
    let url_viewer_cookie = qcookies
        .into_iter()
        .find(|c| c.starts_with("idis_view="))
        .expect("valid /view?token= must set idisplay_view cookie");
    // Standalone viewer cookie must NOT grant admin privileges (401 on Admin port, 404 on Viewer port)
    let (code, _, _) = http_call(addr, "GET", "/api/admin/state", Some(&url_viewer_cookie), None);
    assert_eq!(code, 401);
    let (code, _, _) = http_call(vaddr, "GET", "/api/admin/state", Some(&url_viewer_cookie), None);
    assert_eq!(code, 404);

    let (code, vcookies, _) = http_call(
        vaddr,
        "POST",
        "/api/view/login",
        None,
        Some(r#"{"token":"watch1234"}"#),
    );
    assert_eq!(code, 200);
    let viewer_cookie = vcookies.into_iter().find(|c| c.starts_with("idis_view=")).unwrap();

    // Unauthenticated WebSocket must fail with 401 on Viewer port (and 404 on Admin port)
    let (code, _, _) = http_call(vaddr, "GET", "/ws/stream", None, None);
    assert_eq!(code, 401);
    let (code, _, _) = http_call(addr, "GET", "/ws/stream", Some(&admin_cookie), None);
    assert_eq!(code, 404);

    // Authenticated WebSocket upgrade receives JSON init + binary fMP4 init (0x01) + binary media (0x02)
    let mut ws = TcpStream::connect(vaddr).unwrap();
    ws.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let ws_req = format!(
        "GET /ws/stream HTTP/1.1\r\n\
         Host: {vaddr}\r\n\
         Origin: http://{vaddr}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Cookie: {viewer_cookie}\r\n\r\n"
    );
    ws.write_all(ws_req.as_bytes()).unwrap();
    let mut resp_buf = Vec::new();
    let mut byte = [0u8; 1];
    while !resp_buf.ends_with(b"\r\n\r\n") {
        ws.read_exact(&mut byte).unwrap();
        resp_buf.push(byte[0]);
    }
    let resp_hdr = String::from_utf8_lossy(&resp_buf);
    assert!(resp_hdr.contains("101 Switching Protocols"), "got {resp_hdr}");
    assert!(resp_hdr.contains("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));

    let (op1, p1) = read_ws_frame_client(&mut ws);
    assert_eq!(op1, 0x1, "expected JSON init text frame");
    let meta: serde_json::Value = serde_json::from_slice(&p1).unwrap();
    assert_eq!(meta["type"], "init");
    assert_eq!(meta["width"], 1280);
    assert_eq!(meta["height"], 720);
    assert_eq!(
        meta["reset"], true,
        "first init of every new WebSocket must set reset=true so reconnecting browsers reset MSE timeline"
    );

    let (op2, p2) = read_ws_frame_client(&mut ws);
    assert_eq!(op2, 0x2, "expected binary fMP4 init frame");
    assert_eq!(p2[0], 0x01);
    assert_eq!(&p2[5..9], b"ftyp");

    let (op3, p3) = read_ws_frame_client(&mut ws);
    assert_eq!(op3, 0x2, "expected binary fMP4 media frame");
    assert_eq!(p3[0], 0x02);
    assert_eq!(&p3[5..9], b"moof");

    // 5b) While 1 Web Viewer is active and max_screen_connections=1:
    //     - idle_duration() must be None (active screen connection)
    //     - a 2nd distinct Web Viewer session must be rejected with HTTP 429
    //     - HTML response CSP must allow `media-src 'self' blob:` for MSE playback
    assert!(registry.idle_duration().is_none());
    {
        let mut s = TcpStream::connect(vaddr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let req = format!("GET /view HTTP/1.1\r\nHost: {vaddr}\r\nConnection: close\r\n\r\n");
        s.write_all(req.as_bytes()).unwrap();
        let mut raw = Vec::new();
        let _ = s.read_to_end(&mut raw);
        let text = String::from_utf8_lossy(&raw);
        assert!(
            text.contains("media-src 'self' blob:"),
            "CSP must allow blob: media for MSE fMP4 playback"
        );
    }
    let ws_req2 = format!(
        "GET /ws/stream HTTP/1.1\r\n\
         Host: {vaddr}\r\n\
         Origin: http://{vaddr}\r\n\
         Cookie: {url_viewer_cookie}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\r\n"
    );
    let mut ws2 = TcpStream::connect(vaddr).unwrap();
    ws2.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    ws2.write_all(ws_req2.as_bytes()).unwrap();
    let mut resp2 = Vec::new();
    let _ = ws2.read_to_end(&mut resp2);
    let resp2_text = String::from_utf8_lossy(&resp2);
    assert!(
        resp2_text.starts_with("HTTP/1.1 429"),
        "expected 429 when max_screen_connections=1 is full for a 2nd viewer, got {resp2_text}"
    );

    // 5c) Live video quality preset & resolution hot-reconfigure from Web Admin Console
    let (code, _, body) = http_call(
        addr,
        "POST",
        "/api/admin/settings",
        Some(&admin_cookie),
        Some(r#"{"quality":"high","width":1920,"height":1080,"hidpi":2}"#),
    );
    assert_eq!(code, 200);
    let resp_json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(resp_json["video"]["width"], 1920);
    assert_eq!(resp_json["video"]["height"], 1080);
    assert_eq!(resp_json["video"]["fps"], 60);
    assert_eq!(resp_json["video"]["bitrate_mbps"], 24);
    assert_eq!(resp_json["video"]["hidpi"], 2);
    let vs = registry.video_settings();
    assert_eq!((vs.width, vs.height, vs.fps, vs.bitrate_mbps, vs.hidpi), (1920, 1080, 60, 24, 2));

    // 5d) Reset video settings back to defaults from Web Admin Console
    let (code, _, body) = http_call(
        addr,
        "POST",
        "/api/admin/settings",
        Some(&admin_cookie),
        Some(r#"{"reset_video":true}"#),
    );
    assert_eq!(code, 200);
    let reset_json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(reset_json["video"]["width"], 0);
    assert_eq!(reset_json["video"]["height"], 0);
    assert_eq!(reset_json["video"]["fps"], 30);
    assert_eq!(reset_json["video"]["bitrate_mbps"], 16);
    assert_eq!(reset_json["video"]["hidpi"], 1);
    let vs_reset = registry.video_settings();
    assert_eq!((vs_reset.width, vs_reset.height, vs_reset.fps, vs_reset.bitrate_mbps, vs_reset.hidpi), (0, 0, 30, 16, 1));

    // 6) Admin disables view token -> viewer is kicked, dedicated viewer port closes, and idle timer resumes
    let (code, _, _) = http_call(
        addr,
        "POST",
        "/api/admin/settings",
        Some(&admin_cookie),
        Some(r#"{"disable_view_token":true}"#),
    );
    assert_eq!(code, 200);
    assert!(
        web.viewer_addr().is_none(),
        "disabling view_token must immediately close the dynamic viewer port"
    );
    assert!(
        TcpStream::connect_timeout(&vaddr, Duration::from_millis(300)).is_err(),
        "closed viewer port {vaddr} must refuse new TCP connections"
    );

    drop(ws);
    thread::sleep(Duration::from_millis(80));
    let idle1 = registry
        .idle_duration()
        .expect("idle_duration must be Some once all screen connections are closed");
    assert!(idle1 >= Duration::from_millis(40));

    // Unauthenticated probe MUST NOT reset the idle-exit timer; authenticated admin access DOES reset it
    let (code, _, _) = http_call(addr, "GET", "/api/auth/status", None, None);
    assert_eq!(code, 200);
    let idle_unauth = registry.idle_duration().unwrap();
    assert!(
        idle_unauth >= idle1,
        "unauthenticated probe must NOT reset idle timer (idle1={idle1:?}, after={idle_unauth:?})"
    );
    let (code, _, _) = http_call(addr, "GET", "/api/auth/status", Some(&admin_cookie), None);
    assert_eq!(code, 200);
    let idle2 = registry.idle_duration().unwrap();
    assert!(idle2 < idle_unauth, "authenticated web HTTP access must reset idle timer");

    stop.store(true, Ordering::SeqCst);
    registry.close_all();
    web.stop();
}

#[test]
fn web_independent_screen_coexists_with_ipad_and_switches_live() {
    use idis::transport::FrameWriter;
    use std::sync::atomic::AtomicUsize;
    use std::time::Instant;

    struct CountingWriter(Arc<AtomicUsize>);
    impl FrameWriter for CountingWriter {
        fn send_frame(&self, _payload: &[u8]) -> anyhow::Result<()> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn close(&self) {}
    }

    let mut cfg = test_config();
    cfg.max_extended_screens = 2;
    cfg.max_web_viewers = 4;
    cfg.max_in_flight = idis::config::MaxInFlight::Fixed(0);
    cfg.web_width = 1280;
    cfg.web_height = 720;
    cfg.fps = 30;
    let backend = Arc::new(MockBackend::new());
    let registry = Arc::new(SessionRegistry::new(cfg, backend));

    assert!(registry.supports_independent_web_screen());
    assert!(!registry.is_web_independent_screen());

    // 1) Connect an iPad reporting 1024x768 and attach its data channel
    let tel_count = Arc::new(AtomicUsize::new(0));
    let data_count = Arc::new(AtomicUsize::new(0));
    let tel_w: Arc<dyn FrameWriter> = Arc::new(CountingWriter(tel_count));
    let data_w: Arc<dyn FrameWriter> = Arc::new(CountingWriter(data_count.clone()));
    assert!(registry
        .register_telemetry("192.168.1.20".to_string(), tel_w, 5027, false)
        .is_some());
    registry
        .handle_telemetry_bytes("192.168.1.20", &make_handshake_packet(1024, 768, "5"))
        .unwrap();
    let (_sid, _dgen) = registry
        .attach_data_channel("192.168.1.20", data_w)
        .unwrap();

    // Wait for first iPad frame to arrive on data sink
    let deadline = Instant::now() + Duration::from_secs(3);
    while data_count.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    assert!(
        data_count.load(Ordering::SeqCst) > 0,
        "iPad should receive video frames"
    );

    // 2) Subscribe Web viewer in default follow-iPad mode -> must get iPad's 1024x768 frames
    let sub = registry
        .subscribe_web_stream("127.0.0.1:50001".to_string(), None)
        .unwrap();
    let f_follow = sub
        .rx
        .recv_timeout(Duration::from_secs(2))
        .expect("Web viewer should receive iPad frame in follow mode");
    assert_eq!((f_follow.width, f_follow.height), (1024, 768));
    assert_eq!(registry.current_web_stream_source(), "ipad");
    let info_follow = registry.web_screen_info();
    assert_eq!(info_follow.source, "ipad");
    assert!(!info_follow.independent);
    assert!(info_follow.active);

    // 3) Live toggle to independent Web extended screen -> Web switches to 1280x720 while iPad keeps streaming!
    assert!(registry.set_web_independent_screen(true).unwrap());
    assert!(registry.is_web_independent_screen());
    assert_eq!(registry.current_web_stream_source(), "standalone");

    // Wait for standalone 1280x720 frame and verify NO 1024x768 iPad frames interleave afterwards
    let mut saw_standalone = false;
    let switch_deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < switch_deadline {
        if let Ok(f) = sub.rx.recv_timeout(Duration::from_millis(200)) {
            if (f.width, f.height) == (1280, 720) {
                saw_standalone = true;
                break;
            }
        }
    }
    assert!(
        saw_standalone,
        "Web viewer must switch to independent 1280x720 virtual display"
    );
    // Subsequent frames must all stay 1280x720 (no interleaving from iPad's 1024x768 stream)
    for _ in 0..3 {
        let f = sub
            .rx
            .recv_timeout(Duration::from_secs(1))
            .expect("independent Web stream should keep delivering frames");
        assert_eq!(
            (f.width, f.height),
            (1280, 720),
            "iPad frames must not interleave into independent Web stream"
        );
    }
    // Verify iPad session is still actively streaming concurrently
    let before_ipad_count = data_count.load(Ordering::SeqCst);
    thread::sleep(Duration::from_millis(120));
    let after_ipad_count = data_count.load(Ordering::SeqCst);
    assert!(
        after_ipad_count > before_ipad_count,
        "iPad stream must keep running concurrently while Web uses independent screen"
    );
    let info_indep = registry.web_screen_info();
    assert_eq!(info_indep.source, "standalone");
    assert!(info_indep.independent);
    assert!(info_indep.active);
    assert_eq!((info_indep.width, info_indep.height), (1280, 720));

    // 4) Live toggle back to follow-iPad mode -> standalone shuts down and Web immediately gets iPad 1024x768
    assert!(!registry.set_web_independent_screen(false).unwrap());
    assert_eq!(registry.current_web_stream_source(), "ipad");
    let mut saw_ipad_again = false;
    let back_deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < back_deadline {
        if let Ok(f) = sub.rx.recv_timeout(Duration::from_millis(200)) {
            if (f.width, f.height) == (1024, 768) {
                saw_ipad_again = true;
                break;
            }
        }
    }
    assert!(
        saw_ipad_again,
        "Web viewer must switch back to iPad 1024x768 stream cleanly"
    );
    for _ in 0..3 {
        let f = sub
            .rx
            .recv_timeout(Duration::from_secs(1))
            .expect("follow-iPad stream should keep delivering frames");
        assert_eq!(
            (f.width, f.height),
            (1024, 768),
            "standalone frames must not interleave after switching back to follow-iPad"
        );
    }

    drop(sub);
    registry.close_all();
}

#[test]
fn sleep_disconnect_and_reconnect_resilience() {
    use idis::protocol::framing::read_canal_block_limited_deadline;
    use idis::transport::FrameWriter;
    use std::io::Write;
    use std::time::Instant;

    struct DummyWriter {
        closed: AtomicBool,
    }
    impl FrameWriter for DummyWriter {
        fn send_frame(&self, _payload: &[u8]) -> anyhow::Result<()> {
            Ok(())
        }
        fn close(&self) {
            self.closed.store(true, Ordering::SeqCst);
        }
        fn is_peer_closed(&self) -> bool {
            self.closed.load(Ordering::SeqCst)
        }
    }

    // 1) Same-device reconnect on new DHCP IP (same MAC) & Wi-Fi -> USB switch must supersede
    //    stale session cleanly even under max_screen_connections = 1!
    let mut cfg = test_config();
    cfg.max_extended_screens = 1;
    let backend = Arc::new(MockBackend::new());
    let registry = Arc::new(SessionRegistry::new(cfg, backend));

    let w1 = Arc::new(DummyWriter {
        closed: AtomicBool::new(false),
    });
    let sid1 = registry
        .register_telemetry("192.168.1.10".to_string(), w1.clone(), 5028, false)
        .expect("initial Wi-Fi registration must succeed");
    registry
        .handle_telemetry_bytes_for_session(
            "192.168.1.10",
            Some(sid1),
            &make_handshake_packet(1024, 768, "5"),
        )
        .unwrap();
    assert!(registry.is_authorized("192.168.1.10"));
    assert_eq!(registry.total_screen_connections(), 1);

    // Same iPad roams to new DHCP IP (same handshake fingerprint) while old socket is still half-open
    let w2 = Arc::new(DummyWriter {
        closed: AtomicBool::new(false),
    });
    let sid2 = registry
        .register_telemetry("192.168.1.99".to_string(), w2.clone(), 5028, false)
        .expect("same-device reconnect from new IP must be allowed into pre-auth under max=1");
    registry
        .handle_telemetry_bytes_for_session(
            "192.168.1.99",
            Some(sid2),
            &make_handshake_packet(1024, 768, "5"),
        )
        .unwrap();
    assert!(registry.is_authorized("192.168.1.99"));
    assert!(!registry.is_authorized("192.168.1.10"));
    assert!(w1.closed.load(Ordering::SeqCst), "superseded Wi-Fi session must be closed");

    // Same iPad switches from Wi-Fi to USB (matching hs.uid) under max_screen_connections = 1
    let w_usb_t = Arc::new(DummyWriter {
        closed: AtomicBool::new(false),
    });
    let w_usb_d = Arc::new(DummyWriter {
        closed: AtomicBool::new(false),
    });
    let sid_usb = registry
        .register_usb_telemetry(
            "127.0.0.1:usb-7".to_string(),
            w_usb_t.clone(),
            w_usb_d,
            2345,
        )
        .expect("USB pre-auth must be allowed so on_handshake can supersede same device");
    registry
        .handle_telemetry_bytes_for_session(
            "127.0.0.1:usb-7",
            Some(sid_usb),
            &make_handshake_packet(1024, 768, "5"),
        )
        .unwrap();
    assert!(registry.is_authorized("127.0.0.1:usb-7"));
    assert!(!registry.is_authorized("192.168.1.99"));
    assert!(w2.closed.load(Ordering::SeqCst), "Wi-Fi session superseded by USB must be closed");

    // 2) Loopback Web viewer replacement across IPv4 127.0.0.1 <-> IPv6 [::1] under max_web_viewers = 1
    registry.close_all();
    assert!(
        registry.subscribe_web_stream("127.0.0.1:50000".to_string(), None).is_err(),
        "default max_web_viewers=0 must reject Web viewing"
    );
    registry.set_max_web_viewers(1);
    let sub_v4 = registry
        .subscribe_web_stream("127.0.0.1:50001".to_string(), None)
        .expect("initial IPv4 loopback viewer must succeed");
    let sub_v6 = registry
        .subscribe_web_stream("[::1]:50002".to_string(), None)
        .expect("IPv6 loopback reconnect must replace stale IPv4 loopback viewer under max=1");
    drop(sub_v4);
    drop(sub_v6);

    // 3) Idle pre-handshake USB session must NOT defeat idle_duration() or inflate total_screen_connections()
    let idle_usb_t = Arc::new(DummyWriter {
        closed: AtomicBool::new(false),
    });
    let idle_usb_d = Arc::new(DummyWriter {
        closed: AtomicBool::new(false),
    });
    let _ = registry.register_usb_telemetry(
        "127.0.0.1:usb-99".to_string(),
        idle_usb_t,
        idle_usb_d,
        2345,
    );
    assert_eq!(registry.total_screen_connections(), 0);
    assert!(
        registry.idle_duration().is_some(),
        "idle pre-handshake USB session must not block --idle-exit-secs"
    );

    // 4) Slowloris byte-by-byte trickle must fail at wall-clock deadline (not reset SO_RCVTIMEO)
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let trickler = thread::spawn(move || {
        let mut c = TcpStream::connect(addr).unwrap();
        let _ = c.write_all(&[10, 0, 0, 0]);
        for _ in 0..6 {
            thread::sleep(Duration::from_millis(80));
            if c.write_all(b"A").is_err() {
                break;
            }
        }
    });
    let (mut srv, _) = listener.accept().unwrap();
    let started = Instant::now();
    let res = read_canal_block_limited_deadline(
        &mut srv,
        1024,
        Instant::now() + Duration::from_millis(200),
    );
    assert!(res.is_err(), "Slowloris trickle must time out at hard deadline");
    assert!(
        started.elapsed() < Duration::from_millis(600),
        "deadline reader must abort promptly, took {:?}",
        started.elapsed()
    );
    drop(srv);
    let _ = trickler.join();

    // 5) System wake grace refreshes activity so sessions aren't instantaneously reaped
    registry.on_system_wake();
    registry.close_all();
}

#[test]
fn yaml_config_persistence_web_admin_and_debug_mode() {
    use idis::debug_trace;
    use idis::user_config::UserConfigFile;
    use idis::web::{start_web_server, LogBuffer};
    use std::io::{Read, Write};
    use std::net::SocketAddr;

    fn http_json(
        addr: SocketAddr,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> (u16, String) {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let b = body.unwrap_or("");
        let req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{b}",
            b.len()
        );
        s.write_all(req.as_bytes()).unwrap();
        let mut raw = Vec::new();
        let _ = s.read_to_end(&mut raw);
        let text = String::from_utf8_lossy(&raw).to_string();
        let (head, body_out) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        let status = head
            .lines()
            .next()
            .unwrap_or("")
            .split_whitespace()
            .nth(1)
            .and_then(|v| v.parse::<u16>().ok())
            .unwrap_or(0);
        (status, body_out.to_string())
    }

    // 1) --debug logging toggle enables debug_trace without creating a JSONL file
    debug_trace::set_debug_logging(true);
    assert!(debug_trace::is_enabled());
    assert!(debug_trace::active_path().is_none());
    debug_trace::record("test", "debug_mode_smoke", serde_json::json!({ "ok": true }));
    debug_trace::set_debug_logging(false);

    // 2) Unified YAML config file round-trip + Web Admin API management
    let cfg_path = std::env::temp_dir().join(format!(
        "idis-e2e-config-{}-{}.yaml",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_file(&cfg_path);

    let mut cfg = test_config();
    cfg.config_file = Some(cfg_path.display().to_string());
    let backend = Arc::new(MockBackend::new());
    let registry = Arc::new(SessionRegistry::new(cfg, backend));
    let stop = Arc::new(AtomicBool::new(false));
    let mut web = start_web_server(
        "127.0.0.1:0",
        None,
        None,
        registry.clone(),
        LogBuffer::new(),
        stop.clone(),
    )
    .unwrap();

    // GET /api/auth/status includes active_web_viewers so /view viewer capacity warnings work
    let (code, auth_body) = http_json(web.addr, "GET", "/api/auth/status", None);
    assert_eq!(code, 200);
    let auth_v: serde_json::Value = serde_json::from_str(&auth_body).unwrap();
    assert_eq!(auth_v["active_web_viewers"].as_u64(), Some(0));

    // GET /api/admin/config returns initial YAML, path, and config_corrupt=false
    let (code, body) = http_json(web.addr, "GET", "/api/admin/config", None);
    assert_eq!(code, 200, "GET /api/admin/config failed: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["path"].as_str(), Some(cfg_path.to_str().unwrap()));
    assert_eq!(v["config_corrupt"].as_bool(), Some(false));
    assert!(v["yaml"].as_str().unwrap().contains("trusted_devices"));

    // One-shot CLI `--allow-input` override must NEVER leak onto disk when trusting a device!
    // (test_config() sets allow_input=true while persisted baseline starts at allow_input=false)
    registry
        .trust_device_and_save("fp:12223344556677889900aabb", "u-cli-iso", "IsoPad", "iPad")
        .unwrap();
    let disk_after_cli_iso = UserConfigFile::from_yaml_str(&std::fs::read_to_string(&cfg_path).unwrap()).unwrap();
    assert!(
        !disk_after_cli_iso.allow_input,
        "one-shot CLI --allow-input must NEVER be persisted into ~/.config/idis.yaml by unrelated trust saves"
    );

    // POST /api/admin/config rejects invalid fingerprint in trusted_devices
    let bad_req = serde_json::json!({
        "yaml": "trusted_devices:\n  - fingerprint: \"-\"\n    name: BadDevice\n"
    })
    .to_string();
    let (code, _) = http_json(web.addr, "POST", "/api/admin/config", Some(&bad_req));
    assert_eq!(code, 400, "invalid fingerprint in YAML must be rejected with 400");

    // POST /api/admin/config saves & hot-applies valid YAML with trusted device + per-device prefs
    // Note: `low_power: true` enforces invariants (max_web_viewers=0, p2p_relay_enabled=false, Eco 4M/15fps).
    let valid_yaml = r#"version: 1
allow_input: true
low_power: true
p2p_relay_enabled: true
max_extended_screens: 3
max_web_viewers: 2
lock_action_ipad: disconnect
lock_action_web: pause
lock_delay_secs: 15
ipad:
  fps: 60
  bitrate_mbps: 24
  hidpi: 2
trusted_devices:
  - fingerprint: "fp:020000000001a1b2c3d4e5f6"
    name: "测试平板"
    model: "iPad"
    fps: 15
    bitrate_mbps: 4
    hidpi: 2
"#;
    let save_req = serde_json::json!({ "yaml": valid_yaml }).to_string();
    let (code, body) = http_json(web.addr, "POST", "/api/admin/config", Some(&save_req));
    assert_eq!(code, 200, "POST /api/admin/config failed: {body}");
    assert!(registry.is_low_power());
    assert!(!registry.is_p2p_relay_enabled(), "low_power invariant must force p2p_relay_enabled=false");
    assert_eq!(registry.max_extended_screens(), 3);
    assert_eq!(registry.max_web_viewers(), 0, "low_power invariant must force max_web_viewers=0");
    assert_eq!(registry.video_settings().fps, 15);
    assert_eq!(registry.video_settings().bitrate_mbps, 4);
    assert_eq!(registry.lock_delay_secs(), 15);
    assert!(registry
        .trust_store()
        .is_trusted(Some("fp:020000000001a1b2c3d4e5f6")));
    let dev = registry
        .trust_store()
        .get_device("fp:020000000001a1b2c3d4e5f6")
        .expect("trusted device must exist");
    assert_eq!(dev.prefs.fps, Some(15));
    assert_eq!(dev.prefs.bitrate_mbps, Some(4));
    assert_eq!(dev.prefs.hidpi, Some(2));
    assert!(cfg_path.exists(), "YAML config file must be written to disk");

    // Trusting another device must NEVER clobber ~/.config/idis.yaml with legacy TSV format!
    registry
        .trust_device_and_save("fp:aabbccddeeff001122334455", "u2", "TestPad", "iPad")
        .unwrap();
    let disk_after_trust = std::fs::read_to_string(&cfg_path).unwrap();
    assert!(
        disk_after_trust.contains("trusted_devices:"),
        "idis.yaml must remain valid YAML after trust_device_and_save, got:\n{disk_after_trust}"
    );
    assert!(
        !disk_after_trust.starts_with("# idis trusted devices"),
        "TrustStore must never overwrite idis.yaml with legacy TSV"
    );

    // Edit file directly on disk and POST /api/admin/config/reload (must NOT overwrite disk or clobber per-device prefs)
    let mut on_disk = UserConfigFile::from_yaml_str(&disk_after_trust).unwrap();
    on_disk.low_power = false;
    on_disk.max_web_viewers = 5;
    let custom_yaml_on_disk = on_disk.to_yaml_string().unwrap();
    std::fs::write(&cfg_path, &custom_yaml_on_disk).unwrap();
    let mtime_before = std::fs::metadata(&cfg_path).unwrap().modified().unwrap();
    std::thread::sleep(Duration::from_millis(20));
    let (code, body) = http_json(web.addr, "POST", "/api/admin/config/reload", Some("{}"));
    assert_eq!(code, 200, "POST /api/admin/config/reload failed: {body}");
    assert!(!registry.is_low_power());
    assert_eq!(registry.max_web_viewers(), 5);
    assert_eq!(
        std::fs::metadata(&cfg_path).unwrap().modified().unwrap(),
        mtime_before,
        "reload_user_config_from_disk(persist=false) must perform ZERO disk writes"
    );

    // Sanitizer must redact view_token, cookie, hyphenated MACs, and control chars
    let san = debug_trace::sanitize_log_message(
        "view_token=supersecret cookie=idis_admin=abc123 mac AA-BB-CC-DD-EE-FF \x1b[31mred",
    );
    assert!(!san.contains("supersecret"), "view_token leaked: {san}");
    assert!(!san.contains("abc123"), "cookie leaked: {san}");
    assert!(!san.contains("AA-BB-CC-DD-EE-FF"), "hyphen MAC leaked: {san}");
    assert!(!san.contains('\x1b'), "ANSI control char leaked: {san}");

    // POST /api/admin/config/reset resets global preferences while preserving trusted devices
    let (code, body) = http_json(
        web.addr,
        "POST",
        "/api/admin/config/reset",
        Some(r#"{"keep_trusted":true}"#),
    );
    assert_eq!(code, 200, "POST /api/admin/config/reset failed: {body}");
    assert_eq!(registry.max_web_viewers(), 0);
    assert_eq!(registry.max_extended_screens(), 2);
    assert!(
        registry
            .trust_store()
            .is_trusted(Some("fp:020000000001a1b2c3d4e5f6")),
        "reset with keep_trusted=true must preserve trusted devices"
    );

    stop.store(true, Ordering::SeqCst);
    registry.close_all();
    web.stop();

    // Corrupt YAML read-only protection: startup must NOT overwrite broken file on subsequent saves
    let corrupt_content = "trusted_devices: [unclosed_yaml\n";
    std::fs::write(&cfg_path, corrupt_content).unwrap();
    let mut cfg2 = test_config();
    cfg2.config_file = Some(cfg_path.display().to_string());
    let reg2 = SessionRegistry::new(cfg2, Arc::new(MockBackend::new()));
    reg2.set_max_extended_screens(4);
    assert_eq!(
        std::fs::read_to_string(&cfg_path).unwrap(),
        corrupt_content,
        "corrupt idis.yaml must NOT be overwritten by automatic saves"
    );
    let _ = std::fs::remove_file(&cfg_path);
}

#[test]
fn iteration3_ippp_fmp4_vectored_write_and_p1_security_invariants() {
    use idis::debug_trace::sanitize_json_value;
    use idis::fmp4::Fmp4Muxer;
    use idis::protocol::framing::{read_canal_block, write_canal_parts};
    use idis::protocol::video::{build_video_header, parse_video_header};
    use idis::session::VideoSettingsPatch;
    use idis::transport::FrameWriter;
    use std::io::{Cursor, Write};

    // 1) IPPP fMP4 muxer: IDR produces init + keyframe chunk, subsequent P-frame produces non-keyframe chunk
    let mut muxer = Fmp4Muxer::new(30);
    let c1 = muxer
        .mux_frame(1280, 720, SYNTHETIC_H264_ANNEX_B)
        .expect("IDR must mux cleanly");
    assert!(c1.init_segment.is_some());
    assert!(c1.is_keyframe);
    // Synthetic P-frame (NAL type 1 = non-IDR slice)
    let p_frame: &[u8] = &[0x00, 0x00, 0x00, 0x01, 0x41, 0x9a, 0x24, 0x6c, 0x41, 0x00];
    let c2 = muxer
        .mux_frame(1280, 720, p_frame)
        .expect("P-frame after IDR must mux cleanly");
    assert!(c2.init_segment.is_none());
    assert!(!c2.is_keyframe);
    assert!(!c2.media_segment.is_empty());

    // 2) Short-write-safe vectored canal framing with stack video header matches parse_video_header
    struct ShortWriter {
        max_chunk: usize,
        out: Vec<u8>,
    }
    impl Write for ShortWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let n = buf.len().min(self.max_chunk);
            self.out.extend_from_slice(&buf[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let (hdr, hdr_len) = build_video_header(1280, 720, 5120, COMPRESSION_H264, 4);
    let mut sw = ShortWriter {
        max_chunk: 3,
        out: Vec::new(),
    };
    write_canal_parts(&mut sw, &[&hdr[..hdr_len], p_frame]).unwrap();
    let mut cursor = Cursor::new(sw.out);
    let block = read_canal_block(&mut cursor).unwrap().unwrap();
    let parsed = parse_video_header(&block).unwrap();
    assert_eq!((parsed.width, parsed.height, parsed.compression), (1280, 720, COMPRESSION_H264));
    assert_eq!(&block[parsed.payload_offset..], p_frame);

    // 3) Debug JSON sanitizer redacts sensitive key names (token/cookie/fingerprint/mac/uid/name/secret)
    let dirty = serde_json::json!({
        "admin_token": "tok_secret_123",
        "fingerprint": "fp:020000000001a1b2c3d4e5f6",
        "uid": "00000000-0000-4000-8000-000000000001",
        "name": "Alice iPad",
        "safe_fps": 30
    });
    let clean = sanitize_json_value(dirty);
    let dumped = clean.to_string();
    assert!(!dumped.contains("tok_secret_123"), "token leaked: {dumped}");
    assert!(!dumped.contains("fp:020000"), "fingerprint leaked: {dumped}");
    assert!(!dumped.contains("00000000-0000-4000"), "uid leaked: {dumped}");
    assert!(!dumped.contains("Alice iPad"), "device name leaked: {dumped}");
    assert_eq!(clean["safe_fps"], 30);

    // 4) Data channel attachment strictly rejects unauthorized sessions and mismatched session_ids
    struct DummyWriter;
    impl FrameWriter for DummyWriter {
        fn send_frame(&self, _payload: &[u8]) -> anyhow::Result<()> {
            Ok(())
        }
        fn close(&self) {}
    }
    let mut cfg = test_config();
    cfg.auto_accept = false;
    cfg.no_confirm = true;
    let reg = SessionRegistry::new(cfg, Arc::new(MockBackend::new()));
    let sid = reg
        .register_telemetry("10.0.0.50".to_string(), Arc::new(DummyWriter), 56846, false)
        .unwrap();
    assert!(
        reg.attach_data_channel_checked("10.0.0.50", Some(sid), Arc::new(DummyWriter))
            .is_err(),
        "data channel must be rejected before authorization"
    );
    let hs = make_handshake_packet(1024, 768, "4.0");
    let pkt = MessagePacket::decode(&hs).unwrap();
    let parsed_hs = idis::protocol::messages::ClientHandshake::from_archived(&pkt.param).unwrap();
    let expected_fp = idis::trust::compute_device_fingerprint(&parsed_hs);
    reg.trust_device_and_save(&expected_fp, &parsed_hs.uid, &parsed_hs.name, &parsed_hs.model)
        .unwrap();
    reg.handle_telemetry_bytes_for_session("10.0.0.50", Some(sid), &hs)
        .unwrap();
    assert!(reg.is_authorized("10.0.0.50"));
    assert!(
        reg.attach_data_channel_checked("10.0.0.50", Some(sid + 999), Arc::new(DummyWriter))
            .is_err(),
        "mismatched session_id must be rejected"
    );
    assert!(
        reg.attach_data_channel_checked("10.0.0.50", Some(sid), Arc::new(DummyWriter))
            .is_ok(),
        "authorized session with matching session_id must attach cleanly"
    );
    reg.close_all();

    // 5) Reversible low_power + update_video_settings does not leak CLI overrides into persisted_baseline
    let tmp_cfg = std::env::temp_dir().join(format!("idis_iter3_cfg_{}.yaml", std::process::id()));
    let _ = std::fs::remove_file(&tmp_cfg);
    let mut base_yaml = idis::user_config::UserConfigFile {
        max_web_viewers: 4,
        p2p_relay_enabled: true,
        ..Default::default()
    };
    base_yaml.ipad.fps = 30;
    base_yaml.ipad.bitrate_mbps = 16;
    base_yaml.ipad.hidpi = 2;
    idis::user_config::save_yaml_file(&tmp_cfg, &base_yaml).unwrap();

    let mut cfg3 = test_config();
    cfg3.config_file = Some(tmp_cfg.display().to_string());
    cfg3.fps = 60; // temporary CLI override
    let reg3 = SessionRegistry::new(cfg3, Arc::new(MockBackend::new()));
    assert_eq!(reg3.video_settings().fps, 60);
    // Patching an unrelated field (integer_scale) must NOT leak CLI fps=60 into persisted baseline!
    reg3.update_video_settings(VideoSettingsPatch {
        integer_scale: Some(true),
        ..Default::default()
    })
    .unwrap();
    let exported = reg3.export_persisted_config();
    assert_eq!(exported.ipad.fps, 30, "CLI override fps=60 must not leak into persisted baseline");
    assert!(exported.ipad.integer_scale);

    // Reversible low_power toggle: true -> false restores max_web_viewers/p2p/hidpi/fps
    reg3.set_low_power(true);
    assert!(reg3.is_low_power());
    assert_eq!(reg3.max_web_viewers(), 0);
    assert!(!reg3.is_p2p_relay_enabled());
    assert_eq!(reg3.video_settings().fps, 15);
    assert_eq!(reg3.video_settings().bitrate_mbps, 4);

    reg3.set_low_power(false);
    assert!(!reg3.is_low_power());
    assert_eq!(reg3.max_web_viewers(), 4);
    assert!(reg3.is_p2p_relay_enabled());
    assert_eq!(reg3.video_settings().hidpi, 2);
    assert_eq!(reg3.video_settings().fps, 60);
    let _ = std::fs::remove_file(&tmp_cfg);
}

#[test]
fn iteration4_atomic_frameslot_seed_if_empty_corrupt_raw_yaml_and_debug_bundle() {
    use idis::platform::{latest_frame_channel, EncodedFrame};
    use idis::web::{start_web_server, LogBuffer, SharedWebMuxer};
    use std::io::{Read, Write};
    use std::net::SocketAddr;

    fn http_json(
        addr: SocketAddr,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> (u16, String) {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let b = body.unwrap_or("");
        let req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{b}",
            b.len()
        );
        s.write_all(req.as_bytes()).unwrap();
        let mut raw = Vec::new();
        let _ = s.read_to_end(&mut raw);
        let text = String::from_utf8_lossy(&raw).to_string();
        let (head, body_out) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        let status = head
            .lines()
            .next()
            .unwrap_or("")
            .split_whitespace()
            .nth(1)
            .and_then(|v| v.parse::<u16>().ok())
            .unwrap_or(0);
        (status, body_out.to_string())
    }

    // 1) FrameSlot atomic (seq, frame, overwritten) return under single lock
    let (tx, rx) = latest_frame_channel();
    let mk = |_seq: u64, kf: bool| {
        Arc::new(EncodedFrame {
            width: 1280,
            height: 720,
            bytes_per_row: 5120,
            annex_b: SYNTHETIC_H264_ANNEX_B.to_vec(),
            is_keyframe: kf,
        })
    };
    assert!(tx.send_latest_shared(1, mk(1, true)));
    assert!(tx.send_latest_shared(2, mk(2, false)));
    assert!(tx.send_latest_shared(3, mk(3, false)));
    let (seq, _f, ov) = rx.recv_timeout_shared(Duration::from_millis(50)).unwrap();
    assert_eq!(seq, 3);
    assert_eq!(ov, 2, "must atomically report 2 overwritten frames");
    assert!(tx.send_latest_shared(4, mk(4, true)));
    let (seq2, _f2, ov2) = rx.recv_timeout_shared(Duration::from_millis(50)).unwrap();
    assert_eq!(seq2, 4);
    assert_eq!(ov2, 0);

    // 2) SharedWebMuxer::seed_if_empty never clobbers live seq/packet
    let mux = SharedWebMuxer::new();
    let f_idr = EncodedFrame {
        width: 1280,
        height: 720,
        bytes_per_row: 5120,
        annex_b: SYNTHETIC_H264_ANNEX_B.to_vec(),
        is_keyframe: true,
    };
    let seeded = mux.seed_if_empty("ipad", 1, 30, &f_idr).unwrap();
    assert_eq!(seeded.seq, 0);
    let live = mux.mux_or_get(10, "ipad", 1, 30, &f_idr).unwrap();
    assert_eq!(live.seq, 10);
    let seeded_again = mux.seed_if_empty("ipad", 1, 30, &f_idr).unwrap();
    assert_eq!(
        seeded_again.seq, 10,
        "seed_if_empty must return existing live IDR without resetting seq"
    );

    // 3) Corrupt YAML returns raw_disk_yaml + parse_error; /api/admin/debug & /api/admin/debug/bundle work
    let tmp_cfg = std::env::temp_dir().join(format!("idis_iter4_corrupt_{}.yaml", std::process::id()));
    let broken = "trusted_devices:\n  - mac: [broken_yaml\n";
    std::fs::write(&tmp_cfg, broken).unwrap();
    let mut cfg = test_config();
    cfg.config_file = Some(tmp_cfg.display().to_string());
    let reg = Arc::new(SessionRegistry::new(cfg, Arc::new(MockBackend::new())));
    let stop = Arc::new(AtomicBool::new(false));
    let mut web = start_web_server(
        "127.0.0.1:0",
        None,
        None,
        reg.clone(),
        LogBuffer::new(),
        stop.clone(),
    )
    .unwrap();

    let (code, body) = http_json(web.addr, "GET", "/api/admin/config", None);
    assert_eq!(code, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["config_corrupt"], true);
    assert_eq!(v["raw_disk_yaml"], broken);
    assert!(
        v["parse_error"].as_str().is_some_and(|s| !s.is_empty()),
        "parse_error must be populated on corrupt YAML: {body}"
    );

    let (code, body) = http_json(
        web.addr,
        "POST",
        "/api/admin/debug",
        Some(r#"{"enabled":true}"#),
    );
    assert_eq!(code, 200, "POST /api/admin/debug failed: {body}");
    let (code, body) = http_json(web.addr, "GET", "/api/admin/debug/bundle", None);
    assert_eq!(code, 200, "GET /api/admin/debug/bundle failed: {body}");
    let bundle: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(bundle["schema_version"], 1);
    assert_eq!(bundle["config_corrupt"], true);
    assert!(bundle["capabilities"]["virtual_display"].is_boolean());
    assert!(bundle["recent_trace_events"].is_array());
    let (code, _) = http_json(
        web.addr,
        "POST",
        "/api/admin/debug",
        Some(r#"{"enabled":false}"#),
    );
    assert_eq!(code, 200);

    stop.store(true, Ordering::SeqCst);
    reg.close_all();
    web.stop();
    let _ = std::fs::remove_file(&tmp_cfg);
}

#[test]
fn web_approval_main_screen_dynamic_cursor_and_unfocused_half_fps() {
    use idis::config::WebScreenMode;
    use idis::web::{start_web_server, LogBuffer};
    use std::io::{Read, Write};
    use std::net::SocketAddr;

    fn http_req(
        addr: SocketAddr,
        method: &str,
        path: &str,
        cookies: Option<&str>,
        body: Option<&str>,
    ) -> (u16, Vec<String>, String) {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) Chrome/130.0.0.0 Safari/537.36\r\nConnection: close\r\n"
        );
        if let Some(c) = cookies {
            req.push_str(&format!("Cookie: {c}\r\n"));
        }
        if let Some(b) = body {
            req.push_str(&format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{b}",
                b.len()
            ));
        } else {
            req.push_str("\r\n");
        }
        s.write_all(req.as_bytes()).unwrap();
        let mut raw = Vec::new();
        let _ = s.read_to_end(&mut raw);
        let text = String::from_utf8_lossy(&raw).to_string();
        let (head, body_out) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        let mut lines = head.lines();
        let status = lines
            .next()
            .unwrap_or("")
            .split_whitespace()
            .nth(1)
            .and_then(|v| v.parse::<u16>().ok())
            .unwrap_or(0);
        let set_cookies = lines
            .filter_map(|l| {
                let (k, v) = l.split_once(':')?;
                if k.eq_ignore_ascii_case("set-cookie") {
                    Some(v.trim().split(';').next().unwrap_or("").to_string())
                } else {
                    None
                }
            })
            .collect();
        (status, set_cookies, body_out.to_string())
    }

    fn ws_connect(addr: SocketAddr, cookie_hdr: &str) -> Result<TcpStream, (u16, String)> {
        let mut ws = TcpStream::connect(addr).unwrap();
        ws.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let req = format!(
            "GET /ws/stream HTTP/1.1\r\n\
             Host: {addr}\r\n\
             Origin: http://{addr}\r\n\
             User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) Chrome/130.0.0.0 Safari/537.36\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n\
             Cookie: {cookie_hdr}\r\n\r\n"
        );
        ws.write_all(req.as_bytes()).unwrap();
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            ws.read_exact(&mut b).unwrap();
            head.push(b[0]);
        }
        let hdr = String::from_utf8_lossy(&head).to_string();
        if hdr.contains("101 Switching Protocols") {
            Ok(ws)
        } else {
            let status = hdr
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|s| s.parse::<u16>().ok())
                .unwrap_or(0);
            let mut rest = Vec::new();
            let _ = ws.read_to_end(&mut rest);
            Err((status, String::from_utf8_lossy(&rest).to_string()))
        }
    }

    let tmp_cfg = std::env::temp_dir().join(format!(
        "idis_e2e_4feat_{}.yaml",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&tmp_cfg);

    let mock = Arc::new(MockBackend::new());
    mock.live_abr_quality.store(true, Ordering::Release);
    let mut cfg = test_config();
    cfg.config_file = Some(tmp_cfg.display().to_string());
    cfg.trusted_devices_file = Some("none".to_string());
    cfg.max_extended_screens = 1;
    cfg.max_web_viewers = 4;
    cfg.web_require_approval = true;
    let wifi_cfg = cfg.clone();
    let registry = Arc::new(SessionRegistry::new(cfg, mock.clone()));
    let stop = Arc::new(AtomicBool::new(false));
    let mut web = start_web_server(
        "127.0.0.1:0",
        Some("admin-sec-4feat".to_string()),
        Some("view-sec-4feat".to_string()),
        registry.clone(),
        LogBuffer::new(),
        stop.clone(),
    )
    .unwrap();
    let addr = web.addr;
    let vaddr = std::net::SocketAddr::from(([127, 0, 0, 1], web.viewer_addr().unwrap().port()));

    // Login as admin
    let (code, acookies, _) = http_req(
        addr,
        "POST",
        "/api/admin/login",
        None,
        Some(r#"{"token":"admin-sec-4feat"}"#),
    );
    assert_eq!(code, 200);
    let admin_cookie = acookies
        .into_iter()
        .find(|c| c.starts_with("idis_admin="))
        .unwrap();

    // --- F1: Web Viewer Approval (AllowOnce + AllowAndTrust + Revoke Kick) ---
    let (code, vcookies1, _) = http_req(
        vaddr,
        "POST",
        "/api/view/login",
        None,
        Some(r#"{"token":"view-sec-4feat"}"#),
    );
    assert_eq!(code, 200);
    let v1_cookie_hdr = vcookies1.join("; ");
    assert!(
        vcookies1.iter().any(|c| c.starts_with("idis_vid=")),
        "viewer login must mint persistent idisplay_vid cookie"
    );

    // Unapproved viewer is blocked at /ws/stream with 403 approval_required
    let err = ws_connect(vaddr, &v1_cookie_hdr).expect_err("unapproved viewer must be blocked");
    assert_eq!(err.0, 403);
    assert!(
        err.1.contains("\"approval_required\":true"),
        "expected approval_required=true, got {}",
        err.1
    );

    // Viewer 1 requests approval; Admin approves AllowOnce
    let v1_hdr_clone = v1_cookie_hdr.clone();
    let req_handle = thread::spawn(move || {
        http_req(vaddr, "POST", "/api/view/request-approval", Some(&v1_hdr_clone), Some("{}"))
    });
    let pending_id = {
        let mut found = None;
        for _ in 0..40 {
            let (_, _, st) = http_req(addr, "GET", "/api/admin/state", Some(&admin_cookie), None);
            let v: serde_json::Value = serde_json::from_str(&st).unwrap();
            if let Some(arr) = v["pending_approvals"].as_array() {
                if let Some(item) = arr.iter().find(|p| p["is_web"] == true) {
                    found = item["id"].as_u64();
                    break;
                }
            }
            thread::sleep(Duration::from_millis(50));
        }
        found.expect("web viewer pending approval must appear in admin state")
    };
    let (code, _, _) = http_req(
        addr,
        "POST",
        "/api/admin/pending/decide",
        Some(&admin_cookie),
        Some(&format!(r#"{{"id":{pending_id},"decision":"allow_once"}}"#)),
    );
    assert_eq!(code, 200);
    let (code, _, body) = req_handle.join().unwrap();
    assert_eq!(code, 200, "allow_once response failed: {body}");
    let dec: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(dec["approved"], true);
    assert_eq!(dec["decision"], "allow_once");
    assert!(
        registry.trust_store().list().is_empty(),
        "allow_once must NOT persist viewer to TrustStore"
    );

    // Viewer 1 can now connect to /ws/stream
    let ws1 = ws_connect(vaddr, &v1_cookie_hdr).expect("allow_once viewer must connect");
    drop(ws1);

    // Viewer 2 requests approval; Admin approves AllowAndTrust
    let (code, vcookies2, _) = http_req(
        vaddr,
        "POST",
        "/api/view/login",
        None,
        Some(r#"{"token":"view-sec-4feat"}"#),
    );
    assert_eq!(code, 200);
    let v2_cookie_hdr = vcookies2.join("; ");
    let v2_hdr_clone = v2_cookie_hdr.clone();
    let req2 = thread::spawn(move || {
        http_req(vaddr, "POST", "/api/view/request-approval", Some(&v2_hdr_clone), Some("{}"))
    });
    let pending_id2 = {
        let mut found = None;
        for _ in 0..40 {
            let (_, _, st) = http_req(addr, "GET", "/api/admin/state", Some(&admin_cookie), None);
            let v: serde_json::Value = serde_json::from_str(&st).unwrap();
            if let Some(arr) = v["pending_approvals"].as_array() {
                if let Some(item) = arr.iter().find(|p| p["is_web"] == true) {
                    found = item["id"].as_u64();
                    break;
                }
            }
            thread::sleep(Duration::from_millis(50));
        }
        found.expect("viewer 2 pending approval must appear")
    };
    let (code, _, _) = http_req(
        addr,
        "POST",
        "/api/admin/pending/decide",
        Some(&admin_cookie),
        Some(&format!(r#"{{"id":{pending_id2},"decision":"allow_and_trust"}}"#)),
    );
    assert_eq!(code, 200);
    let (code, _, body2) = req2.join().unwrap();
    assert_eq!(code, 200, "allow_and_trust failed: {body2}");
    let dec2: serde_json::Value = serde_json::from_str(&body2).unwrap();
    let v2_fp = dec2["fingerprint"].as_str().unwrap().to_string();
    assert!(v2_fp.starts_with("fp:"));
    assert!(
        registry.trust_store().is_trusted(Some(&v2_fp)),
        "allow_and_trust must persist web viewer fingerprint to TrustStore"
    );

    // --- F2: Web Watch Host Primary Display (web_screen_mode: "main") ---
    mock.recorded_capture_modes.lock().unwrap().clear();
    let (code, _, body) = http_req(
        addr,
        "POST",
        "/api/admin/settings",
        Some(&admin_cookie),
        Some(r#"{"web_screen_mode":"main"}"#),
    );
    assert_eq!(code, 200, "switching to main screen mode failed: {body}");
    assert_eq!(registry.web_screen_mode(), WebScreenMode::Main);

    let mut ws2 = ws_connect(vaddr, &v2_cookie_hdr).expect("trusted viewer 2 must connect");
    let (_, _, st_main) = http_req(addr, "GET", "/api/admin/state", Some(&admin_cookie), None);
    let st_v: serde_json::Value = serde_json::from_str(&st_main).unwrap();
    assert_eq!(st_v["web_screen"]["mode"], "main");
    assert_eq!(st_v["web_screen"]["source"], "main");
    assert_eq!(
        st_v["settings"]["active_extended_screens"], 0,
        "watching host primary display must NOT consume an extended screen slot"
    );
    assert!(
        mock.recorded_capture_modes
            .lock()
            .unwrap()
            .contains(&CaptureMode::Main),
        "MockBackend must receive CaptureMode::Main"
    );

    // Revoking Viewer 2's fingerprint kicks active WebSocket and blocks reconnect
    let (code, _, _) = http_req(
        addr,
        "POST",
        "/api/admin/trusted/revoke",
        Some(&admin_cookie),
        Some(&format!(r#"{{"fingerprint":"{v2_fp}"}}"#)),
    );
    assert_eq!(code, 200);
    // Drain ws2 until EOF/close
    ws2.set_read_timeout(Some(Duration::from_millis(800))).unwrap();
    let mut drain = [0u8; 256];
    let mut closed = false;
    for _ in 0..20 {
        match ws2.read(&mut drain) {
            Ok(0) => {
                closed = true;
                break;
            }
            Ok(_) => continue,
            Err(_) => {
                closed = true;
                break;
            }
        }
    }
    assert!(closed, "revoking trusted web viewer must close active WS stream");
    let err2 = ws_connect(vaddr, &v2_cookie_hdr).expect_err("revoked viewer must be blocked");
    assert_eq!(err2.0, 403);

    // --- F3 & F4: Dynamic Client Cursor Toggle + Unfocused Half-FPS on Active iPad ---
    let mut wifi = start_wifi_server(wifi_cfg, mock.clone(), registry.clone(), stop.clone()).unwrap();
    let mut tel = TcpStream::connect(wifi.telemetry_addr).unwrap();
    tel.set_read_timeout(Some(Duration::from_secs(3))).unwrap();

    write_canal_block(&mut tel, &make_handshake_packet(1024, 768, "5")).unwrap();
    let _hs_reply = read_canal_block(&mut tel).unwrap().unwrap();
    let _port_reply = read_canal_block(&mut tel).unwrap().unwrap();
    let mut data = TcpStream::connect(wifi.data_addr).unwrap();
    data.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    // Wait until MockBackend captures start and video frames flow
    let first_video = read_canal_block(&mut data).unwrap().unwrap();
    assert!(!first_video.is_empty());

    // F3: Toggle client_cursor true -> false and verify set_show_cursor(false) -> set_show_cursor(true)
    mock.recorded_show_cursor.lock().unwrap().clear();
    let (code, _, _) = http_req(
        addr,
        "POST",
        "/api/admin/settings",
        Some(&admin_cookie),
        Some(r#"{"client_cursor":true}"#),
    );
    assert_eq!(code, 200);
    let (code, _, _) = http_req(
        addr,
        "POST",
        "/api/admin/settings",
        Some(&admin_cookie),
        Some(r#"{"client_cursor":false}"#),
    );
    assert_eq!(code, 200);
    assert_eq!(
        *mock.recorded_show_cursor.lock().unwrap(),
        vec![false, true],
        "toggling client_cursor must live-toggle OS cursor visibility on active capture"
    );

    // F4: Enable half_fps_when_unfocused, move cursor off iPad for >1.5s, verify FPS halves to 15, then restores to 30
    mock.recorded_quality_updates.lock().unwrap().clear();
    let (code, _, _) = http_req(
        addr,
        "POST",
        "/api/admin/settings",
        Some(&admin_cookie),
        Some(r#"{"half_fps_when_unfocused":true}"#),
    );
    assert_eq!(code, 200);

    // Keep draining data frames in background so data channel never stalls while focus check runs
    let stop_drain = Arc::new(AtomicBool::new(false));
    let stop_drain_c = stop_drain.clone();
    let drain_thread = thread::spawn(move || {
        data.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
        while !stop_drain_c.load(Ordering::Acquire) {
            let _ = read_canal_block(&mut data);
        }
    });

    mock.cursor_visible.store(false, Ordering::Release);
    let mut saw_halved = false;
    for _ in 0..30 {
        if mock
            .recorded_quality_updates
            .lock()
            .unwrap()
            .iter()
            .any(|(fps, _, _)| *fps == 15)
        {
            saw_halved = true;
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    assert!(
        saw_halved,
        "unfocused iPad must halve FPS from 30 to 15 after 1.5s grace; updates={:?}",
        *mock.recorded_quality_updates.lock().unwrap()
    );
    let (_, _, st_half) = http_req(addr, "GET", "/api/admin/state", Some(&admin_cookie), None);
    let st_half_v: serde_json::Value = serde_json::from_str(&st_half).unwrap();
    assert_eq!(
        st_half_v["sessions"][0]["abr"]["unfocused_fps_halved"], true,
        "admin state must report unfocused_fps_halved=true"
    );

    // Move cursor back onto iPad -> instant recovery to 30 FPS
    mock.recorded_quality_updates.lock().unwrap().clear();
    mock.cursor_visible.store(true, Ordering::Release);
    let mut saw_restored = false;
    for _ in 0..15 {
        if mock
            .recorded_quality_updates
            .lock()
            .unwrap()
            .iter()
            .any(|(fps, _, _)| *fps == 30)
        {
            saw_restored = true;
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(
        saw_restored,
        "returning cursor to iPad must immediately restore 30 FPS; updates={:?}",
        *mock.recorded_quality_updates.lock().unwrap()
    );

    stop_drain.store(true, Ordering::Release);
    let _ = drain_thread.join();
    drop(tel);
    stop.store(true, Ordering::SeqCst);
    registry.close_all();
    wifi.stop();
    web.stop();
    let _ = std::fs::remove_file(&tmp_cfg);
}

#[test]
fn iter1_ippp_dpb_multi_ipad_abr_focus_and_cursor_e2e() {
    use idis::platform::mock::SYNTHETIC_H264_P_FRAME;
    use idis::platform::EncodedFrame;
    use idis::protocol::video::parse_video_header;
    use std::net::UdpSocket;

    let mock = Arc::new(MockBackend::new());
    mock.manual_frame_mode.store(true, Ordering::Release);
    mock.live_abr_quality.store(true, Ordering::Release);
    *mock.cursor_png.lock().unwrap() = Some(vec![0x89, b'P', b'N', b'G', 1, 2, 3, 4]);

    let mut cfg = test_config();
    cfg.max_extended_screens = 2;
    cfg.max_web_viewers = 4;
    let wifi_cfg = cfg.clone();
    let registry = Arc::new(SessionRegistry::new(cfg, mock.clone()));
    let stop = Arc::new(AtomicBool::new(false));
    let mut wifi = start_wifi_server(wifi_cfg, mock.clone(), registry.clone(), stop.clone()).unwrap();

    // Bind a loopback UDP socket to test real 9-byte UDP cursor delivery + hide packet on toggle OFF!
    let udp_recv = UdpSocket::bind("127.0.0.1:0").unwrap();
    udp_recv
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let udp_port = udp_recv.local_addr().unwrap().port();

    // Connect iPad #1 with telemetry cursor + UDP cursor enabled
    let mut tel1 = TcpStream::connect(wifi.telemetry_addr).unwrap();
    tel1.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut hs1 = BTreeMap::new();
    hs1.insert("uid".to_string(), ArchivedValue::String("ipad-1-uid".to_string()));
    hs1.insert("name".to_string(), ArchivedValue::String("iPad One".to_string()));
    hs1.insert("model".to_string(), ArchivedValue::String("iPad Air".to_string()));
    hs1.insert("screenWidth".to_string(), ArchivedValue::Int(1024));
    hs1.insert("screenHeight".to_string(), ArchivedValue::Int(768));
    hs1.insert("clientOrientationKey".to_string(), ArchivedValue::Int(1));
    hs1.insert("clientDataProtocolVersionKey".to_string(), ArchivedValue::String("5".to_string()));
    hs1.insert("udpPort".to_string(), ArchivedValue::Int(udp_port as i64));
    hs1.insert("MSMClientTelemetryCursorSupportedKey".to_string(), ArchivedValue::Bool(true));
    let pkt1 = MessagePacket::new_send("Handshake", ArchivedValue::Dict(hs1));
    write_canal_block(&mut tel1, &pkt1.encode().unwrap()).unwrap();
    let _ = read_canal_block(&mut tel1).unwrap().unwrap(); // AccessConfirmed
    let _ = read_canal_block(&mut tel1).unwrap().unwrap(); // VideoServiceAccessibleOnPort

    let mut data1 = TcpStream::connect(wifi.data_addr).unwrap();
    data1.set_read_timeout(Some(Duration::from_secs(2))).unwrap();

    // Wait for iPad #1's capture to register on the session BEFORE subscribing FollowIpad Web viewer
    // (avoids transient standalone capture creation at frame_senders[1] under CPU load; Iter-7 P2-B2).
    for _ in 0..80 {
        if registry.list_sessions().iter().any(|s| s.streaming) {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    let ipad1_cap_idx = mock.frame_senders.lock().unwrap().len() - 1;

    // Subscribe a FollowIpad Web viewer directly to verify IPPP + Multi-iPad non-interleaving
    let web_sub = registry
        .subscribe_web_stream("127.0.0.1:55555".to_string(), None)
        .unwrap();

    // 1) Cursor thread starts OFF: zero cursor polling + initial ChangeCursorVisible(false)
    thread::sleep(Duration::from_millis(120));
    assert_eq!(
        mock.query_cursor_calls.load(Ordering::Acquire),
        0,
        "cursor_thread must do ZERO cursor polling while client_cursor=false"
    );
    let init_cur = read_canal_block(&mut tel1).unwrap().unwrap();
    let init_cur_pkt = MessagePacket::decode(&init_cur).unwrap();
    assert_eq!(init_cur_pkt.name_method, "ChangeCursorVisible");

    // 2) IPPP DPB Gate (GAP-B1): P-frame BEFORE first IDR is dropped; IDR passes; P after IDR passes!
    let make_frame = |w: u32, h: u32, is_idr: bool| EncodedFrame {
        width: w,
        height: h,
        bytes_per_row: w * 4,
        annex_b: if is_idr {
            SYNTHETIC_H264_ANNEX_B.to_vec()
        } else {
            SYNTHETIC_H264_P_FRAME.to_vec()
        },
        is_keyframe: is_idr,
    };
    mock.push_frame_to(ipad1_cap_idx, make_frame(1024, 768, false)); // Dropped!
    thread::sleep(Duration::from_millis(30));
    mock.push_frame_to(ipad1_cap_idx, make_frame(1024, 768, true)); // IDR passes!
    let f1 = read_canal_block(&mut data1).unwrap().unwrap();
    let h1 = parse_video_header(&f1).unwrap();
    assert_eq!(&f1[h1.payload_offset..], SYNTHETIC_H264_ANNEX_B);
    let wf1 = web_sub.rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(wf1.is_keyframe);
    assert_eq!(wf1.width, 1024);

    // Ack frame so flow control allows P-frame cleanly
    let ack = MessagePacket::new_send("FrameReceived", ArchivedValue::Null);
    write_canal_block(&mut tel1, &ack.encode().unwrap()).unwrap();
    thread::sleep(Duration::from_millis(20));
    mock.push_frame_to(ipad1_cap_idx, make_frame(1024, 768, false));
    let f2 = read_canal_block(&mut data1).unwrap().unwrap();
    let h2 = parse_video_header(&f2).unwrap();
    assert_eq!(&f2[h2.payload_offset..], SYNTHETIC_H264_P_FRAME);
    let wf2 = web_sub.rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(!wf2.is_keyframe);

    // 3) StopStream / StartStream (GAP-A4) + FollowIpad shared capture pause matrix
    mock.recorded_pauses.lock().unwrap().clear();
    let stop_pkt = MessagePacket::new_send("StopStream", ArchivedValue::Null);
    write_canal_block(&mut tel1, &stop_pkt.encode().unwrap()).unwrap();
    thread::sleep(Duration::from_millis(60));
    registry.set_web_viewer_visible(web_sub.id, false);
    thread::sleep(Duration::from_millis(60));
    assert!(
        mock.recorded_pauses.lock().unwrap().contains(&true),
        "StopStream + hidden FollowIpad Web viewer must pause capture"
    );
    registry.set_web_viewer_visible(web_sub.id, true);
    let start_pkt = MessagePacket::new_send("StartStream", ArchivedValue::Null);
    write_canal_block(&mut tel1, &start_pkt.encode().unwrap()).unwrap();
    thread::sleep(Duration::from_millis(60));
    assert!(
        mock.recorded_pauses.lock().unwrap().last() == Some(&false),
        "StartStream must resume capture"
    );

    // 4) Dynamic client_cursor ON -> UDP packet + PNG -> OFF -> UDP hide packet (BUG-B6)!
    registry.set_client_cursor(true);
    let mut udp_buf = [0u8; 32];
    let (n, _) = udp_recv
        .recv_from(&mut udp_buf)
        .expect("UDP cursor packet must arrive when client_cursor=true");
    assert_eq!(n, 9);
    assert_eq!(udp_buf[8], 0, "UDP cursor byte[8]==0 means visible");
    assert!(mock.query_cursor_calls.load(Ordering::Acquire) > 0);

    registry.set_client_cursor(false);
    let mut saw_udp_hide = false;
    for _ in 0..20 {
        match udp_recv.recv_from(&mut udp_buf) {
            Ok((9, _)) if udp_buf[8] == 1 => {
                saw_udp_hide = true;
                break;
            }
            Ok(_) => continue,
            Err(_) => break,
        }
    }
    assert!(
        saw_udp_hide,
        "BUG-B6 regression: toggling client_cursor=false must send UDP hide packet (byte[8]=1)"
    );

    // 5) Focus-FPS fault-injection retry (BUG-B4): fail update_stream_quality once, then recover!
    mock.fail_quality_updates.store(true, Ordering::Release);
    mock.recorded_quality_updates.lock().unwrap().clear();
    let _ = registry.update_video_settings(idis::session::VideoSettingsPatch {
        half_fps_when_unfocused: Some(true),
        ..Default::default()
    });
    mock.cursor_visible.store(false, Ordering::Release);
    thread::sleep(Duration::from_millis(1800));
    assert!(mock.recorded_quality_updates.lock().unwrap().is_empty());
    mock.fail_quality_updates.store(false, Ordering::Release);
    let mut retried_ok = false;
    for _ in 0..15 {
        if mock
            .recorded_quality_updates
            .lock()
            .unwrap()
            .iter()
            .any(|(fps, _, _)| *fps == 15)
        {
            retried_ok = true;
            break;
        }
        thread::sleep(Duration::from_millis(80));
    }
    assert!(
        retried_ok,
        "BUG-B4 regression: focus-FPS update must retry after transient update_stream_quality error"
    );

    // 6) ResolutionChange (BUG-A4) updates resize
    let mut rc = BTreeMap::new();
    rc.insert("screenWidth".to_string(), ArchivedValue::Int(2048));
    rc.insert("screenHeight".to_string(), ArchivedValue::Int(1536));
    let rc_pkt = MessagePacket::new_send("ResolutionChange", ArchivedValue::Dict(rc));
    write_canal_block(&mut tel1, &rc_pkt.encode().unwrap()).unwrap();
    let mut saw_resize = false;
    for _ in 0..20 {
        if mock.recorded_resizes.lock().unwrap().contains(&(2048, 1536)) {
            saw_resize = true;
            break;
        }
        thread::sleep(Duration::from_millis(30));
    }
    assert!(saw_resize, "ResolutionChange must resize capture to 2048x1536");

    // 7) BUG-B3 regression: 2nd iPad connects concurrently in FollowIpad mode -> Web viewer
    //    must ONLY receive frames from iPad #1 (no interleaving!), then fail over when iPad #1 closes!
    let usb_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let usb_addr = usb_listener.local_addr().unwrap();
    let reg_u = registry.clone();
    let usb_srv = thread::spawn(move || {
        let (srv_stream, _) = usb_listener.accept().unwrap();
        let _ = serve_peertalk_stream(UsbmuxStream::Tcp(srv_stream), "usb:2".to_string(), reg_u);
    });
    let mut usb_cli = TcpStream::connect(usb_addr).unwrap();
    usb_cli.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    write_pt_frame(
        &mut usb_cli,
        PT_FRAME_TYPE_TELEMETRY,
        1,
        &make_handshake_packet_custom("ipad-2-usb-uid", "iPad Two", 1280, 960, "5"),
    )
    .unwrap();
    let _ = read_pt_frame(&mut usb_cli).unwrap().unwrap(); // AccessConfirmed
    let _ = read_pt_frame(&mut usb_cli).unwrap().unwrap(); // VideoServiceAccessibleOnPort
    let ping_start = MessagePacket::new_request(
        "Ping",
        ArchivedValue::String("START".to_string()),
        5.0,
    );
    write_pt_frame(
        &mut usb_cli,
        PT_FRAME_TYPE_TELEMETRY,
        2,
        &ping_start.encode().unwrap(),
    )
    .unwrap();
    for _ in 0..80 {
        if registry
            .list_sessions()
            .iter()
            .filter(|s| s.streaming)
            .count()
            >= 2
        {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    assert!(
        registry
            .list_sessions()
            .iter()
            .filter(|s| s.streaming)
            .count()
            >= 2
    );
    let ipad2_cap_idx = mock.frame_senders.lock().unwrap().len() - 1;
    while web_sub.rx.recv_timeout(Duration::from_millis(20)).is_ok() {}
    mock.push_frame_to(ipad2_cap_idx, make_frame(1280, 960, true));
    assert!(
        web_sub.rx.recv_timeout(Duration::from_millis(120)).is_err(),
        "BUG-B3 regression: secondary iPad #2 must NOT interleave frames into FollowIpad Web viewer"
    );
    drop(data1);
    drop(tel1);
    registry.close_session("127.0.0.1");
    thread::sleep(Duration::from_millis(80));
    mock.push_frame_to(ipad2_cap_idx, make_frame(1280, 960, true));
    let failover_f = web_sub
        .rx
        .recv_timeout(Duration::from_secs(1))
        .expect("iPad #2 must seamlessly take over FollowIpad after iPad #1 disconnects");
    assert_eq!(failover_f.width, 1280);

    drop(web_sub);
    drop(usb_cli);
    stop.store(true, Ordering::SeqCst);
    registry.close_all();
    wifi.stop();
    let _ = usb_srv.join();
}

#[test]
fn iter1_web_security_instant_approval_kick_csrf_and_corrupt_reset() {
    use idis::web::{start_web_server, LogBuffer};
    use std::io::{Read, Write};
    use std::net::SocketAddr;

    fn raw_http(addr: SocketAddr, raw_req: &str) -> (u16, Vec<String>, String) {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        s.write_all(raw_req.as_bytes()).unwrap();
        let mut raw = Vec::new();
        let _ = s.read_to_end(&mut raw);
        let text = String::from_utf8_lossy(&raw).to_string();
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        let mut lines = head.lines();
        let status = lines
            .next()
            .unwrap_or("")
            .split_whitespace()
            .nth(1)
            .and_then(|v| v.parse::<u16>().ok())
            .unwrap_or(0);
        let cookies = lines
            .filter_map(|l| {
                let (k, v) = l.split_once(':')?;
                if k.eq_ignore_ascii_case("set-cookie") {
                    Some(v.trim().split(';').next().unwrap_or("").to_string())
                } else {
                    None
                }
            })
            .collect();
        (status, cookies, body.to_string())
    }

    let tmp_cfg = std::env::temp_dir().join(format!("idis_iter1_sec_{}.yaml", std::process::id()));
    let _ = std::fs::remove_file(&tmp_cfg);
    let mut cfg = test_config();
    cfg.config_file = Some(tmp_cfg.display().to_string());
    cfg.max_web_viewers = 4;
    let reg = Arc::new(SessionRegistry::new(cfg, Arc::new(MockBackend::new())));
    let stop = Arc::new(AtomicBool::new(false));
    let mut web = start_web_server(
        "127.0.0.1:0",
        Some("admin-iter1-sec".to_string()),
        Some("view-iter1-sec".to_string()),
        reg.clone(),
        LogBuffer::new(),
        stop.clone(),
    )
    .unwrap();
    let addr = web.addr;

    // 1) GAP-C2: Proxy header spoofing blocks loopback auto-admin; CSRF Origin / Content-Type rejected!
    let (code, acookies, _) = raw_http(
        addr,
        &format!(
            "POST /api/admin/login HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nContent-Type: application/json\r\nContent-Length: 27\r\nConnection: close\r\n\r\n{{\"token\":\"admin-iter1-sec\"}}"
        ),
    );
    assert_eq!(code, 200);
    let admin_cookie = acookies
        .into_iter()
        .find(|c| c.starts_with("idis_admin="))
        .unwrap();

    let (code, _, _) = raw_http(
        addr,
        &format!(
            "POST /api/admin/settings HTTP/1.1\r\nHost: {addr}\r\nOrigin: https://evil.example\r\nCookie: {admin_cookie}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
        ),
    );
    assert_eq!(code, 403, "Cross-origin POST must be rejected with 403");

    let (code, _, _) = raw_http(
        addr,
        &format!(
            "POST /api/admin/settings HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nCookie: {admin_cookie}\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
        ),
    );
    assert_eq!(code, 403, "Non-JSON Content-Type POST must be rejected with 403");

    // 2) BUG-C2 regression: Toggling web_require_approval false -> true IMMEDIATELY kicks active unapproved WS (<1s)!
    let vaddr = std::net::SocketAddr::from(([127, 0, 0, 1], web.viewer_addr().unwrap().port()));
    let (code, vcookies, _) = raw_http(
        vaddr,
        &format!(
            "POST /api/view/login HTTP/1.1\r\nHost: {vaddr}\r\nOrigin: http://{vaddr}\r\nContent-Type: application/json\r\nContent-Length: 26\r\nConnection: close\r\n\r\n{{\"token\":\"view-iter1-sec\"}}"
        ),
    );
    assert_eq!(code, 200);
    let v_cookie_hdr = vcookies.join("; ");
    let mut ws = TcpStream::connect(vaddr).unwrap();
    ws.set_read_timeout(Some(Duration::from_millis(800))).unwrap();
    let ws_req = format!(
        "GET /ws/stream HTTP/1.1\r\nHost: {vaddr}\r\nOrigin: http://{vaddr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nCookie: {v_cookie_hdr}\r\n\r\n"
    );
    ws.write_all(ws_req.as_bytes()).unwrap();
    let mut hdr = Vec::new();
    let mut b = [0u8; 1];
    while !hdr.ends_with(b"\r\n\r\n") {
        ws.read_exact(&mut b).unwrap();
        hdr.push(b[0]);
    }
    assert!(String::from_utf8_lossy(&hdr).contains("101 Switching Protocols"));

    let t_kick = std::time::Instant::now();
    let body = r#"{"web_require_approval":true}"#;
    let (code, _, _) = raw_http(
        addr,
        &format!(
            "POST /api/admin/settings HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nCookie: {admin_cookie}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    );
    assert_eq!(code, 200);
    let mut drain = [0u8; 256];
    let mut closed = false;
    for _ in 0..20 {
        match ws.read(&mut drain) {
            Ok(0) | Err(_) => {
                closed = true;
                break;
            }
            Ok(_) => continue,
        }
    }
    assert!(closed, "toggling web_require_approval=true must immediately close unapproved WS");
    assert!(
        t_kick.elapsed() < Duration::from_secs(2),
        "instant kick took too long: {:?}",
        t_kick.elapsed()
    );

    // 3) BUG-C4 regression: single IP with rotating cookies cannot occupy >1 pending approval slot
    let view_tok_cookie = vcookies
        .iter()
        .find(|c| c.starts_with("idis_view="))
        .unwrap()
        .clone();
    let vc1 = format!("{view_tok_cookie}; idis_vid=aaaaaaaaaaaaaaaa");
    let vc2 = format!("{view_tok_cookie}; idis_vid=bbbbbbbbbbbbbbbb");
    let t1 = thread::spawn(move || {
        raw_http(
            vaddr,
            &format!(
                "POST /api/view/request-approval HTTP/1.1\r\nHost: {vaddr}\r\nOrigin: http://{vaddr}\r\nCookie: {vc1}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
            ),
        )
    });
    thread::sleep(Duration::from_millis(80));
    let t2 = thread::spawn(move || {
        raw_http(
            vaddr,
            &format!(
                "POST /api/view/request-approval HTTP/1.1\r\nHost: {vaddr}\r\nOrigin: http://{vaddr}\r\nCookie: {vc2}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
            ),
        )
    });
    let (c1, _, _) = t1.join().unwrap();
    assert_eq!(c1, 403, "duplicate web approval from same IP must supersede earlier slot");
    let (_, _, st) = raw_http(
        addr,
        &format!("GET /api/admin/state HTTP/1.1\r\nHost: {addr}\r\nCookie: {admin_cookie}\r\nConnection: close\r\n\r\n"),
    );
    let st_v: serde_json::Value = serde_json::from_str(&st).unwrap();
    let arr = st_v["pending_approvals"].as_array().unwrap();
    assert_eq!(arr.len(), 1, "single IP must occupy at most 1 web pending slot");
    let pid = arr[0]["id"].as_u64().unwrap();
    let deny_body = format!(r#"{{"id":{pid},"decision":"deny"}}"#);
    let _ = raw_http(
        addr,
        &format!(
            "POST /api/admin/pending/decide HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nCookie: {admin_cookie}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{deny_body}",
            deny_body.len()
        ),
    );
    let (c2, _, _) = t2.join().unwrap();
    assert_eq!(c2, 403);

    stop.store(true, Ordering::SeqCst);
    reg.close_all();
    web.stop();
    let _ = std::fs::remove_file(&tmp_cfg);

    // 4) Proxy header spoofing blocks loopback auto-admin + BUG-C3 corrupt YAML reset returns 409
    let tmp_bad = std::env::temp_dir().join(format!("idis_iter1_reset_{}.yaml", std::process::id()));
    let broken = "trusted_devices:\n  - [corrupt_yaml\n";
    std::fs::write(&tmp_bad, broken).unwrap();
    let mut cfg2 = test_config();
    cfg2.config_file = Some(tmp_bad.display().to_string());
    let reg2 = Arc::new(SessionRegistry::new(cfg2, Arc::new(MockBackend::new())));
    let stop2 = Arc::new(AtomicBool::new(false));
    let mut web2 = start_web_server(
        "127.0.0.1:0",
        None,
        None,
        reg2.clone(),
        LogBuffer::new(),
        stop2.clone(),
    )
    .unwrap();
    let (code, _, _) = raw_http(
        web2.addr,
        &format!(
            "GET /api/admin/state HTTP/1.1\r\nHost: {}\r\nX-Forwarded-For: 1.2.3.4\r\nConnection: close\r\n\r\n",
            web2.addr
        ),
    );
    assert_eq!(code, 401, "X-Forwarded-For must disable loopback auto-admin");
    let reset_body = r#"{"keep_trusted":true}"#;
    let (code, _, _) = raw_http(
        web2.addr,
        &format!(
            "POST /api/admin/config/reset HTTP/1.1\r\nHost: {}\r\nOrigin: http://{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reset_body}",
            web2.addr,
            web2.addr,
            reset_body.len()
        ),
    );
    assert_eq!(code, 409, "reset with keep_trusted=true must return 409 when disk YAML is corrupt");
    assert_eq!(
        std::fs::read_to_string(&tmp_bad).unwrap(),
        broken,
        "corrupt disk YAML must remain untouched"
    );
    stop2.store(true, Ordering::SeqCst);
    reg2.close_all();
    web2.stop();
    let _ = std::fs::remove_file(&tmp_bad);
}

#[test]
fn iter2_usbmux_watcher_lifecycle_split_frames_and_detach_race() {
    use idis::transport::usbmux::start_usbmux_watcher;
    use plist::{Dictionary, Value};
    use std::io::{Read, Write};

    fn read_usbmux_msg(s: &mut TcpStream) -> Option<(u32, Dictionary)> {
        let mut hdr = [0u8; 16];
        if s.read_exact(&mut hdr).is_err() {
            return None;
        }
        let len = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
        let tag = u32::from_le_bytes([hdr[12], hdr[13], hdr[14], hdr[15]]);
        let mut body = vec![0u8; len.saturating_sub(16)];
        s.read_exact(&mut body).ok()?;
        let val = Value::from_reader(std::io::Cursor::new(&body)).ok()?;
        Some((tag, val.into_dictionary()?))
    }

    fn write_usbmux_msg(s: &mut TcpStream, tag: u32, dict: &Dictionary) {
        let mut xml = Vec::new();
        Value::Dictionary(dict.clone()).to_writer_xml(&mut xml).unwrap();
        let total = (16 + xml.len()) as u32;
        let mut hdr = [0u8; 16];
        hdr[0..4].copy_from_slice(&total.to_le_bytes());
        hdr[4..8].copy_from_slice(&1u32.to_le_bytes());
        hdr[8..12].copy_from_slice(&8u32.to_le_bytes());
        hdr[12..16].copy_from_slice(&tag.to_le_bytes());
        s.write_all(&hdr).unwrap();
        s.write_all(&xml).unwrap();
        s.flush().unwrap();
    }

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mux_addr = listener.local_addr().unwrap();
    let srv_stop = Arc::new(AtomicBool::new(false));
    let srv_stop_c = srv_stop.clone();
    let saw_network_connect = Arc::new(AtomicBool::new(false));
    let saw_network_c = saw_network_connect.clone();
    let saw_swapped_port = Arc::new(AtomicBool::new(false));
    let saw_swapped_c = saw_swapped_port.clone();
    let detach_trigger = Arc::new(AtomicBool::new(false));
    let detach_trigger_c = detach_trigger.clone();

    let mux_srv = thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let mut listen_sock: Option<TcpStream> = None;
        let mut sent_attach = false;
        let mut sent_detach = false;
        let mut connect_count = 0usize;
        let start = std::time::Instant::now();
        while !srv_stop_c.load(Ordering::Acquire) && start.elapsed() < Duration::from_secs(10) {
            if let Ok((mut s, _)) = listener.accept() {
                let _ = s.set_nonblocking(false);
                let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
                if let Some((tag, dict)) = read_usbmux_msg(&mut s) {
                    let mt = dict.get("MessageType").and_then(|v| v.as_string()).unwrap_or("");
                    if mt == "Listen" {
                        let mut ok = Dictionary::new();
                        ok.insert("MessageType".into(), Value::String("Result".into()));
                        ok.insert("Number".into(), Value::Integer(0i64.into()));
                        write_usbmux_msg(&mut s, tag, &ok);
                        // First send a Network device (MUST be ignored!)
                        let mut net_props = Dictionary::new();
                        net_props.insert("ConnectionType".into(), Value::String("Network".into()));
                        let mut net_att = Dictionary::new();
                        net_att.insert("MessageType".into(), Value::String("Attached".into()));
                        net_att.insert("DeviceID".into(), Value::Integer(99i64.into()));
                        net_att.insert("Properties".into(), Value::Dictionary(net_props));
                        write_usbmux_msg(&mut s, 0, &net_att);
                        // Then send USB DeviceID=7
                        let mut usb_props = Dictionary::new();
                        usb_props.insert("ConnectionType".into(), Value::String("USB".into()));
                        let mut usb_att = Dictionary::new();
                        usb_att.insert("MessageType".into(), Value::String("Attached".into()));
                        usb_att.insert("DeviceID".into(), Value::Integer(7i64.into()));
                        usb_att.insert("Properties".into(), Value::Dictionary(usb_props));
                        write_usbmux_msg(&mut s, 0, &usb_att);
                        sent_attach = true;
                        listen_sock = Some(s);
                    } else if mt == "Connect" {
                        let dev_id = dict.get("DeviceID").and_then(|v| v.as_signed_integer()).unwrap_or(0);
                        let port_num = dict.get("PortNumber").and_then(|v| v.as_signed_integer()).unwrap_or(0);
                        if dev_id == 99 {
                            saw_network_c.store(true, Ordering::Release);
                        }
                        if port_num == i64::from(2345u16.swap_bytes()) {
                            saw_swapped_c.store(true, Ordering::Release);
                        }
                        let mut ok = Dictionary::new();
                        ok.insert("MessageType".into(), Value::String("Result".into()));
                        ok.insert("Number".into(), Value::Integer(0i64.into()));
                        write_usbmux_msg(&mut s, tag, &ok);
                        connect_count += 1;
                        let my_conn = connect_count;
                        // Serve PeerTalk client over this proxied connection!
                        let stop_inner = srv_stop_c.clone();
                        thread::spawn(move || {
                            let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
                            // Send handshake in split 7-byte chunks to verify split PeerTalk framing
                            let hs_payload = make_handshake_packet_custom(
                                &format!("usb-watch-{my_conn}"),
                                "USB Watcher iPad",
                                1024,
                                768,
                                "5",
                            );
                            let mut pt_buf = Vec::new();
                            write_pt_frame(&mut pt_buf, PT_FRAME_TYPE_TELEMETRY, 1, &hs_payload).unwrap();
                            for ch in pt_buf.chunks(7) {
                                let _ = s.write_all(ch);
                                thread::sleep(Duration::from_millis(2));
                            }
                            let _ = read_pt_frame(&mut s); // AccessConfirmed
                            let _ = read_pt_frame(&mut s); // VideoServiceAccessibleOnPort
                            let ping_start = MessagePacket::new_request(
                                "Ping",
                                ArchivedValue::String("START".into()),
                                5.0,
                            );
                            let _ = write_pt_frame(
                                &mut s,
                                PT_FRAME_TYPE_TELEMETRY,
                                2,
                                &ping_start.encode().unwrap(),
                            );
                            // Also send non-standard frame_type=105 touch event!
                            let touch_bytes = make_touch_event_bytes(0, 123.0, 234.0);
                            let _ = write_pt_frame(&mut s, 105, 3, &touch_bytes);
                            while !stop_inner.load(Ordering::Acquire) {
                                match read_pt_frame(&mut s) {
                                    Ok(Some(_)) => continue,
                                    _ => break,
                                }
                            }
                        });
                    }
                }
            }
            if sent_attach && !sent_detach && detach_trigger_c.load(Ordering::Acquire) {
                sent_detach = true;
                if let Some(ref mut ls) = listen_sock {
                    // Rapid Detached(7) + re-Attached(7) to verify attach_gen isolation!
                    let mut det = Dictionary::new();
                    det.insert("MessageType".into(), Value::String("Detached".into()));
                    det.insert("DeviceID".into(), Value::Integer(7i64.into()));
                    write_usbmux_msg(ls, 0, &det);
                    let mut usb_props = Dictionary::new();
                    usb_props.insert("ConnectionType".into(), Value::String("USB".into()));
                    let mut usb_att = Dictionary::new();
                    usb_att.insert("MessageType".into(), Value::String("Attached".into()));
                    usb_att.insert("DeviceID".into(), Value::Integer(7i64.into()));
                    usb_att.insert("Properties".into(), Value::Dictionary(usb_props));
                    write_usbmux_msg(ls, 0, &usb_att);
                }
            }
            thread::sleep(Duration::from_millis(10));
        }
    });

    let mock = Arc::new(MockBackend::new());
    let mut cfg = test_config();
    cfg.no_usb = false;
    cfg.trust_usb = true;
    cfg.allow_input = true;
    let reg = Arc::new(SessionRegistry::new(cfg, mock.clone()));
    let global_stop = Arc::new(AtomicBool::new(false));
    let mut watcher = start_usbmux_watcher(mux_addr.to_string(), reg.clone(), global_stop.clone());

    // Wait for USB gen=1 session + frame_type=105 touch injection
    let mut saw_gen1 = false;
    for _ in 0..60 {
        if reg
            .list_sessions()
            .iter()
            .any(|s| s.key == "127.0.0.1:usb-7-1" && s.streaming)
        {
            saw_gen1 = true;
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(saw_gen1, "usbmux watcher must connect USB DeviceID=7 gen=1");
    assert!(!saw_network_connect.load(Ordering::Acquire), "Network device must be ignored");
    assert!(saw_swapped_port.load(Ordering::Acquire), "Connect must send byte-swapped port 2345");
    let mut saw_touch = false;
    for _ in 0..40 {
        if mock.recorded_inputs.lock().unwrap().iter().any(|e| matches!(e, InputEvent::MouseDown { x, y, .. } if (*x - 123.0).abs() < 1.0 && (*y - 234.0).abs() < 1.0)) {
            saw_touch = true;
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    assert!(saw_touch, "frame_type=105 touch event must be injected");

    // Trigger rapid Detached(7) + Attached(7) -> gen=2 must come online and survive gen=1 teardown!
    detach_trigger.store(true, Ordering::Release);
    let mut saw_gen2 = false;
    for _ in 0..60 {
        let sess = reg.list_sessions();
        if sess.iter().any(|s| s.key == "127.0.0.1:usb-7-2" && s.streaming)
            && !sess.iter().any(|s| s.key == "127.0.0.1:usb-7-1")
        {
            saw_gen2 = true;
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(saw_gen2, "rapid detach+reattach must bring up gen=2 and tear down gen=1 cleanly");

    // Stopping watcher must NOT mutate caller's global_stop (Bug A5 fix)!
    watcher.stop();
    assert!(!global_stop.load(Ordering::Acquire), "UsbmuxWatcherHandle::stop must NOT set caller global_stop");
    srv_stop.store(true, Ordering::Release);
    reg.close_all();
    let _ = mux_srv.join();
}

#[test]
fn iter2_ws_stream_ippp_failover_mode_switch_p2p_and_security_matrix_e2e() {
    use idis::platform::mock::SYNTHETIC_H264_P_FRAME;
    use idis::platform::EncodedFrame;
    use idis::web::{start_web_server, LogBuffer};
    use std::io::{Read, Write};
    use std::net::SocketAddr;

    fn raw_http(addr: SocketAddr, req: &str) -> (u16, Vec<String>, String) {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        s.write_all(req.as_bytes()).unwrap();
        let mut raw = Vec::new();
        let _ = s.read_to_end(&mut raw);
        let text = String::from_utf8_lossy(&raw).to_string();
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        let mut lines = head.lines();
        let status = lines
            .next()
            .unwrap_or("")
            .split_whitespace()
            .nth(1)
            .and_then(|v| v.parse::<u16>().ok())
            .unwrap_or(0);
        let cookies = lines
            .filter_map(|l| {
                let (k, v) = l.split_once(':')?;
                if k.eq_ignore_ascii_case("set-cookie") {
                    Some(v.trim().split(';').next().unwrap_or("").to_string())
                } else {
                    None
                }
            })
            .collect();
        (status, cookies, body.to_string())
    }

    fn ws_open(addr: SocketAddr, cookie: &str) -> TcpStream {
        let mut ws = TcpStream::connect(addr).unwrap();
        ws.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let req = format!(
            "GET /ws/stream HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nCookie: {cookie}\r\n\r\n"
        );
        ws.write_all(req.as_bytes()).unwrap();
        let mut hdr = Vec::new();
        let mut b = [0u8; 1];
        while !hdr.ends_with(b"\r\n\r\n") {
            ws.read_exact(&mut b).unwrap();
            hdr.push(b[0]);
        }
        assert!(String::from_utf8_lossy(&hdr).contains("101 Switching Protocols"));
        ws
    }

    fn read_ws_frame_client(ws: &mut TcpStream) -> (u8, Vec<u8>) {
        let mut h = [0u8; 2];
        ws.read_exact(&mut h).unwrap();
        let opcode = h[0] & 0x0F;
        let len_code = h[1] & 0x7F;
        let len = match len_code {
            126 => {
                let mut b = [0u8; 2];
                ws.read_exact(&mut b).unwrap();
                u16::from_be_bytes(b) as usize
            }
            127 => {
                let mut b = [0u8; 8];
                ws.read_exact(&mut b).unwrap();
                u64::from_be_bytes(b) as usize
            }
            n => n as usize,
        };
        let mut pay = vec![0u8; len];
        ws.read_exact(&mut pay).unwrap();
        (opcode, pay)
    }

    fn send_ws_masked_frame(ws: &mut TcpStream, opcode: u8, payload: &[u8]) {
        let mask = [0x11u8, 0x22, 0x33, 0x44];
        let mut out = vec![0x80 | (opcode & 0x0F)];
        if payload.len() < 126 {
            out.push(0x80 | (payload.len() as u8));
        } else {
            out.push(0x80 | 126);
            out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        }
        out.extend_from_slice(&mask);
        for (i, &b) in payload.iter().enumerate() {
            out.push(b ^ mask[i % 4]);
        }
        ws.write_all(&out).unwrap();
    }

    let mock = Arc::new(MockBackend::new());
    mock.manual_frame_mode.store(true, Ordering::Release);
    mock.live_abr_quality.store(true, Ordering::Release);
    let mut cfg = test_config();
    cfg.max_extended_screens = 3;
    cfg.max_web_viewers = 4;
    let wifi_cfg = cfg.clone();
    let reg = Arc::new(SessionRegistry::new(cfg, mock.clone()));
    let stop = Arc::new(AtomicBool::new(false));
    let mut wifi = start_wifi_server(wifi_cfg, mock.clone(), reg.clone(), stop.clone()).unwrap();
    let mut web = start_web_server(
        "127.0.0.1:0",
        Some("adm-iter2-sec".to_string()),
        Some("view-iter2-sec".to_string()),
        reg.clone(),
        LogBuffer::new(),
        stop.clone(),
    )
    .unwrap();
    let addr = web.addr;
    let vaddr = SocketAddr::from(([127, 0, 0, 1], web.viewer_addr().unwrap().port()));

    // 1) GAP-C2: Security header matrix (Sec-Fetch-Site: cross-site, Origin: null, duplicate Host, /view?token= subresource guard)
    let (code, _, _) = raw_http(
        vaddr,
        &format!(
            "POST /api/view/login HTTP/1.1\r\nHost: {vaddr}\r\nOrigin: http://{vaddr}\r\nSec-Fetch-Site: cross-site\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
        ),
    );
    assert_eq!(code, 403, "Sec-Fetch-Site: cross-site POST must be 403");
    let (code, _, _) = raw_http(
        vaddr,
        &format!(
            "POST /api/view/login HTTP/1.1\r\nHost: {vaddr}\r\nOrigin: null\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
        ),
    );
    assert_eq!(code, 403, "Origin: null POST must be 403");
    let (code, _, _) = raw_http(
        addr,
        &format!("GET /api/auth/status HTTP/1.1\r\nHost: {addr}\r\nHost: evil.local\r\nConnection: close\r\n\r\n"),
    );
    assert_eq!(code, 0, "duplicate Host header must abort connection");
    let (code, sub_cookies, _) = raw_http(
        vaddr,
        &format!(
            "GET /view?token=view-iter2-sec HTTP/1.1\r\nHost: {vaddr}\r\nSec-Fetch-Mode: no-cors\r\nSec-Fetch-Dest: image\r\nConnection: close\r\n\r\n"
        ),
    );
    assert_eq!(code, 200);
    assert!(sub_cookies.is_empty(), "subresource /view?token= must NOT mint auth cookie");

    // 2) Login as admin & 3 viewers BEFORE exercising 8-fail -> 9th 429 rate-limit & bucket isolation!
    let (code, acookies, _) = raw_http(
        addr,
        &format!(
            "POST /api/admin/login HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nContent-Type: application/json\r\nContent-Length: 25\r\nConnection: close\r\n\r\n{{\"token\":\"adm-iter2-sec\"}}"
        ),
    );
    assert_eq!(code, 200);
    let admin_cookie = acookies.into_iter().find(|c| c.starts_with("idis_admin=")).unwrap();
    let mut viewer_cookies = Vec::new();
    for _ in 0..3 {
        let (cv, vc, _) = raw_http(
            vaddr,
            &format!(
                "POST /api/view/login HTTP/1.1\r\nHost: {vaddr}\r\nOrigin: http://{vaddr}\r\nContent-Type: application/json\r\nContent-Length: 26\r\nConnection: close\r\n\r\n{{\"token\":\"view-iter2-sec\"}}"
            ),
        );
        assert_eq!(cv, 200);
        viewer_cookies.push(vc.into_iter().find(|c| c.starts_with("idis_view=")).unwrap());
    }

    // 8 failed viewer logins -> 9th is 429, while admin login still works!
    for _ in 0..8 {
        let (c, _, _) = raw_http(
            vaddr,
            &format!(
                "POST /api/view/login HTTP/1.1\r\nHost: {vaddr}\r\nOrigin: http://{vaddr}\r\nContent-Type: application/json\r\nContent-Length: 17\r\nConnection: close\r\n\r\n{{\"token\":\"wrong\"}}"
            ),
        );
        assert_eq!(c, 401);
    }
    let (c9, _, _) = raw_http(
        vaddr,
        &format!(
            "POST /api/view/login HTTP/1.1\r\nHost: {vaddr}\r\nOrigin: http://{vaddr}\r\nContent-Type: application/json\r\nContent-Length: 26\r\nConnection: close\r\n\r\n{{\"token\":\"view-iter2-sec\"}}"
        ),
    );
    assert_eq!(c9, 429, "9th viewer attempt must be rate-limited 429");
    let (c_adm, _, _) = raw_http(
        addr,
        &format!(
            "POST /api/admin/login HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nContent-Type: application/json\r\nContent-Length: 25\r\nConnection: close\r\n\r\n{{\"token\":\"adm-iter2-sec\"}}"
        ),
    );
    assert_eq!(c_adm, 200, "viewer rate-limit must NOT block admin bucket");

    // 3) BUG-B2-2 + BUG-B2-3 E2E: Connect 2 same-resolution (1024x768) IPPP iPads + real /ws/stream!
    let mut tel1 = TcpStream::connect(wifi.telemetry_addr).unwrap();
    tel1.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    write_canal_block(&mut tel1, &make_handshake_packet_custom("fp-i1", "iPad 1", 1024, 768, "5")).unwrap();
    let _ = read_canal_block(&mut tel1).unwrap().unwrap();
    let _ = read_canal_block(&mut tel1).unwrap().unwrap();
    let mut data1 = TcpStream::connect(wifi.data_addr).unwrap();
    data1.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    for _ in 0..40 {
        if !mock.frame_senders.lock().unwrap().is_empty() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    let ipad1_idx = 0;

    let usb_l = TcpListener::bind("127.0.0.1:0").unwrap();
    let usb_a = usb_l.local_addr().unwrap();
    let reg_u = reg.clone();
    let usb_t = thread::spawn(move || {
        let (s, _) = usb_l.accept().unwrap();
        let _ = serve_peertalk_stream(UsbmuxStream::Tcp(s), "usb:failover2".to_string(), reg_u);
    });
    let mut usb_c = TcpStream::connect(usb_a).unwrap();
    usb_c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    write_pt_frame(
        &mut usb_c,
        PT_FRAME_TYPE_TELEMETRY,
        1,
        &make_handshake_packet_custom("fp-i2", "iPad 2", 1024, 768, "5"),
    )
    .unwrap();
    let _ = read_pt_frame(&mut usb_c).unwrap().unwrap();
    let _ = read_pt_frame(&mut usb_c).unwrap().unwrap();
    write_pt_frame(
        &mut usb_c,
        PT_FRAME_TYPE_TELEMETRY,
        2,
        &MessagePacket::new_request("Ping", ArchivedValue::String("START".into()), 5.0)
            .encode()
            .unwrap(),
    )
    .unwrap();
    for _ in 0..40 {
        if mock.frame_senders.lock().unwrap().len() >= 2 {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    let ipad2_idx = 1;

    let make_f = |is_idr: bool| EncodedFrame {
        width: 1024,
        height: 768,
        bytes_per_row: 4096,
        annex_b: if is_idr {
            SYNTHETIC_H264_ANNEX_B.to_vec()
        } else {
            SYNTHETIC_H264_P_FRAME.to_vec()
        },
        is_keyframe: is_idr,
    };

    // Open real /ws/stream on dedicated Viewer port
    let mut ws = ws_open(vaddr, &viewer_cookies[0]);
    // Push IDR on iPad #1 -> WS receives JSON init + 0x01 ftyp + 0x02 IDR
    mock.push_frame_to(ipad1_idx, make_f(true));
    let _ = read_canal_block(&mut data1).unwrap();
    let (op1, _) = read_ws_frame_client(&mut ws);
    assert_eq!(op1, 0x1);
    let (op2, p2) = read_ws_frame_client(&mut ws);
    assert_eq!((op2, p2[0]), (0x2, 0x01));
    let (op3, p3) = read_ws_frame_client(&mut ws);
    assert_eq!((op3, p3[0]), (0x2, 0x02));

    // Verify RFC 6455 Ping -> Pong control frame over live WS (skipping any interleaved video frames).
    send_ws_masked_frame(&mut ws, 0x9, b"hi-ping");
    let mut saw_pong = false;
    for _ in 0..8 {
        let (op_f, p_f) = read_ws_frame_client(&mut ws);
        if op_f == 0xA {
            assert_eq!(p_f.as_slice(), b"hi-ping");
            saw_pong = true;
            break;
        }
    }
    assert!(saw_pong, "WS server must answer RFC 6455 Ping with matching Pong");

    // BUG-B2-2 regression: Close iPad #1, immediately push P-frame on same-resolution iPad #2!
    // WS MUST NOT receive a 0x03 P-frame from iPad #2 before iPad #2 emits an IDR!
    drop(data1);
    drop(tel1);
    reg.close_session("127.0.0.1");
    thread::sleep(Duration::from_millis(40));
    mock.push_frame_to(ipad2_idx, make_f(false)); // P-frame from iPad #2 MUST be gated!
    thread::sleep(Duration::from_millis(60));
    mock.push_frame_to(ipad2_idx, make_f(true)); // IDR from iPad #2 MUST pass!
    let mut saw_idr_after_failover = false;
    for _ in 0..8 {
        let (op, pay) = read_ws_frame_client(&mut ws);
        if op == 0x2 {
            assert_ne!(
                pay[0], 0x03,
                "BUG-B2-2 regression: iPad #2 P-frame (0x03) leaked onto iPad #1 Web DPB before IDR!"
            );
            if pay[0] == 0x02 {
                saw_idr_after_failover = true;
                break;
            }
        }
    }
    assert!(saw_idr_after_failover, "iPad #2 IDR must arrive after failover");

    // 4) GAP-C5: max_web_viewers partial eviction (3 -> 1 keeps 1, closes 2) & POST /api/debug/event caps!
    let mut ws2 = ws_open(vaddr, &viewer_cookies[1]);
    let ws3 = ws_open(vaddr, &viewer_cookies[2]);
    assert_eq!(reg.active_web_viewers(), 3);
    reg.set_max_web_viewers(1);
    assert_eq!(reg.active_web_viewers(), 1, "lowering max_web_viewers 3->1 must evict 2 excess viewers");
    ws2.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
    ws3.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
    let mut d = [0u8; 512];
    let mut ws2_closed = false;
    for _ in 0..32 {
        match ws2.read(&mut d) {
            Ok(0) | Err(_) => {
                ws2_closed = true;
                break;
            }
            Ok(_) => continue,
        }
    }
    assert!(ws2_closed, "evicted excess viewer ws2 must close promptly");

    // POST /api/debug/event: unauth -> 401; admin >4096B -> 413
    let (c_unauth, _, _) = raw_http(
        addr,
        &format!(
            "POST /api/debug/event HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
        ),
    );
    assert_eq!(c_unauth, 401);
    let big_body = format!("{{\"event\":\"x\",\"pad\":\"{}\"}}", "a".repeat(4200));
    idis::debug_trace::set_debug_logging(true);
    let (c_big, _, _) = raw_http(
        addr,
        &format!(
            "POST /api/debug/event HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nCookie: {admin_cookie}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{big_body}",
            big_body.len()
        ),
    );
    idis::debug_trace::set_debug_logging(false);
    assert_eq!(c_big, 413, "oversized /api/debug/event payload must return 413 when debug enabled");

    drop(ws);
    drop(ws2);
    drop(ws3);
    drop(usb_c);
    stop.store(true, Ordering::SeqCst);
    reg.close_all();
    wifi.stop();
    web.stop();
    let _ = usb_t.join();
}

#[test]
fn iter3_ippp_dpb_stress_p2p_visibility_and_mode_switch_e2e() {
    use idis::platform::mock::SYNTHETIC_H264_P_FRAME;
    use idis::platform::EncodedFrame;
    use idis::web::{start_web_server, LogBuffer};
    use std::io::{Read, Write};
    use std::net::SocketAddr;

    fn http_json(
        addr: SocketAddr,
        method: &str,
        path: &str,
        cookie: Option<&str>,
        body: Option<&str>,
    ) -> (u16, Vec<String>, String) {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let b = body.unwrap_or("");
        let mut req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nConnection: close\r\n"
        );
        if let Some(c) = cookie {
            req.push_str(&format!("Cookie: {c}\r\n"));
        }
        if !b.is_empty() {
            req.push_str("Content-Type: application/json\r\n");
            req.push_str(&format!("Content-Length: {}\r\n", b.len()));
        }
        req.push_str("\r\n");
        req.push_str(b);
        s.write_all(req.as_bytes()).unwrap();
        let mut raw = Vec::new();
        let _ = s.read_to_end(&mut raw);
        let text = String::from_utf8_lossy(&raw).to_string();
        let (head, resp_body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        let code = head
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        let cookies = head
            .lines()
            .filter_map(|l| {
                let (k, v) = l.split_once(':')?;
                if k.eq_ignore_ascii_case("set-cookie") {
                    Some(v.trim().split(';').next().unwrap_or("").to_string())
                } else {
                    None
                }
            })
            .collect();
        (code, cookies, resp_body.to_string())
    }

    fn ws_open(addr: SocketAddr, cookie: &str) -> TcpStream {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let req = format!(
            "GET /ws/stream HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nCookie: {cookie}\r\n\r\n"
        );
        s.write_all(req.as_bytes()).unwrap();
        let mut hdr = Vec::new();
        let mut b = [0u8; 1];
        while !hdr.ends_with(b"\r\n\r\n") {
            s.read_exact(&mut b).unwrap();
            hdr.push(b[0]);
        }
        assert!(String::from_utf8_lossy(&hdr).starts_with("HTTP/1.1 101"));
        s
    }

    fn ws_read(ws: &mut TcpStream) -> Option<(u8, Vec<u8>)> {
        let mut h = [0u8; 2];
        if ws.read_exact(&mut h).is_err() {
            return None;
        }
        let op = h[0] & 0x0f;
        let mut len = (h[1] & 0x7f) as usize;
        if len == 126 {
            let mut ext = [0u8; 2];
            ws.read_exact(&mut ext).ok()?;
            len = u16::from_be_bytes(ext) as usize;
        } else if len == 127 {
            let mut ext = [0u8; 8];
            ws.read_exact(&mut ext).ok()?;
            len = u64::from_be_bytes(ext) as usize;
        }
        let mut payload = vec![0u8; len];
        ws.read_exact(&mut payload).ok()?;
        Some((op, payload))
    }

    fn ws_send_text(ws: &mut TcpStream, txt: &str) {
        let payload = txt.as_bytes();
        let mask = [0x12, 0x34, 0x56, 0x78];
        let mut f = vec![0x81u8];
        if payload.len() < 126 {
            f.push(0x80 | (payload.len() as u8));
        } else {
            f.push(0x80 | 126);
            f.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        }
        f.extend_from_slice(&mask);
        for (i, b) in payload.iter().enumerate() {
            f.push(b ^ mask[i % 4]);
        }
        ws.write_all(&f).unwrap();
    }

    let mock = Arc::new(MockBackend::new());
    mock.manual_frame_mode.store(true, Ordering::Release);
    let mut cfg = test_config();
    cfg.max_web_viewers = 4;
    cfg.max_in_flight = idis::config::MaxInFlight::Fixed(1);
    let wifi_cfg = cfg.clone();
    let reg = Arc::new(SessionRegistry::new(cfg, mock.clone()));
    let stop = Arc::new(AtomicBool::new(false));
    let mut wifi = start_wifi_server(wifi_cfg, mock.clone(), reg.clone(), stop.clone()).unwrap();
    let mut web = start_web_server(
        "127.0.0.1:0",
        Some("adm-iter3-dpb".to_string()),
        Some("view-iter3-dpb".to_string()),
        reg.clone(),
        LogBuffer::new(),
        stop.clone(),
    )
    .unwrap();
    let addr = web.addr;
    let vaddr = SocketAddr::from(([127, 0, 0, 1], web.viewer_addr().unwrap().port()));
    let (code, ac, _) = http_json(
        addr,
        "POST",
        "/api/admin/login",
        None,
        Some(r#"{"token":"adm-iter3-dpb"}"#),
    );
    assert_eq!(code, 200);
    let admin_cookie = ac.into_iter().find(|c| c.starts_with("idis_admin=")).unwrap();
    let (cv1, vc1, _) = http_json(
        vaddr,
        "POST",
        "/api/view/login",
        None,
        Some(r#"{"token":"view-iter3-dpb"}"#),
    );
    assert_eq!(cv1, 200);
    let view_cookie_1 = vc1.into_iter().find(|c| c.starts_with("idis_view=")).unwrap();
    let (cv2, vc2, _) = http_json(
        vaddr,
        "POST",
        "/api/view/login",
        None,
        Some(r#"{"token":"view-iter3-dpb"}"#),
    );
    assert_eq!(cv2, 200);
    let view_cookie_2 = vc2.into_iter().find(|c| c.starts_with("idis_view=")).unwrap();

    // Connect iPad #1 over Wi-Fi with max_in_flight=1
    let mut tel = TcpStream::connect(wifi.telemetry_addr).unwrap();
    tel.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    write_canal_block(&mut tel, &make_handshake_packet_custom("dpb-u1", "DPB iPad", 1024, 768, "5")).unwrap();
    let _ = read_canal_block(&mut tel).unwrap().unwrap();
    let _ = read_canal_block(&mut tel).unwrap().unwrap();
    let mut data = TcpStream::connect(wifi.data_addr).unwrap();
    data.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    for _ in 0..40 {
        if !mock.frame_senders.lock().unwrap().is_empty() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    let ipad_cap_idx = 0;

    let make_f = |is_idr: bool| EncodedFrame {
        width: 1024,
        height: 768,
        bytes_per_row: 4096,
        annex_b: if is_idr {
            SYNTHETIC_H264_ANNEX_B.to_vec()
        } else {
            SYNTHETIC_H264_P_FRAME.to_vec()
        },
        is_keyframe: is_idr,
    };

    // Open 2 live WS viewers (`ws1` root, `ws2` child) on dedicated Viewer port
    let mut ws1 = ws_open(vaddr, &view_cookie_1);
    let mut ws2 = ws_open(vaddr, &view_cookie_2);
    ws_send_text(
        &mut ws1,
        r#"{"type":"p2p_hello","supported":true,"can_relay":true,"relay_priority":3}"#,
    );
    ws_send_text(
        &mut ws2,
        r#"{"type":"p2p_hello","supported":true,"can_relay":true,"relay_priority":1}"#,
    );

    // Wait for P2P assignment on ws2 (`p2p_assign_parent`) and record assigned parent_id
    ws2.set_read_timeout(Some(Duration::from_millis(800))).unwrap();
    let mut assigned_parent_id: Option<u64> = None;
    for _ in 0..10 {
        if let Some((0x1, payload)) = ws_read(&mut ws2) {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&payload) {
                if v.get("type").and_then(|t| t.as_str()) == Some("p2p_assign_parent") {
                    assigned_parent_id = v.get("parent_id").and_then(|p| p.as_u64());
                    break;
                }
            }
        }
    }
    let parent_id = assigned_parent_id.expect("2nd WS viewer must receive p2p_assign_parent from P2P hub");

    // 1) Push IDR #1 -> ws1 receives 0x02 IDR; iPad receives IDR #1 and sends `FrameReceived` ACK
    //    to arm FlowControl (`acked_ever = true`). Then push IDR #2 without ACKing so `in_flight == 1 == max_in_flight`!
    let ack = MessagePacket::new_send("FrameReceived", ArchivedValue::Null)
        .encode()
        .unwrap();
    mock.push_frame_to(ipad_cap_idx, make_f(true));
    let _ = read_canal_block(&mut data).unwrap().unwrap();
    write_canal_block(&mut tel, &ack).unwrap();
    thread::sleep(Duration::from_millis(30));

    let mut ws1_got_idr = false;
    ws1.set_read_timeout(Some(Duration::from_millis(800))).unwrap();
    for _ in 0..10 {
        if let Some((op, pay)) = ws_read(&mut ws1) {
            if op == 0x2 && pay.first() == Some(&0x02) {
                ws1_got_idr = true;
                break;
            }
        }
    }
    assert!(ws1_got_idr, "ws1 must receive initial IDR");

    // Push IDR #2 without ACKing -> saturates max_in_flight=1.
    // Wait for BOTH iPad (`data`) AND `ws1` to consume IDR #2 before pushing P-frame #1 so P-frame #1
    // never overwrites unread IDR #2 inside `ws1`'s 1-slot FrameSlot on coarser Windows timers!
    mock.push_frame_to(ipad_cap_idx, make_f(true));
    let _ = read_canal_block(&mut data).unwrap().unwrap();
    let mut ws1_got_idr2 = false;
    ws1.set_read_timeout(Some(Duration::from_millis(800))).unwrap();
    for _ in 0..8 {
        if let Some((op, pay)) = ws_read(&mut ws1) {
            if op == 0x2 && pay.first() == Some(&0x02) {
                ws1_got_idr2 = true;
                break;
            }
        }
    }
    assert!(ws1_got_idr2, "ws1 must receive IDR #2 before P-frame overflow burst");

    // 2) pending_queue overflow (>4 P-frames while iPad max_in_flight=1 is saturated within <120ms):
    //    - First push 1 P-frame and confirm ws1 receives it cleanly (`ws1_p_count >= 1`).
    //    - Then push 6 more P-frames 5ms apart (still <120ms even under Windows 15.6ms timer ticks)
    //      so iPad pending_queue (cap=4) overflows deterministically!
    let mut ws1_p_count = 0usize;
    mock.push_frame_to(ipad_cap_idx, make_f(false));
    ws1.set_read_timeout(Some(Duration::from_millis(800))).unwrap();
    for _ in 0..8 {
        if let Some((op, pay)) = ws_read(&mut ws1) {
            if op == 0x2 && pay.first() == Some(&0x03) {
                ws1_p_count += 1;
                break;
            }
        }
    }
    for _ in 0..6 {
        mock.push_frame_to(ipad_cap_idx, make_f(false));
        thread::sleep(Duration::from_millis(5));
    }
    ws1.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
    while let Some((op, pay)) = ws_read(&mut ws1) {
        if op == 0x2 && pay.first() == Some(&0x03) {
            ws1_p_count += 1;
        }
    }
    assert!(
        ws1_p_count >= 1,
        "FollowIpad Web viewer must continue receiving P-frames even while iPad pending_queue overflows"
    );
    // Now ACK IDR #2 -> push another P-frame -> iPad MUST NOT receive bare P-frame (awaiting IDR)!
    write_canal_block(&mut tel, &ack).unwrap();
    thread::sleep(Duration::from_millis(40));
    mock.push_frame_to(ipad_cap_idx, make_f(false));
    data.set_read_timeout(Some(Duration::from_millis(180))).unwrap();
    assert!(
        read_canal_block(&mut data).is_err(),
        "after pending_queue overflow, iPad must drop bare P-frame until fresh IDR"
    );
    mock.push_frame_to(ipad_cap_idx, make_f(true));
    data.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let resync_idr = read_canal_block(&mut data).unwrap().unwrap();
    let rh = parse_video_header(&resync_idr).unwrap();
    assert_eq!(&resync_idr[rh.payload_offset..], SYNTHETIC_H264_ANNEX_B);
    write_canal_block(&mut tel, &ack).unwrap();

    // 3) P2P active -> WS direct pauses on ws2 -> p2p_fallback -> ws2 drops P-frame until IDR!
    ws_send_text(
        &mut ws2,
        &format!(r#"{{"type":"p2p_active","parent_id":{parent_id}}}"#),
    );
    thread::sleep(Duration::from_millis(40));
    // Drain any queued ws2 frames before testing direct pause
    ws2.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
    while ws_read(&mut ws2).is_some() {}
    mock.push_frame_to(ipad_cap_idx, make_f(false));
    let mut ws2_saw_bin_while_p2p = false;
    while let Some((op, _)) = ws_read(&mut ws2) {
        if op == 0x2 {
            ws2_saw_bin_while_p2p = true;
        }
    }
    assert!(
        !ws2_saw_bin_while_p2p,
        "ws2 must receive ZERO binary video frames while p2p_active"
    );
    ws_send_text(&mut ws2, r#"{"type":"p2p_fallback","reason":"test"}"#);
    thread::sleep(Duration::from_millis(40));
    mock.push_frame_to(ipad_cap_idx, make_f(false)); // MUST be dropped on ws2!
    let mut ws2_saw_p_before_idr = false;
    while let Some((op, pay)) = ws_read(&mut ws2) {
        if op == 0x2 && pay.first() == Some(&0x03) {
            ws2_saw_p_before_idr = true;
        }
    }
    assert!(
        !ws2_saw_p_before_idr,
        "after p2p_fallback, ws2 MUST NOT receive P-frame before fresh IDR"
    );
    mock.push_frame_to(ipad_cap_idx, make_f(true));
    ws2.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let mut ws2_saw_idr = false;
    for _ in 0..8 {
        if let Some((op, pay)) = ws_read(&mut ws2) {
            if op == 0x2 && pay.first() == Some(&0x02) {
                ws2_saw_idr = true;
                break;
            }
        }
    }
    assert!(ws2_saw_idr, "ws2 must recover cleanly on fresh IDR after p2p_fallback");

    // 4) P1-B1 + P1-B3 regression: follow_ipad -> main -> follow_ipad must NOT leak iPad P-frame!
    let (c_m, _, _) = http_json(
        addr,
        "POST",
        "/api/admin/settings",
        Some(&admin_cookie),
        Some(r#"{"web_screen_mode":"main"}"#),
    );
    assert_eq!(c_m, 200);
    // Push a P-frame on iPad while in Main mode -> sets web_follow_needs_idr=true
    mock.push_frame_to(ipad_cap_idx, make_f(false));
    thread::sleep(Duration::from_millis(40));
    // Switch straight back to follow_ipad and push P-frame -> MUST NOT reach ws1 before IDR!
    let (c_f, _, _) = http_json(
        addr,
        "POST",
        "/api/admin/settings",
        Some(&admin_cookie),
        Some(r#"{"web_screen_mode":"follow_ipad"}"#),
    );
    assert_eq!(c_f, 200);
    ws1.set_read_timeout(Some(Duration::from_millis(120))).unwrap();
    while ws_read(&mut ws1).is_some() {}
    mock.push_frame_to(ipad_cap_idx, make_f(false));
    let mut leaked_p = false;
    while let Some((op, pay)) = ws_read(&mut ws1) {
        if op == 0x2 && pay.first() == Some(&0x03) {
            leaked_p = true;
        }
    }
    assert!(
        !leaked_p,
        "P1-B1 regression: follow_ipad -> main -> follow_ipad must NOT leak P-frame before IDR"
    );

    // 5) viewer_visibility: false pauses standalone Main capture; true unpauses it!
    drop(ws2);
    let (c_m2, _, _) = http_json(
        addr,
        "POST",
        "/api/admin/settings",
        Some(&admin_cookie),
        Some(r#"{"web_screen_mode":"main"}"#),
    );
    assert_eq!(c_m2, 200);
    mock.recorded_pauses.lock().unwrap().clear();
    ws_send_text(&mut ws1, r#"{"type":"viewer_visibility","visible":false}"#);
    let mut saw_pause = false;
    for _ in 0..20 {
        if mock.recorded_pauses.lock().unwrap().contains(&true) {
            saw_pause = true;
            break;
        }
        thread::sleep(Duration::from_millis(25));
    }
    assert!(saw_pause, "viewer_visibility=false must pause standalone capture");
    mock.recorded_pauses.lock().unwrap().clear();
    ws_send_text(&mut ws1, r#"{"type":"viewer_visibility","visible":true}"#);
    let mut saw_unpause = false;
    for _ in 0..20 {
        if mock.recorded_pauses.lock().unwrap().contains(&false) {
            saw_unpause = true;
            break;
        }
        thread::sleep(Duration::from_millis(25));
    }
    assert!(saw_unpause, "viewer_visibility=true must resume standalone capture");

    drop(ws1);
    drop(data);
    drop(tel);
    stop.store(true, Ordering::SeqCst);
    reg.close_all();
    wifi.stop();
    web.stop();
}

#[test]
fn iter3_live_abr_and_non_abr_focus_fps_matrix_e2e() {
    use idis::platform::mock::SYNTHETIC_H264_P_FRAME;
    use idis::platform::EncodedFrame;

    // Part 1: live_abr_quality=false -> unfocused half-FPS must NOT call update_stream_quality
    //         and must report unfocused_fps_halved=false.
    {
        let mock = Arc::new(MockBackend::new());
        mock.live_abr_quality.store(false, Ordering::Release);
        mock.cursor_visible.store(false, Ordering::Release);
        let mut cfg = test_config();
        cfg.half_fps_unfocused = true;
        let wifi_cfg = cfg.clone();
        let reg = Arc::new(SessionRegistry::new(cfg, mock.clone()));
        let stop = Arc::new(AtomicBool::new(false));
        let mut wifi = start_wifi_server(wifi_cfg, mock.clone(), reg.clone(), stop.clone()).unwrap();

        let mut tel = TcpStream::connect(wifi.telemetry_addr).unwrap();
        tel.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        write_canal_block(&mut tel, &make_handshake_packet_custom("noabr-u1", "NoABR iPad", 1024, 768, "5")).unwrap();
        let _ = read_canal_block(&mut tel).unwrap().unwrap();
        let _ = read_canal_block(&mut tel).unwrap().unwrap();
        let mut data = TcpStream::connect(wifi.data_addr).unwrap();
        data.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
        let _ = read_canal_block(&mut data);
        thread::sleep(Duration::from_millis(350));
        assert!(
            mock.recorded_quality_updates.lock().unwrap().is_empty(),
            "non-ABR backend must never receive focus-FPS update_stream_quality calls"
        );
        let list = reg.list_sessions();
        assert_eq!(list.len(), 1);
        assert!(
            !list[0].abr.as_ref().is_some_and(|a| a.unfocused_fps_halved),
            "non-ABR backend must report unfocused_fps_halved=false"
        );
        drop(data);
        drop(tel);
        stop.store(true, Ordering::SeqCst);
        reg.close_all();
        wifi.stop();
    }

    // Part 2: live_abr_quality=true + sustained frame drops -> live ABR steps down Tier 0 -> >=1,
    //         then disabling adaptive_quality restores Tier 0!
    {
        let mock = Arc::new(MockBackend::new());
        mock.manual_frame_mode.store(true, Ordering::Release);
        mock.live_abr_quality.store(true, Ordering::Release);
        let mut cfg = test_config();
        cfg.max_in_flight = idis::config::MaxInFlight::Fixed(1);
        let wifi_cfg = cfg.clone();
        let reg = Arc::new(SessionRegistry::new(cfg, mock.clone()));
        let stop = Arc::new(AtomicBool::new(false));
        let mut wifi = start_wifi_server(wifi_cfg, mock.clone(), reg.clone(), stop.clone()).unwrap();

        let mut tel = TcpStream::connect(wifi.telemetry_addr).unwrap();
        tel.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        write_canal_block(&mut tel, &make_handshake_packet_custom("abr-u1", "ABR iPad", 1024, 768, "5")).unwrap();
        let _ = read_canal_block(&mut tel).unwrap().unwrap();
        let _ = read_canal_block(&mut tel).unwrap().unwrap();
        let mut data = TcpStream::connect(wifi.data_addr).unwrap();
        data.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        for _ in 0..40 {
            if !mock.frame_senders.lock().unwrap().is_empty() {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }

        let make_f = |is_idr: bool| EncodedFrame {
            width: 1024,
            height: 768,
            bytes_per_row: 4096,
            annex_b: if is_idr {
                SYNTHETIC_H264_ANNEX_B.to_vec()
            } else {
                SYNTHETIC_H264_P_FRAME.to_vec()
            },
            is_keyframe: is_idr,
        };
        // Arm FlowControl (`acked_ever = true`) with 1 ACK, then saturate max_in_flight=1 and
        // generate heavy drops across 2+ consecutive 1s windows so live ABR steps down!
        let ack = MessagePacket::new_send("FrameReceived", ArchivedValue::Null)
            .encode()
            .unwrap();
        mock.push_frame_to(0, make_f(true));
        let _ = read_canal_block(&mut data).unwrap().unwrap();
        write_canal_block(&mut tel, &ack).unwrap();
        thread::sleep(Duration::from_millis(25));
        mock.push_frame_to(0, make_f(true));
        let _ = read_canal_block(&mut data).unwrap().unwrap();

        let mut stepped_down = false;
        for _tick in 0..70 {
            for _ in 0..6 {
                mock.push_frame_to(0, make_f(true));
                thread::sleep(Duration::from_millis(8));
            }
            thread::sleep(Duration::from_millis(45));
            if let Some(s) = reg.list_sessions().first() {
                if s.abr.as_ref().is_some_and(|a| a.tier >= 1) {
                    stepped_down = true;
                    break;
                }
            }
        }
        assert!(
            stepped_down,
            "live data_channel ABR must step down under sustained frame drops; updates={:?}",
            *mock.recorded_quality_updates.lock().unwrap()
        );
        assert!(
            !mock.recorded_quality_updates.lock().unwrap().is_empty(),
            "ABR step-down must invoke update_stream_quality on capture backend"
        );

        // Toggle adaptive_quality=false -> must reset ABR back to Tier 0!
        let _ = reg.update_video_settings(idis::session::VideoSettingsPatch {
            adaptive_quality: Some(false),
            ..Default::default()
        });
        let mut restored_t0 = false;
        for _ in 0..25 {
            thread::sleep(Duration::from_millis(100));
            if let Some(s) = reg.list_sessions().first() {
                if s.abr.as_ref().is_some_and(|a| a.tier == 0) {
                    restored_t0 = true;
                    break;
                }
            }
        }
        assert!(restored_t0, "disabling adaptive_quality must restore ABR to Tier 0");

        drop(data);
        drop(tel);
        stop.store(true, Ordering::SeqCst);
        reg.close_all();
        wifi.stop();
    }
}

#[test]
fn iter3_web_eviction_ghost_trust_and_cli_builder_bridge_e2e() {
    use idis::web::{start_web_server, LogBuffer};
    use std::io::{Read, Write};
    use std::net::SocketAddr;
    use std::process::Command;

    fn raw_http(addr: SocketAddr, req: &str) -> (u16, Vec<String>, String) {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        s.write_all(req.as_bytes()).unwrap();
        let mut raw = Vec::new();
        let _ = s.read_to_end(&mut raw);
        let text = String::from_utf8_lossy(&raw).to_string();
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        let code = head
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        let cookies = head
            .lines()
            .filter_map(|l| {
                let (k, v) = l.split_once(':')?;
                if k.eq_ignore_ascii_case("set-cookie") {
                    Some(v.trim().split(';').next().unwrap_or("").to_string())
                } else {
                    None
                }
            })
            .collect();
        (code, cookies, body.to_string())
    }

    fn ws_try(addr: SocketAddr, cookie: &str) -> Result<TcpStream, u16> {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let req = format!(
            "GET /ws/stream HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nCookie: {cookie}\r\n\r\n"
        );
        s.write_all(req.as_bytes()).unwrap();
        let mut hdr = Vec::new();
        let mut b = [0u8; 1];
        while !hdr.ends_with(b"\r\n\r\n") {
            s.read_exact(&mut b).unwrap();
            hdr.push(b[0]);
        }
        let head = String::from_utf8_lossy(&hdr);
        let code = head
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        if code == 101 {
            Ok(s)
        } else {
            Err(code)
        }
    }

    fn assert_ws_closed(mut ws: TcpStream, label: &str) {
        ws.set_read_timeout(Some(Duration::from_millis(600))).unwrap();
        let mut buf = [0u8; 256];
        let mut closed = false;
        for _ in 0..20 {
            match ws.read(&mut buf) {
                Ok(0) | Err(_) => {
                    closed = true;
                    break;
                }
                Ok(_) => continue,
            }
        }
        assert!(closed, "{label}: WS must close promptly");
    }

    let mock = Arc::new(MockBackend::new());
    let mut cfg = test_config();
    cfg.max_web_viewers = 4;
    cfg.web_require_approval = true;
    let reg = Arc::new(SessionRegistry::new(cfg, mock.clone()));
    let stop = Arc::new(AtomicBool::new(false));
    let mut web = start_web_server(
        "127.0.0.1:0",
        Some("adm-iter3-sec".to_string()),
        Some("view-init".to_string()),
        reg.clone(),
        LogBuffer::new(),
        stop.clone(),
    )
    .unwrap();
    let addr = web.addr;
    let vaddr = SocketAddr::from(([127, 0, 0, 1], web.viewer_addr().unwrap().port()));

    // Login Admin
    let (c, ac, _) = raw_http(
        addr,
        &format!(
            "POST /api/admin/login HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nContent-Type: application/json\r\nContent-Length: 25\r\nConnection: close\r\n\r\n{{\"token\":\"adm-iter3-sec\"}}"
        ),
    );
    assert_eq!(c, 200);
    let admin_cookie = ac.into_iter().find(|x| x.starts_with("idis_admin=")).unwrap();

    // Login Viewer A (AllowOnce) on Viewer port
    let (c, vc, _) = raw_http(
        vaddr,
        &format!(
            "POST /api/view/login HTTP/1.1\r\nHost: {vaddr}\r\nOrigin: http://{vaddr}\r\nUser-Agent: TestBrowser/1\r\nContent-Type: application/json\r\nContent-Length: 21\r\nConnection: close\r\n\r\n{{\"token\":\"view-init\"}}"
        ),
    );
    assert_eq!(c, 200);
    let v_cookie = vc.join("; ");

    // Approve Viewer A with AllowOnce
    let v_cookie_c = v_cookie.clone();
    let req_t = thread::spawn(move || {
        raw_http(
            vaddr,
            &format!(
                "POST /api/view/request-approval HTTP/1.1\r\nHost: {vaddr}\r\nOrigin: http://{vaddr}\r\nUser-Agent: TestBrowser/1\r\nCookie: {v_cookie_c}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
            ),
        )
    });
    let mut pid = None;
    for _ in 0..40 {
        let (_, _, st) = raw_http(
            addr,
            &format!("GET /api/admin/state HTTP/1.1\r\nHost: {addr}\r\nCookie: {admin_cookie}\r\nConnection: close\r\n\r\n"),
        );
        let v: serde_json::Value = serde_json::from_str(&st).unwrap();
        if let Some(id) = v["pending_approvals"][0]["id"].as_u64() {
            pid = Some(id);
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    let dec = format!(r#"{{"id":{},"decision":"allow_once"}}"#, pid.unwrap());
    let (cd, _, _) = raw_http(
        addr,
        &format!(
            "POST /api/admin/pending/decide HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nCookie: {admin_cookie}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{dec}",
            dec.len()
        ),
    );
    assert_eq!(cd, 200);
    assert_eq!(req_t.join().unwrap().0, 200);

    // 1) P1-C2: Unrelated YAML save (keeping max_web_viewers=4 & web_require_approval=true)
    //    must NOT evict valid AllowOnce Viewer A!
    let ws_a = ws_try(vaddr, &v_cookie).expect("AllowOnce viewer must open WS");
    let mut cfg_snapshot = reg.export_user_config();
    cfg_snapshot.lock_delay_secs = 15;
    let yaml_str = cfg_snapshot.to_yaml_string().unwrap();
    let save_body = serde_json::json!({ "yaml": yaml_str }).to_string();
    let (cs, _, _) = raw_http(
        addr,
        &format!(
            "POST /api/admin/config HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nCookie: {admin_cookie}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{save_body}",
            save_body.len()
        ),
    );
    assert_eq!(cs, 200);
    assert_eq!(reg.active_web_viewers(), 1, "P1-C2: unrelated YAML save must keep AllowOnce viewer connected");

    // 2) Kick-all `/api/admin/viewers/disconnect` (id=None) closes ws_a AND revokes AllowOnce!
    let (ck, _, _) = raw_http(
        addr,
        &format!(
            "POST /api/admin/viewers/disconnect HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nCookie: {admin_cookie}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
        ),
    );
    assert_eq!(ck, 200);
    assert_ws_closed(ws_a, "kick-all");
    assert_eq!(
        ws_try(vaddr, &v_cookie).unwrap_err(),
        403,
        "kick-all must revoke AllowOnce so viewer cannot silently reconnect"
    );

    // 3) P2-C4: Ghost AllowOnce & Ghost AllowAndTrust aborted when client closes (FIN) before admin decides!
    {
        let mut s_fin = TcpStream::connect(vaddr).unwrap();
        let req = format!(
            "POST /api/view/request-approval HTTP/1.1\r\nHost: {vaddr}\r\nOrigin: http://{vaddr}\r\nUser-Agent: GhostFin/1\r\nCookie: {v_cookie}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
        );
        s_fin.write_all(req.as_bytes()).unwrap();
        let mut gid = None;
        for _ in 0..40 {
            let (_, _, st) = raw_http(
                addr,
                &format!("GET /api/admin/state HTTP/1.1\r\nHost: {addr}\r\nCookie: {admin_cookie}\r\nConnection: close\r\n\r\n"),
            );
            let v: serde_json::Value = serde_json::from_str(&st).unwrap();
            if let Some(id) = v["pending_approvals"][0]["id"].as_u64() {
                gid = Some(id);
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        // Close client BEFORE admin clicks AllowOnce!
        drop(s_fin);
        thread::sleep(Duration::from_millis(40));
        let dec = format!(r#"{{"id":{},"decision":"allow_once"}}"#, gid.unwrap());
        let _ = raw_http(
            addr,
            &format!(
                "POST /api/admin/pending/decide HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nCookie: {admin_cookie}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{dec}",
                dec.len()
            ),
        );
        thread::sleep(Duration::from_millis(50));
        assert_eq!(
            ws_try(vaddr, &v_cookie).unwrap_err(),
            403,
            "P2-C4: disconnected peer must NOT be granted ghost AllowOnce approval"
        );
    }

    // 4) rotate_view_token evicts active viewer WS; /api/view/logout evicts viewer WS; /api/admin/logout revokes admin cookie!
    reg.set_web_require_approval(false);
    let ws_v = ws_try(vaddr, &v_cookie).unwrap();
    let (cr, _, rot_body) = raw_http(
        addr,
        &format!(
            "POST /api/admin/settings HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nCookie: {admin_cookie}\r\nContent-Type: application/json\r\nContent-Length: 26\r\nConnection: close\r\n\r\n{{\"rotate_view_token\":true}}"
        ),
    );
    assert_eq!(cr, 200);
    assert_ws_closed(ws_v, "rotate_view_token");
    let rot_json: serde_json::Value = serde_json::from_str(&rot_body).unwrap();
    let new_tok = rot_json["generated_view_token"].as_str().unwrap().to_string();
    let login_new_body = format!(r#"{{"token":"{new_tok}"}}"#);
    let (cn, vc_new, _) = raw_http(
        vaddr,
        &format!(
            "POST /api/view/login HTTP/1.1\r\nHost: {vaddr}\r\nOrigin: http://{vaddr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{login_new_body}",
            login_new_body.len()
        ),
    );
    assert_eq!(cn, 200);
    let v_cookie_new = vc_new.join("; ");
    let ws_v2 = ws_try(vaddr, &v_cookie_new).unwrap();
    let (cvl, _, _) = raw_http(
        vaddr,
        &format!(
            "POST /api/view/logout HTTP/1.1\r\nHost: {vaddr}\r\nOrigin: http://{vaddr}\r\nCookie: {v_cookie_new}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
        ),
    );
    assert_eq!(cvl, 200);
    assert_ws_closed(ws_v2, "/api/view/logout");

    let (cl, _, _) = raw_http(
        addr,
        &format!(
            "POST /api/admin/logout HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nCookie: {admin_cookie}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
        ),
    );
    assert_eq!(cl, 200);
    let (c_after_lo, _, _) = raw_http(
        addr,
        &format!("GET /api/admin/state HTTP/1.1\r\nHost: {addr}\r\nCookie: {admin_cookie}\r\nConnection: close\r\n\r\n"),
    );
    assert_eq!(c_after_lo, 401);

    // 5) low_power closes dynamic Viewer port immediately!
    reg.set_web_require_approval(true);
    reg.set_low_power(true);
    assert!(
        web.viewer_addr().is_none(),
        "low_power must close dynamic Web Viewer listener immediately"
    );
    assert!(
        TcpStream::connect_timeout(&vaddr, Duration::from_millis(300)).is_err(),
        "low_power must refuse connections on previously open viewer port"
    );

    stop.store(true, Ordering::SeqCst);
    reg.close_all();
    web.stop();

    // 6) Rust <-> JS CLI Builder Contract Bridge: run admin.html's `buildCliCommand()` via Node.js
    //    and parse EVERY emitted CLI command with Rust's real `clap::Parser` (`AppConfig::try_parse_from`)!
    use clap::Parser;
    let node_script = r#"
const fs = require('fs');
const vm = require('vm');
const html = fs.readFileSync('src/web/admin.html', 'utf8');
const scripts = [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].map(m => m[1]).join('\n');
const mq = scripts.match(/function shellQuote\([\s\S]*?\n\}/);
const m = scripts.match(/function buildCliCommand\([\s\S]*?\n\}/);
if (!mq || !m) throw new Error('shellQuote/buildCliCommand not found');
const ctx = vm.createContext({ encodeURIComponent, Number, String, Boolean, Array, Object, document: { getElementById: () => ({ checked: false }) } });
vm.runInContext(mq[0] + '\n' + m[0], ctx);
const profiles = [
  {
    cli_config: {
      mode: 'extend', wifi: true, no_usb: false, no_bonjour: false, bind_addr: '0.0.0.0',
      telemetry_port: 5026, data_port: 5027, host_name: 'Mac', display_id: 0,
      client_cursor: true, half_fps_when_unfocused: true, web_screen_mode: 'main', web_require_approval: true,
      ping_timeout_secs: 20, idle_exit_secs: 300, trust_usb: false, require_usb_confirm: false,
      low_power: false, auto_accept: false, no_confirm: false, web_bind: '0.0.0.0:8787',
      web_width: 1280, web_height: 720, web_fps: 30, web_bitrate_mbps: 16, web_hidpi: 1,
      web_max_pixel_edge: 0, qr: false, debug: false, all_intra: false, allow_ips: ['192.168.1.5'], allow_fingerprints: ['fp:0123456789abcdef01234567'],
    },
    video: { width: 1440, height: 900, fps: 45, bitrate_mbps: 20, hidpi: 2, integer_scale: true, max_pixel_edge: 2048, adaptive_quality: false, half_fps_when_unfocused: true, web_width: 1920, web_height: 1080, web_fps: 25, web_bitrate_mbps: 12, web_hidpi: 2, web_max_pixel_edge: 1920 },
    settings: { allow_input: true, client_cursor: true, max_extended_screens: 3, max_web_viewers: 4, auto_max_in_flight: false, max_in_flight: 4, web_screen_mode: 'main', web_require_approval: true, lock_action_ipad: 'disconnect', lock_action_web: 'keep', lock_delay_secs: 15, low_power: false },
  },
  {
    cli_config: {
      mode: 'mirror', wifi: false, no_usb: true, no_bonjour: true, bind_addr: '127.0.0.1',
      telemetry_port: 5126, data_port: 5127, host_name: 'Studio', display_id: 2,
      client_cursor: false, half_fps_when_unfocused: false, web_screen_mode: 'independent', web_require_approval: false,
      ping_timeout_secs: 30, idle_exit_secs: 0, trust_usb: false, require_usb_confirm: true,
      low_power: true, auto_accept: false, no_confirm: true, web_bind: '127.0.0.1:9999',
      web_width: 1280, web_height: 720, web_fps: 30, web_bitrate_mbps: 16, web_hidpi: 1,
      web_max_pixel_edge: 0, qr: true, debug: true, all_intra: true, allow_ips: [], allow_fingerprints: [],
    },
    video: { width: 0, height: 0, fps: 15, bitrate_mbps: 6, hidpi: 1, integer_scale: false, max_pixel_edge: 0, adaptive_quality: true, half_fps_when_unfocused: false, web_width: 1280, web_height: 720, web_fps: 30, web_bitrate_mbps: 16, web_hidpi: 1, web_max_pixel_edge: 0 },
    settings: { allow_input: false, client_cursor: false, max_extended_screens: 1, max_web_viewers: 0, auto_max_in_flight: true, max_in_flight: 2, web_screen_mode: 'independent', web_require_approval: false, lock_action_ipad: 'pause', lock_action_web: 'pause', lock_delay_secs: 10, low_power: true },
  },
];
console.log(JSON.stringify(profiles.map(p => ctx.buildCliCommand(p))));
"#;
    let out = Command::new("node")
        .arg("-e")
        .arg(node_script)
        .output()
        .expect("node must be available to run CLI builder contract bridge");
    assert!(
        out.status.success(),
        "node script failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let cmds: Vec<String> = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(cmds.len(), 2);

    // Split shell-quoted tokens cleanly and verify Rust clap parses EVERY emitted command!
    fn split_shell(cmd: &str) -> Vec<String> {
        let mut tokens = Vec::new();
        let mut cur = String::new();
        let mut in_sq = false;
        let mut in_dq = false;
        for ch in cmd.chars() {
            match ch {
                '\'' if !in_dq => in_sq = !in_sq,
                '"' if !in_sq => in_dq = !in_dq,
                c if c.is_whitespace() && !in_sq && !in_dq => {
                    if !cur.is_empty() {
                        tokens.push(std::mem::take(&mut cur));
                    }
                }
                c => cur.push(c),
            }
        }
        if !cur.is_empty() {
            tokens.push(cur);
        }
        tokens
    }

    let p1 = AppConfig::try_parse_from(split_shell(&cmds[0]))
        .unwrap_or_else(|e| panic!("buildCliCommand profile 1 failed clap parse ({:?}): {e}", cmds[0]));
    assert!(p1.client_cursor);
    assert!(p1.half_fps_unfocused);
    assert!(p1.web_require_approval);
    assert_eq!(p1.web_screen_mode, Some(idis::config::WebScreenMode::Main));
    assert_eq!(p1.fps, 45);
    assert_eq!(p1.hidpi, 2);
    assert!(p1.integer_scale);
    assert!(p1.no_adaptive_quality);

    let p2 = AppConfig::try_parse_from(split_shell(&cmds[1]))
        .unwrap_or_else(|e| panic!("buildCliCommand profile 2 failed clap parse ({:?}): {e}", cmds[1]));
    assert!(p2.low_power);
    assert!(p2.no_confirm);
    assert!(p2.all_intra);
    assert!(p2.require_usb_confirm);
    assert!(p2.web_independent_screen);
}

#[test]
fn iter4_quiet_lock_pause_idr_clear_and_closed_tab_approval_eviction_e2e() {
    use idis::platform::mock::SYNTHETIC_H264_P_FRAME;
    use idis::platform::EncodedFrame;
    use idis::web::{start_web_server, LogBuffer};
    use std::io::{Read, Write};
    use std::net::SocketAddr;

    fn raw_http(addr: SocketAddr, req: &str) -> (u16, Vec<String>, String) {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        s.write_all(req.as_bytes()).unwrap();
        let mut raw = Vec::new();
        let _ = s.read_to_end(&mut raw);
        let text = String::from_utf8_lossy(&raw).to_string();
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        let code = head
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        let cookies = head
            .lines()
            .filter_map(|l| {
                let (k, v) = l.split_once(':')?;
                if k.eq_ignore_ascii_case("set-cookie") {
                    Some(v.trim().split(';').next().unwrap_or("").to_string())
                } else {
                    None
                }
            })
            .collect();
        (code, cookies, body.to_string())
    }

    // Part 1 (P2-B3): Quiet/hardware-paused capture (no frames arriving -> Timeout branch) under
    // `host_lock_paused_ipad` MUST clear `last_sent_idr` so host unlock does NOT re-send pre-lock IDR!
    let mock = Arc::new(MockBackend::new());
    mock.manual_frame_mode.store(true, Ordering::Release);
    let mut cfg = test_config();
    cfg.max_web_viewers = 4;
    cfg.web_require_approval = true;
    let wifi_cfg = cfg.clone();
    let reg = Arc::new(SessionRegistry::new(cfg, mock.clone()));
    reg.set_lock_action_ipad(idis::config::LockAction::Pause);
    reg.set_lock_delay_secs(0);
    let stop = Arc::new(AtomicBool::new(false));
    let mut wifi = start_wifi_server(wifi_cfg, mock.clone(), reg.clone(), stop.clone()).unwrap();
    let mut web = start_web_server(
        "127.0.0.1:0",
        Some("adm-iter4-sec".to_string()),
        Some("view-iter4".to_string()),
        reg.clone(),
        LogBuffer::new(),
        stop.clone(),
    )
    .unwrap();

    let mut tel = TcpStream::connect(wifi.telemetry_addr).unwrap();
    tel.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    write_canal_block(&mut tel, &make_handshake_packet_custom("u-quiet", "Quiet", 1024, 768, "5")).unwrap();
    let _ = read_canal_block(&mut tel).unwrap().unwrap();
    let _ = read_canal_block(&mut tel).unwrap().unwrap();
    let mut data = TcpStream::connect(wifi.data_addr).unwrap();
    data.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    for _ in 0..40 {
        if !mock.frame_senders.lock().unwrap().is_empty() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }

    // Send 1 pre-lock IDR so `last_sent_idr` is populated on data_channel
    mock.push_frame_to(
        0,
        EncodedFrame {
            width: 1024,
            height: 768,
            bytes_per_row: 4096,
            annex_b: SYNTHETIC_H264_ANNEX_B.to_vec(),
            is_keyframe: true,
        },
    );
    let _ = read_canal_block(&mut data).unwrap().unwrap();

    // Lock host (ipad=pause, delay=0) WITHOUT pushing any frames (simulates macOS SCStream pause -> Timeout branch!)
    mock.screen_locked.store(true, Ordering::Release);
    reg.on_host_screen_lock_changed(true);
    thread::sleep(Duration::from_millis(220)); // >120ms recv_timeout so Timeout branch runs while locked!

    // Unlock host -> MUST NOT re-send stale pre-lock `last_sent_idr`!
    mock.screen_locked.store(false, Ordering::Release);
    reg.on_host_screen_lock_changed(false);
    data.set_read_timeout(Some(Duration::from_millis(250))).unwrap();
    assert!(
        read_canal_block(&mut data).is_err(),
        "P2-B3: unlocking after quiet/hardware-paused lock MUST NOT re-send stale pre-lock last_sent_idr"
    );
    // And a bare P-frame must still be gated until a fresh post-unlock IDR arrives
    mock.push_frame_to(
        0,
        EncodedFrame {
            width: 1024,
            height: 768,
            bytes_per_row: 4096,
            annex_b: SYNTHETIC_H264_P_FRAME.to_vec(),
            is_keyframe: false,
        },
    );
    assert!(read_canal_block(&mut data).is_err(), "bare P-frame after unlock must be gated");
    mock.push_frame_to(
        0,
        EncodedFrame {
            width: 1024,
            height: 768,
            bytes_per_row: 4096,
            annex_b: SYNTHETIC_H264_ANNEX_B.to_vec(),
            is_keyframe: true,
        },
    );
    data.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    assert!(read_canal_block(&mut data).unwrap().is_some(), "fresh post-unlock IDR must deliver cleanly");

    // Part 2 (P2-C4): Closed-tab Web viewer pending approval slot is evicted within <1s (NOT lingering 60s!)
    let addr = web.addr;
    let vaddr = SocketAddr::from(([127, 0, 0, 1], web.viewer_addr().unwrap().port()));
    let (_, ac, _) = raw_http(
        addr,
        &format!(
            "POST /api/admin/login HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nContent-Type: application/json\r\nContent-Length: 25\r\nConnection: close\r\n\r\n{{\"token\":\"adm-iter4-sec\"}}"
        ),
    );
    let admin_cookie = ac.into_iter().find(|c| c.starts_with("idis_admin=")).unwrap();
    let (_, vc, _) = raw_http(
        vaddr,
        &format!(
            "POST /api/view/login HTTP/1.1\r\nHost: {vaddr}\r\nOrigin: http://{vaddr}\r\nContent-Type: application/json\r\nContent-Length: 22\r\nConnection: close\r\n\r\n{{\"token\":\"view-iter4\"}}"
        ),
    );
    let v_cookie = vc.join("; ");

    let mut s_tab = TcpStream::connect(vaddr).unwrap();
    let req = format!(
        "POST /api/view/request-approval HTTP/1.1\r\nHost: {vaddr}\r\nOrigin: http://{vaddr}\r\nCookie: {v_cookie}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
    );
    s_tab.write_all(req.as_bytes()).unwrap();
    // Confirm pending slot appeared
    let mut saw_pending = false;
    for _ in 0..30 {
        let (_, _, st) = raw_http(
            addr,
            &format!("GET /api/admin/state HTTP/1.1\r\nHost: {addr}\r\nCookie: {admin_cookie}\r\nConnection: close\r\n\r\n"),
        );
        let v: serde_json::Value = serde_json::from_str(&st).unwrap();
        if v["pending_approvals"].as_array().is_some_and(|a| !a.is_empty()) {
            saw_pending = true;
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    assert!(saw_pending, "pending web approval must enqueue");
    // Close browser tab immediately -> pending slot MUST vanish within <= 1s (not linger 60s)!
    drop(s_tab);
    let mut evicted = false;
    for _ in 0..25 {
        thread::sleep(Duration::from_millis(50));
        let (_, _, st) = raw_http(
            addr,
            &format!("GET /api/admin/state HTTP/1.1\r\nHost: {addr}\r\nCookie: {admin_cookie}\r\nConnection: close\r\n\r\n"),
        );
        let v: serde_json::Value = serde_json::from_str(&st).unwrap();
        if v["pending_approvals"].as_array().is_some_and(|a| a.is_empty()) {
            evicted = true;
            break;
        }
    }
    assert!(evicted, "P2-C4: closed-tab Web viewer pending slot must evict within <=1s instead of lingering 60s");

    drop(data);
    drop(tel);
    stop.store(true, Ordering::SeqCst);
    reg.close_all();
    wifi.stop();
    web.stop();
}

#[test]
fn iter5_web_logout_token_rotate_yaml_baseline_and_static_source_switch_e2e() {
    use idis::platform::mock::SYNTHETIC_H264_P_FRAME;
    use idis::platform::EncodedFrame;
    use idis::web::{start_web_server, LogBuffer};
    use std::io::{Read, Write};
    use std::net::SocketAddr;

    fn raw_http(addr: SocketAddr, req: &str) -> (u16, Vec<String>, String) {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        s.write_all(req.as_bytes()).unwrap();
        let mut raw = Vec::new();
        let _ = s.read_to_end(&mut raw);
        let text = String::from_utf8_lossy(&raw).to_string();
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        let code = head
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        let cookies = head
            .lines()
            .filter_map(|l| {
                let (k, v) = l.split_once(':')?;
                if k.eq_ignore_ascii_case("set-cookie") {
                    Some(v.trim().split(';').next().unwrap_or("").to_string())
                } else {
                    None
                }
            })
            .collect();
        (code, cookies, body.to_string())
    }

    fn ws_open(addr: SocketAddr, cookie: &str) -> TcpStream {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let req = format!(
            "GET /ws/stream HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nCookie: {cookie}\r\n\r\n"
        );
        s.write_all(req.as_bytes()).unwrap();
        let mut hdr = Vec::new();
        let mut b = [0u8; 1];
        while !hdr.ends_with(b"\r\n\r\n") {
            s.read_exact(&mut b).unwrap();
            hdr.push(b[0]);
        }
        assert!(String::from_utf8_lossy(&hdr).starts_with("HTTP/1.1 101"));
        s
    }

    fn ws_read(ws: &mut TcpStream) -> Option<(u8, Vec<u8>)> {
        let mut h = [0u8; 2];
        if ws.read_exact(&mut h).is_err() {
            return None;
        }
        let op = h[0] & 0x0f;
        let mut len = (h[1] & 0x7f) as usize;
        if len == 126 {
            let mut ext = [0u8; 2];
            ws.read_exact(&mut ext).ok()?;
            len = u16::from_be_bytes(ext) as usize;
        } else if len == 127 {
            let mut ext = [0u8; 8];
            ws.read_exact(&mut ext).ok()?;
            len = u64::from_be_bytes(ext) as usize;
        }
        let mut payload = vec![0u8; len];
        ws.read_exact(&mut payload).ok()?;
        Some((op, payload))
    }

    let tmp_dir = std::env::temp_dir().join(format!("idis_iter5_e2e_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp_dir);
    std::fs::create_dir_all(&tmp_dir).unwrap();
    let cfg_file = tmp_dir.join("idis.yaml");

    let mock = Arc::new(MockBackend::new());
    mock.manual_frame_mode.store(true, Ordering::Release);
    let mut cfg = test_config();
    cfg.config_file = Some(cfg_file.display().to_string());
    cfg.max_web_viewers = 4;
    cfg.web_require_approval = true;
    let wifi_cfg = cfg.clone();
    let reg = Arc::new(SessionRegistry::new(cfg, mock.clone()));
    let stop = Arc::new(AtomicBool::new(false));
    let mut wifi = start_wifi_server(wifi_cfg, mock.clone(), reg.clone(), stop.clone()).unwrap();
    let mut web = start_web_server(
        "127.0.0.1:0",
        Some("adm-iter5-sec".to_string()),
        Some("view-iter5".to_string()),
        reg.clone(),
        LogBuffer::new(),
        stop.clone(),
    )
    .unwrap();
    let addr = web.addr;
    let vaddr = SocketAddr::from(([127, 0, 0, 1], web.viewer_addr().unwrap().port()));

    let (_, ac, _) = raw_http(
        addr,
        &format!(
            "POST /api/admin/login HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nContent-Type: application/json\r\nContent-Length: 25\r\nConnection: close\r\n\r\n{{\"token\":\"adm-iter5-sec\"}}"
        ),
    );
    let admin_cookie = ac.into_iter().find(|c| c.starts_with("idis_admin=")).unwrap();

    // 1) P1-C1: POST /api/view/logout while POST /api/view/request-approval is blocking cancels the pending slot!
    let (_, vc1, _) = raw_http(
        vaddr,
        &format!(
            "POST /api/view/login HTTP/1.1\r\nHost: {vaddr}\r\nOrigin: http://{vaddr}\r\nContent-Type: application/json\r\nContent-Length: 22\r\nConnection: close\r\n\r\n{{\"token\":\"view-iter5\"}}"
        ),
    );
    let v_cookie1 = vc1.join("; ");
    let vc1_c = v_cookie1.clone();
    let t_appr1 = thread::spawn(move || {
        raw_http(
            vaddr,
            &format!(
                "POST /api/view/request-approval HTTP/1.1\r\nHost: {vaddr}\r\nOrigin: http://{vaddr}\r\nCookie: {vc1_c}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
            ),
        )
    });
    for _ in 0..30 {
        let (_, _, st) = raw_http(
            addr,
            &format!("GET /api/admin/state HTTP/1.1\r\nHost: {addr}\r\nCookie: {admin_cookie}\r\nConnection: close\r\n\r\n"),
        );
        let v: serde_json::Value = serde_json::from_str(&st).unwrap();
        if v["pending_approvals"].as_array().is_some_and(|a| !a.is_empty()) {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    let (c_lo, _, _) = raw_http(
        vaddr,
        &format!(
            "POST /api/view/logout HTTP/1.1\r\nHost: {vaddr}\r\nOrigin: http://{vaddr}\r\nCookie: {v_cookie1}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
        ),
    );
    assert_eq!(c_lo, 200);
    let (c_a1, _, _) = t_appr1.join().unwrap();
    assert_eq!(c_a1, 401, "Iter-7 P2-C4: viewer logout must cancel in-flight approval request with 401 Unauthorized");
    assert!(reg.trust_store().list().is_empty());

    // P1-C1 (b): rotate_view_token while POST /api/view/request-approval is blocking cancels pending slot!
    let (_, vc2, _) = raw_http(
        vaddr,
        &format!(
            "POST /api/view/login HTTP/1.1\r\nHost: {vaddr}\r\nOrigin: http://{vaddr}\r\nContent-Type: application/json\r\nContent-Length: 22\r\nConnection: close\r\n\r\n{{\"token\":\"view-iter5\"}}"
        ),
    );
    let v_cookie2 = vc2.join("; ");
    let vc2_c = v_cookie2.clone();
    let t_appr2 = thread::spawn(move || {
        raw_http(
            vaddr,
            &format!(
                "POST /api/view/request-approval HTTP/1.1\r\nHost: {vaddr}\r\nOrigin: http://{vaddr}\r\nCookie: {vc2_c}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
            ),
        )
    });
    for _ in 0..30 {
        let (_, _, st) = raw_http(
            addr,
            &format!("GET /api/admin/state HTTP/1.1\r\nHost: {addr}\r\nCookie: {admin_cookie}\r\nConnection: close\r\n\r\n"),
        );
        let v: serde_json::Value = serde_json::from_str(&st).unwrap();
        if v["pending_approvals"].as_array().is_some_and(|a| !a.is_empty()) {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    let (c_rot, _, _) = raw_http(
        addr,
        &format!(
            "POST /api/admin/settings HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nCookie: {admin_cookie}\r\nContent-Type: application/json\r\nContent-Length: 26\r\nConnection: close\r\n\r\n{{\"rotate_view_token\":true}}"
        ),
    );
    assert_eq!(c_rot, 200);
    let (c_a2, _, _) = t_appr2.join().unwrap();
    assert_eq!(c_a2, 401, "Iter-7 P2-C4: rotating view_token must immediately cancel in-flight web approval with 401 Unauthorized");

    // 2) P1-C2: POST /api/admin/config & /reload with low_power: true return preserved baseline YAML (fps: 60, max_web_viewers: 4)
    let lp_yaml = "version: 1\nlow_power: true\nmax_web_viewers: 4\np2p_relay_enabled: true\nipad:\n  fps: 60\n  bitrate_mbps: 24\n  hidpi: 2\n";
    let save_body = serde_json::json!({ "yaml": lp_yaml }).to_string();
    let (c_sv, _, sv_resp) = raw_http(
        addr,
        &format!(
            "POST /api/admin/config HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nCookie: {admin_cookie}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{save_body}",
            save_body.len()
        ),
    );
    assert_eq!(c_sv, 200);
    let sv_json: serde_json::Value = serde_json::from_str(&sv_resp).unwrap();
    let returned_yaml = sv_json["yaml"].as_str().unwrap();
    let parsed_ret = idis::user_config::UserConfigFile::from_yaml_str(returned_yaml).unwrap();
    assert_eq!(
        parsed_ret.ipad.fps, 60,
        "P1-C2: POST /api/admin/config must return preserved baseline YAML (fps=60), not eco runtime 15"
    );
    assert_eq!(parsed_ret.max_web_viewers, 4);
    let (c_rl, _, rl_resp) = raw_http(
        addr,
        &format!(
            "POST /api/admin/config/reload HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nCookie: {admin_cookie}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
        ),
    );
    assert_eq!(c_rl, 200);
    let rl_json: serde_json::Value = serde_json::from_str(&rl_resp).unwrap();
    let parsed_rl =
        idis::user_config::UserConfigFile::from_yaml_str(rl_json["yaml"].as_str().unwrap()).unwrap();
    assert_eq!(
        parsed_rl.ipad.fps, 60,
        "P1-C2: POST /api/admin/config/reload must return preserved baseline YAML (fps=60)"
    );
    reg.set_low_power(false);

    // 3) P2-C1: GET /api/auth/status reports host_lock_disconnect_blocked=true when host is locked with web=disconnect
    reg.set_lock_action_web(idis::config::LockAction::Disconnect);
    reg.set_lock_delay_secs(0);
    mock.screen_locked.store(true, Ordering::Release);
    reg.on_host_screen_lock_changed(true);
    let (c_st, _, st_body) = raw_http(
        addr,
        &format!("GET /api/auth/status HTTP/1.1\r\nHost: {addr}\r\nCookie: {admin_cookie}\r\nConnection: close\r\n\r\n"),
    );
    assert_eq!(c_st, 200);
    let st_v: serde_json::Value = serde_json::from_str(&st_body).unwrap();
    assert_eq!(st_v["host_lock_disconnect_blocked"], true);
    mock.screen_locked.store(false, Ordering::Release);
    reg.on_host_screen_lock_changed(false);

    // 4) P1-B1: Static iPad FollowIpad -> Main (emits IDR) -> FollowIpad (leftover Main IDR + iPad P-frame)
    //    MUST NOT mux iPad P-frame onto Main's IDR!
    let mut tel = TcpStream::connect(wifi.telemetry_addr).unwrap();
    tel.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    write_canal_block(&mut tel, &make_handshake_packet_custom("u-st5", "Static5", 1280, 720, "5")).unwrap();
    let _ = read_canal_block(&mut tel).unwrap().unwrap();
    let _ = read_canal_block(&mut tel).unwrap().unwrap();
    let mut data = TcpStream::connect(wifi.data_addr).unwrap();
    data.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    for _ in 0..40 {
        if !mock.frame_senders.lock().unwrap().is_empty() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    let ipad_idx = 0;
    let make_f = |is_idr: bool| EncodedFrame {
        width: 1280,
        height: 720,
        bytes_per_row: 1280 * 4,
        annex_b: if is_idr {
            SYNTHETIC_H264_ANNEX_B.to_vec()
        } else {
            SYNTHETIC_H264_P_FRAME.to_vec()
        },
        is_keyframe: is_idr,
    };
    // Exiting low_power re-opens the dynamic Viewer listener; set a known view_token and open WS on it
    let vaddr2 = SocketAddr::from(([127, 0, 0, 1], web.viewer_addr().unwrap().port()));
    let tok_body = r#"{"view_token":"view-iter5-p4","web_require_approval":false}"#;
    let (ct, _, _) = raw_http(
        addr,
        &format!(
            "POST /api/admin/settings HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nCookie: {admin_cookie}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{tok_body}",
            tok_body.len()
        ),
    );
    assert_eq!(ct, 200);
    let login_p4 = r#"{"token":"view-iter5-p4"}"#;
    let (cv3, vc3, _) = raw_http(
        vaddr2,
        &format!(
            "POST /api/view/login HTTP/1.1\r\nHost: {vaddr2}\r\nOrigin: http://{vaddr2}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{login_p4}",
            login_p4.len()
        ),
    );
    assert_eq!(cv3, 200);
    let v_cookie3 = vc3.into_iter().find(|c| c.starts_with("idis_view=")).unwrap();
    let mut ws = ws_open(vaddr2, &v_cookie3);
    mock.push_frame_to(ipad_idx, make_f(true));
    let _ = read_canal_block(&mut data).unwrap().unwrap();
    ws.set_read_timeout(Some(Duration::from_millis(800))).unwrap();
    let mut saw_init_epoch = false;
    for _ in 0..10 {
        if let Some((op, pay)) = ws_read(&mut ws) {
            if op == 0x1 {
                if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&pay) {
                    if v.get("type").and_then(|t| t.as_str()) == Some("init")
                        && v.get("epoch").and_then(|e| e.as_u64()).is_some()
                    {
                        saw_init_epoch = true;
                    }
                }
            }
            if op == 0x2 && pay.first() == Some(&0x02) {
                break;
            }
        }
    }
    assert!(saw_init_epoch, "P1-B2: init JSON must include numeric epoch field");

    // Switch to Main (standalone starts -> emits 1 Main IDR) WITHOUT pushing any frame on iPad (static iPad!)
    reg.set_web_screen_mode(idis::config::WebScreenMode::Main).unwrap();
    let main_idx = mock.frame_senders.lock().unwrap().len() - 1;
    mock.push_frame_to(main_idx, make_f(true));
    thread::sleep(Duration::from_millis(20));
    // Immediately switch back to FollowIpad BEFORE draining WS, then push a bare P-frame on iPad!
    reg.set_web_screen_mode(idis::config::WebScreenMode::FollowIpad).unwrap();
    thread::sleep(Duration::from_millis(30));
    ws.set_read_timeout(Some(Duration::from_millis(150))).unwrap();
    while ws_read(&mut ws).is_some() {}
    mock.push_frame_to(ipad_idx, make_f(false)); // MUST be dropped (web_follow_needs_idr=true on epoch change)!
    let mut leaked_p = false;
    while let Some((op, pay)) = ws_read(&mut ws) {
        if op == 0x2 && pay.first() == Some(&0x03) {
            leaked_p = true;
        }
    }
    assert!(
        !leaked_p,
        "P1-B1: static iPad FollowIpad -> Main -> FollowIpad MUST NOT leak bare P-frame before fresh iPad IDR"
    );

    drop(ws);
    drop(data);
    drop(tel);
    stop.store(true, Ordering::SeqCst);
    reg.close_all();
    wifi.stop();
    web.stop();
    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[test]
fn iter6_standalone_epoch_lock_resume_mux_cache_and_auth_status_e2e() {
    use idis::config::LockAction;
    use idis::platform::mock::SYNTHETIC_H264_P_FRAME;
    use idis::platform::EncodedFrame;
    use idis::web::{start_web_server, LogBuffer};
    use std::io::{Read, Write};
    use std::net::SocketAddr;

    fn raw_http(addr: SocketAddr, req: &str) -> (u16, Vec<String>, String) {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        s.write_all(req.as_bytes()).unwrap();
        let mut raw = Vec::new();
        let _ = s.read_to_end(&mut raw);
        let text = String::from_utf8_lossy(&raw).to_string();
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        let code = head
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        let cookies = head
            .lines()
            .filter_map(|l| {
                let (k, v) = l.split_once(':')?;
                if k.eq_ignore_ascii_case("set-cookie") {
                    Some(v.trim().split(';').next().unwrap_or("").to_string())
                } else {
                    None
                }
            })
            .collect();
        (code, cookies, body.to_string())
    }

    fn ws_open(addr: SocketAddr, cookie: &str) -> TcpStream {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let req = format!(
            "GET /ws/stream HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nCookie: {cookie}\r\n\r\n"
        );
        s.write_all(req.as_bytes()).unwrap();
        let mut hdr = Vec::new();
        let mut b = [0u8; 1];
        while !hdr.ends_with(b"\r\n\r\n") {
            s.read_exact(&mut b).unwrap();
            hdr.push(b[0]);
        }
        assert!(String::from_utf8_lossy(&hdr).starts_with("HTTP/1.1 101"));
        s
    }

    fn ws_read(ws: &mut TcpStream) -> Option<(u8, Vec<u8>)> {
        let mut h = [0u8; 2];
        if ws.read_exact(&mut h).is_err() {
            return None;
        }
        let op = h[0] & 0x0f;
        let mut len = (h[1] & 0x7f) as usize;
        if len == 126 {
            let mut ext = [0u8; 2];
            ws.read_exact(&mut ext).ok()?;
            len = u16::from_be_bytes(ext) as usize;
        } else if len == 127 {
            let mut ext = [0u8; 8];
            ws.read_exact(&mut ext).ok()?;
            len = u64::from_be_bytes(ext) as usize;
        }
        let mut payload = vec![0u8; len];
        ws.read_exact(&mut payload).ok()?;
        Some((op, payload))
    }

    let tmp_dir = std::env::temp_dir().join(format!(
        "idis_iter6_e2e_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&tmp_dir).unwrap();
    let mock = Arc::new(MockBackend::new());
    mock.manual_frame_mode.store(true, Ordering::Release);
    let mut cfg = test_config();
    cfg.config_file = Some(tmp_dir.join("idis.yaml").display().to_string());
    cfg.max_web_viewers = 4;
    cfg.auto_accept = true;
    cfg.on_lock_delay_secs = 0;
    let wifi_cfg = cfg.clone();

    let reg = Arc::new(SessionRegistry::new(cfg, mock.clone()));
    reg.set_lock_action_web(LockAction::Pause);
    reg.set_lock_delay_secs(0);
    let stop = Arc::new(AtomicBool::new(false));
    let mut wifi = start_wifi_server(wifi_cfg, mock.clone(), reg.clone(), stop.clone()).unwrap();
    let mut web = start_web_server(
        "127.0.0.1:0",
        Some("admin-i6".into()),
        Some("view-i6".into()),
        reg.clone(),
        LogBuffer::new(),
        stop.clone(),
    )
    .unwrap();
    let addr = web.addr;
    let vaddr = SocketAddr::from(([127, 0, 0, 1], web.viewer_addr().unwrap().port()));

    let (st_a, ac, _) = raw_http(
        addr,
        &format!(
            "POST /api/admin/login HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nContent-Type: application/json\r\nContent-Length: 20\r\nConnection: close\r\n\r\n{{\"token\":\"admin-i6\"}}"
        ),
    );
    assert_eq!(st_a, 200);
    let admin_cookie = ac.into_iter().find(|c| c.starts_with("idis_admin=")).unwrap();
    let (st_v, vc1, _) = raw_http(
        vaddr,
        &format!(
            "POST /api/view/login HTTP/1.1\r\nHost: {vaddr}\r\nOrigin: http://{vaddr}\r\nContent-Type: application/json\r\nContent-Length: 19\r\nConnection: close\r\n\r\n{{\"token\":\"view-i6\"}}"
        ),
    );
    assert_eq!(st_v, 200);
    let view_cookie_1 = vc1.into_iter().find(|c| c.starts_with("idis_view=")).unwrap();

    // Iter-6 P1-C3: Re-logging in with an existing viewer cookie MUST revoke the old cookie!
    let (st_v2, vc2, _) = raw_http(
        vaddr,
        &format!(
            "POST /api/view/login HTTP/1.1\r\nHost: {vaddr}\r\nOrigin: http://{vaddr}\r\nCookie: {view_cookie_1}\r\nContent-Type: application/json\r\nContent-Length: 19\r\nConnection: close\r\n\r\n{{\"token\":\"view-i6\"}}"
        ),
    );
    assert_eq!(st_v2, 200);
    let view_cookie_2 = vc2.into_iter().find(|c| c.starts_with("idis_view=")).unwrap();
    assert_ne!(view_cookie_1, view_cookie_2);
    let (_, _, old_auth_body) = raw_http(
        vaddr,
        &format!(
            "GET /api/auth/status HTTP/1.1\r\nHost: {vaddr}\r\nCookie: {view_cookie_1}\r\nConnection: close\r\n\r\n"
        ),
    );
    let old_auth: serde_json::Value = serde_json::from_str(&old_auth_body).unwrap();
    assert_eq!(
        old_auth["viewer_logged_in"], false,
        "Iter-6 P1-C3: re-login must revoke prior viewer cookie"
    );
    let (st_va, vca, _) = raw_http(
        vaddr,
        &format!(
            "POST /api/view/login HTTP/1.1\r\nHost: {vaddr}\r\nOrigin: http://{vaddr}\r\nContent-Type: application/json\r\nContent-Length: 19\r\nConnection: close\r\n\r\n{{\"token\":\"view-i6\"}}"
        ),
    );
    assert_eq!(st_va, 200);
    let view_cookie_a = vca.into_iter().find(|c| c.starts_with("idis_view=")).unwrap();

    let make_f = |is_idr: bool| EncodedFrame {
        width: 1280,
        height: 720,
        bytes_per_row: 1280 * 4,
        annex_b: if is_idr {
            SYNTHETIC_H264_ANNEX_B.to_vec()
        } else {
            SYNTHETIC_H264_P_FRAME.to_vec()
        },
        is_keyframe: is_idr,
    };

    // 1) Iter-6 P0-B1 (Case 1) + P1-B2: Standalone Main Web survives lock-pause -> unlock, AND a second
    //    viewer connecting right after unlock (before live post-unlock IDR) MUST NOT receive stale pre-lock IDR!
    reg.set_web_screen_mode(idis::config::WebScreenMode::Main).unwrap();
    let mut ws1 = ws_open(vaddr, &view_cookie_a);
    for _ in 0..40 {
        if !mock.frame_senders.lock().unwrap().is_empty() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    let main_idx = mock.frame_senders.lock().unwrap().len() - 1;
    mock.push_frame_to(main_idx, make_f(true));
    ws1.set_read_timeout(Some(Duration::from_millis(800))).unwrap();
    let mut got_pre_lock_idr = false;
    for _ in 0..10 {
        if let Some((0x2, pay)) = ws_read(&mut ws1) {
            if pay.first() == Some(&0x02) {
                got_pre_lock_idr = true;
                break;
            }
        }
    }
    assert!(got_pre_lock_idr, "viewer 1 should receive initial Main IDR");

    // Lock with web=Pause -> Unlock (Viewer 1 stays connected so SharedWebMuxer.reset() does NOT run!)
    mock.screen_locked.store(true, Ordering::Release);
    reg.on_host_screen_lock_changed(true);
    thread::sleep(Duration::from_millis(30));
    mock.screen_locked.store(false, Ordering::Release);
    reg.on_host_screen_lock_changed(false);
    thread::sleep(Duration::from_millis(30));

    // Viewer 2 joins BEFORE any live post-unlock IDR is pushed -> MUST NOT get stale pre-lock IDR from SharedWebMuxer!
    let mut ws2 = ws_open(vaddr, &view_cookie_2);
    ws2.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
    let mut ws2_leaked_pre_lock = false;
    while let Some((op, pay)) = ws_read(&mut ws2) {
        if op == 0x2 && (pay.first() == Some(&0x02) || pay.first() == Some(&0x03)) {
            ws2_leaked_pre_lock = true;
        }
    }
    assert!(
        !ws2_leaked_pre_lock,
        "Iter-6 P1-B2: SharedWebMuxer MUST NOT serve stale pre-lock IDR across lock-pause epoch bump"
    );

    // Now push a fresh post-unlock IDR on the SAME standalone capture -> BOTH ws1 and ws2 MUST receive it!
    ws1.set_read_timeout(Some(Duration::from_millis(150))).unwrap();
    while ws_read(&mut ws1).is_some() {}
    mock.push_frame_to(main_idx, make_f(true));
    ws1.set_read_timeout(Some(Duration::from_millis(800))).unwrap();
    ws2.set_read_timeout(Some(Duration::from_millis(800))).unwrap();
    let mut ws1_got_post_unlock = false;
    for _ in 0..10 {
        if let Some((0x2, pay)) = ws_read(&mut ws1) {
            if pay.first() == Some(&0x02) {
                ws1_got_post_unlock = true;
                break;
            }
        }
    }
    let mut ws2_got_post_unlock = false;
    for _ in 0..10 {
        if let Some((0x2, pay)) = ws_read(&mut ws2) {
            if pay.first() == Some(&0x02) {
                ws2_got_post_unlock = true;
                break;
            }
        }
    }
    assert!(
        ws1_got_post_unlock && ws2_got_post_unlock,
        "Iter-6 P0-B1: standalone Web capture must re-sync web_source_epoch after lock-pause -> unlock (ws1={ws1_got_post_unlock}, ws2={ws2_got_post_unlock})"
    );
    drop(ws2);

    // 2) Iter-6 P0-B1 (Case 3): Connect an iPad in FollowIpad -> switch to Main -> disconnect iPad ->
    //    Main standalone capture MUST still deliver IDRs!
    reg.set_web_screen_mode(idis::config::WebScreenMode::FollowIpad).unwrap();
    let mut tel = TcpStream::connect(wifi.telemetry_addr).unwrap();
    tel.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    write_canal_block(&mut tel, &make_handshake_packet_custom("u-i6-owner", "Iter6Owner", 1280, 720, "5")).unwrap();
    let _ = read_canal_block(&mut tel).unwrap().unwrap();
    let _ = read_canal_block(&mut tel).unwrap().unwrap();
    let data = TcpStream::connect(wifi.data_addr).unwrap();
    data.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    for _ in 0..40 {
        if reg.list_sessions().iter().any(|s| s.streaming) {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    reg.set_web_screen_mode(idis::config::WebScreenMode::Main).unwrap();
    let main_idx2 = mock.frame_senders.lock().unwrap().len() - 1;
    // Disconnect the former FollowIpad owner iPad while Web is in Main!
    drop(data);
    drop(tel);
    for _ in 0..40 {
        if reg.list_sessions().is_empty() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    ws1.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
    while ws_read(&mut ws1).is_some() {}
    mock.push_frame_to(main_idx2, make_f(true));
    ws1.set_read_timeout(Some(Duration::from_millis(800))).unwrap();
    let mut ws1_after_ipad_drop = false;
    for _ in 0..10 {
        if let Some((0x2, pay)) = ws_read(&mut ws1) {
            if pay.first() == Some(&0x02) {
                ws1_after_ipad_drop = true;
                break;
            }
        }
    }
    assert!(
        ws1_after_ipad_drop,
        "Iter-6 P0-B1: disconnecting former FollowIpad iPad while Web is in Main must NOT break Main stream"
    );

    // 3) Iter-6 P1-C1: Idle standby unlock recovery via GET /api/auth/status!
    reg.set_lock_action_web(LockAction::Disconnect);
    mock.screen_locked.store(true, Ordering::Release);
    reg.on_host_screen_lock_changed(true);
    drop(ws1);
    assert!(reg.is_web_lock_disconnect_admit_blocked());
    // Simulate OS unlock during zero-wakeup idle standby (main loop did NOT call on_host_screen_lock_changed!)
    mock.screen_locked.store(false, Ordering::Release);
    let (st_as, _, auth_body) = raw_http(
        vaddr,
        &format!(
            "GET /api/auth/status HTTP/1.1\r\nHost: {vaddr}\r\nCookie: {view_cookie_2}\r\nConnection: close\r\n\r\n"
        ),
    );
    assert_eq!(st_as, 200);
    let auth_json: serde_json::Value = serde_json::from_str(&auth_body).unwrap();
    assert_eq!(
        auth_json["host_lock_disconnect_blocked"], false,
        "Iter-6 P1-C1: GET /api/auth/status must refresh OS lock state so viewers recover after idle unlock"
    );

    // 4) Iter-7 P2-C3: Short view_token + max_web_viewers=1 MUST return 400 WITHOUT opening max_web_viewers!
    reg.set_max_web_viewers(0);
    let bad_tok_body = r#"{"view_token":"ab","max_web_viewers":1}"#;
    let (st_bad_tok, _, _) = raw_http(
        addr,
        &format!(
            "POST /api/admin/settings HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nCookie: {admin_cookie}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{bad_tok_body}",
            bad_tok_body.len()
        ),
    );
    assert_eq!(st_bad_tok, 400);
    assert_eq!(
        reg.max_web_viewers(), 0,
        "Iter-7 P2-C3: rejected short view_token must NOT leave max_web_viewers mutated to 1"
    );

    // 5) Iter-7 P2-C1: POST /api/admin/settings { reset_video: true } under corrupt YAML MUST return
    //    409 Conflict WITHOUT flipping client_cursor!
    reg.set_client_cursor(true);
    let tmp_corrupt = tmp_dir.join("corrupt_i7.yaml");
    std::fs::write(&tmp_corrupt, "trusted_devices:\n  - [broken\n").unwrap();
    let mut cfg_c = test_config();
    cfg_c.config_file = Some(tmp_corrupt.display().to_string());
    let reg_c = Arc::new(SessionRegistry::new(cfg_c, Arc::new(MockBackend::new())));
    reg_c.set_client_cursor(true);
    let stop_c = Arc::new(AtomicBool::new(false));
    let mut web_c = start_web_server(
        "127.0.0.1:0",
        Some("adm-c7".into()),
        None,
        reg_c.clone(),
        LogBuffer::new(),
        stop_c.clone(),
    )
    .unwrap();
    let (_, ac_c, _) = raw_http(
        web_c.addr,
        &format!(
            "POST /api/admin/login HTTP/1.1\r\nHost: {}\r\nOrigin: http://{}\r\nContent-Type: application/json\r\nContent-Length: 18\r\nConnection: close\r\n\r\n{{\"token\":\"adm-c7\"}}",
            web_c.addr, web_c.addr
        ),
    );
    let adm_c_cookie = ac_c.into_iter().find(|c| c.starts_with("idis_admin=")).unwrap();
    let rv_body = r#"{"reset_video":true}"#;
    let (st_rv, _, _) = raw_http(
        web_c.addr,
        &format!(
            "POST /api/admin/settings HTTP/1.1\r\nHost: {}\r\nOrigin: http://{}\r\nCookie: {adm_c_cookie}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{rv_body}",
            web_c.addr, web_c.addr, rv_body.len()
        ),
    );
    assert_eq!(st_rv, 409, "Iter-7 P2-C1: reset_video under corrupt YAML must return 409 Conflict");
    assert!(reg_c.is_client_cursor(), "Iter-7 P2-C1: failed reset_video must NOT mutate client_cursor");
    stop_c.store(true, Ordering::SeqCst);
    reg_c.close_all();
    web_c.stop();

    stop.store(true, Ordering::SeqCst);
    reg.close_all();
    wifi.stop();
    web.stop();
    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[test]
fn web_admin_virtual_displays_and_window_routing_e2e() {
    use idis::web::{start_web_server, LogBuffer};
    use std::io::{Read, Write};
    use std::net::SocketAddr;

    fn http_call(
        addr: SocketAddr,
        method: &str,
        path: &str,
        cookie: Option<&str>,
        body: Option<&str>,
    ) -> (u16, String) {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let body_str = body.unwrap_or("");
        let mut req = format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nOrigin: http://127.0.0.1:{}\r\nConnection: close\r\n",
            addr.port(),
            addr.port()
        );
        if let Some(c) = cookie {
            req.push_str(&format!("Cookie: {c}\r\n"));
        }
        if !body_str.is_empty() {
            req.push_str(&format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                body_str.len()
            ));
        }
        req.push_str("\r\n");
        req.push_str(body_str);
        s.write_all(req.as_bytes()).unwrap();
        let mut raw = Vec::new();
        let _ = s.read_to_end(&mut raw);
        let text = String::from_utf8_lossy(&raw).into_owned();
        let (hdr, b) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        let code = hdr
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|c| c.parse::<u16>().ok())
            .unwrap_or(0);
        (code, b.to_string())
    }

    let tmp_dir = std::env::temp_dir().join(format!(
        "idis-e2e-vd-win-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&tmp_dir);
    std::fs::create_dir_all(&tmp_dir).unwrap();
    let cfg_path = tmp_dir.join("idis.yaml");

    let mut cfg = test_config();
    cfg.config_file = Some(cfg_path.display().to_string());
    let mock = Arc::new(MockBackend::new());
    *mock.mock_windows.lock().unwrap() = vec![
        idis::platform::DesktopWindowInfo {
            window_id: 201,
            pid: 9001,
            app_name: "Notion".into(),
            bundle_id: "notion.id".into(),
            title: "Meeting Notes".into(),
            x: 60,
            y: 60,
            width: 1000,
            height: 700,
            layer: 0,
            is_floating: false,
            display_id: 1,
        },
        idis::platform::DesktopWindowInfo {
            window_id: 202,
            pid: 9001,
            app_name: "Notion".into(),
            bundle_id: "notion.id".into(),
            title: "".into(),
            x: 1100,
            y: 40,
            width: 220,
            height: 48,
            layer: 3,
            is_floating: true,
            display_id: 1,
        },
    ];
    let reg = Arc::new(SessionRegistry::new(cfg, mock.clone()));
    let stop = Arc::new(AtomicBool::new(false));
    let mut web = start_web_server(
        "127.0.0.1:0",
        None,
        None,
        reg.clone(),
        LogBuffer::new(),
        stop.clone(),
    )
    .unwrap();
    let addr = web.addr;

    // 1) Create ephemeral virtual display via POST /api/admin/virtual-displays
    let (code, body) = http_call(
        addr,
        "POST",
        "/api/admin/virtual-displays",
        None,
        Some(r#"{"name":"隐藏屏","width":1280,"height":720}"#),
    );
    assert_eq!(code, 200, "create virtual display failed: {body}");
    let created: serde_json::Value = serde_json::from_str(&body).unwrap();
    let vd_id = created["virtual_display"]["id"].as_u64().unwrap();
    let vd_display_id = created["virtual_display"]["display_id"].as_u64().unwrap() as u32;
    assert!(vd_display_id >= 100);

    // 2) GET /api/admin/screens lists main + virtual display
    let (code, screens_body) = http_call(addr, "GET", "/api/admin/screens", None, None);
    assert_eq!(code, 200);
    let screens_json: serde_json::Value = serde_json::from_str(&screens_body).unwrap();
    let screens = screens_json["screens"].as_array().unwrap();
    assert!(screens.iter().any(|s| s["kind"] == "main"));
    assert!(screens.iter().any(|s| s["kind"] == "virtual" && s["name"] == "隐藏屏"));

    // 3) GET /api/admin/windows returns normal + floating Notion windows
    let (code, win_body) = http_call(addr, "GET", "/api/admin/windows", None, None);
    assert_eq!(code, 200);
    let win_json: serde_json::Value = serde_json::from_str(&win_body).unwrap();
    assert_eq!(win_json["windows"].as_array().unwrap().len(), 2);

    // 4) POST /api/admin/windows/move moves floating widget #202 onto virtual display
    let move_payload = format!(
        r#"{{"window_id":202,"pid":9001,"target_display_id":{vd_display_id},"layout":"keep_size"}}"#
    );
    let (code, move_body) = http_call(addr, "POST", "/api/admin/windows/move", None, Some(&move_payload));
    assert_eq!(code, 200, "move window failed: {move_body}");
    assert_eq!(mock.mock_windows.lock().unwrap()[1].display_id, vd_display_id);

    // 5) POST /api/admin/window-rules/upsert persists rule & /apply executes it cleanly
    let rule_payload = r#"{"id":"notion-pill","enabled":true,"app_name":"Notion","bundle_id":"notion.id","title_contains":"","floating_only":true,"target":{"kind":"any_virtual"},"layout":"keep_size"}"#;
    let (code, rule_body) = http_call(
        addr,
        "POST",
        "/api/admin/window-rules/upsert",
        None,
        Some(rule_payload),
    );
    assert_eq!(code, 200, "upsert rule failed: {rule_body}");
    mock.mock_windows.lock().unwrap()[1].display_id = 1;
    let (code, apply_body) = http_call(addr, "POST", "/api/admin/window-rules/apply", None, Some("{}"));
    assert_eq!(code, 200, "apply rules failed: {apply_body}");
    let apply_json: serde_json::Value = serde_json::from_str(&apply_body).unwrap();
    assert_eq!(apply_json["report"]["moved"], 1);
    assert_eq!(mock.mock_windows.lock().unwrap()[0].display_id, 1);
    assert_eq!(mock.mock_windows.lock().unwrap()[1].display_id, vd_display_id);

    // 6) Delete rule & destroy ephemeral virtual display
    let (code, _) = http_call(
        addr,
        "POST",
        "/api/admin/window-rules/delete",
        None,
        Some(r#"{"id":"notion-pill"}"#),
    );
    assert_eq!(code, 200);
    let rm_payload = format!(r#"{{"id":{vd_id}}}"#);
    let (code, _) = http_call(
        addr,
        "POST",
        "/api/admin/virtual-displays/remove",
        None,
        Some(&rm_payload),
    );
    assert_eq!(code, 200);
    assert!(!reg.has_standalone_virtual_displays());

    stop.store(true, Ordering::SeqCst);
    reg.close_all();
    web.stop();
    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[test]
fn web_admin_and_dynamic_viewer_port_separation_e2e() {
    use idis::web::{start_web_server, LogBuffer};
    use std::io::{Read, Write};
    use std::net::SocketAddr;

    fn http_call(
        addr: SocketAddr,
        method: &str,
        path: &str,
        cookie: Option<&str>,
        body: Option<&str>,
    ) -> (u16, String, String) {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let b = body.unwrap_or("");
        let mut req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nConnection: close\r\n"
        );
        if let Some(c) = cookie {
            req.push_str(&format!("Cookie: {c}\r\n"));
        }
        if !b.is_empty() {
            req.push_str("Content-Type: application/json\r\n");
            req.push_str(&format!("Content-Length: {}\r\n", b.len()));
        }
        req.push_str("\r\n");
        req.push_str(b);
        s.write_all(req.as_bytes()).unwrap();
        let mut raw = Vec::new();
        let _ = s.read_to_end(&mut raw);
        let text = String::from_utf8_lossy(&raw).to_string();
        let (head, resp_body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        let code = head
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        (code, head.to_string(), resp_body.to_string())
    }

    let mock = Arc::new(MockBackend::new());
    let mut cfg = test_config();
    cfg.max_web_viewers = 0;
    let reg = Arc::new(SessionRegistry::new(cfg, mock));
    let stop = Arc::new(AtomicBool::new(false));
    let mut web = start_web_server(
        "127.0.0.1:0",
        None,
        None,
        reg.clone(),
        LogBuffer::new(),
        stop.clone(),
    )
    .unwrap();
    let admin_addr = web.addr;

    // 1) Default state: Admin listens on 127.0.0.1:<port>, dynamic Viewer listener is CLOSED
    assert!(admin_addr.ip().is_loopback());
    assert!(web.viewer_addr().is_none());
    assert_eq!(http_call(admin_addr, "GET", "/", None, None).0, 200);
    assert_eq!(http_call(admin_addr, "GET", "/view", None, None).0, 404);
    assert_eq!(
        http_call(admin_addr, "POST", "/api/view/login", None, Some(r#"{"token":"abcd"}"#)).0,
        404
    );
    assert_eq!(http_call(admin_addr, "GET", "/ws/stream", None, None).0, 404);
    let (st_code, _, st_body) = http_call(admin_addr, "GET", "/api/admin/state", None, None);
    assert_eq!(st_code, 200);
    let st_json: serde_json::Value = serde_json::from_str(&st_body).unwrap();
    assert_eq!(st_json["connection"]["web_viewer_listening"], false);
    assert!(st_json["connection"]["web_viewer_port"].is_null());
    assert_eq!(st_json["connection"]["web_viewer_urls"].as_array().unwrap().len(), 0);

    // 2) Turning on Web viewing (max_web_viewers=2 + view_token) opens random port on 0.0.0.0
    let (code, _, set_body) = http_call(
        admin_addr,
        "POST",
        "/api/admin/settings",
        None,
        Some(r#"{"max_web_viewers":2,"view_token":"split-view-99"}"#),
    );
    assert_eq!(code, 200, "settings failed: {set_body}");
    let set_json: serde_json::Value = serde_json::from_str(&set_body).unwrap();
    let raw_vaddr = web
        .viewer_addr()
        .expect("dynamic Viewer listener must open on 0.0.0.0:<random>");
    assert!(raw_vaddr.ip().is_unspecified(), "viewer must bind 0.0.0.0, got {raw_vaddr}");
    assert_ne!(raw_vaddr.port(), admin_addr.port());
    assert_eq!(set_json["web_viewer_listening"], true);
    assert_eq!(set_json["web_viewer_port"], raw_vaddr.port());
    assert_eq!(set_json["web_viewer_bind"], format!("0.0.0.0:{}", raw_vaddr.port()));

    let vaddr = SocketAddr::from(([127, 0, 0, 1], raw_vaddr.port()));
    let (st_code2, _, st_body2) = http_call(admin_addr, "GET", "/api/admin/state", None, None);
    assert_eq!(st_code2, 200);
    let st_json2: serde_json::Value = serde_json::from_str(&st_body2).unwrap();
    assert_eq!(st_json2["connection"]["web_viewer_listening"], true);
    assert_eq!(st_json2["connection"]["web_viewer_port"], raw_vaddr.port());
    assert!(
        st_json2["connection"]["web_viewer_urls"][0]
            .as_str()
            .unwrap()
            .contains(&format!(":{}/view", raw_vaddr.port()))
    );

    // 3) Viewer port strictly serves Viewer routes ONLY (never grants loopback auto-admin!)
    let (c_root, h_root, _) = http_call(vaddr, "GET", "/?token=abc", None, None);
    assert_eq!(c_root, 302);
    assert!(h_root.contains("Location: /view?token=abc"), "got headers:\n{h_root}");
    assert_eq!(http_call(vaddr, "GET", "/view", None, None).0, 200);
    assert_eq!(http_call(vaddr, "GET", "/admin", None, None).0, 404);
    assert_eq!(http_call(vaddr, "GET", "/api/admin/state", None, None).0, 404);
    assert_eq!(
        http_call(vaddr, "POST", "/api/admin/settings", None, Some(r#"{"allow_input":true}"#)).0,
        404
    );
    let (c_auth, _, auth_body) = http_call(vaddr, "GET", "/api/auth/status", None, None);
    assert_eq!(c_auth, 200);
    let auth_v: serde_json::Value = serde_json::from_str(&auth_body).unwrap();
    assert_eq!(auth_v["admin_logged_in"], false, "Viewer port must NEVER grant loopback auto-admin");
    assert_eq!(auth_v["viewer_logged_in"], false);

    // 4) Low-power mode closes the random port immediately; exiting low-power re-opens it
    let (c_lp, _, _) = http_call(admin_addr, "POST", "/api/admin/settings", None, Some(r#"{"low_power":true}"#));
    assert_eq!(c_lp, 200);
    assert!(web.viewer_addr().is_none(), "low_power=true must close viewer port");
    assert!(
        TcpStream::connect_timeout(&vaddr, Duration::from_millis(300)).is_err(),
        "old viewer port {vaddr} must be closed under low_power"
    );
    let (c_lp_off, _, _) = http_call(admin_addr, "POST", "/api/admin/settings", None, Some(r#"{"low_power":false}"#));
    assert_eq!(c_lp_off, 200);
    let raw_vaddr2 = web
        .viewer_addr()
        .expect("exiting low_power must re-open dynamic 0.0.0.0 viewer port");
    assert!(raw_vaddr2.ip().is_unspecified());
    let vaddr2 = SocketAddr::from(([127, 0, 0, 1], raw_vaddr2.port()));
    assert_eq!(http_call(vaddr2, "GET", "/view", None, None).0, 200);

    // 5) Closing Web viewing (`max_web_viewers: 0`) closes the random port immediately
    let (c_off, _, off_body) = http_call(
        admin_addr,
        "POST",
        "/api/admin/settings",
        None,
        Some(r#"{"max_web_viewers":0}"#),
    );
    assert_eq!(c_off, 200, "disable failed: {off_body}");
    assert!(web.viewer_addr().is_none(), "max_web_viewers=0 must close viewer port");
    assert!(
        TcpStream::connect_timeout(&vaddr2, Duration::from_millis(300)).is_err(),
        "closed viewer port {vaddr2} must refuse new connections"
    );

    // 6) Re-opening then clicking `disable_view_token: true` also closes the random port
    let (c_on, _, _) = http_call(admin_addr, "POST", "/api/admin/settings", None, Some(r#"{"max_web_viewers":1}"#));
    assert_eq!(c_on, 200);
    let vaddr3 = SocketAddr::from(([127, 0, 0, 1], web.viewer_addr().unwrap().port()));
    assert_eq!(http_call(vaddr3, "GET", "/view", None, None).0, 200);
    let (c_dt, _, _) = http_call(
        admin_addr,
        "POST",
        "/api/admin/settings",
        None,
        Some(r#"{"disable_view_token":true}"#),
    );
    assert_eq!(c_dt, 200);
    assert!(web.viewer_addr().is_none(), "disable_view_token must close viewer port");
    assert!(TcpStream::connect_timeout(&vaddr3, Duration::from_millis(300)).is_err());

    stop.store(true, Ordering::SeqCst);
    reg.close_all();
    web.stop();
}

#[test]
fn wifi_port_dynamic_toggle_and_port_idle_auto_close_e2e() {
    use idis::web::{start_web_server, LogBuffer};
    use std::io::{Read, Write};
    use std::net::SocketAddr;

    fn http_call(
        addr: SocketAddr,
        method: &str,
        path: &str,
        cookie: Option<&str>,
        body: Option<&str>,
    ) -> (u16, Vec<String>, String) {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let b = body.unwrap_or("");
        let mut req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nConnection: close\r\n"
        );
        if let Some(c) = cookie {
            req.push_str(&format!("Cookie: {c}\r\n"));
        }
        if !b.is_empty() {
            req.push_str("Content-Type: application/json\r\n");
            req.push_str(&format!("Content-Length: {}\r\n", b.len()));
        }
        req.push_str("\r\n");
        req.push_str(b);
        s.write_all(req.as_bytes()).unwrap();
        let mut raw = Vec::new();
        let _ = s.read_to_end(&mut raw);
        let text = String::from_utf8_lossy(&raw).to_string();
        let (head, resp_body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        let code = head
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        let cookies = head
            .lines()
            .filter_map(|l| {
                let (k, v) = l.split_once(':')?;
                if k.eq_ignore_ascii_case("set-cookie") {
                    Some(v.trim().split(';').next().unwrap_or("").to_string())
                } else {
                    None
                }
            })
            .collect();
        (code, cookies, resp_body.to_string())
    }

    let mock = Arc::new(MockBackend::new());
    let mut cfg = test_config();
    cfg.wifi = false;
    cfg.max_web_viewers = 0;
    cfg.port_idle_close_secs = 0;
    let reg = Arc::new(SessionRegistry::new(cfg, mock));
    let stop = Arc::new(AtomicBool::new(false));
    let mut web = start_web_server(
        "127.0.0.1:0",
        None,
        None,
        reg.clone(),
        LogBuffer::new(),
        stop.clone(),
    )
    .unwrap();
    let admin_addr = web.addr;
    let wifi_ctrl = web.wifi_controller();

    // 1) Initially both iPad Wi-Fi port and Web Viewer port are CLOSED
    assert!(!wifi_ctrl.is_running());
    assert!(web.viewer_addr().is_none());

    // 2) Dynamically turn ON iPad Wi-Fi port via Admin API -> opens real telemetry/data listeners!
    let (code, _, body) = http_call(
        admin_addr,
        "POST",
        "/api/admin/settings",
        None,
        Some(r#"{"wifi_enabled":true}"#),
    );
    assert_eq!(code, 200, "enabling wifi failed: {body}");
    let (tel_addr, data_addr) = wifi_ctrl.addrs().expect("Wi-Fi listener must be open");
    assert!(TcpStream::connect_timeout(&tel_addr, Duration::from_millis(300)).is_ok());
    assert!(TcpStream::connect_timeout(&data_addr, Duration::from_millis(300)).is_ok());
    let (_, _, st_body) = http_call(admin_addr, "GET", "/api/admin/state", None, None);
    let st_json: serde_json::Value = serde_json::from_str(&st_body).unwrap();
    assert_eq!(st_json["connection"]["wifi_enabled"], true);
    assert_eq!(st_json["settings"]["wifi_enabled"], true);
    assert_eq!(st_json["host"]["wifi"], true);

    // 3) Dynamically turn OFF iPad Wi-Fi port -> closes listeners immediately!
    let (code, _, _) = http_call(
        admin_addr,
        "POST",
        "/api/admin/settings",
        None,
        Some(r#"{"wifi_enabled":false}"#),
    );
    assert_eq!(code, 200);
    assert!(!wifi_ctrl.is_running());
    assert!(TcpStream::connect_timeout(&tel_addr, Duration::from_millis(300)).is_err());

    // 4) Idle auto-close: open BOTH Wi-Fi + Web Viewer, connect 1 active Web viewer, set port_idle_close_secs=1:
    //    - Idle Wi-Fi port (0 clients) MUST auto-close after 1s
    //    - Active Web Viewer port (1 client) MUST STAY OPEN
    //    - Once the Web viewer disconnects, Web Viewer port MUST auto-close after 1s while keeping view_token!
    let (code, _, _) = http_call(
        admin_addr,
        "POST",
        "/api/admin/settings",
        None,
        Some(r#"{"wifi_enabled":true,"max_web_viewers":2,"view_token":"idle-tok-99"}"#),
    );
    assert_eq!(code, 200);
    let (tel_addr2, _) = wifi_ctrl.addrs().expect("Wi-Fi port must re-open");
    let vaddr = SocketAddr::from(([127, 0, 0, 1], web.viewer_addr().unwrap().port()));
    let (cv, vc, _) = http_call(
        vaddr,
        "POST",
        "/api/view/login",
        None,
        Some(r#"{"token":"idle-tok-99"}"#),
    );
    assert_eq!(cv, 200);
    let v_cookie = vc.into_iter().find(|c| c.starts_with("idis_view=")).unwrap();
    let mut ws = TcpStream::connect(vaddr).unwrap();
    ws.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let ws_req = format!(
        "GET /ws/stream HTTP/1.1\r\nHost: {vaddr}\r\nOrigin: http://{vaddr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nCookie: {v_cookie}\r\n\r\n"
    );
    ws.write_all(ws_req.as_bytes()).unwrap();
    let mut hdr = Vec::new();
    let mut b = [0u8; 1];
    while !hdr.ends_with(b"\r\n\r\n") {
        ws.read_exact(&mut b).unwrap();
        hdr.push(b[0]);
    }
    assert!(String::from_utf8_lossy(&hdr).contains("101 Switching Protocols"));
    assert_eq!(reg.active_web_viewers(), 1);

    let (code, _, _) = http_call(
        admin_addr,
        "POST",
        "/api/admin/settings",
        None,
        Some(r#"{"port_idle_close_secs":1}"#),
    );
    assert_eq!(code, 200);
    assert_eq!(reg.port_idle_close_secs(), 1);

    // Wait up to 2.2s for idle Wi-Fi port to auto-close
    let mut wifi_auto_closed = false;
    for _ in 0..44 {
        if !wifi_ctrl.is_running() {
            wifi_auto_closed = true;
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(wifi_auto_closed, "idle iPad Wi-Fi port must auto-close after port_idle_close_secs=1");
    assert!(TcpStream::connect_timeout(&tel_addr2, Duration::from_millis(250)).is_err());
    // Active Web Viewer port MUST still be open!
    assert!(
        web.viewer_addr().is_some(),
        "Web Viewer port with an active WS client must NOT auto-close"
    );

    // Drop the active Web viewer -> Web Viewer port MUST auto-close after 1s while keeping view_token!
    drop(ws);
    let mut viewer_auto_closed = false;
    for _ in 0..50 {
        if web.viewer_addr().is_none() {
            viewer_auto_closed = true;
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(
        viewer_auto_closed,
        "Web Viewer port must auto-close after last viewer disconnects + port_idle_close_secs=1"
    );
    assert!(TcpStream::connect_timeout(&vaddr, Duration::from_millis(250)).is_err());
    let (_, _, st_after) = http_call(admin_addr, "GET", "/api/admin/state", None, None);
    let st_after_json: serde_json::Value = serde_json::from_str(&st_after).unwrap();
    assert_eq!(st_after_json["settings"]["view_token_enabled"], true, "idle close must preserve view_token");
    assert_eq!(st_after_json["connection"]["web_viewer_listening"], false);

    stop.store(true, Ordering::SeqCst);
    reg.close_all();
    web.stop();
}
