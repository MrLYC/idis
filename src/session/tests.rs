use super::config_store::{load_persisted_settings, save_persisted_settings, PersistedSettings};
use super::*;
use crate::platform::{FrameReceiver, RecvFrameError};
use std::thread;
use std::time::Duration;

    #[test]
    fn flow_control_backpressure_and_ack_recovery() {
        let fc = FlowControl::new(2);
        // Before client sends any ACK, never stalls
        assert!(fc.try_acquire_send());
        assert!(fc.try_acquire_send());
        assert!(fc.try_acquire_send());

        // Once client sends an ACK, max_in_flight = 2 is enforced
        fc.on_ack();
        assert!(fc.try_acquire_send()); // in_flight -> 1
        assert!(fc.try_acquire_send()); // in_flight -> 2
        assert!(!fc.try_acquire_send()); // dropped!
        assert_eq!(fc.dropped_frames(), 1);

        // ACK frees a slot immediately
        fc.on_ack();
        assert_eq!(fc.in_flight(), 1);
        assert!(fc.try_acquire_send()); // in_flight -> 2

        // Safety timeout recovers even if no more ACKs arrive
        thread::sleep(Duration::from_millis(360));
        assert!(fc.try_acquire_send());
    }

    #[test]
    fn adaptive_per_screen_max_pixel_edge_handles_multi_screen_and_override() {
        let make_hs = |w: u32, h: u32| ClientHandshake {
            uid: "u".to_string(),
            name: "iPad".to_string(),
            model: "iPad".to_string(),
            system_name: "iOS".to_string(),
            system_version: "12.5".to_string(),
            client_version: "6.2".to_string(),
            data_protocol_version: 5,
            orientation: 1,
            screen_width: w,
            screen_height: h,
            udp_port: 0,
            supports_telemetry_cursor: true,
            supports_mirror_mode: false,
            supports_shared_main_mode: false,
            max_compression: None,
            preferred_compression: None,
            preferred_fps: None,
        };
        let mut vs = VideoSettings {
            width: 0,
            height: 0,
            fps: 30,
            bitrate_mbps: 16,
            hidpi: 2,
            integer_scale: false,
            max_pixel_edge: 0,
            adaptive_quality: true,
            abr_sensitivity: crate::config::AbrSensitivity::Balanced,
            half_fps_when_unfocused: false,
            quality: QualityPreset::Balanced,
            web_width: 1280,
            web_height: 720,
            web_fps: 30,
            web_bitrate_mbps: 16,
            web_hidpi: 1,
            web_max_pixel_edge: 0,
            web_quality: QualityPreset::Balanced,
        };
        // Default auto (0): adapts independently per connected screen, respecting 2x Retina!
        assert_eq!(SessionRegistry::effective_ipad_max_pixel_edge(&make_hs(2048, 1536), &vs), 2048);
        assert_eq!(SessionRegistry::effective_ipad_max_pixel_edge(&make_hs(2732, 2048), &vs), 2732);
        // Legacy iPad reporting 1024x768 points at 2x Retina streams true 2048px (not clamped to 1024px)
        assert_eq!(SessionRegistry::effective_ipad_max_pixel_edge(&make_hs(1024, 768), &vs), 2048);
        assert_eq!(SessionRegistry::effective_web_max_pixel_edge(&vs), 3840);
        // Manual 2048x1536 @ 2x with auto max_pixel_edge=0 on a 2048x1536 iPad MUST cap at the
        // iPad's physical 2048px long edge instead of oversampling to 3840x2880 (3.5x wasted pixels).
        vs.width = 2048;
        vs.height = 1536;
        assert_eq!(SessionRegistry::effective_ipad_max_pixel_edge(&make_hs(2048, 1536), &vs), 2048);
        assert_eq!(SessionRegistry::effective_ipad_max_pixel_edge(&make_hs(2732, 2048), &vs), 2732);
        // Manual lower 1x resolution does not wastefully upscale beyond its own backing size.
        vs.width = 1024;
        vs.height = 768;
        vs.hidpi = 1;
        assert_eq!(SessionRegistry::effective_ipad_max_pixel_edge(&make_hs(2048, 1536), &vs), 1024);
        // Explicit manual max_pixel_edge override still takes precedence.
        vs.width = 2048;
        vs.height = 1536;
        vs.hidpi = 2;
        vs.max_pixel_edge = 3840;
        assert_eq!(SessionRegistry::effective_ipad_max_pixel_edge(&make_hs(2048, 1536), &vs), 3840);
        vs.width = 0;
        vs.height = 0;
        vs.max_pixel_edge = 0;
        vs.hidpi = 1;
        assert_eq!(SessionRegistry::effective_ipad_max_pixel_edge(&make_hs(1024, 768), &vs), 1024);
        vs.hidpi = 2;

        // Explicit manual overrides for iPad and Web are independent
        vs.max_pixel_edge = 1536;
        assert_eq!(SessionRegistry::effective_ipad_max_pixel_edge(&make_hs(2732, 2048), &vs), 1536);
        assert_eq!(SessionRegistry::effective_web_max_pixel_edge(&vs), 3840);
        vs.web_max_pixel_edge = 1920;
        assert_eq!(SessionRegistry::effective_web_max_pixel_edge(&vs), 1920);
        vs.web_max_pixel_edge = 0;

        // Auto-resolution + 2x HiDPI on Retina iPad Air (2048x1536) resolves to 1024x768 logical (exact 1:1)
        vs.max_pixel_edge = 0;
        assert_eq!(
            SessionRegistry::resolve_dimensions_for_settings(&make_hs(2048, 1536), &vs, true),
            (1024, 768)
        );

        // Persisted settings round-trip
        let tmp = std::env::temp_dir().join(format!("idis_settings_test_{}.json", std::process::id()));
        let saved = PersistedSettings {
            width: 1280,
            height: 960,
            web_width: 1920,
            web_height: 1080,
            web_fps: 60,
            web_bitrate_mbps: 24,
            web_hidpi: 2,
            web_max_pixel_edge: 2560,
            fps: 60,
            bitrate_mbps: 24,
            hidpi: 2,
            integer_scale: true,
            max_pixel_edge: 2048,
            adaptive_quality: false,
            web_independent_screen: true,
            lock_action_ipad: LockAction::Disconnect,
            lock_action_web: LockAction::Keep,
            lock_delay_secs: 15,
            auto_max_in_flight: false,
            max_in_flight: 4,
            max_extended_screens: 3,
            max_web_viewers: 5,
            low_power: true,
        };
        save_persisted_settings(&tmp, &saved).unwrap();
        let loaded = load_persisted_settings(&tmp).unwrap();
        let _ = std::fs::remove_file(&tmp);
        assert_eq!((loaded.width, loaded.height, loaded.fps, loaded.bitrate_mbps, loaded.hidpi), (1280, 960, 60, 24, 2));
        assert_eq!((loaded.web_width, loaded.web_height, loaded.web_fps, loaded.web_bitrate_mbps, loaded.web_hidpi, loaded.web_max_pixel_edge), (1920, 1080, 60, 24, 2, 2560));
        assert!(loaded.integer_scale);
        assert_eq!(loaded.max_pixel_edge, 2048);
        assert!(!loaded.adaptive_quality);
        assert!(loaded.web_independent_screen);
        assert_eq!(loaded.lock_action_ipad, LockAction::Disconnect);
        assert_eq!(loaded.lock_action_web, LockAction::Keep);
        assert_eq!(loaded.lock_delay_secs, 15);
        assert!(!loaded.auto_max_in_flight);
        assert_eq!(loaded.max_in_flight, 4);
        assert_eq!(loaded.max_extended_screens, 3);
        assert_eq!(loaded.max_web_viewers, 5);
    }

    #[test]
    fn new_feature_settings_round_trip_and_cli_override_isolation() {
        use clap::Parser;
        let tmp = std::env::temp_dir().join(format!(
            "idis_feat_cfg_{}.yaml",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&tmp);

        let mut cfg = AppConfig::try_parse_from([
            "idis",
            "--client-cursor",
            "--half-fps-unfocused",
            "--web-screen-mode",
            "main",
            "--web-require-approval",
        ])
        .unwrap();
        cfg.config_file = Some(tmp.display().to_string());
        cfg.trusted_devices_file = Some("none".to_string());
        let reg = SessionRegistry::new(cfg, Arc::new(crate::platform::mock::MockBackend::new()));
        assert!(reg.is_client_cursor());
        assert!(reg.video_settings().half_fps_when_unfocused);
        assert_eq!(reg.web_screen_mode(), crate::config::WebScreenMode::Main);
        assert!(!reg.is_web_independent_screen());
        assert!(reg.is_web_require_approval());

        // Modifying an unrelated setting must NOT leak CLI overrides to disk baseline (CFG-1)
        reg.set_max_web_viewers(3);
        let on_disk = crate::user_config::UserConfigFile::from_yaml_str(
            &std::fs::read_to_string(&tmp).unwrap(),
        )
        .unwrap();
        assert_eq!(on_disk.max_web_viewers, 3);
        assert!(!on_disk.client_cursor, "CLI --client-cursor must not leak");
        assert!(
            !on_disk.ipad.half_fps_when_unfocused,
            "CLI --half-fps-unfocused must not leak"
        );
        assert_eq!(
            on_disk.web_screen_mode,
            crate::config::WebScreenMode::FollowIpad,
            "CLI --web-screen-mode must not leak"
        );
        assert!(
            !on_disk.web_require_approval,
            "CLI --web-require-approval must not leak"
        );

        // Explicit runtime toggles MUST persist to disk
        reg.set_client_cursor(true);
        reg.set_web_require_approval(true);
        reg.set_web_screen_mode(crate::config::WebScreenMode::Main)
            .unwrap();
        let _ = reg.update_video_settings(VideoSettingsPatch {
            half_fps_when_unfocused: Some(true),
            ..Default::default()
        });
        let on_disk2 = crate::user_config::UserConfigFile::from_yaml_str(
            &std::fs::read_to_string(&tmp).unwrap(),
        )
        .unwrap();
        assert!(on_disk2.client_cursor);
        assert!(on_disk2.web_require_approval);
        assert_eq!(on_disk2.web_screen_mode, crate::config::WebScreenMode::Main);
        assert!(!on_disk2.web_independent_screen);
        assert!(on_disk2.ipad.half_fps_when_unfocused);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn host_screen_lock_policies_pause_disconnect_and_keep() {
        use clap::Parser;
        let mut cfg = AppConfig::try_parse_from(["idis"]).unwrap();
        cfg.trusted_devices_file = Some("none".to_string());
        let backend = Arc::new(crate::platform::mock::MockBackend::new());
        let reg = SessionRegistry::new(cfg, backend.clone());
        assert_eq!(reg.max_extended_screens(), 2);
        assert_eq!(reg.max_web_viewers(), 0);
        // Default max_web_viewers == 0 must disallow Web viewing!
        assert!(reg
            .subscribe_web_stream("127.0.0.1:50000".to_string(), None)
            .is_err());
        reg.set_max_web_viewers(2);

        assert_eq!(reg.lock_action_ipad(), LockAction::Pause);
        assert_eq!(reg.lock_action_web(), LockAction::Pause);
        assert_eq!(reg.lock_delay_secs(), 10);
        assert!(!reg.is_host_screen_locked());
        assert!(!reg.is_host_lock_paused_ipad());
        assert!(!reg.is_host_lock_paused_web());
        assert!(!reg.is_ipad_lock_disconnect_blocking());
        assert!(!reg.is_web_lock_disconnect_blocking());

        // 0) Default 10s grace delay: locking then unlocking quickly must NOT pause or disconnect!
        let sub1 = reg
            .subscribe_web_stream("127.0.0.1:50001".to_string(), None)
            .unwrap();
        reg.on_host_screen_lock_changed(true);
        assert!(reg.is_host_screen_locked());
        assert!(!reg.is_host_lock_enforced());
        assert!(!reg.is_host_lock_paused_web());
        assert!(!reg.is_web_lock_disconnect_blocking());
        assert_eq!(reg.list_web_viewers().len(), 1);
        reg.on_host_screen_lock_changed(false);
        assert!(!reg.is_host_screen_locked());

        // 1) Independent policies (delay=0): iPad=Keep while Web=Pause
        reg.set_lock_delay_secs(0);
        reg.set_lock_action_ipad(LockAction::Keep);
        reg.set_lock_action_web(LockAction::Pause);
        reg.on_host_screen_lock_changed(true);
        assert!(reg.is_host_lock_enforced());
        assert!(!reg.is_host_lock_paused_ipad());
        assert!(reg.is_host_lock_paused_web());
        assert_eq!(reg.list_web_viewers().len(), 1);
        reg.on_host_screen_lock_changed(false);
        assert!(!reg.is_host_lock_paused_web());

        let assert_disconnected = |rx: &FrameReceiver| {
            for _ in 0..2 {
                match rx.recv_timeout(Duration::from_millis(50)) {
                    Ok(_) => continue,
                    Err(RecvFrameError::Disconnected) => return,
                    Err(RecvFrameError::Timeout) => {
                        panic!("expected channel to be Disconnected, got Timeout");
                    }
                }
            }
            panic!("channel never reported Disconnected after draining buffered frame");
        };

        // 2) Web=Disconnect while iPad=Pause: lock kicks Web viewers without blocking iPad disconnect
        reg.set_lock_action_ipad(LockAction::Pause);
        reg.set_lock_action_web(LockAction::Disconnect);
        backend.screen_locked.store(true, Ordering::Release);
        reg.on_host_screen_lock_changed(true);
        assert!(reg.is_web_lock_disconnect_blocking());
        assert!(!reg.is_ipad_lock_disconnect_blocking());
        assert!(reg.is_host_lock_paused_ipad());
        assert!(!reg.is_host_lock_paused_web());
        assert_eq!(reg.list_web_viewers().len(), 0);
        assert_disconnected(&sub1.rx);
        assert!(reg
            .subscribe_web_stream("127.0.0.1:50002".to_string(), None)
            .is_err());
        drop(sub1);
        backend.screen_locked.store(false, Ordering::Release);
        reg.on_host_screen_lock_changed(false);
        assert!(!reg.is_web_lock_disconnect_blocking());

        // 2b) BUG-A2 regression: idle-wakeup race — even if lock entered with 10s grace,
        // `refresh_host_lock_state_now(true)` immediately enforces on incoming admission!
        reg.set_lock_delay_secs(10);
        backend.screen_locked.store(true, Ordering::Release);
        reg.on_host_screen_lock_changed(true);
        assert!(reg.is_host_screen_locked());
        assert!(!reg.is_host_lock_enforced());
        reg.refresh_host_lock_state_now(true);
        assert!(
            reg.is_host_lock_enforced(),
            "refresh_host_lock_state_now(true) must enforce immediately without leaking 10s grace"
        );
        assert!(reg
            .subscribe_web_stream("127.0.0.1:50099".to_string(), None)
            .is_err());
        backend.screen_locked.store(false, Ordering::Release);
        reg.refresh_host_lock_state_now(true);
        assert!(!reg.is_host_screen_locked());
        assert!(!reg.is_web_lock_disconnect_blocking());
        reg.set_lock_delay_secs(0);

        // 3) Both Keep: lock keeps viewers alive and does not pause or disconnect.
        reg.set_lock_action(LockAction::Keep);
        let sub2 = reg
            .subscribe_web_stream("127.0.0.1:50003".to_string(), None)
            .unwrap();
        reg.on_host_screen_lock_changed(true);
        assert!(reg.is_host_screen_locked());
        assert!(!reg.is_host_lock_paused_web());
        assert!(!reg.is_web_lock_disconnect_blocking());
        assert_eq!(reg.list_web_viewers().len(), 1);

        // 4) Switching Web policy to Disconnect while already locked kicks active viewers immediately.
        reg.set_lock_action_web(LockAction::Disconnect);
        assert!(reg.is_web_lock_disconnect_blocking());
        assert_eq!(reg.list_web_viewers().len(), 0);
        assert_disconnected(&sub2.rx);
        drop(sub2);
        reg.close_all();
    }

    #[test]
    fn wait_idle_wakes_immediately_on_activity_or_stop() {
        use clap::Parser;
        let mut cfg = AppConfig::try_parse_from(["idis"]).unwrap();
        cfg.config_file = Some("none".to_string());
        cfg.trusted_devices_file = Some("none".to_string());
        cfg.max_web_viewers = 2;
        let backend = Arc::new(crate::platform::mock::MockBackend::new());
        let reg = Arc::new(SessionRegistry::new(cfg, backend));
        assert!(!reg.has_any_sessions_or_viewers());

        // 1. Wakes promptly when a stop flag + lifecycle notification fires
        let stop = Arc::new(AtomicBool::new(false));
        let stop_c = stop.clone();
        let reg_c = reg.clone();
        let t0 = std::time::Instant::now();
        let waker = thread::spawn(move || {
            thread::sleep(Duration::from_millis(25));
            stop_c.store(true, Ordering::SeqCst);
            reg_c.notify_lifecycle_wakeup();
        });
        reg.wait_idle(&stop, Some(Duration::from_secs(5)));
        assert!(
            t0.elapsed() < Duration::from_millis(400),
            "wait_idle should wake immediately on notify_lifecycle_wakeup"
        );
        waker.join().unwrap();

        // 2. Returns immediately without blocking when a Web viewer is active
        stop.store(false, Ordering::SeqCst);
        let sub = reg
            .subscribe_web_stream("127.0.0.1:50099".to_string(), None)
            .unwrap();
        assert!(reg.has_any_sessions_or_viewers());
        let t1 = std::time::Instant::now();
        reg.wait_idle(&stop, Some(Duration::from_secs(5)));
        assert!(
            t1.elapsed() < Duration::from_millis(100),
            "wait_idle must return immediately while viewers are active"
        );
        drop(sub);
        assert!(!reg.has_any_sessions_or_viewers());
        reg.close_all();
    }

    #[test]
    fn config_presets_save_apply_delete_preserve_trusted_devices() {
        use clap::Parser;
        let tmp = std::env::temp_dir().join(format!(
            "idis_presets_test_{}.yaml",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&tmp);

        let mut cfg = AppConfig::try_parse_from(["idis"]).unwrap();
        cfg.config_file = Some(tmp.display().to_string());
        let backend = Arc::new(crate::platform::mock::MockBackend::new());
        let reg = SessionRegistry::new(cfg, backend);

        // Seed a trusted device — switching presets must NEVER clobber it.
        reg.trust_device_and_save("fp:a1b2c3d4e5f60718293a4b5c", "", "My iPad", "iPad")
            .unwrap();

        // Customize runtime settings and save as custom preset "会议投屏"
        reg.set_max_web_viewers(5);
        reg.update_polling_config(PollingPatch {
            main_loop_ms: Some(333),
            cursor_poll_ms: Some(25),
            usb_retry_ms: Some(1500),
            admin_poll_ms: Some(3500),
        });
        let saved = reg.save_current_as_preset("会议投屏").unwrap();
        assert_eq!(saved.name, "会议投屏");
        assert_eq!(saved.max_web_viewers, 5);
        assert_eq!(saved.polling.main_loop_ms, 333);

        // Apply built-in "极简省电" preset -> switches to low_power & eco polling while keeping trusted device
        let eco = reg.apply_preset("极简省电").unwrap();
        assert!(eco.low_power);
        assert_eq!(eco.max_web_viewers, 0);
        assert_eq!(eco.polling.main_loop_ms, 500);
        assert_eq!(eco.active_preset.as_deref(), Some("极简省电"));
        assert!(reg
            .trust_store()
            .is_trusted(Some("fp:a1b2c3d4e5f60718293a4b5c")));

        // Switch back to custom preset "会议投屏"
        let meeting = reg.apply_preset("会议投屏").unwrap();
        assert!(!meeting.low_power);
        assert_eq!(meeting.max_web_viewers, 5);
        assert_eq!(meeting.polling.main_loop_ms, 333);
        assert_eq!(meeting.polling.admin_poll_ms, 3500);
        assert_eq!(meeting.active_preset.as_deref(), Some("会议投屏"));
        assert!(reg
            .trust_store()
            .is_trusted(Some("fp:a1b2c3d4e5f60718293a4b5c")));

        // Delete custom preset -> clears active_preset & persists cleanly
        assert!(reg.delete_preset("会议投屏").unwrap());
        let (active_after, list_after) = reg.list_presets();
        assert!(active_after.is_none());
        assert!(list_after.is_empty());
        assert!(reg
            .trust_store()
            .is_trusted(Some("fp:a1b2c3d4e5f60718293a4b5c")));

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn apply_preset_guards_corrupt_yaml_and_preserves_allow_input_on_builtins() {
        use clap::Parser;
        let tmp = std::env::temp_dir().join(format!(
            "idis_preset_invariants_{}.yaml",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&tmp);

        // 1) Invariant CFG-2: corrupt disk YAML MUST reject apply_preset without overwriting disk.
        let corrupt_body = "version: 1\nallow_input: [broken yaml\n";
        std::fs::write(&tmp, corrupt_body).unwrap();
        let mut cfg_corrupt = AppConfig::try_parse_from(["idis"]).unwrap();
        cfg_corrupt.config_file = Some(tmp.display().to_string());
        let reg_corrupt = SessionRegistry::new(
            cfg_corrupt,
            Arc::new(crate::platform::mock::MockBackend::new()),
        );
        assert!(reg_corrupt.is_config_corrupt());
        assert!(
            reg_corrupt.apply_preset("极简省电").is_err(),
            "apply_preset must refuse to overwrite corrupt YAML (Invariant CFG-2)"
        );
        assert_eq!(
            std::fs::read_to_string(&tmp).unwrap(),
            corrupt_body,
            "corrupt disk YAML must remain byte-for-byte untouched"
        );
        let _ = std::fs::remove_file(&tmp);

        // 2) Applying built-in starter presets must preserve persisted `allow_input: true`.
        let mut cfg = AppConfig::try_parse_from(["idis"]).unwrap();
        cfg.config_file = Some(tmp.display().to_string());
        let reg = SessionRegistry::new(cfg, Arc::new(crate::platform::mock::MockBackend::new()));
        reg.set_input_allowed(true);
        assert!(reg.is_input_allowed());

        let eco = reg.apply_preset("极简省电").unwrap();
        assert!(
            eco.allow_input && reg.is_input_allowed(),
            "built-in starter presets must not silently revoke allow_input"
        );

        let hd = reg.apply_preset("高清副屏").unwrap();
        assert!(
            hd.allow_input && reg.is_input_allowed(),
            "built-in starter presets must preserve allow_input across switches"
        );

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn input_stats_tracks_view_only_drops_and_successful_injection() {
        use clap::Parser;
        let mut cfg = AppConfig::try_parse_from(["idis", "--auto-accept", "--config", "none"]).unwrap();
        cfg.allow_input = false;
        let backend = Arc::new(crate::platform::mock::MockBackend::new());
        let reg = SessionRegistry::new(cfg, backend.clone());

        struct DummyWriter;
        impl crate::transport::FrameWriter for DummyWriter {
            fn send_frame(&self, _payload: &[u8]) -> anyhow::Result<()> {
                Ok(())
            }
            fn close(&self) {}
        }
        let key = "127.0.0.1";
        let sid = reg
            .register_telemetry(key.to_string(), Arc::new(DummyWriter), 56846, false)
            .unwrap();
        let mut hdict = std::collections::BTreeMap::new();
        hdict.insert(
            "uniqueIdentifier".to_string(),
            crate::protocol::keyed_archive::ArchivedValue::String("ipad-in-1".to_string()),
        );
        hdict.insert(
            "name".to_string(),
            crate::protocol::keyed_archive::ArchivedValue::String("iPad".to_string()),
        );
        let hs = crate::protocol::messages::MessagePacket::new_send(
            "Handshake",
            crate::protocol::keyed_archive::ArchivedValue::Dict(hdict),
        );
        reg.handle_telemetry_bytes_for_session(key, Some(sid), &hs.encode().unwrap())
            .unwrap();
        let (_sid, dgen) = reg
            .attach_data_channel_checked(key, Some(sid), Arc::new(DummyWriter))
            .unwrap();

        let mut kb = std::collections::BTreeMap::new();
        kb.insert(
            "specialValue".to_string(),
            crate::protocol::keyed_archive::ArchivedValue::Int(0),
        );
        kb.insert(
            "value".to_string(),
            crate::protocol::keyed_archive::ArchivedValue::Int(b'x' as i64),
        );
        let kb_bytes = crate::protocol::keyed_archive::archive(
            &crate::protocol::keyed_archive::ArchivedValue::Object {
                class_name: "MSMKeyboardEvent".to_string(),
                classes: vec!["MSMKeyboardEvent".to_string(), "NSObject".to_string()],
                fields: kb,
            },
        )
        .unwrap();

        // While view-only (allow_input=false), event is counted as dropped_view_only.
        reg.handle_data_bytes_for_session(key, Some(sid), Some(dgen), &kb_bytes)
            .unwrap();
        let st1 = reg.input_stats();
        assert_eq!(st1.received, 1);
        assert_eq!(st1.dropped_view_only, 1);
        assert_eq!(st1.injected, 0);

        // Enable allow_input -> event is injected and counted.
        reg.set_input_allowed(true);
        reg.handle_data_bytes_for_session(key, Some(sid), Some(dgen), &kb_bytes)
            .unwrap();
        let st2 = reg.input_stats();
        assert_eq!(st2.received, 2);
        assert_eq!(st2.injected, 1);
        assert!(backend
            .recorded_inputs
            .lock()
            .unwrap()
            .contains(&crate::protocol::messages::InputEvent::KeyUnicode { ch: b'x' as u16 }));

        reg.close_session_if_id(key, sid);
    }

    #[test]
    fn edge_gestures_trigger_custom_actions_pause_toggle_input_and_disconnect() {
        use crate::protocol::keyed_archive::{archive, ArchivedValue};
        use crate::protocol::messages::{InputEvent, KEY_MOD_CTRL};
        use crate::user_config::{EdgeGestureSlot, EdgeGesturesConfig, GestureAction};
        use clap::Parser;
        use std::collections::BTreeMap;

        let mut cfg =
            AppConfig::try_parse_from(["idis", "--auto-accept", "--allow-input", "--config", "none"])
                .unwrap();
        cfg.allow_input = true;
        let backend = Arc::new(crate::platform::mock::MockBackend::new());
        let reg = SessionRegistry::new(cfg, backend.clone());

        struct DummyWriter;
        impl crate::transport::FrameWriter for DummyWriter {
            fn send_frame(&self, _payload: &[u8]) -> anyhow::Result<()> {
                Ok(())
            }
            fn close(&self) {}
        }

        let encode_touch = |phase: i64, x: f64, y: f64| -> Vec<u8> {
            let mut touch_fields = BTreeMap::new();
            touch_fields.insert("_phase".to_string(), ArchivedValue::Int(phase));
            touch_fields.insert("_tapCount".to_string(), ArchivedValue::Int(1));
            touch_fields.insert("_location.x".to_string(), ArchivedValue::Real(x));
            touch_fields.insert("_location.y".to_string(), ArchivedValue::Real(y));
            let touch = ArchivedValue::Object {
                class_name: "MSMTouch".to_string(),
                classes: vec!["MSMTouch".to_string(), "NSObject".to_string()],
                fields: touch_fields,
            };
            let mut ev_fields = BTreeMap::new();
            ev_fields.insert("_subtype".to_string(), ArchivedValue::Int(0));
            ev_fields.insert("_allTouches".to_string(), ArchivedValue::Set(vec![touch]));
            archive(&ArchivedValue::Object {
                class_name: "MSMTouchEvent".to_string(),
                classes: vec![
                    "MSMTouchEvent".to_string(),
                    "MSMEvent".to_string(),
                    "NSObject".to_string(),
                ],
                fields: ev_fields,
            })
            .unwrap()
        };

        let key = "127.0.0.1";
        let sid = reg
            .register_telemetry(key.to_string(), Arc::new(DummyWriter), 56846, false)
            .unwrap();
        let mut hdict = BTreeMap::new();
        hdict.insert(
            "uniqueIdentifier".to_string(),
            ArchivedValue::String("ipad-gesture-1".to_string()),
        );
        hdict.insert("name".to_string(), ArchivedValue::String("iPad".to_string()));
        hdict.insert("width".to_string(), ArchivedValue::Int(1024));
        hdict.insert("height".to_string(), ArchivedValue::Int(768));
        let hs = crate::protocol::messages::MessagePacket::new_send(
            "Handshake",
            ArchivedValue::Dict(hdict),
        );
        reg.handle_telemetry_bytes_for_session(key, Some(sid), &hs.encode().unwrap())
            .unwrap();
        let (_sid, dgen) = reg
            .attach_data_channel_checked(key, Some(sid), Arc::new(DummyWriter))
            .unwrap();

        let (sw, sh) = {
            let map = reg.sessions.lock().unwrap();
            let sz = *map
                .get(key)
                .unwrap()
                .capture
                .as_ref()
                .unwrap()
                .actual_size
                .lock()
                .unwrap();
            sz
        };
        assert!(sw >= 320 && sh >= 240);

        reg.set_gestures_config(EdgeGesturesConfig {
            enabled: true,
            edge_zone_pct: 10,
            min_swipe_pct: 8,
            screenshot_dir: String::new(),
            left_top_swipe_right: GestureAction::Hotkey {
                keys: "ctrl+left".to_string(),
            },
            left_bottom_swipe_right: GestureAction::RightClick,
            right_top_swipe_left: GestureAction::TogglePause,
            right_bottom_swipe_left: GestureAction::ToggleInput,
        })
        .unwrap();

        let send_swipe = |sx: f64, sy: f64, ex: f64, ey: f64| {
            reg.handle_data_bytes_for_session(key, Some(sid), Some(dgen), &encode_touch(0, sx, sy))
                .unwrap();
            reg.handle_data_bytes_for_session(key, Some(sid), Some(dgen), &encode_touch(1, ex, ey))
                .unwrap();
            reg.handle_data_bytes_for_session(key, Some(sid), Some(dgen), &encode_touch(3, ex, ey))
                .unwrap();
        };

        // 1) Left-top swipe right -> injects ctrl+left hotkey without leaking MouseDown/MouseUp.
        send_swipe(12.0, sh as f64 * 0.2, sw as f64 * 0.25, sh as f64 * 0.21);
        {
            let rec = backend.recorded_inputs.lock().unwrap();
            assert_eq!(
                *rec,
                vec![InputEvent::KeyModified {
                    key_code: Some(0x7B),
                    ch: None,
                    modifiers: KEY_MOD_CTRL,
                }]
            );
        }
        assert_eq!(
            reg.last_gesture().unwrap().slot,
            EdgeGestureSlot::LeftTopSwipeRight
        );
        backend.recorded_inputs.lock().unwrap().clear();

        // 2) Edge tap near left-top replays normal MouseDown + MouseUp (never breaks edge buttons).
        reg.handle_data_bytes_for_session(key, Some(sid), Some(dgen), &encode_touch(0, 14.0, 30.0))
            .unwrap();
        reg.handle_data_bytes_for_session(key, Some(sid), Some(dgen), &encode_touch(3, 16.0, 31.0))
            .unwrap();
        {
            let rec = backend.recorded_inputs.lock().unwrap();
            assert_eq!(rec.len(), 2);
            assert!(matches!(rec[0], InputEvent::MouseDown { .. }));
            assert!(matches!(rec[1], InputEvent::MouseUp { .. }));
        }
        backend.recorded_inputs.lock().unwrap().clear();

        // 3) Right-top swipe left -> toggles stream_paused ON then OFF while preserving session.
        send_swipe(
            sw as f64 - 12.0,
            sh as f64 * 0.2,
            sw as f64 * 0.75,
            sh as f64 * 0.21,
        );
        assert!(reg.list_sessions()[0].stream_paused);
        send_swipe(
            sw as f64 - 12.0,
            sh as f64 * 0.2,
            sw as f64 * 0.75,
            sh as f64 * 0.21,
        );
        assert!(!reg.list_sessions()[0].stream_paused);

        // 4) Right-bottom swipe left -> toggles allow_input OFF; hotkey gesture is blocked while
        //    view-only, yet right-bottom swipe left still re-enables allow_input!
        send_swipe(
            sw as f64 - 12.0,
            sh as f64 * 0.8,
            sw as f64 * 0.75,
            sh as f64 * 0.81,
        );
        assert!(!reg.is_input_allowed());
        send_swipe(12.0, sh as f64 * 0.2, sw as f64 * 0.25, sh as f64 * 0.21);
        assert!(backend.recorded_inputs.lock().unwrap().is_empty());
        assert!(reg.last_gesture().unwrap().blocked_reason.is_some());
        send_swipe(
            sw as f64 - 12.0,
            sh as f64 * 0.8,
            sw as f64 * 0.75,
            sh as f64 * 0.81,
        );
        assert!(reg.is_input_allowed());

        // 4.5) Rebind left-bottom swipe right to Screenshot into a custom temp directory ->
        //      creates `<dir>/idis-YYYY-MM-DD/*.png` with valid PNG header even when view-only.
        let shot_tmp = std::env::temp_dir().join(format!(
            "idis-shot-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut scfg = reg.gestures_config();
        scfg.screenshot_dir = shot_tmp.to_string_lossy().into_owned();
        scfg.left_bottom_swipe_right = GestureAction::Screenshot;
        reg.set_gestures_config(scfg).unwrap();
        reg.set_input_allowed(false);
        send_swipe(12.0, sh as f64 * 0.8, sw as f64 * 0.25, sh as f64 * 0.81);
        let lg = reg.last_gesture().unwrap();
        assert_eq!(lg.slot, EdgeGestureSlot::LeftBottomSwipeRight);
        assert!(lg.blocked_reason.is_none());
        let saved_path = std::path::PathBuf::from(lg.detail.expect("screenshot saved path"));
        assert!(saved_path.is_file());
        let parent_name = saved_path
            .parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_string_lossy();
        assert!(
            parent_name.starts_with("idis-") && parent_name.len() == "idis-YYYY-MM-DD".len(),
            "unexpected dated folder name: {parent_name}"
        );
        let png_bytes = std::fs::read(&saved_path).unwrap();
        assert!(png_bytes.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]));
        let _ = std::fs::remove_dir_all(&shot_tmp);

        // 4.6) Rebind left-top to CloseWebSharing & left-bottom to LockHost (both work while view-only!)
        let close_web_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let close_web_calls_cb = close_web_calls.clone();
        reg.set_close_web_sharing_handler(Arc::new(move || {
            close_web_calls_cb.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            true
        }));
        let mut g_priv = reg.gestures_config();
        g_priv.left_top_swipe_right = GestureAction::CloseWebSharing;
        g_priv.left_bottom_swipe_right = GestureAction::LockHost;
        reg.set_gestures_config(g_priv).unwrap();

        send_swipe(12.0, sh as f64 * 0.2, sw as f64 * 0.25, sh as f64 * 0.21);
        assert_eq!(close_web_calls.load(std::sync::atomic::Ordering::Acquire), 1);
        assert!(reg.last_gesture().unwrap().blocked_reason.is_none());

        send_swipe(12.0, sh as f64 * 0.8, sw as f64 * 0.25, sh as f64 * 0.81);
        assert_eq!(
            backend
                .lock_host_screen_calls
                .load(std::sync::atomic::Ordering::Acquire),
            1
        );
        assert!(reg.is_host_screen_locked());
        assert!(reg.last_gesture().unwrap().blocked_reason.is_none());
        backend
            .screen_locked
            .store(false, std::sync::atomic::Ordering::Release);
        reg.refresh_host_lock_state_now(true);
        reg.set_input_allowed(true);

        // 5) Rebind right-top swipe left to Disconnect -> closes the session cleanly.
        let mut gcfg = reg.gestures_config();
        gcfg.right_top_swipe_left = GestureAction::Disconnect;
        reg.set_gestures_config(gcfg).unwrap();
        send_swipe(
            sw as f64 - 12.0,
            sh as f64 * 0.2,
            sw as f64 * 0.75,
            sh as f64 * 0.21,
        );
        assert!(reg.list_sessions().is_empty());
    }

    #[test]
    fn list_sessions_reports_live_os_display_bounds_when_windowserver_clamps_mode() {
        use crate::protocol::keyed_archive::ArchivedValue;
        use clap::Parser;
        use std::collections::BTreeMap;

        let cfg = AppConfig::try_parse_from(["idis", "--auto-accept", "--config", "none"]).unwrap();
        let backend = Arc::new(crate::platform::mock::MockBackend::new());
        let reg = SessionRegistry::new(cfg, backend.clone());

        struct DummyWriter;
        impl crate::transport::FrameWriter for DummyWriter {
            fn send_frame(&self, _payload: &[u8]) -> anyhow::Result<()> {
                Ok(())
            }
            fn close(&self) {}
        }

        let key = "127.0.0.1";
        let sid = reg
            .register_telemetry(key.to_string(), Arc::new(DummyWriter), 56846, false)
            .unwrap();
        let mut hdict = BTreeMap::new();
        hdict.insert(
            "uniqueIdentifier".to_string(),
            ArchivedValue::String("ipad-bounds-1".to_string()),
        );
        hdict.insert("name".to_string(), ArchivedValue::String("iPad".to_string()));
        hdict.insert("width".to_string(), ArchivedValue::Int(2048));
        hdict.insert("height".to_string(), ArchivedValue::Int(1536));
        let hs = crate::protocol::messages::MessagePacket::new_send(
            "Handshake",
            ArchivedValue::Dict(hdict),
        );
        reg.handle_telemetry_bytes_for_session(key, Some(sid), &hs.encode().unwrap())
            .unwrap();
        reg.attach_data_channel_checked(key, Some(sid), Arc::new(DummyWriter))
            .unwrap();

        // Simulate macOS WindowServer falling back the virtual display mode to 1600x1200.
        let did = {
            let map = reg.sessions.lock().unwrap();
            let hdl = map.get(key).unwrap().capture.as_ref().unwrap().handle.clone();
            let id = hdl.lock().unwrap().display_id().unwrap();
            id
        };
        backend
            .mock_display_bounds
            .lock()
            .unwrap()
            .insert(did, (0, 900, 1600, 1200));

        let snap = &reg.list_sessions()[0];
        assert_eq!(snap.logical_width, 1600);
        assert_eq!(snap.logical_height, 1200);
        assert!(!snap.is_pixel_exact);

        reg.close_session_if_id(key, sid);
    }

    #[test]
    fn usb_input_handles_be_prefix_coalesced_blocks_and_telemetry_channel() {
        use clap::Parser;
        let mut cfg =
            AppConfig::try_parse_from(["idis", "--auto-accept", "--allow-input", "--config", "none"])
                .unwrap();
        cfg.allow_input = true;
        let backend = Arc::new(crate::platform::mock::MockBackend::new());
        let reg = SessionRegistry::new(cfg, backend.clone());

        struct DummyWriter;
        impl crate::transport::FrameWriter for DummyWriter {
            fn send_frame(&self, _payload: &[u8]) -> anyhow::Result<()> {
                Ok(())
            }
            fn close(&self) {}
        }
        let key = "127.0.0.1:usb-99-1";
        let sid = reg
            .register_usb_telemetry(
                key.to_string(),
                Arc::new(DummyWriter),
                Arc::new(DummyWriter),
                2345,
            )
            .unwrap();
        let mut hdict = std::collections::BTreeMap::new();
        hdict.insert(
            "uniqueIdentifier".to_string(),
            crate::protocol::keyed_archive::ArchivedValue::String("ipad-usb-1".to_string()),
        );
        hdict.insert(
            "name".to_string(),
            crate::protocol::keyed_archive::ArchivedValue::String("iPad USB".to_string()),
        );
        let hs = crate::protocol::messages::MessagePacket::new_send(
            "Handshake",
            crate::protocol::keyed_archive::ArchivedValue::Dict(hdict),
        );
        reg.handle_telemetry_bytes_for_session(key, Some(sid), &hs.encode().unwrap())
            .unwrap();
        let ping_start = crate::protocol::messages::MessagePacket::new_request(
            "Ping",
            crate::protocol::keyed_archive::ArchivedValue::String("START".to_string()),
            5.0,
        );
        reg.handle_telemetry_bytes_for_session(key, Some(sid), &ping_start.encode().unwrap())
            .unwrap();

        let make_kb = |ch: u8| {
            let mut kb = std::collections::BTreeMap::new();
            kb.insert(
                "specialValue".to_string(),
                crate::protocol::keyed_archive::ArchivedValue::Int(0),
            );
            kb.insert(
                "value".to_string(),
                crate::protocol::keyed_archive::ArchivedValue::Int(ch as i64),
            );
            crate::protocol::keyed_archive::archive(
                &crate::protocol::keyed_archive::ArchivedValue::Object {
                    class_name: "MSMKeyboardEvent".to_string(),
                    classes: vec!["MSMKeyboardEvent".to_string(), "NSObject".to_string()],
                    fields: kb,
                },
            )
            .unwrap()
        };

        // 1) Big-endian u32 length prefix on PT_FRAME_TYPE_DATA
        let kb_a = make_kb(b'a');
        let mut be_framed = (kb_a.len() as u32).to_be_bytes().to_vec();
        be_framed.extend_from_slice(&kb_a);
        reg.handle_data_bytes_for_session(key, Some(sid), None, &be_framed)
            .unwrap();

        // 2) Two coalesced u32_le Canal blocks in a single USB PeerTalk frame
        let kb_b = make_kb(b'b');
        let kb_c = make_kb(b'c');
        let mut coalesced = Vec::new();
        coalesced.extend_from_slice(&(kb_b.len() as u32).to_le_bytes());
        coalesced.extend_from_slice(&kb_b);
        coalesced.extend_from_slice(&(kb_c.len() as u32).to_le_bytes());
        coalesced.extend_from_slice(&kb_c);
        reg.handle_data_bytes_for_session(key, Some(sid), None, &coalesced)
            .unwrap();

        // 3) Direct input event arriving on USB Telemetry channel (PT type 100)
        let kb_d = make_kb(b'd');
        reg.handle_telemetry_bytes_for_session(key, Some(sid), &kb_d)
            .unwrap();

        let recorded = backend.recorded_inputs.lock().unwrap().clone();
        for ch in *b"abcd" {
            assert!(
                recorded.contains(&crate::protocol::messages::InputEvent::KeyUnicode {
                    ch: ch as u16
                }),
                "missing expected USB key '{}'",
                ch as char
            );
        }
        assert_eq!(reg.input_stats().injected, 4);

        reg.close_session_if_id(key, sid);
    }

    #[test]
    fn flow_control_fifo_rtt_avoids_pipelining_aliasing_and_clears_on_reset() {
        let fc = FlowControl::new(4);
        // Prime `acked_ever = true` so strict pipelined accounting is active.
        assert!(fc.try_acquire_send());
        fc.on_picture_rendered();
        fc.reset_in_flight();
        assert_eq!(fc.ewma_rtt_ms(), None);

        // Send frame #1, wait 25ms, send frame #2, wait 25ms, then ACK frame #1 (~50ms true RTT).
        assert!(fc.try_acquire_send());
        std::thread::sleep(Duration::from_millis(25));
        assert!(fc.try_acquire_send());
        std::thread::sleep(Duration::from_millis(25));
        fc.on_picture_rendered();
        let rtt = fc.ewma_rtt_ms().expect("RTT should be recorded");
        assert!(
            rtt >= 40.0,
            "pipelined FIFO RTT must measure frame #1 (~50ms), not alias against frame #2 (~25ms); got {rtt:.1}ms"
        );
        fc.reset_in_flight();
        assert_eq!(fc.ewma_rtt_ms(), None);

        // Safety-release probe (after >120ms stall with empty send_times_ms) must seed a timestamp
        // so returning ACKs unfreeze `ewma_rtt_ms` instead of staying stuck on a stale high value!
        let fc2 = FlowControl::new(1);
        assert!(fc2.try_acquire_send());
        std::thread::sleep(Duration::from_millis(20));
        fc2.on_picture_rendered();
        let rtt_initial = fc2.ewma_rtt_ms().expect("initial RTT recorded");
        assert!(rtt_initial >= 15.0);
        // Saturate max_in_flight=1, let send_times_ms drain, then hit 120ms safety release probe
        assert!(fc2.try_acquire_send());
        assert!(!fc2.try_acquire_send());
        // Simulate empty timestamp queue (as happens after expired timestamps) while in_flight == limit
        fc2.clear_send_timestamps_for_test();
        std::thread::sleep(Duration::from_millis(130));
        assert!(fc2.try_acquire_send(), "120ms safety probe must release");
        std::thread::sleep(Duration::from_millis(5));
        fc2.on_picture_rendered();
        let rtt_after_probe = fc2.ewma_rtt_ms().expect("probe ACK must refresh RTT");
        assert!(
            rtt_after_probe < rtt_initial || rtt_after_probe <= 30.0,
            "returning ACK after safety probe must update EWMA instead of freezing; initial={rtt_initial:.1}, after={rtt_after_probe:.1}"
        );
    }

    #[test]
    fn apply_preset_and_reset_clear_stale_per_device_prefs() {
        use clap::Parser;
        let tmp = std::env::temp_dir().join(format!(
            "idis_dev_prefs_sync_{}.yaml",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&tmp);

        let mut cfg = AppConfig::try_parse_from(["idis"]).unwrap();
        cfg.config_file = Some(tmp.display().to_string());
        let reg = SessionRegistry::new(cfg, Arc::new(crate::platform::mock::MockBackend::new()));
        let fp = "fp:020000000001a1b2c3d4e5f6";
        reg.trust_device_and_save(fp, "u1", "iPad", "iPad").unwrap();
        reg.trust_store()
            .update_device_prefs(
                fp,
                crate::trust::DevicePreferences {
                    fps: Some(60),
                    bitrate_mbps: Some(24),
                    hidpi: Some(2),
                    adaptive_quality: Some(false),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(reg.effective_video_for_fingerprint(Some(fp)).fps, 60);

        // Applying a preset clears stale per-device overrides so preset settings take effect cleanly.
        reg.apply_preset("极简省电").unwrap();
        assert!(reg.trust_store().get_device(fp).unwrap().prefs.is_empty());
        assert_eq!(reg.effective_video_for_fingerprint(Some(fp)).fps, 15);

        // Re-set per-device prefs while device is offline -> reset_video_settings must clear them too.
        reg.trust_store()
            .update_device_prefs(
                fp,
                crate::trust::DevicePreferences {
                    fps: Some(60),
                    ..Default::default()
                },
            )
            .unwrap();
        reg.reset_video_settings().unwrap();
        assert!(reg.trust_store().get_device(fp).unwrap().prefs.is_empty());
        // Low-power mode ("极简省电") remains enforced at runtime (15fps Eco cap) until turned off,
        // at which point the reset Balanced default (30fps) takes effect (Iter-6 P2-C4).
        assert_eq!(reg.effective_video_for_fingerprint(Some(fp)).fps, 15);
        reg.set_low_power(false);
        assert_eq!(reg.effective_video_for_fingerprint(Some(fp)).fps, 30);

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn iter1_hidpi_integer_scale_clear_prefs_corrupt_guard_and_lock_reap_invariants() {
        use clap::Parser;
        // 1) BUG-A3 regression: legacy 1x-point Retina iPad (1024x768) with hidpi=2 + integer_scale=true
        //    must stay 1024x768 logical (2048x1536 backing), NEVER halved to 512x384!
        let make_hs = |w: u32, h: u32| ClientHandshake {
            uid: "u".to_string(),
            name: "iPad".to_string(),
            model: "iPad Air".to_string(),
            system_name: "iOS".to_string(),
            system_version: "12.5".to_string(),
            client_version: "3.3".to_string(),
            screen_width: w,
            screen_height: h,
            orientation: if w > h { 1 } else { 0 },
            data_protocol_version: 5,
            udp_port: 0,
            supports_telemetry_cursor: true,
            supports_mirror_mode: false,
            supports_shared_main_mode: false,
            max_compression: None,
            preferred_compression: None,
            preferred_fps: None,
        };
        let vs_int = VideoSettings {
            width: 0,
            height: 0,
            fps: 30,
            bitrate_mbps: 16,
            hidpi: 2,
            integer_scale: true,
            max_pixel_edge: 0,
            adaptive_quality: true,
            abr_sensitivity: crate::config::AbrSensitivity::Balanced,
            half_fps_when_unfocused: false,
            quality: QualityPreset::Balanced,
            web_width: 1280,
            web_height: 720,
            web_fps: 30,
            web_bitrate_mbps: 16,
            web_hidpi: 1,
            web_max_pixel_edge: 0,
            web_quality: QualityPreset::Balanced,
        };
        assert_eq!(
            SessionRegistry::resolve_dimensions_for_settings(&make_hs(1024, 768), &vs_int, true),
            (1024, 768),
            "1024x768 legacy Retina iPad with hidpi=2 + integer_scale must NOT shrink to 512x384"
        );
        assert_eq!(
            SessionRegistry::resolve_dimensions_for_settings(&make_hs(2048, 1536), &vs_int, true),
            (1024, 768)
        );
        assert_eq!(
            SessionRegistry::resolve_dimensions_for_settings(&make_hs(2732, 2048), &vs_int, true),
            (1366, 1024)
        );

        // 2) BUG-C1 regression: clear_trusted_device_prefs_and_save MUST persist cleared prefs to YAML disk!
        let tmp = std::env::temp_dir().join(format!("idis_iter1_clear_{}.yaml", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        let mut cfg = AppConfig::try_parse_from(["idis"]).unwrap();
        cfg.config_file = Some(tmp.display().to_string());
        let reg = SessionRegistry::new(cfg.clone(), Arc::new(crate::platform::mock::MockBackend::new()));
        let fp = "fp:1234567890abcdef12345678";
        reg.trust_device_and_save(fp, "u1", "iPad", "iPad").unwrap();
        reg.trust_store()
            .update_device_prefs(
                fp,
                crate::trust::DevicePreferences {
                    fps: Some(60),
                    ..Default::default()
                },
            )
            .unwrap();
        reg.save_config_file().unwrap();
        assert!(reg.clear_trusted_device_prefs_and_save(fp).unwrap());
        let reloaded = crate::user_config::UserConfigFile::from_yaml_str(
            &std::fs::read_to_string(&tmp).unwrap(),
        )
        .unwrap();
        assert!(
            reloaded
                .trusted_devices
                .iter()
                .find(|d| d.fingerprint == fp)
                .unwrap()
                .prefs
                .is_empty(),
            "cleared per-device prefs must persist to disk"
        );

        // 3) BUG-C6 regression: apply_user_config with low_power=true enforces hidpi=1 & low_power polling
        let mut lp_cfg = crate::user_config::UserConfigFile {
            low_power: true,
            ..Default::default()
        };
        lp_cfg.ipad.hidpi = 2;
        lp_cfg.polling.cursor_poll_ms = 8;
        let applied = reg.apply_user_config(lp_cfg, true).unwrap();
        assert_eq!(applied.ipad.hidpi, 1);
        assert_eq!(
            applied.polling,
            crate::user_config::PollingConfigSection::low_power_defaults()
        );
        let _ = std::fs::remove_file(&tmp);

        // 4) BUG-C6 regression: corrupt YAML rejects trust_device_and_save with Err & rolls back RAM
        let tmp_bad =
            std::env::temp_dir().join(format!("idis_iter1_corrupt_{}.yaml", std::process::id()));
        let broken = "trusted_devices:\n  - [unclosed_yaml\n";
        std::fs::write(&tmp_bad, broken).unwrap();
        let mut cfg_bad = AppConfig::try_parse_from(["idis"]).unwrap();
        cfg_bad.config_file = Some(tmp_bad.display().to_string());
        let reg_bad =
            SessionRegistry::new(cfg_bad, Arc::new(crate::platform::mock::MockBackend::new()));
        assert!(reg_bad.is_config_corrupt());
        assert!(
            reg_bad
                .trust_device_and_save(fp, "u1", "iPad", "iPad")
                .is_err(),
            "trust_device_and_save must return Err when disk YAML is corrupt"
        );
        assert!(
            !reg_bad.trust_store().is_trusted(Some(fp)),
            "failed trust_device_and_save must roll back RAM trust_store"
        );
        reg_bad.set_client_cursor(true);
        assert!(
            !reg_bad.export_persisted_config().client_cursor,
            "persist_config_patch must NOT mutate persisted_baseline while corrupt"
        );
        assert_eq!(std::fs::read_to_string(&tmp_bad).unwrap(), broken);
        let _ = std::fs::remove_file(&tmp_bad);
    }

    #[test]
    fn iter2_session_isolation_quota_flow_control_lock_grace_and_config_rollback() {
        use clap::Parser;

        struct CapturingWriter {
            frames: Arc<Mutex<Vec<Vec<u8>>>>,
            closed: Arc<AtomicBool>,
        }
        impl crate::transport::FrameWriter for CapturingWriter {
            fn send_frame(&self, payload: &[u8]) -> anyhow::Result<()> {
                self.frames.lock().unwrap().push(payload.to_vec());
                Ok(())
            }
            fn close(&self) {
                self.closed.store(true, Ordering::SeqCst);
            }
            fn is_peer_closed(&self) -> bool {
                self.closed.load(Ordering::Acquire)
            }
        }

        // 1) GAP-A10: FlowControl ACK dedup (FrameReceived ignored after PictureRendered),
        //    no-drop-count acquire, & 500ms idle decay.
        let fc = FlowControl::new(2);
        assert!(fc.try_acquire_send());
        fc.on_frame_received(); // enables backpressure (`seen_any_ack = true`) and measures RTT
        assert_eq!(fc.in_flight(), 0);
        assert!(fc.ewma_rtt_ms().is_some());
        assert!(fc.try_acquire_send());
        assert!(fc.try_acquire_send());
        assert!(!fc.try_acquire_send_no_drop_count());
        assert_eq!(fc.dropped_frames(), 0);
        fc.on_picture_rendered();
        assert_eq!(fc.in_flight(), 1);
        fc.on_picture_rendered();
        assert_eq!(fc.in_flight(), 0);
        assert!(fc.try_acquire_send());
        assert!(fc.try_acquire_send());
        fc.on_frame_received(); // Must be ignored once PictureRendered seen!
        assert_eq!(fc.in_flight(), 2);
        std::thread::sleep(Duration::from_millis(530));
        assert!(fc.try_acquire_send());
        assert!(fc.try_acquire_send());
        assert_eq!(fc.in_flight(), 2);

        // 2) GAP-A1 + GAP-A3 + BUG-A2-4: Stale session_id isolation, unauth_count>=4 cap,
        //    on_system_wake() real reap survival, & active-iPad lock policy!
        let mock = Arc::new(crate::platform::mock::MockBackend::new());
        let mut cfg = AppConfig::try_parse_from(["idis", "--auto-accept", "--allow-input", "--config", "none"]).unwrap();
        cfg.max_extended_screens = 2;
        cfg.max_web_viewers = 2;
        let reg = SessionRegistry::new(cfg, mock.clone());

        for i in 1..=4 {
            let w: SharedFrameWriter = Arc::new(CapturingWriter {
                frames: Arc::new(Mutex::new(Vec::new())),
                closed: Arc::new(AtomicBool::new(false)),
            });
            assert!(reg.register_telemetry(format!("10.0.0.{i}"), w, 5027, false).is_some());
        }
        let w5: SharedFrameWriter = Arc::new(CapturingWriter {
            frames: Arc::new(Mutex::new(Vec::new())),
            closed: Arc::new(AtomicBool::new(false)),
        });
        assert!(
            reg.register_telemetry("10.0.0.5".to_string(), w5, 5027, false).is_none(),
            "5th concurrent unauthenticated IP must be rejected"
        );
        reg.close_all();

        let frames1 = Arc::new(Mutex::new(Vec::new()));
        let closed1 = Arc::new(AtomicBool::new(false));
        let tw1: SharedFrameWriter = Arc::new(CapturingWriter {
            frames: frames1.clone(),
            closed: closed1.clone(),
        });
        let dw1: SharedFrameWriter = Arc::new(CapturingWriter {
            frames: Arc::new(Mutex::new(Vec::new())),
            closed: Arc::new(AtomicBool::new(false)),
        });
        let sid1 = reg.register_telemetry("10.0.1.1".to_string(), tw1, 5027, false).unwrap();
        let mut hs_dict = std::collections::BTreeMap::new();
        hs_dict.insert("uid".to_string(), crate::protocol::keyed_archive::ArchivedValue::String("u-lock".into()));
        hs_dict.insert("name".to_string(), crate::protocol::keyed_archive::ArchivedValue::String("iPad Lock".into()));
        hs_dict.insert("screenWidth".to_string(), crate::protocol::keyed_archive::ArchivedValue::Int(1024));
        hs_dict.insert("screenHeight".to_string(), crate::protocol::keyed_archive::ArchivedValue::Int(768));
        hs_dict.insert("clientDataProtocolVersionKey".to_string(), crate::protocol::keyed_archive::ArchivedValue::String("5".into()));
        let hs_pkt = crate::protocol::messages::MessagePacket::new_send(
            "Handshake",
            crate::protocol::keyed_archive::ArchivedValue::Dict(hs_dict.clone()),
        )
        .encode()
        .unwrap();
        reg.handle_telemetry_bytes_for_session("10.0.1.1", Some(sid1), &hs_pkt).unwrap();
        let (_sid, dgen1) = reg.attach_data_channel_checked("10.0.1.1", Some(sid1), dw1).unwrap();

        let stop_pkt = crate::protocol::messages::MessagePacket::new_send(
            "StopStream",
            crate::protocol::keyed_archive::ArchivedValue::Null,
        )
        .encode()
        .unwrap();
        reg.handle_telemetry_bytes_for_session("10.0.1.1", Some(sid1 + 999), &stop_pkt).unwrap();
        assert!(!reg.sessions.lock().unwrap().get("10.0.1.1").unwrap().stream_paused.load(Ordering::Acquire));

        let hijack_w: SharedFrameWriter = Arc::new(CapturingWriter {
            frames: Arc::new(Mutex::new(Vec::new())),
            closed: Arc::new(AtomicBool::new(false)),
        });
        assert!(
            reg.register_telemetry("10.0.1.1".to_string(), hijack_w, 5027, false).is_none(),
            "same-IP hijack must be rejected while active stream is healthy"
        );

        std::thread::sleep(Duration::from_millis(70));
        reg.on_system_wake();
        assert_eq!(reg.reap_timed_out_with_limit(Duration::from_millis(50)), 0);

        // BUG-A2-4 + GAP-A3: Unauth handshake during 10s grace rejected with 0 frames & active iPad survives
        reg.set_lock_delay_secs(10);
        reg.set_lock_action_ipad(LockAction::Disconnect);
        mock.screen_locked.store(true, Ordering::Release);
        reg.on_host_screen_lock_changed(true);
        assert!(!reg.is_host_lock_enforced(), "10s grace countdown must be active");
        let frames_intruder = Arc::new(Mutex::new(Vec::new()));
        let tw_intruder: SharedFrameWriter = Arc::new(CapturingWriter {
            frames: frames_intruder.clone(),
            closed: Arc::new(AtomicBool::new(false)),
        });
        let sid_intr = reg.register_telemetry("10.0.9.9".to_string(), tw_intruder, 5027, false).unwrap();
        reg.handle_telemetry_bytes_for_session("10.0.9.9", Some(sid_intr), &hs_pkt).unwrap();
        assert!(
            frames_intruder.lock().unwrap().is_empty(),
            "locked ipad=disconnect rejection must send ZERO AccessConfirmed blacklist packets"
        );
        assert!(
            reg.sessions.lock().unwrap().contains_key("10.0.1.1"),
            "BUG-A2-4 regression: unauth probe during grace must NOT prematurely kill active iPad #1"
        );

        // Switch to ipad=pause with delay=0 -> dropped_locked increments, PingTimeout exempt!
        reg.set_lock_action_ipad(LockAction::Pause);
        reg.set_lock_delay_secs(0);
        assert!(reg.is_host_lock_paused_ipad());
        reg.handle_data_bytes_for_session("10.0.1.1", Some(sid1), Some(dgen1), b"bplist00").unwrap();
        assert_eq!(reg.input_stats().dropped_locked, 1);
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(
            reg.reap_timed_out_with_limit(Duration::from_millis(40)),
            0,
            "BUG-A6 regression: host_lock_paused_ipad must exempt active sessions from PingTimeout"
        );
        mock.screen_locked.store(false, Ordering::Release);
        reg.on_host_screen_lock_changed(false);

        // 3) BUG-A2-3 regression: max_extended_screens=1 with 1 active iPad + 1 FollowIpad Web viewer
        reg.set_max_extended_screens(1);
        let sub = reg.subscribe_web_stream("127.0.0.1:50123".to_string(), None).unwrap();
        assert!(
            reg.set_web_screen_mode(crate::config::WebScreenMode::Independent).is_err(),
            "BUG-A2-3 regression: live switch to Independent must enforce max_extended_screens=1"
        );
        assert!(
            reg.set_web_screen_mode(crate::config::WebScreenMode::Main).is_ok(),
            "switching to Main must succeed without consuming virtual screen quota"
        );
        drop(sub);
        reg.close_all();

        // 4) BUG-C2-3 + BUG-C2-4 + GAP-C6 + GAP-C7
        let tmp_dir = std::env::temp_dir().join(format!("idis_iter2_cfg_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let cfg_file = tmp_dir.join("idis.yaml");

        std::fs::write(
            &cfg_file,
            "low_power: true\nipad:\n  hidpi: 2\npolling:\n  cursor_poll_ms: 8\ntrusted_devices:\n  - mac: \"aa:bb:cc:dd:ee:ff\"\n  - fingerprint: \"fp:abcdef0123456789abcdef01\"\n    name: \"Kept iPad\"\n",
        )
        .unwrap();
        let mut cfg_lp = AppConfig::try_parse_from(["idis"]).unwrap();
        cfg_lp.config_file = Some(cfg_file.display().to_string());
        let reg_lp = SessionRegistry::new(cfg_lp, Arc::new(crate::platform::mock::MockBackend::new()));
        assert_eq!(reg_lp.video_settings().hidpi, 1, "BUG-C2-3: low_power startup must enforce hidpi=1");
        assert_eq!(
            reg_lp.polling_config(),
            crate::user_config::PollingConfigSection::low_power_defaults(),
            "BUG-C2-3: low_power startup must enforce low_power_defaults polling"
        );
        assert!(reg_lp.trust_store().is_trusted(Some("fp:abcdef0123456789abcdef01")));
        assert_eq!(reg_lp.trust_store().list().len(), 1, "legacy mac-only entry must be dropped");

        reg_lp.set_low_power(false);
        let _ = reg_lp.update_video_settings(VideoSettingsPatch { fps: Some(60), ..Default::default() });
        reg_lp.set_low_power(true);
        reg_lp.apply_preset("极简省电").unwrap();
        reg_lp.set_low_power(false);
        assert_eq!(
            reg_lp.video_settings().fps,
            15,
            "BUG-C2-4: apply_preset must clear stale low_power_snapshot"
        );

        std::fs::remove_file(&cfg_file).unwrap();
        std::fs::create_dir_all(&cfg_file).unwrap();
        let fp_new = "fp:99887766554433221100ffaa";
        assert!(reg_lp.trust_device_and_save(fp_new, "u", "Fail", "iPad").is_err());
        assert!(!reg_lp.trust_store().is_trusted(Some(fp_new)), "failed trust_device_and_save must roll back RAM");
        assert!(reg_lp.revoke_trusted_device_and_save("fp:abcdef0123456789abcdef01").is_err());
        assert!(reg_lp.trust_store().is_trusted(Some("fp:abcdef0123456789abcdef01")), "failed revoke must roll back RAM");
        assert!(reg_lp.save_current_as_preset("ShouldNotSave").is_err());
        assert!(!reg_lp.list_presets().1.iter().any(|p| p.name == "ShouldNotSave"));

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn iter3_session_lifecycle_lock_grace_failover_and_migration_tests() {
        use crate::platform::mock::MockBackend;
        use crate::protocol::keyed_archive::ArchivedValue;
        use crate::protocol::messages::MessagePacket;
        use crate::transport::FrameWriter;
        use anyhow::Result;
        use clap::Parser;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        struct ControllableWriter {
            peer_closed: Arc<AtomicBool>,
            closed: Arc<AtomicBool>,
        }
        impl FrameWriter for ControllableWriter {
            fn send_frame(&self, _payload: &[u8]) -> Result<()> {
                Ok(())
            }
            fn close(&self) {
                self.closed.store(true, Ordering::Release);
            }
            fn is_peer_closed(&self) -> bool {
                self.peer_closed.load(Ordering::Acquire)
            }
        }

        // 1) PeerClosedWhilePending: disconnecting mid-approval fires cancel_pending_handler
        let mut cfg = AppConfig::try_parse_from(["idis"]).unwrap();
        cfg.config_file = Some("none".into());
        cfg.auto_accept = false;
        cfg.max_web_viewers = 4;
        cfg.max_extended_screens = 2;
        let mock = Arc::new(MockBackend::new());
        let reg = Arc::new(SessionRegistry::new(cfg, mock.clone()));

        let cancel_count = Arc::new(AtomicUsize::new(0));
        let cancel_c = cancel_count.clone();
        reg.set_cancel_pending_handler(Arc::new(move |_sid, _key| {
            cancel_c.fetch_add(1, Ordering::AcqRel);
        }));
        let confirm_entered = Arc::new(AtomicBool::new(false));
        let ce_c = confirm_entered.clone();
        let release_confirm = Arc::new(AtomicBool::new(false));
        let rc_c = release_confirm.clone();
        reg.set_confirm_handler(Arc::new(move |_pending| {
            ce_c.store(true, Ordering::Release);
            while !rc_c.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(5));
            }
            ConfirmDecision::Deny
        }));

        let peer_closed = Arc::new(AtomicBool::new(false));
        let tw = Arc::new(ControllableWriter {
            peer_closed: peer_closed.clone(),
            closed: Arc::new(AtomicBool::new(false)),
        });
        let sid = reg
            .register_telemetry("10.0.5.5".to_string(), tw, 5027, false)
            .unwrap();
        let reg_hs = reg.clone();
        let hs_t = std::thread::spawn(move || {
            let mut hs = std::collections::BTreeMap::new();
            hs.insert("uid".into(), ArchivedValue::String("u-pending".into()));
            hs.insert("name".into(), ArchivedValue::String("Pending iPad".into()));
            hs.insert("model".into(), ArchivedValue::String("iPad".into()));
            hs.insert("screenWidth".into(), ArchivedValue::Int(1024));
            hs.insert("screenHeight".into(), ArchivedValue::Int(768));
            let pkt = MessagePacket::new_send("Handshake", ArchivedValue::Dict(hs))
                .encode()
                .unwrap();
            let _ = reg_hs.handle_telemetry_bytes_for_session("10.0.5.5", Some(sid), &pkt);
        });
        for _ in 0..50 {
            if confirm_entered.load(Ordering::Acquire) {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(confirm_entered.load(Ordering::Acquire));
        peer_closed.store(true, Ordering::Release);
        reg.close_session_if_id("10.0.5.5", sid);
        assert!(
            cancel_count.load(Ordering::Acquire) >= 1,
            "closing a pending session must fire cancel_pending_handler"
        );
        release_confirm.store(true, Ordering::Release);
        hs_t.join().unwrap();

        // 2) DataChannelNeverConnected + stale data_generation guards
        let mut cfg2 = AppConfig::try_parse_from(["idis"]).unwrap();
        cfg2.config_file = Some("none".into());
        cfg2.auto_accept = true;
        cfg2.max_web_viewers = 4;
        cfg2.max_extended_screens = 2;
        let mock2 = Arc::new(MockBackend::new());
        mock2.manual_frame_mode.store(true, Ordering::Release);
        let reg2 = Arc::new(SessionRegistry::new(cfg2, mock2.clone()));

        let make_hs = |uid: &str, name: &str| {
            let mut hs = std::collections::BTreeMap::new();
            hs.insert("uid".into(), ArchivedValue::String(uid.into()));
            hs.insert("name".into(), ArchivedValue::String(name.into()));
            hs.insert("model".into(), ArchivedValue::String("iPad".into()));
            hs.insert("screenWidth".into(), ArchivedValue::Int(1024));
            hs.insert("screenHeight".into(), ArchivedValue::Int(768));
            hs.insert("clientDataProtocolVersionKey".into(), ArchivedValue::String("5".into()));
            MessagePacket::new_send("Handshake", ArchivedValue::Dict(hs))
                .encode()
                .unwrap()
        };

        // Never-connect-data session reaps cleanly on timeout
        let tw_nodata = Arc::new(ControllableWriter {
            peer_closed: Arc::new(AtomicBool::new(false)),
            closed: Arc::new(AtomicBool::new(false)),
        });
        let sid_nd = reg2
            .register_telemetry("10.0.6.1".to_string(), tw_nodata, 5027, false)
            .unwrap();
        reg2.handle_telemetry_bytes_for_session("10.0.6.1", Some(sid_nd), &make_hs("u-nd", "NoData"))
            .unwrap();
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(
            reg2.reap_timed_out_with_limit(Duration::from_millis(20)),
            1,
            "telemetry-only session whose Data channel never connected must reap cleanly"
        );

        // 3) P1-A1 + P1-A2: Pre-poll OS lock probe preserves grace for active iPad, rejects new Web
        //    viewer during grace, AND 2-iPad FollowIpad failover immediately unpauses iPad #2!
        let tw1 = Arc::new(ControllableWriter {
            peer_closed: Arc::new(AtomicBool::new(false)),
            closed: Arc::new(AtomicBool::new(false)),
        });
        let dw1 = Arc::new(ControllableWriter {
            peer_closed: Arc::new(AtomicBool::new(false)),
            closed: Arc::new(AtomicBool::new(false)),
        });
        let sid1 = reg2
            .register_telemetry("10.0.7.1".to_string(), tw1, 5027, false)
            .unwrap();
        reg2.handle_telemetry_bytes_for_session("10.0.7.1", Some(sid1), &make_hs("u-f1", "iPad 1"))
            .unwrap();
        let (_, dgen1) = reg2.attach_data_channel("10.0.7.1", dw1).unwrap();

        // Stale data_generation must NOT detach active capture or inject input!
        reg2.close_data_attachment_if_match("10.0.7.1", sid1, dgen1 + 99);
        assert!(
            reg2.sessions.lock().unwrap().get("10.0.7.1").unwrap().capture.is_some(),
            "stale data_generation must not detach active capture"
        );
        reg2.handle_data_bytes_for_session("10.0.7.1", Some(sid1), Some(dgen1 + 99), b"bplist00")
            .unwrap();

        // P1-A1: Host OS locks BEFORE main loop polls (`cached_locked=false`, `os_locked=true`),
        // with `on_lock_ipad=disconnect`, `on_lock_web=disconnect`, `delay=30s`.
        // Incoming Web viewer admission calls `refresh_host_lock_state_now(true)`:
        // - MUST reject the new Web viewer immediately (even during grace!)
        // - MUST preserve grace delay for active iPad #1 (NOT kill iPad #1 with 0s grace!)
        reg2.set_lock_action_ipad(LockAction::Disconnect);
        reg2.set_lock_action_web(LockAction::Disconnect);
        reg2.set_lock_delay_secs(30);
        mock2.screen_locked.store(true, Ordering::Release);
        assert!(
            reg2.subscribe_web_stream("127.0.0.1:59001".to_string(), None).is_err(),
            "P1-A1: incoming Web viewer must be rejected immediately while host OS is locked (even during grace)"
        );
        assert!(
            reg2.sessions.lock().unwrap().contains_key("10.0.7.1"),
            "P1-A1: pre-poll incoming probe must preserve grace period for already-active iPad #1"
        );
        assert!(!reg2.is_host_lock_enforced(), "grace must still be active, not immediately enforced");
        mock2.screen_locked.store(false, Ordering::Release);
        reg2.refresh_host_lock_state_now(false);

        // P1-A2: Connect iPad #2 (paused via StopStream) + FollowIpad Web viewer.
        // iPad #1 is FollowIpad owner; iPad #2 is paused (`set_paused(true)`).
        // When iPad #1 disconnects, iPad #2 MUST immediately be elected & unpaused (`set_paused(false)`)!
        let tw2 = Arc::new(ControllableWriter {
            peer_closed: Arc::new(AtomicBool::new(false)),
            closed: Arc::new(AtomicBool::new(false)),
        });
        let dw2 = Arc::new(ControllableWriter {
            peer_closed: Arc::new(AtomicBool::new(false)),
            closed: Arc::new(AtomicBool::new(false)),
        });
        let sid2 = reg2
            .register_telemetry("10.0.7.2".to_string(), tw2, 5027, false)
            .unwrap();
        reg2.handle_telemetry_bytes_for_session("10.0.7.2", Some(sid2), &make_hs("u-f2", "iPad 2"))
            .unwrap();
        let _ = reg2.attach_data_channel("10.0.7.2", dw2).unwrap();

        let _web_sub = reg2
            .subscribe_web_stream("127.0.0.1:59002".to_string(), None)
            .unwrap();
        // Force iPad #1 as owner and pause iPad #2
        reg2.web_follow_ipad_session_id.store(sid1, Ordering::Release);
        let stop_pkt = MessagePacket::new_send("StopStream", ArchivedValue::Null)
            .encode()
            .unwrap();
        reg2.handle_telemetry_bytes_for_session("10.0.7.2", Some(sid2), &stop_pkt)
            .unwrap();
        mock2.recorded_pauses.lock().unwrap().clear();
        // Disconnect iPad #1 -> iPad #2 must immediately be unpaused and elected as FollowIpad owner!
        reg2.close_session("10.0.7.1");
        assert_eq!(
            reg2.web_follow_ipad_session_id.load(Ordering::Acquire),
            sid2,
            "P1-A2: closing FollowIpad owner iPad #1 must deterministically elect iPad #2"
        );
        assert!(
            mock2.recorded_pauses.lock().unwrap().contains(&false),
            "P1-A2: closing FollowIpad owner iPad #1 must immediately unpause paused iPad #2 for Web viewers"
        );
        drop(_web_sub);
        reg2.close_all();

        // 4) P2-C5 + Legacy Migration + CFG-1 CLI isolation:
        let tmp_dir = std::env::temp_dir().join(format!("idis_iter3_mig_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let cfg_file = tmp_dir.join("idis.yaml");
        let legacy_settings = tmp_dir.join("settings.json");
        let legacy_trusted = tmp_dir.join("trusted_devices.txt");
        std::fs::write(
            &legacy_settings,
            r#"{"fps":45,"bitrate_mbps":22,"allow_input":true,"max_web_viewers":3}"#,
        )
        .unwrap();
        std::fs::write(&legacy_trusted, "# comment\n11:22:33:44:55:66\n").unwrap();

        // Launch with CLI `--fps 60` override: migration must save migrated fps=45 to disk, NOT CLI 60 (CFG-1)!
        let mut cfg_mig = AppConfig::try_parse_from(["idis", "--fps", "60"]).unwrap();
        cfg_mig.config_file = Some(cfg_file.display().to_string());
        cfg_mig.trusted_devices_file = Some(legacy_trusted.display().to_string());
        let reg_mig = SessionRegistry::new(cfg_mig, Arc::new(MockBackend::new()));
        assert_eq!(reg_mig.video_settings().fps, 60, "runtime honors CLI --fps 60");
        assert_eq!(
            reg_mig.export_persisted_config().ipad.fps,
            45,
            "CFG-1: legacy migration must preserve migrated fps=45 on baseline, never CLI 60"
        );
        assert!(cfg_file.exists(), "legacy migration must create unified idis.yaml");
        let on_disk = crate::user_config::load_yaml_file(&cfg_file).unwrap();
        assert_eq!(on_disk.ipad.fps, 45);
        assert_eq!(on_disk.max_web_viewers, 3);

        // P2-C5: Make config path unwritable (directory) -> persist_config_patch must NOT advance persisted_baseline!
        std::fs::remove_file(&cfg_file).unwrap();
        std::fs::create_dir_all(&cfg_file).unwrap();
        let prev_base_input = reg_mig.export_persisted_config().allow_input;
        reg_mig.set_input_allowed(!prev_base_input);
        assert_eq!(
            reg_mig.export_persisted_config().allow_input,
            prev_base_input,
            "P2-C5: failed persist_config_patch must NOT advance persisted_baseline ahead of disk"
        );
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn iter4_adversarial_regression_tests() {
        use crate::platform::mock::MockBackend;
        use crate::protocol::keyed_archive::ArchivedValue;
        use crate::protocol::messages::MessagePacket;
        use crate::transport::FrameWriter;
        use anyhow::Result;
        use clap::Parser;
        use std::sync::atomic::{AtomicBool, Ordering};

        struct LiveWriter {
            peer_closed: Arc<AtomicBool>,
        }
        impl FrameWriter for LiveWriter {
            fn send_frame(&self, _payload: &[u8]) -> Result<()> {
                Ok(())
            }
            fn close(&self) {}
            fn is_peer_closed(&self) -> bool {
                self.peer_closed.load(Ordering::Acquire)
            }
        }

        let make_hs = |uid: &str, name: &str, w: i64, h: i64| {
            let mut hs = std::collections::BTreeMap::new();
            hs.insert("uid".into(), ArchivedValue::String(uid.into()));
            hs.insert("name".into(), ArchivedValue::String(name.into()));
            hs.insert("model".into(), ArchivedValue::String("iPad".into()));
            hs.insert("screenWidth".into(), ArchivedValue::Int(w));
            hs.insert("screenHeight".into(), ArchivedValue::Int(h));
            hs.insert("clientDataProtocolVersionKey".into(), ArchivedValue::String("5".into()));
            MessagePacket::new_send("Handshake", ArchivedValue::Dict(hs))
                .encode()
                .unwrap()
        };

        // 1) P1-A1: Pre-auth / lock-rejected handshakes & pre-auth closes must NOT reset idle_duration()
        let mut cfg = AppConfig::try_parse_from(["idis"]).unwrap();
        cfg.config_file = Some("none".into());
        cfg.auto_accept = false;
        cfg.max_web_viewers = 4;
        let mock = Arc::new(MockBackend::new());
        let reg = Arc::new(SessionRegistry::new(cfg, mock.clone()));
        reg.set_lock_action_ipad(LockAction::Disconnect);
        reg.set_lock_delay_secs(0);
        mock.screen_locked.store(true, Ordering::Release);
        reg.refresh_host_lock_state_now(true);
        std::thread::sleep(Duration::from_millis(60));
        let idle_before = reg.idle_duration();
        let tw_rej = Arc::new(LiveWriter {
            peer_closed: Arc::new(AtomicBool::new(false)),
        });
        let sid_rej = reg
            .register_telemetry("10.1.1.1".into(), tw_rej, 5027, false)
            .unwrap();
        reg.handle_telemetry_bytes_for_session("10.1.1.1", Some(sid_rej), &make_hs("u-rej", "Rej", 1024, 768))
            .unwrap();
        let idle_after = reg.idle_duration();
        assert!(
            idle_after >= idle_before,
            "P1-A1: lock-rejected pre-auth handshake must NOT reset idle_duration (before={idle_before:?}, after={idle_after:?})"
        );
        mock.screen_locked.store(false, Ordering::Release);
        reg.refresh_host_lock_state_now(false);

        // 2) P1-A2 + P1-C3: Post-approval lock TOCTOU AND iPad ghost-trust prevention
        let mock_lock_c = mock.clone();
        reg.set_lock_action_ipad(LockAction::Disconnect);
        reg.set_lock_delay_secs(30);
        reg.set_confirm_handler(Arc::new(move |_p| {
            // Simulate host locking mid-approval while admin clicks AllowOnce!
            mock_lock_c.screen_locked.store(true, Ordering::Release);
            ConfirmDecision::AllowOnce
        }));
        let tw_toctou = Arc::new(LiveWriter {
            peer_closed: Arc::new(AtomicBool::new(false)),
        });
        let sid_toctou = reg
            .register_telemetry("10.1.1.2".into(), tw_toctou, 5027, false)
            .unwrap();
        reg.handle_telemetry_bytes_for_session(
            "10.1.1.2",
            Some(sid_toctou),
            &make_hs("u-toctou", "TOCTOU iPad", 1024, 768),
        )
        .unwrap();
        assert!(
            !reg.sessions.lock().unwrap().contains_key("10.1.1.2"),
            "P1-A2: iPad must be rejected if host locked during confirm_handler wait"
        );
        mock.screen_locked.store(false, Ordering::Release);
        reg.refresh_host_lock_state_now(false);

        // P1-C3: iPad disconnects (`peer_closed = true`) before confirm_handler returns AllowAndTrust -> NO ghost trust!
        let peer_gone = Arc::new(AtomicBool::new(false));
        let pg_c = peer_gone.clone();
        reg.set_confirm_handler(Arc::new(move |_p| {
            pg_c.store(true, Ordering::Release);
            ConfirmDecision::AllowAndTrust
        }));
        let tw_ghost = Arc::new(LiveWriter {
            peer_closed: peer_gone,
        });
        let sid_ghost = reg
            .register_telemetry("10.1.1.3".into(), tw_ghost, 5027, false)
            .unwrap();
        reg.handle_telemetry_bytes_for_session(
            "10.1.1.3",
            Some(sid_ghost),
            &make_hs("u-ghost", "Ghost iPad", 1024, 768),
        )
        .unwrap();
        assert!(
            reg.trust_store().list().is_empty(),
            "P1-C3: disconnected iPad must NOT be persisted into trust_store (ghost trust)"
        );

        // 3) P1-A3: FollowIpad + ipad=disconnect + web=pause must NOT spawn standalone capture while locked,
        //    and MUST spawn standalone capture cleanly once unlocked!
        let mut cfg_a3 = AppConfig::try_parse_from(["idis"]).unwrap();
        cfg_a3.config_file = Some("none".into());
        cfg_a3.auto_accept = true;
        cfg_a3.max_web_viewers = 4;
        let mock_a3 = Arc::new(MockBackend::new());
        let reg_a3 = Arc::new(SessionRegistry::new(cfg_a3, mock_a3.clone()));
        reg_a3.set_lock_action_ipad(LockAction::Disconnect);
        reg_a3.set_lock_action_web(LockAction::Pause);
        reg_a3.set_lock_delay_secs(0);
        let tw_a3 = Arc::new(LiveWriter { peer_closed: Arc::new(AtomicBool::new(false)) });
        let dw_a3 = Arc::new(LiveWriter { peer_closed: Arc::new(AtomicBool::new(false)) });
        let sid_a3 = reg_a3.register_telemetry("10.1.2.1".into(), tw_a3, 5027, false).unwrap();
        reg_a3.handle_telemetry_bytes_for_session("10.1.2.1", Some(sid_a3), &make_hs("u-a3", "A3", 1024, 768)).unwrap();
        let _ = reg_a3.attach_data_channel("10.1.2.1", dw_a3).unwrap();
        let _sub_a3 = reg_a3.subscribe_web_stream("127.0.0.1:59100".into(), None).unwrap();
        assert!(reg_a3.standalone_web_capture.lock().unwrap().is_none());
        // Lock host -> iPad disconnects, Web pauses -> standalone capture MUST stay None while locked!
        mock_a3.screen_locked.store(true, Ordering::Release);
        reg_a3.on_host_screen_lock_changed(true);
        reg_a3.resume_standalone_web_capture_if_needed();
        assert!(
            reg_a3.standalone_web_capture.lock().unwrap().is_none(),
            "P1-A3: standalone Web capture must NOT spawn while host is locked & Web paused"
        );
        // Unlock host -> standalone Web capture MUST resume automatically for connected Web viewer!
        mock_a3.screen_locked.store(false, Ordering::Release);
        reg_a3.on_host_screen_lock_changed(false);
        assert!(
            reg_a3.standalone_web_capture.lock().unwrap().is_some(),
            "P1-A3: unlocking host must resume standalone Web capture when iPad was disconnected while locked"
        );
        drop(_sub_a3);
        reg_a3.close_all();

        // 4) P1-B1 + P2-B2: ResolutionChange enlarging 1024x768 -> 2048x1536 updates max_pixel_edge,
        //    AND low_power(true->false) / partial video patch preserves trusted iPad DevicePreferences!
        let mut cfg_b = AppConfig::try_parse_from(["idis"]).unwrap();
        cfg_b.config_file = Some("none".into());
        cfg_b.auto_accept = true;
        let mock_b = Arc::new(MockBackend::new());
        let reg_b = Arc::new(SessionRegistry::new(cfg_b, mock_b.clone()));
        let tw_b = Arc::new(LiveWriter { peer_closed: Arc::new(AtomicBool::new(false)) });
        let dw_b = Arc::new(LiveWriter { peer_closed: Arc::new(AtomicBool::new(false)) });
        let sid_b = reg_b.register_telemetry("10.1.3.1".into(), tw_b, 5027, false).unwrap();
        reg_b.handle_telemetry_bytes_for_session("10.1.3.1", Some(sid_b), &make_hs("u-b1", "B1", 1024, 768)).unwrap();
        let _ = reg_b.attach_data_channel("10.1.3.1", dw_b).unwrap();
        let fp_b = reg_b.sessions.lock().unwrap().get("10.1.3.1").unwrap().fingerprint.clone().unwrap();

        mock_b.recorded_reconfigures.lock().unwrap().clear();
        let gen_before = reg_b.ipad_video_settings_gen.load(Ordering::Acquire);
        let mut rc_dict = std::collections::BTreeMap::new();
        rc_dict.insert("screenWidth".into(), ArchivedValue::Int(2048));
        rc_dict.insert("screenHeight".into(), ArchivedValue::Int(1536));
        let rc_pkt = MessagePacket::new_send("ResolutionChange", ArchivedValue::Dict(rc_dict))
            .encode()
            .unwrap();
        reg_b.handle_telemetry_bytes_for_session("10.1.3.1", Some(sid_b), &rc_pkt).unwrap();
        let recs = mock_b.recorded_reconfigures.lock().unwrap().clone();
        assert_eq!(recs.len(), 1, "P1-B1: ResolutionChange must invoke reconfigure()");
        assert_eq!(recs[0].0, 2048);
        assert_eq!(recs[0].1, 1536);
        assert_eq!(recs[0].5, 2048, "P1-B1: ResolutionChange must update max_pixel_edge to 2048, not stale 1024");
        assert!(
            reg_b.ipad_video_settings_gen.load(Ordering::Acquire) > gen_before,
            "P1-B1: ResolutionChange must bump ipad_video_settings_gen"
        );

        // P2-B2: Trust iPad with DevicePreferences { fps: 60, bitrate_mbps: 24, hidpi: 2 } while global is 30fps/16M/1x
        reg_b.trust_device_and_save(&fp_b, "u-b1", "B1", "iPad").unwrap();
        reg_b
            .trust_store()
            .update_device_prefs(
                &fp_b,
                crate::trust::DevicePreferences {
                    fps: Some(60),
                    bitrate_mbps: Some(24),
                    hidpi: Some(2),
                    ..Default::default()
                },
            )
            .unwrap();
        reg_b.set_low_power(true);
        mock_b.recorded_reconfigures.lock().unwrap().clear();
        reg_b.set_low_power(false);
        let recs_lp = mock_b.recorded_reconfigures.lock().unwrap().clone();
        let expected_hidpi = if mock_b.supports_hidpi() { 2 } else { 1 };
        assert!(
            recs_lp.iter().any(|r| r.2 == 60 && r.3 == 24 && r.4 == expected_hidpi),
            "P2-B2: exiting low_power must hot-reconfigure active trusted iPad with its DevicePreferences (60fps/24M/hidpi={expected_hidpi}); got {recs_lp:?}"
        );
        reg_b.close_all();

        // 5) P1-C1 + P1-C2 + P2-C6 + P2-C7: CFG-3 concurrent writes, CFG-4 low_power reload reversibility,
        //    Independent quota pre-check before disk write, and `--low-power --fps 45` CLI precedence!
        let tmp_dir = std::env::temp_dir().join(format!("idis_iter4_cfg_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let cfg_file = tmp_dir.join("idis.yaml");

        // P1-C2: set_low_power(true) -> reload_user_config_from_disk() -> set_low_power(false) preserves pre-LP settings!
        let mut cfg_c = AppConfig::try_parse_from(["idis"]).unwrap();
        cfg_c.config_file = Some(cfg_file.display().to_string());
        cfg_c.auto_accept = true;
        let reg_c = Arc::new(SessionRegistry::new(cfg_c, Arc::new(MockBackend::new())));
        let _ = reg_c.update_video_settings(VideoSettingsPatch {
            fps: Some(60),
            bitrate_mbps: Some(24),
            hidpi: Some(2),
            ..Default::default()
        });
        reg_c.set_max_web_viewers(4);
        reg_c.set_p2p_relay_enabled(true);
        reg_c.set_low_power(true);
        // Reload from disk while low_power: true!
        let reloaded = reg_c.reload_user_config_from_disk().unwrap();
        assert!(reloaded.low_power);
        assert_eq!(reloaded.ipad.fps, 15, "runtime under low_power must enforce Eco 15fps");
        // Now turn low_power OFF -> MUST restore pre-low-power 60fps / 24Mbps / 2x / 4 viewers!
        reg_c.set_low_power(false);
        assert_eq!(reg_c.video_settings().fps, 60, "P1-C2: turning off low_power after disk reload must restore 60fps");
        assert_eq!(reg_c.video_settings().bitrate_mbps, 24);
        assert_eq!(reg_c.video_settings().hidpi, 2);
        assert_eq!(reg_c.max_web_viewers(), 4);

        // P1-C1: Concurrent persist_config_patch + apply_user_config + trust_device_and_save -> disk == persisted_baseline!
        let reg_t1 = reg_c.clone();
        let reg_t2 = reg_c.clone();
        let t1 = std::thread::spawn(move || {
            for i in 0..8 {
                reg_t1.set_input_allowed(i % 2 == 0);
                let _ = reg_t1.trust_device_and_save(
                    &format!("fp:{:024x}", i + 1),
                    "u",
                    "Dev",
                    "iPad",
                );
            }
        });
        let t2 = std::thread::spawn(move || {
            for i in 0..5 {
                let mut u = reg_t2.export_persisted_config();
                u.lock_delay_secs = 10 + i;
                let _ = reg_t2.apply_user_config(u, true);
            }
        });
        t1.join().unwrap();
        t2.join().unwrap();
        let disk_final = crate::user_config::load_yaml_file(&cfg_file).unwrap();
        let base_final = reg_c.export_persisted_config();
        assert_eq!(
            disk_final.allow_input, base_final.allow_input,
            "P1-C1 (CFG-3): disk allow_input must match persisted_baseline after concurrent writes"
        );
        assert_eq!(
            disk_final.lock_delay_secs, base_final.lock_delay_secs,
            "P1-C1 (CFG-3): disk lock_delay_secs must match persisted_baseline after concurrent writes"
        );
        assert_eq!(
            disk_final.trusted_devices.len(),
            base_final.trusted_devices.len(),
            "P1-C1 (CFG-3): disk trusted_devices must match memory after concurrent writes"
        );

        // P2-C6: apply_user_config with Independent exceeding max_extended_screens=1 must fail BEFORE touching disk!
        reg_c.set_max_extended_screens(1);
        reg_c.set_max_web_viewers(4);
        let tw_q = Arc::new(LiveWriter { peer_closed: Arc::new(AtomicBool::new(false)) });
        let dw_q = Arc::new(LiveWriter { peer_closed: Arc::new(AtomicBool::new(false)) });
        let sid_q = reg_c.register_telemetry("10.1.9.1".into(), tw_q, 5027, false).unwrap();
        reg_c
            .handle_telemetry_bytes_for_session("10.1.9.1", Some(sid_q), &make_hs("u-q", "Q", 1024, 768))
            .unwrap();
        let _ = reg_c.attach_data_channel("10.1.9.1", dw_q).unwrap();
        let _sub_q = reg_c.subscribe_web_stream("127.0.0.1:59199".into(), None).unwrap();
        let mut indep_cfg = reg_c.export_persisted_config();
        indep_cfg.max_extended_screens = 1;
        indep_cfg.max_web_viewers = 4;
        indep_cfg.web_screen_mode = crate::config::WebScreenMode::Independent;
        indep_cfg.web_independent_screen = true;
        assert!(
            reg_c.apply_user_config(indep_cfg, true).is_err(),
            "P2-C6: apply_user_config must reject Independent mode when quota is full"
        );
        let disk_after_rej = crate::user_config::load_yaml_file(&cfg_file).unwrap();
        assert_ne!(
            disk_after_rej.web_screen_mode,
            crate::config::WebScreenMode::Independent,
            "P2-C6: rejected Independent mode must NOT have been written to disk"
        );
        drop(_sub_q);
        reg_c.close_session_if_id("10.1.9.1", sid_q);

        // P2-C7: `--low-power --fps 45` (without `--bitrate-mbps`) applies Eco bitrate (4 Mbps) while honoring `--fps 45`!
        let mut cfg_cli = AppConfig::try_parse_from(["idis", "--low-power", "--fps", "45"]).unwrap();
        cfg_cli.config_file = Some(cfg_file.display().to_string());
        let reg_cli = SessionRegistry::new(cfg_cli, Arc::new(MockBackend::new()));
        assert_eq!(reg_cli.video_settings().fps, 45);
        assert_eq!(
            reg_cli.video_settings().bitrate_mbps,
            4,
            "P2-C7: --low-power --fps 45 must still apply Eco bitrate (4 Mbps) when --bitrate-mbps is omitted"
        );

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn iter5_adversarial_regression_tests() {
        use crate::platform::mock::MockBackend;
        use crate::protocol::keyed_archive::ArchivedValue;
        use crate::protocol::messages::MessagePacket;
        use crate::transport::FrameWriter;
        use anyhow::Result;
        use clap::Parser;
        use std::sync::atomic::Ordering;

        struct OkWriter;
        impl FrameWriter for OkWriter {
            fn send_frame(&self, _payload: &[u8]) -> Result<()> {
                Ok(())
            }
            fn close(&self) {}
        }

        // 1) P2-A3: Unlock -> rapid re-lock with grace delay MUST clear residual `web_lock_disconnecting`
        //    and `host_lock_paused_*` during the grace window!
        let mut cfg = AppConfig::try_parse_from(["idis"]).unwrap();
        cfg.config_file = Some("none".into());
        cfg.auto_accept = true;
        cfg.max_web_viewers = 4;
        let mock = Arc::new(MockBackend::new());
        let reg = Arc::new(SessionRegistry::new(cfg, mock.clone()));
        reg.set_lock_action_ipad(LockAction::Pause);
        reg.set_lock_action_web(LockAction::Disconnect);
        reg.set_lock_delay_secs(0);
        mock.screen_locked.store(true, Ordering::Release);
        reg.on_host_screen_lock_changed(true);
        assert!(reg.is_web_lock_disconnect_blocking());
        assert!(reg.is_host_lock_paused_ipad());

        // Simulate stale unlock + rapid re-lock with delay=30s
        reg.set_lock_delay_secs(30);
        reg.host_screen_locked.store(false, Ordering::SeqCst);
        // Note: residual flags still true before re-lock!
        reg.on_host_screen_lock_changed_with_grace(true, true);
        assert!(
            !reg.is_web_lock_disconnect_blocking(),
            "P2-A3: entering unenforced grace window must clear residual web_lock_disconnecting"
        );
        assert!(
            !reg.is_host_lock_paused_ipad(),
            "P2-A3: entering unenforced grace window must clear residual host_lock_paused_ipad"
        );
        mock.screen_locked.store(false, Ordering::Release);
        reg.on_host_screen_lock_changed(false);

        // 2) P1-A2: ensure_standalone_web_capture refuses while locked with web=disconnect or web=pause
        reg.set_lock_delay_secs(0);
        mock.screen_locked.store(true, Ordering::Release);
        reg.on_host_screen_lock_changed(true);
        assert!(reg.subscribe_web_stream("127.0.0.1:59200".into(), None).is_err());
        reg.ensure_standalone_web_capture().unwrap();
        assert!(
            reg.standalone_web_capture.lock().unwrap().is_none(),
            "P1-A2: standalone capture must never spawn while host is locked"
        );
        mock.screen_locked.store(false, Ordering::Release);
        reg.on_host_screen_lock_changed(false);

        // 3) P2-B1: reset_video_settings() with an ONLINE connected trusted iPad must NOT re-stamp
        //    non-empty DevicePreferences onto that online device!
        let mut hs = std::collections::BTreeMap::new();
        hs.insert("uid".into(), ArchivedValue::String("u-online-reset".into()));
        hs.insert("name".into(), ArchivedValue::String("Online iPad".into()));
        hs.insert("model".into(), ArchivedValue::String("iPad".into()));
        hs.insert("screenWidth".into(), ArchivedValue::Int(1024));
        hs.insert("screenHeight".into(), ArchivedValue::Int(768));
        hs.insert("clientDataProtocolVersionKey".into(), ArchivedValue::String("5".into()));
        let hs_pkt = MessagePacket::new_send("Handshake", ArchivedValue::Dict(hs))
            .encode()
            .unwrap();
        let sid = reg.register_telemetry("10.2.1.1".into(), Arc::new(OkWriter), 5027, false).unwrap();
        reg.handle_telemetry_bytes_for_session("10.2.1.1", Some(sid), &hs_pkt).unwrap();
        let _ = reg.attach_data_channel("10.2.1.1", Arc::new(OkWriter)).unwrap();
        let fp = reg.sessions.lock().unwrap().get("10.2.1.1").unwrap().fingerprint.clone().unwrap();
        reg.trust_device_and_save(&fp, "u-online-reset", "Online iPad", "iPad").unwrap();
        reg.trust_store()
            .update_device_prefs(
                &fp,
                crate::trust::DevicePreferences {
                    fps: Some(60),
                    ..Default::default()
                },
            )
            .unwrap();
        reg.reset_video_settings().unwrap();
        let dev_after = reg.trust_store().get_device(&fp).unwrap();
        assert!(
            dev_after.prefs.is_empty(),
            "P2-B1: reset_video_settings() must NOT re-stamp DevicePreferences onto online trusted iPad; got {:?}",
            dev_after.prefs
        );

        // 4) P1-B1: web_source_epoch bumps on mode switch and tagged FrameSlot preserves epoch tag
        let ep0 = reg.web_source_epoch();
        reg.set_web_screen_mode(crate::config::WebScreenMode::Main).unwrap();
        assert!(reg.web_source_epoch() > ep0, "P1-B1: mode switch must bump web_source_epoch");
        let (tx, rx) = crate::platform::latest_frame_channel();
        tx.send_latest_shared_tagged(
            1,
            42,
            Arc::new(crate::platform::EncodedFrame {
                width: 640,
                height: 480,
                bytes_per_row: 2560,
                annex_b: vec![0, 0, 0, 1, 0x65],
                is_keyframe: true,
            }),
        );
        let (seq, tag, _f, ov) = rx.recv_timeout_shared_tagged(Duration::from_millis(100)).unwrap();
        assert_eq!((seq, tag, ov), (1, 42, 0));
        reg.close_all();
    }

    #[test]
    fn iter6_adversarial_regression_tests() {
        use crate::platform::mock::MockBackend;
        use crate::protocol::keyed_archive::ArchivedValue;
        use crate::protocol::messages::MessagePacket;
        use crate::transport::FrameWriter;
        use anyhow::Result;
        use clap::Parser;
        use std::sync::atomic::Ordering;

        struct OkWriter;
        impl FrameWriter for OkWriter {
            fn send_frame(&self, _payload: &[u8]) -> Result<()> {
                Ok(())
            }
            fn close(&self) {}
        }

        let tmp_dir = std::env::temp_dir().join(format!(
            "idis_iter6_unit_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let cfg_path = tmp_dir.join("idis.yaml");

        // 1) Iter-6 P1-A3: Active iPad + Web viewer joining while host is locked (`on_lock_web=Pause`)
        //    in `Main` mode -> host unlocks -> standalone Web capture MUST resume!
        let mut cfg = AppConfig::try_parse_from(["idis"]).unwrap();
        cfg.config_file = Some(cfg_path.display().to_string());
        cfg.auto_accept = true;
        cfg.max_web_viewers = 4;
        cfg.max_extended_screens = 1;
        let mock = Arc::new(MockBackend::new());
        let reg = Arc::new(SessionRegistry::new(cfg, mock.clone()));
        reg.set_lock_action_ipad(LockAction::Keep);
        reg.set_lock_action_web(LockAction::Pause);
        reg.set_lock_delay_secs(0);
        reg.set_web_screen_mode(crate::config::WebScreenMode::Main).unwrap();

        let mut hs = std::collections::BTreeMap::new();
        hs.insert("uid".into(), ArchivedValue::String("u-iter6-ipad".into()));
        hs.insert("name".into(), ArchivedValue::String("Iter6 iPad".into()));
        hs.insert("model".into(), ArchivedValue::String("iPad".into()));
        hs.insert("screenWidth".into(), ArchivedValue::Int(1024));
        hs.insert("screenHeight".into(), ArchivedValue::Int(768));
        hs.insert("clientDataProtocolVersionKey".into(), ArchivedValue::String("5".into()));
        let hs_pkt = MessagePacket::new_send("Handshake", ArchivedValue::Dict(hs))
            .encode()
            .unwrap();
        let sid = reg.register_telemetry("10.6.1.1".into(), Arc::new(OkWriter), 5027, false).unwrap();
        reg.handle_telemetry_bytes_for_session("10.6.1.1", Some(sid), &hs_pkt).unwrap();
        let _ = reg.attach_data_channel("10.6.1.1", Arc::new(OkWriter)).unwrap();

        // Lock host BEFORE Web viewer joins -> viewer joins while paused -> unlock!
        mock.screen_locked.store(true, Ordering::Release);
        reg.on_host_screen_lock_changed(true);
        let _sub = reg.subscribe_web_stream("127.0.0.1:59601".into(), None).unwrap();
        assert!(reg.standalone_web_capture.lock().unwrap().is_none());
        mock.screen_locked.store(false, Ordering::Release);
        reg.on_host_screen_lock_changed(false);
        assert!(
            reg.standalone_web_capture.lock().unwrap().is_some(),
            "Iter-6 P1-A3: unlocking host in Main mode with active iPad MUST start standalone capture"
        );

        // 2) Iter-6 P2-A4: Switching Main -> Independent fails due to max_extended_screens=1 quota
        //    (1 active iPad) -> rollback MUST restore Main standalone capture so viewer isn't stuck black!
        let sw_res = reg.set_web_screen_mode(crate::config::WebScreenMode::Independent);
        if reg.supports_independent_web_screen() {
            assert!(sw_res.is_err());
            assert_eq!(reg.web_screen_mode(), crate::config::WebScreenMode::Main);
            assert!(
                reg.standalone_web_capture.lock().unwrap().is_some(),
                "Iter-6 P2-A4: failed mode switch rollback must restore prev Main standalone capture"
            );
        }
        drop(_sub);

        // 3) Iter-6 P2-C3: reset_polling_config() while low_power=true must NOT clobber disk baseline
        //    with low-power defaults; turning low_power off must restore standard defaults (250/8/1000/2000)!
        let _ = reg.update_polling_config(crate::session::PollingPatch {
            main_loop_ms: Some(100),
            ..Default::default()
        });
        reg.set_low_power(true);
        let lp_poll = reg.reset_polling_config();
        assert_eq!(lp_poll.main_loop_ms, crate::user_config::PollingConfigSection::low_power_defaults().main_loop_ms);
        let disk_after_poll_reset = crate::user_config::load_yaml_file(&cfg_path).unwrap();
        assert_eq!(
            disk_after_poll_reset.polling.main_loop_ms,
            crate::user_config::PollingConfigSection::default().main_loop_ms,
            "Iter-6 P2-C3: reset_polling_config under low_power must persist standard defaults, not low_power_defaults"
        );
        reg.set_low_power(false);
        assert_eq!(
            reg.polling_config().main_loop_ms,
            crate::user_config::PollingConfigSection::default().main_loop_ms,
            "Iter-6 P2-C3: exiting low_power after reset_polling_config must restore standard defaults"
        );

        // 4) Iter-6 P2-C4: reset_video_settings() under low_power=true preserves Eco runtime caps
        //    while resetting disk baseline + clearing device prefs; and refuses on corrupt YAML!
        let fp = reg.sessions.lock().unwrap().get("10.6.1.1").unwrap().fingerprint.clone().unwrap();
        reg.trust_device_and_save(&fp, "u-iter6-ipad", "Iter6 iPad", "iPad").unwrap();
        reg.trust_store()
            .update_device_prefs(
                &fp,
                crate::trust::DevicePreferences {
                    fps: Some(60),
                    ..Default::default()
                },
            )
            .unwrap();
        reg.set_low_power(true);
        let vs_lp = reg.reset_video_settings().unwrap();
        let (eco_fps, eco_br) = crate::config::QualityPreset::Eco.defaults();
        assert_eq!(vs_lp.fps, eco_fps, "Iter-6 P2-C4: reset_video_settings must keep Eco fps under low_power");
        assert_eq!(vs_lp.bitrate_mbps, eco_br, "Iter-6 P2-C4: reset_video_settings must keep Eco bitrate under low_power");
        assert!(reg.trust_store().get_device(&fp).unwrap().prefs.is_empty());
        let disk_after_vid_reset = crate::user_config::load_yaml_file(&cfg_path).unwrap();
        assert_eq!(disk_after_vid_reset.ipad.fps, 30);
        reg.set_low_power(false);
        assert_eq!(reg.video_settings().fps, 30, "exiting low_power restores reset Balanced 30fps");

        // Corrupt-YAML read-only guard on reset_video_settings
        reg.trust_store()
            .update_device_prefs(
                &fp,
                crate::trust::DevicePreferences {
                    fps: Some(45),
                    ..Default::default()
                },
            )
            .unwrap();
        reg.config_read_only_corrupt.store(true, Ordering::Release);
        assert!(reg.reset_video_settings().is_err());
        assert_eq!(
            reg.trust_store().get_device(&fp).unwrap().prefs.fps,
            Some(45),
            "Iter-6 P2-C4: corrupt YAML must block reset_video_settings without wiping device prefs"
        );
        reg.config_read_only_corrupt.store(false, Ordering::Release);

        // 5) Iter-6 P1-C2: apply_user_config revoking trusted device updates trust_store atomically inside settings_save_lock
        let mut revoke_cfg = reg.export_persisted_config();
        revoke_cfg.trusted_devices.clear();
        reg.apply_user_config(revoke_cfg, true).unwrap();
        reg.set_input_allowed(true);
        let disk_after_revoke = crate::user_config::load_yaml_file(&cfg_path).unwrap();
        assert!(
            disk_after_revoke.trusted_devices.is_empty(),
            "Iter-6 P1-C2: revoked trusted device must stay absent on disk after subsequent persist_config_patch"
        );

        reg.close_all();
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn iter7_adversarial_regression_tests() {
        use crate::platform::mock::MockBackend;
        use clap::Parser;
        use std::sync::atomic::Ordering;

        let tmp_dir = std::env::temp_dir().join(format!(
            "idis_iter7_unit_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let cfg_path = tmp_dir.join("idis.yaml");

        let mut cfg = AppConfig::try_parse_from(["idis"]).unwrap();
        cfg.config_file = Some(cfg_path.display().to_string());
        cfg.auto_accept = true;
        cfg.max_web_viewers = 4;
        let mock = Arc::new(MockBackend::new());
        let reg = Arc::new(SessionRegistry::new(cfg, mock.clone()));

        // 1) Iter-7 P2-A3: Actually exercise `set_web_screen_mode_inner` rollback & restore AFTER
        //    `prev_cap` teardown by injecting a one-shot `start_capture` failure!
        reg.set_web_screen_mode(crate::config::WebScreenMode::Main).unwrap();
        let _sub = reg.subscribe_web_stream("127.0.0.1:59701".into(), None).unwrap();
        let cap_id_before = reg
            .standalone_web_capture
            .lock()
            .unwrap()
            .as_ref()
            .expect("Main standalone capture must be running")
            .id;
        mock.fail_next_start_capture.store(true, Ordering::Release);
        let sw_err = reg.set_web_screen_mode(crate::config::WebScreenMode::FollowIpad);
        assert!(sw_err.is_err(), "injected start_capture failure must fail mode switch");
        assert_eq!(reg.web_screen_mode(), crate::config::WebScreenMode::Main);
        let cap_id_after = reg
            .standalone_web_capture
            .lock()
            .unwrap()
            .as_ref()
            .expect("Iter-7 P2-A3: rollback must restart previous Main standalone capture")
            .id;
        assert_ne!(
            cap_id_before, cap_id_after,
            "Iter-7 P2-A3: prev_cap must have been torn down and cleanly restarted on rollback"
        );

        // 2) Iter-7 P1-B1: `cached_web_idr_frame()` MUST reject a cached frame whose recorded
        //    `source_epoch` differs from `web_source_epoch()` (blocks dead-iPad & lock write-back races)!
        let stale_ep = reg.web_source_epoch();
        let fake_idr = Arc::new(crate::platform::EncodedFrame {
            width: 1280,
            height: 720,
            bytes_per_row: 1280 * 4,
            annex_b: crate::platform::mock::SYNTHETIC_H264_ANNEX_B.to_vec(),
            is_keyframe: true,
        });
        *reg.last_standalone_web_frame.lock().unwrap() = Some((stale_ep, fake_idr.clone()));
        assert!(reg.cached_web_idr_frame().is_some());
        reg.bump_web_source_epoch();
        assert!(
            reg.cached_web_idr_frame().is_none(),
            "Iter-7 P1-B1: cached_web_idr_frame() MUST reject frame from previous web_source_epoch"
        );
        drop(_sub);

        // 3) Iter-7 P2-C1: `reset_video_settings()` clears `active_preset` both in memory and on disk!
        reg.apply_preset("高清副屏").unwrap();
        assert_eq!(reg.list_presets().0.as_deref(), Some("高清副屏"));
        reg.reset_video_settings().unwrap();
        assert_eq!(
            reg.list_presets().0, None,
            "Iter-7 P2-C1: reset_video_settings() must clear active_preset in memory"
        );
        let disk_after_reset = crate::user_config::load_yaml_file(&cfg_path).unwrap();
        assert_eq!(
            disk_after_reset.active_preset, None,
            "Iter-7 P2-C1: reset_video_settings() must clear active_preset on disk"
        );

        // 4) Iter-7 P2-C2: Under `low_power == true`, `update_video_settings`, `update_polling_config`,
        //    `set_max_web_viewers(0)`, and `set_p2p_relay_enabled(true)` keep runtime Eco/low-power
        //    caps enforced while updating persisted_baseline + low_power_snapshot so exiting low_power
        //    applies user edits cleanly without CFG-4 divergence!
        reg.set_max_web_viewers(4);
        reg.set_low_power(true);
        let (eco_fps, eco_br) = crate::config::QualityPreset::Eco.defaults();
        let vs_during_lp = reg
            .update_video_settings(VideoSettingsPatch {
                fps: Some(60),
                bitrate_mbps: Some(24),
                hidpi: Some(2),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(vs_during_lp.fps, eco_fps, "Iter-7 P2-C2: Eco fps cap must hold during low_power");
        assert_eq!(vs_during_lp.bitrate_mbps, eco_br, "Iter-7 P2-C2: Eco bitrate cap must hold during low_power");
        assert_eq!(vs_during_lp.hidpi, 1, "Iter-7 P2-C2: Eco 1x HiDPI cap must hold during low_power");
        let pol_during_lp = reg.update_polling_config(PollingPatch {
            main_loop_ms: Some(150),
            ..Default::default()
        });
        assert_eq!(
            pol_during_lp.main_loop_ms,
            crate::user_config::PollingConfigSection::low_power_defaults().main_loop_ms,
            "Iter-7 P2-C2: low-power polling cap must hold during low_power"
        );
        reg.set_max_web_viewers(0);
        reg.set_p2p_relay_enabled(true);
        reg.set_low_power(false);
        let vs_after_lp = reg.video_settings();
        assert_eq!(vs_after_lp.fps, 60, "Iter-7 P2-C2: exiting low_power must apply edited 60fps");
        assert_eq!(vs_after_lp.bitrate_mbps, 24, "Iter-7 P2-C2: exiting low_power must apply edited 24Mbps");
        assert_eq!(vs_after_lp.hidpi, 2, "Iter-7 P2-C2: exiting low_power must apply edited 2x HiDPI");
        assert_eq!(reg.polling_config().main_loop_ms, 150, "Iter-7 P2-C2: exiting low_power must apply edited polling");
        assert_eq!(reg.max_web_viewers(), 0, "Iter-7 P2-C2: exiting low_power must NOT resurrect max_web_viewers=4 after reset to 0");
        assert!(reg.is_p2p_relay_enabled(), "Iter-7 P2-C2: exiting low_power must apply p2p_relay_enabled=true");

        reg.close_all();
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn iter8_adversarial_regression_tests() {
        use crate::platform::mock::{MockBackend, SYNTHETIC_H264_ANNEX_B};
        use crate::platform::EncodedFrame;
        use crate::protocol::keyed_archive::ArchivedValue;
        use crate::protocol::messages::MessagePacket;
        use crate::transport::FrameWriter;
        use anyhow::Result;
        use clap::Parser;
        use std::sync::atomic::Ordering;

        struct OkWriter;
        impl FrameWriter for OkWriter {
            fn send_frame(&self, _payload: &[u8]) -> Result<()> {
                Ok(())
            }
            fn close(&self) {}
        }

        let tmp_dir = std::env::temp_dir().join(format!(
            "idis_iter8_unit_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let cfg_path = tmp_dir.join("idis.yaml");

        let mut cfg = AppConfig::try_parse_from(["idis"]).unwrap();
        cfg.config_file = Some(cfg_path.display().to_string());
        cfg.auto_accept = true;
        cfg.max_web_viewers = 4;
        cfg.max_extended_screens = 4;
        let mock = Arc::new(MockBackend::new());
        mock.manual_frame_mode.store(true, Ordering::Release);
        let reg = Arc::new(SessionRegistry::new(cfg, mock.clone()));

        let make_hs = |uid: &str, name: &str| {
            let mut hs = std::collections::BTreeMap::new();
            hs.insert("uid".into(), ArchivedValue::String(uid.into()));
            hs.insert("name".into(), ArchivedValue::String(name.into()));
            hs.insert("model".into(), ArchivedValue::String("iPad".into()));
            hs.insert("screenWidth".into(), ArchivedValue::Int(1024));
            hs.insert("screenHeight".into(), ArchivedValue::Int(768));
            hs.insert("clientDataProtocolVersionKey".into(), ArchivedValue::String("5".into()));
            MessagePacket::new_send("Handshake", ArchivedValue::Dict(hs))
                .encode()
                .unwrap()
        };
        let make_idr = |w: u32, h: u32| EncodedFrame {
            width: w,
            height: h,
            bytes_per_row: w * 4,
            annex_b: SYNTHETIC_H264_ANNEX_B.to_vec(),
            is_keyframe: true,
        };

        // 1) Iter-8 P1-B1: `on_lock_web=disconnect` + `on_lock_ipad=keep` with active FollowIpad iPad
        //    pushing IDRs while locked -> after unlock, `cached_web_idr_frame()` MUST be None!
        reg.set_lock_action_ipad(LockAction::Keep);
        reg.set_lock_action_web(LockAction::Disconnect);
        reg.set_lock_delay_secs(0);
        let sid1 = reg.register_telemetry("10.8.1.1".into(), Arc::new(OkWriter), 5027, false).unwrap();
        reg.handle_telemetry_bytes_for_session("10.8.1.1", Some(sid1), &make_hs("u-i8-1", "iPad1")).unwrap();
        let _ = reg.attach_data_channel("10.8.1.1", Arc::new(OkWriter)).unwrap();
        let ipad1_idx = mock.frame_senders.lock().unwrap().len() - 1;
        mock.push_frame_to(ipad1_idx, make_idr(1024, 768));
        std::thread::sleep(Duration::from_millis(40));
        assert!(reg.cached_web_idr_frame().is_some());

        mock.screen_locked.store(true, Ordering::Release);
        reg.on_host_screen_lock_changed(true);
        // Push IDRs while host is STILL locked (iPad stays running under LockAction::Keep!)
        for _ in 0..3 {
            mock.push_frame_to(ipad1_idx, make_idr(1024, 768));
            std::thread::sleep(Duration::from_millis(20));
        }
        mock.screen_locked.store(false, Ordering::Release);
        reg.on_host_screen_lock_changed(false);
        assert!(
            reg.cached_web_idr_frame().is_none(),
            "Iter-8 P1-B1: IDR emitted while host was locked under web=disconnect MUST NOT be cached after unlock"
        );

        // 2) Iter-8 P2-C2: `set_max_in_flight(0)` on an active session -> BOTH `reset_video_settings()`
        //    and `apply_preset("日常均衡")` MUST restore `sess.flow.max_in_flight()` from 0 to 2!
        reg.set_max_in_flight(0);
        assert_eq!(
            reg.sessions.lock().unwrap().get("10.8.1.1").unwrap().flow.max_in_flight(),
            0
        );
        reg.reset_video_settings().unwrap();
        assert_eq!(
            reg.sessions.lock().unwrap().get("10.8.1.1").unwrap().flow.max_in_flight(),
            2,
            "Iter-8 P2-C2: reset_video_settings() must restore live session flow window from 0 to 2"
        );
        reg.set_max_in_flight(12);
        assert_eq!(
            reg.sessions.lock().unwrap().get("10.8.1.1").unwrap().flow.max_in_flight(),
            12
        );
        reg.apply_preset("日常均衡").unwrap();
        assert_eq!(
            reg.sessions.lock().unwrap().get("10.8.1.1").unwrap().flow.max_in_flight(),
            2,
            "Iter-8 P2-C2: apply_preset with auto_max_in_flight=true must restore live session flow window from 12 to 2"
        );

        // 3) Iter-8 P1-B2: Multi-iPad FollowIpad teardown while disconnecting iPad #1 pushes IDRs ->
        //    `web_follow_ipad_session_id` MUST NOT stay stuck on dead iPad #1 and `cached_web_idr_frame()`
        //    MUST NOT serve dead iPad #1's IDR!
        let sid2 = reg.register_telemetry("10.8.1.2".into(), Arc::new(OkWriter), 5027, false).unwrap();
        reg.handle_telemetry_bytes_for_session("10.8.1.2", Some(sid2), &make_hs("u-i8-2", "iPad2")).unwrap();
        let _ = reg.attach_data_channel("10.8.1.2", Arc::new(OkWriter)).unwrap();
        mock.push_frame_to(ipad1_idx, make_idr(1024, 768));
        std::thread::sleep(Duration::from_millis(30));
        let mock_push = mock.clone();
        let stop_push = Arc::new(AtomicBool::new(false));
        let sp_c = stop_push.clone();
        let pusher = std::thread::spawn(move || {
            while !sp_c.load(Ordering::Acquire) {
                mock_push.push_frame_to(ipad1_idx, make_idr(1024, 768));
                std::thread::sleep(Duration::from_millis(2));
            }
        });
        reg.close_session("10.8.1.1");
        stop_push.store(true, Ordering::Release);
        let _ = pusher.join();
        assert_ne!(
            reg.web_follow_ipad_session_id.load(Ordering::Acquire),
            sid1,
            "Iter-8 P1-B2: web_follow_ipad_session_id must never stay stuck on torn-down iPad #1"
        );
        assert!(
            reg.cached_web_idr_frame().is_none(),
            "Iter-8 P1-B2: dead iPad #1 IDR must not survive teardown in cached_web_idr_frame()"
        );

        reg.close_all();
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn iter9_adversarial_regression_tests() {
        use crate::platform::mock::{MockBackend, SYNTHETIC_H264_ANNEX_B};
        use crate::platform::EncodedFrame;
        use crate::protocol::keyed_archive::ArchivedValue;
        use crate::protocol::messages::MessagePacket;
        use crate::transport::FrameWriter;
        use anyhow::Result;
        use clap::Parser;
        use std::sync::atomic::Ordering;

        struct OkWriter;
        impl FrameWriter for OkWriter {
            fn send_frame(&self, _payload: &[u8]) -> Result<()> {
                Ok(())
            }
            fn close(&self) {}
        }

        let tmp_dir = std::env::temp_dir().join(format!(
            "idis_iter9_unit_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let cfg_path = tmp_dir.join("idis.yaml");

        let mut cfg = AppConfig::try_parse_from(["idis"]).unwrap();
        cfg.config_file = Some(cfg_path.display().to_string());
        cfg.auto_accept = true;
        cfg.max_web_viewers = 4;
        cfg.max_extended_screens = 4;
        let mock = Arc::new(MockBackend::new());
        mock.manual_frame_mode.store(true, Ordering::Release);
        let reg = Arc::new(SessionRegistry::new(cfg, mock.clone()));

        let make_hs = |uid: &str, name: &str| {
            let mut hs = std::collections::BTreeMap::new();
            hs.insert("uid".into(), ArchivedValue::String(uid.into()));
            hs.insert("name".into(), ArchivedValue::String(name.into()));
            hs.insert("model".into(), ArchivedValue::String("iPad".into()));
            hs.insert("screenWidth".into(), ArchivedValue::Int(1024));
            hs.insert("screenHeight".into(), ArchivedValue::Int(768));
            hs.insert("clientDataProtocolVersionKey".into(), ArchivedValue::String("5".into()));
            MessagePacket::new_send("Handshake", ArchivedValue::Dict(hs))
                .encode()
                .unwrap()
        };
        let make_idr = |w: u32, h: u32| EncodedFrame {
            width: w,
            height: h,
            bytes_per_row: w * 4,
            annex_b: SYNTHETIC_H264_ANNEX_B.to_vec(),
            is_keyframe: true,
        };

        // 1) Iter-9 P1-B1: Visible Web viewer subscribed in FollowIpad with 2 iPads; when iPad #1's
        //    capture is removed mid-teardown BEFORE teardown's owner CAS runs and `sync_capture_pause_states()`
        //    elects iPad #2, `web_source_epoch` MUST bump and `cached_web_idr_frame()` MUST be None!
        let sid1 = reg.register_telemetry("10.9.1.1".into(), Arc::new(OkWriter), 5027, false).unwrap();
        reg.handle_telemetry_bytes_for_session("10.9.1.1", Some(sid1), &make_hs("u-i9-1", "iPad1")).unwrap();
        let _ = reg.attach_data_channel("10.9.1.1", Arc::new(OkWriter)).unwrap();
        let ipad1_idx = mock.frame_senders.lock().unwrap().len() - 1;

        let sid2 = reg.register_telemetry("usb:9".into(), Arc::new(OkWriter), 5027, true).unwrap();
        reg.handle_telemetry_bytes_for_session("usb:9", Some(sid2), &make_hs("u-i9-2", "iPad2USB")).unwrap();
        let _ = reg.attach_data_channel("usb:9", Arc::new(OkWriter)).unwrap();

        let _sub = reg.subscribe_web_stream("127.0.0.1:59901".into(), None).unwrap();
        mock.push_frame_to(ipad1_idx, make_idr(1024, 768));
        std::thread::sleep(Duration::from_millis(40));
        assert_eq!(reg.web_follow_ipad_session_id.load(Ordering::Acquire), sid1);
        assert!(reg.cached_web_idr_frame().is_some());
        let ep_before = reg.web_source_epoch();

        // Simulate mid-teardown: remove sid1 from `sessions` while `web_follow_ipad_session_id` is still `sid1`
        let removed_s1 = reg.sessions.lock().unwrap().remove("10.9.1.1");
        reg.sync_capture_pause_states();
        assert_eq!(
            reg.web_follow_ipad_session_id.load(Ordering::Acquire),
            sid2,
            "sync_capture_pause_states must elect sid2"
        );
        assert!(
            reg.web_source_epoch() > ep_before,
            "Iter-9 P1-B1: sync_capture_pause_states owner handover must bump web_source_epoch"
        );
        assert!(
            reg.cached_web_idr_frame().is_none(),
            "Iter-9 P1-B1: sync_capture_pause_states owner handover must clear dead iPad #1 cached IDR"
        );
        if let Some(mut s) = removed_s1 {
            if let Some(mut cap) = s.capture.take() {
                cap.shutdown();
            }
        }
        drop(_sub);

        // 2) Iter-9 P2-C1: USB session (`is_usb = true`) with manual `max_in_flight = 4` -> returning
        //    to `auto_max_in_flight = true` via `set_auto_max_in_flight`, `reset_video_settings`, or
        //    `apply_preset` MUST clamp USB flow window back to 2 (USB_MAX_WINDOW)!
        reg.set_max_in_flight(4);
        assert_eq!(reg.sessions.lock().unwrap().get("usb:9").unwrap().flow.max_in_flight(), 4);
        reg.set_auto_max_in_flight(true);
        assert_eq!(
            reg.sessions.lock().unwrap().get("usb:9").unwrap().flow.max_in_flight(),
            2,
            "Iter-9 P2-C1: USB session must reset from manual 4 to USB auto cap 2"
        );
        reg.set_max_in_flight(3);
        reg.reset_video_settings().unwrap();
        assert_eq!(reg.sessions.lock().unwrap().get("usb:9").unwrap().flow.max_in_flight(), 2);
        reg.set_max_in_flight(4);
        reg.apply_preset("日常均衡").unwrap();
        assert_eq!(reg.sessions.lock().unwrap().get("usb:9").unwrap().flow.max_in_flight(), 2);

        reg.close_all();
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn standalone_virtual_displays_and_notion_floating_window_routing() {
        use crate::platform::mock::MockBackend;
        use crate::platform::{DesktopWindowInfo, WindowMoveLayout};
        use crate::user_config::{load_yaml_file, WindowRouteTarget, WindowRule};
        use clap::Parser;

        let tmp_dir = std::env::temp_dir().join(format!(
            "idis-win-routing-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let cfg_file = tmp_dir.join("idis.yaml");

        let mut cfg = AppConfig::try_parse_from(["idis"]).unwrap();
        cfg.config_file = Some(cfg_file.display().to_string());
        let mock = Arc::new(MockBackend::new());
        *mock.mock_windows.lock().unwrap() = vec![
            DesktopWindowInfo {
                window_id: 10,
                pid: 4201,
                app_name: "Notion".into(),
                bundle_id: "notion.id".into(),
                title: "Q4 Notes".into(),
                x: 100,
                y: 80,
                width: 1100,
                height: 760,
                layer: 0,
                is_floating: false,
                display_id: 1,
            },
            DesktopWindowInfo {
                window_id: 11,
                pid: 4201,
                app_name: "Notion".into(),
                bundle_id: "notion.id".into(),
                title: "".into(),
                x: 1120,
                y: 60,
                width: 240,
                height: 54,
                layer: 3,
                is_floating: true,
                display_id: 1,
            },
        ];

        let reg = SessionRegistry::new(cfg, mock.clone());
        assert!(!reg.has_any_sessions_or_viewers());
        assert!(reg.idle_duration().is_some());

        // Invalid rule with empty matchers must fail validation.
        let bad_rule = WindowRule {
            id: "".into(),
            enabled: true,
            app_name: "".into(),
            bundle_id: "".into(),
            title_contains: "".into(),
            floating_only: true,
            target: WindowRouteTarget::AnyVirtual,
            layout: WindowMoveLayout::KeepSize,
        };
        assert!(reg.upsert_window_rule(bad_rule).is_err());

        // Persist rule targeting ONLY Notion floating widgets -> AnyVirtual.
        let saved = reg
            .upsert_window_rule(WindowRule {
                id: "notion-rec".into(),
                enabled: true,
                app_name: "Notion".into(),
                bundle_id: "notion.id".into(),
                title_contains: "".into(),
                floating_only: true,
                target: WindowRouteTarget::AnyVirtual,
                layout: WindowMoveLayout::KeepSize,
            })
            .unwrap();
        assert_eq!(saved.id, "notion-rec");
        let on_disk = load_yaml_file(&cfg_file).unwrap();
        assert_eq!(on_disk.window_rules.len(), 1);
        assert!(on_disk.window_rules[0].floating_only);

        // No virtual display yet -> floating widget stays on main display.
        assert_eq!(mock.recorded_window_moves.lock().unwrap().len(), 0);

        // Create ephemeral standalone virtual display -> floating widget auto-moves, main Notion window stays put!
        let vd = reg
            .create_standalone_virtual_display("隐藏屏", 1024, 768)
            .unwrap();
        assert_eq!(vd.name, "隐藏屏");
        assert!(reg.has_any_sessions_or_viewers());
        assert!(reg.idle_duration().is_none());

        let wins = mock.mock_windows.lock().unwrap().clone();
        assert_eq!(wins[0].window_id, 10);
        assert_eq!(wins[0].display_id, 1, "Notion main editor window must remain on main screen");
        assert_eq!(wins[1].window_id, 11);
        assert_eq!(
            wins[1].display_id, vd.display_id,
            "Notion floating recording widget must auto-move to ephemeral virtual display"
        );

        // Anti-fighting: if user drags floating widget #11 back to main screen, periodic tick must NOT yank it back.
        mock.mock_windows.lock().unwrap()[1].display_id = 1;
        let rep_skip = reg.tick_window_rules().unwrap();
        assert_eq!(rep_skip.moved, 0);
        assert_eq!(mock.mock_windows.lock().unwrap()[1].display_id, 1);

        // New floating recording widget #12 appearing later MUST auto-move immediately on tick!
        mock.mock_windows.lock().unwrap().push(DesktopWindowInfo {
            window_id: 12,
            pid: 4201,
            app_name: "Notion".into(),
            bundle_id: "notion.id".into(),
            title: "Recording".into(),
            x: 900,
            y: 50,
            width: 240,
            height: 54,
            layer: 3,
            is_floating: true,
            display_id: 1,
        });
        let rep_new = reg.tick_window_rules().unwrap();
        assert_eq!(rep_new.moved, 1);
        assert_eq!(mock.mock_windows.lock().unwrap()[2].display_id, vd.display_id);

        // Explicit apply_window_rules_now() re-moves even previously dragged #11.
        let rep_force = reg.apply_window_rules_now().unwrap();
        assert_eq!(rep_force.moved, 1);
        assert_eq!(mock.mock_windows.lock().unwrap()[1].display_id, vd.display_id);

        // Enforce max 4 ephemeral virtual displays.
        let vd2 = reg.create_standalone_virtual_display("V2", 1280, 720).unwrap();
        let vd3 = reg.create_standalone_virtual_display("V3", 1280, 720).unwrap();
        let vd4 = reg.create_standalone_virtual_display("V4", 1280, 720).unwrap();
        assert!(reg.create_standalone_virtual_display("V5", 1280, 720).is_err());

        // Ephemeral virtual displays are NEVER persisted to YAML, and close_all() destroys all of them.
        assert!(reg.remove_standalone_virtual_display(vd2.id));
        assert!(!reg.remove_standalone_virtual_display(vd2.id));
        let _ = (vd3, vd4);
        reg.close_all();
        assert!(!reg.has_standalone_virtual_displays());
        assert!(!reg.has_any_sessions_or_viewers());
        assert!(reg.delete_window_rule("notion-rec"));
        assert_eq!(load_yaml_file(&cfg_file).unwrap().window_rules.len(), 0);

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
