//! Tier 0 TLA+ Shadow-Model Stateful Action-Sequence Fuzzer & Multi-Thread Lock-Order Chaos:
//! Bridges the refinement gap between `docs/tla/{SessionLockAndIdle,VideoDpbAndPause,ConfigAndPresets}.tla`
//! and the live Rust `SessionRegistry` + `MockBackend` + temp YAML persistence.
//!
//! Features automatic 3-phase `ddmin` sequence shrinking on any invariant violation.

mod common {
    pub mod fuzz;
}

use clap::Parser;
use common::fuzz::{fuzz_seeds, fuzz_steps, shrink_sequence, FuzzRng};
use idis::config::{AppConfig, LockAction, WebScreenMode};
use idis::platform::mock::MockBackend;
use idis::session::SessionRegistry;
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
enum StateAction {
    HostLock,
    HostUnlock,
    SetLockPolicyIpad(LockAction),
    SetLockPolicyWeb(LockAction),
    SetLockDelay(u64),
    TickLockPolicy,
    RefreshLockImmediate,
    SwitchWebMode(WebScreenMode),
    ToggleLowPower(bool),
    ToggleAllowInput(bool),
    ToggleP2pRelay(bool),
    ApplyBuiltinPreset(&'static str),
    SaveCustomPreset(u8),
    ResetVideoSettings,
    CreateStandaloneVd(u8),
    RemoveStandaloneVd,
    TickWindowRules(bool),
    InjectCorruptDiskYaml,
    RepairDiskYaml,
}

fn gen_actions(rng: &mut FuzzRng, len: usize) -> Vec<StateAction> {
    let lock_actions = [LockAction::Pause, LockAction::Disconnect, LockAction::Keep];
    let web_modes = [
        WebScreenMode::FollowIpad,
        WebScreenMode::Main,
        WebScreenMode::Independent,
    ];
    let presets = ["eco", "balanced", "max"];
    (0..len)
        .map(|_| match rng.next_usize(19) {
            0 => StateAction::HostLock,
            1 => StateAction::HostUnlock,
            2 => StateAction::SetLockPolicyIpad(*rng.pick(&lock_actions)),
            3 => StateAction::SetLockPolicyWeb(*rng.pick(&lock_actions)),
            4 => StateAction::SetLockDelay(*rng.pick(&[0u64, 5, 10])),
            5 => StateAction::TickLockPolicy,
            6 => StateAction::RefreshLockImmediate,
            7 => StateAction::SwitchWebMode(*rng.pick(&web_modes)),
            8 => StateAction::ToggleLowPower(rng.next_bool()),
            9 => StateAction::ToggleAllowInput(rng.next_bool()),
            10 => StateAction::ToggleP2pRelay(rng.next_bool()),
            11 => StateAction::ApplyBuiltinPreset(rng.pick(&presets)),
            12 => StateAction::SaveCustomPreset(rng.range_u64(1, 3) as u8),
            13 => StateAction::ResetVideoSettings,
            14 => StateAction::CreateStandaloneVd(rng.range_u64(1, 4) as u8),
            15 => StateAction::RemoveStandaloneVd,
            16 => StateAction::TickWindowRules(rng.next_bool()),
            17 => StateAction::InjectCorruptDiskYaml,
            _ => StateAction::RepairDiskYaml,
        })
        .collect()
}

fn make_temp_yaml_path(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "idis_state_fuzz_{}_{}_{}.yaml",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

fn run_trace(actions: &[StateAction], tag: &str) -> Option<String> {
    let yaml_path = make_temp_yaml_path(tag);
    let mut cfg = AppConfig::parse_from(["idis"]);
    cfg.mock = true;
    cfg.no_bonjour = true;
    cfg.no_usb = true;
    cfg.wifi = false;
    cfg.auto_accept = true;
    cfg.config_file = Some(yaml_path.to_string_lossy().to_string());
    cfg.trusted_devices_file = Some("none".to_string());
    cfg.max_web_viewers = 2;

    let backend = Arc::new(MockBackend::new());
    backend.manual_frame_mode.store(true, Ordering::Release);
    let reg = Arc::new(SessionRegistry::new(cfg, backend.clone()));

    let mut last_lock_epoch = reg.lock_state_epoch();
    let mut corrupt_disk_bytes: Option<Vec<u8>> = None;

    let mut check = |corrupt_disk_bytes: Option<&[u8]>| -> Option<String> {
        // INV-LOCK-3: monotonic lock_state_epoch
        let ep = reg.lock_state_epoch();
        if ep < last_lock_epoch {
            return Some(format!("INV-LOCK-3: lock_state_epoch regressed {ep} < {last_lock_epoch}"));
        }
        last_lock_epoch = ep;

        // INV-CFG-LOWPOWER: while low_power is true, runtime caps must hold
        if reg.is_low_power() {
            let vs = reg.video_settings();
            if vs.fps > 15 || reg.max_web_viewers() != 0 || reg.is_p2p_relay_enabled() {
                return Some(format!(
                    "INV-CFG-LOWPOWER: violated while low_power=true (fps={}, max_web={}, p2p={})",
                    vs.fps,
                    reg.max_web_viewers(),
                    reg.is_p2p_relay_enabled()
                ));
            }
        }

        // INV-CFG-CORRUPT: corrupt YAML on disk must NEVER be auto-overwritten
        if let Some(orig_bytes) = corrupt_disk_bytes {
            if reg.is_config_corrupt() {
                let on_disk = fs::read(&yaml_path).unwrap_or_default();
                if on_disk.as_slice() != orig_bytes {
                    return Some("INV-CFG-CORRUPT: corrupt disk YAML was overwritten while in read-only corrupt guard".to_string());
                }
            }
        }

        // INV-RES-GHOST: live virtual displays in MockBackend MUST exactly equal standalone virtual displays
        // (since no iPad or Web viewer capture is running in this trace)
        let expected_vds: BTreeSet<u32> = reg
            .list_standalone_virtual_displays()
            .into_iter()
            .map(|v| v.display_id)
            .collect();
        let live_vds = backend.live_virtual_display_ids();
        if live_vds != expected_vds {
            return Some(format!(
                "INV-RES-GHOST: live_vds={live_vds:?} != expected_vds={expected_vds:?}"
            ));
        }

        // INV-WIN-IDEMPOTENT: second tick_window_rules without changes moves 0 windows
        if let Ok(r2) = reg.tick_window_rules() {
            if r2.moved > 0 {
                return Some(format!("INV-WIN-IDEMPOTENT: second tick moved {} windows", r2.moved));
            }
        }

        None
    };

    let mut failure = None;
    for action in actions {
        match action {
            StateAction::HostLock => {
                backend.screen_locked.store(true, Ordering::Release);
            }
            StateAction::HostUnlock => {
                backend.screen_locked.store(false, Ordering::Release);
            }
            StateAction::SetLockPolicyIpad(a) => {
                reg.set_lock_action_ipad(*a);
            }
            StateAction::SetLockPolicyWeb(a) => {
                reg.set_lock_action_web(*a);
            }
            StateAction::SetLockDelay(s) => {
                reg.set_lock_delay_secs(*s);
            }
            StateAction::TickLockPolicy => {
                reg.tick_host_lock_policy();
            }
            StateAction::RefreshLockImmediate => {
                reg.refresh_host_lock_state_now(true);
            }
            StateAction::SwitchWebMode(m) => {
                let _ = reg.set_web_screen_mode(*m);
            }
            StateAction::ToggleLowPower(en) => {
                reg.set_low_power(*en);
            }
            StateAction::ToggleAllowInput(en) => {
                reg.set_input_allowed(*en);
            }
            StateAction::ToggleP2pRelay(en) => {
                reg.set_p2p_relay_enabled(*en);
            }
            StateAction::ApplyBuiltinPreset(name) => {
                let _ = reg.apply_preset(name);
            }
            StateAction::SaveCustomPreset(i) => {
                let _ = reg.save_current_as_preset(&format!("fuzz-preset-{i}"));
            }
            StateAction::ResetVideoSettings => {
                let _ = reg.reset_video_settings();
            }
            StateAction::CreateStandaloneVd(i) => {
                let _ = reg.create_standalone_virtual_display(&format!("VD-{i}"), 1280, 720);
            }
            StateAction::RemoveStandaloneVd => {
                if let Some(first) = reg.list_standalone_virtual_displays().first() {
                    reg.remove_standalone_virtual_display(first.id);
                }
            }
            StateAction::TickWindowRules(force) => {
                let _ = if *force {
                    reg.apply_window_rules_now()
                } else {
                    reg.tick_window_rules()
                };
            }
            StateAction::InjectCorruptDiskYaml => {
                let corrupt = b"ipad: [\nunclosed-corrupt-yaml".to_vec();
                let _ = fs::write(&yaml_path, &corrupt);
                let _ = reg.reload_user_config_from_disk();
                if reg.is_config_corrupt() {
                    corrupt_disk_bytes = Some(corrupt);
                }
            }
            StateAction::RepairDiskYaml => {
                if reg.apply_user_config(idis::user_config::UserConfigFile::default(), true).is_ok()
                {
                    corrupt_disk_bytes = None;
                }
            }
        }

        if let Some(err) = check(corrupt_disk_bytes.as_deref()) {
            failure = Some(err);
            break;
        }
    }

    reg.shutdown_all_virtual_displays();
    let _ = fs::remove_file(&yaml_path);
    failure
}

#[test]
fn fuzz_state_machine_tla_refinement_with_ddmin_shrinker() {
    let steps = fuzz_steps(40);
    for seed in fuzz_seeds(0xC301, 12) {
        let mut rng = FuzzRng::new(seed);
        let trace = gen_actions(&mut rng, steps);
        if let Some(err) = run_trace(&trace, &format!("s{seed:x}")) {
            let shrunk = shrink_sequence(&trace, &err, |cand| {
                run_trace(cand, &format!("sh{seed:x}"))
            });
            panic!(
                "Stateful refinement invariant failed: {err}\nShrunk from {} -> {} steps:\n{:#?}\nReproduce: IDIS_FUZZ_SEED=0x{seed:x} cargo test --locked --test fuzz_stateful_chaos fuzz_state_machine_tla_refinement_with_ddmin_shrinker -- --exact --nocapture",
                trace.len(),
                shrunk.len(),
                shrunk
            );
        }
    }
}

#[test]
fn fuzz_multithread_lock_order_chaos_with_deadlock_watchdog() {
    let mut cfg = AppConfig::parse_from(["idis"]);
    cfg.mock = true;
    cfg.no_bonjour = true;
    cfg.no_usb = true;
    cfg.wifi = false;
    cfg.auto_accept = true;
    // Run pure in-memory lock-order chaos so 4 concurrent threads hammer mutex interleavings
    // at maximum speed without stalling on filesystem rename contention.
    cfg.config_file = Some("none".to_string());
    cfg.trusted_devices_file = Some("none".to_string());
    cfg.max_web_viewers = 2;

    let backend = Arc::new(MockBackend::new());
    backend.manual_frame_mode.store(true, Ordering::Release);
    let reg = Arc::new(SessionRegistry::new(cfg, backend.clone()));

    let done = Arc::new(AtomicBool::new(false));
    let done_wd = done.clone();
    let watchdog = thread::spawn(move || {
        let start = Instant::now();
        while !done_wd.load(Ordering::Acquire) {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "CON-1 DEADLOCK DETECTED: multithread chaos exceeded 10s watchdog!"
            );
            thread::sleep(Duration::from_millis(20));
        }
    });

    let mut workers = Vec::new();
    for tid in 0..4u64 {
        let r = reg.clone();
        let b = backend.clone();
        workers.push(thread::spawn(move || {
            let mut rng = FuzzRng::new(0xD400 + tid * 997);
            for _ in 0..40 {
                match rng.next_usize(10) {
                    0 => r.set_low_power(rng.next_bool()),
                    1 => {
                        let _ = r.reset_video_settings();
                    }
                    2 => {
                        let _ = r.apply_preset(rng.pick(&["eco", "balanced", "max"]));
                    }
                    3 => {
                        b.screen_locked.store(rng.next_bool(), Ordering::Release);
                        r.refresh_host_lock_state_now(rng.next_bool());
                    }
                    4 => {
                        let _ = r.set_web_screen_mode(*rng.pick(&[
                            WebScreenMode::FollowIpad,
                            WebScreenMode::Main,
                            WebScreenMode::Independent,
                        ]));
                    }
                    5 => {
                        let _ = r.create_standalone_virtual_display("ChaosVD", 1280, 720);
                    }
                    6 => {
                        if let Some(v) = r.list_standalone_virtual_displays().first() {
                            r.remove_standalone_virtual_display(v.id);
                        }
                    }
                    7 => r.set_lock_action_ipad(*rng.pick(&[
                        LockAction::Pause,
                        LockAction::Disconnect,
                        LockAction::Keep,
                    ])),
                    8 => r.set_lock_action_web(*rng.pick(&[
                        LockAction::Pause,
                        LockAction::Disconnect,
                        LockAction::Keep,
                    ])),
                    _ => {
                        let _ = r.tick_window_rules();
                    }
                }
                thread::yield_now();
            }
        }));
    }

    for w in workers {
        w.join().expect("chaos worker must not panic");
    }
    done.store(true, Ordering::Release);
    watchdog.join().unwrap();

    // Post-chaos consistency check: if low_power ended up true, runtime caps MUST still hold!
    if reg.is_low_power() {
        let vs = reg.video_settings();
        assert!(
            vs.fps <= 15 && reg.max_web_viewers() == 0 && !reg.is_p2p_relay_enabled(),
            "post-chaos low_power invariant violated: fps={}, max_web={}, p2p={}",
            vs.fps,
            reg.max_web_viewers(),
            reg.is_p2p_relay_enabled()
        );
    }

    reg.shutdown_all_virtual_displays();
    assert!(
        backend.live_virtual_display_ids().is_empty(),
        "ghost virtual display leaked after shutdown"
    );
}
