use anyhow::Result;
use clap::Parser;
use idis::config::AppConfig;
use idis::debug_trace::{self, DebugTraceLayer};
use idis::netinfo::{self, HostConnectionInfo};
use idis::platform::{self, default_backend};
use idis::proxy::{self, ResolvedProxy};
use idis::qr::QrCode;
use idis::session::SessionRegistry;
use idis::transport::{usbmux, wifi};
use idis::web::{self, LogBuffer, LogBufferLayer};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

fn init_sentry(config: &AppConfig, resolved_proxy: &ResolvedProxy) -> Option<sentry::ClientInitGuard> {
    let dsn = config
        .sentry_dsn
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())?;

    let mut options = sentry::ClientOptions::default();
    options.release = sentry::release_name!();
    options.environment = Some(config.sentry_env.clone().into());
    options.attach_stacktrace = true;
    options.send_default_pii = false;
    options.http_proxy = resolved_proxy.http_proxy.clone().map(Into::into);
    options.https_proxy = resolved_proxy.https_proxy.clone().map(Into::into);
    options.before_breadcrumb = Some(Arc::new(|mut crumb| {
        if let Some(msg) = crumb.message.take() {
            crumb.message = Some(debug_trace::sanitize_log_message(&msg));
        }
        Some(crumb)
    }));
    options.before_send = Some(Arc::new(|mut event| {
        if let Some(msg) = event.message.take() {
            event.message = Some(debug_trace::sanitize_log_message(&msg));
        }
        Some(event)
    }));
    let guard = sentry::init((dsn, options));

    let (eff_fps, eff_bitrate) = config
        .quality
        .map(|q| q.defaults())
        .unwrap_or((config.fps, config.bitrate_mbps));
    sentry::configure_scope(|scope| {
        scope.set_tag("os", std::env::consts::OS);
        scope.set_tag("arch", std::env::consts::ARCH);
        scope.set_tag("capture_mode", format!("{:?}", config.mode));
        scope.set_tag("fps", eff_fps.to_string());
        scope.set_tag("bitrate_mbps", eff_bitrate.to_string());
        scope.set_tag("client_cursor", config.client_cursor.to_string());
    });

    Some(guard)
}

fn main() -> Result<()> {
    // Fast-path internal helper on macOS: select exact CGDisplayMode from a fresh process before
    // any CoreGraphics/Tokio/logging initialization so CGDisplayCopyAllDisplayModes sees virtual
    // display HiDPI modes reliably.
    #[cfg(target_os = "macos")]
    {
        let mut args = std::env::args().skip(1);
        if args.next().as_deref() == Some("--internal-macos-set-display-mode") {
            let parse_u32 = |a: Option<String>| a.and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
            let display_id = parse_u32(args.next());
            let logical_w = parse_u32(args.next());
            let logical_h = parse_u32(args.next());
            let pixel_w = parse_u32(args.next());
            let pixel_h = parse_u32(args.next());
            let rc = platform::macos::run_set_display_mode_helper(
                display_id,
                logical_w,
                logical_h,
                pixel_w,
                pixel_h,
            );
            std::process::exit(rc);
        }
    }
    platform::init_process_runtime();
    let config = AppConfig::parse();
    // Apply proxy policy AND adopt OS-activated sockets BEFORE initializing Sentry or spawning any
    // threads so `std::env::remove_var` (proxy & systemd LISTEN_* vars) runs strictly single-threaded.
    let resolved_proxy =
        proxy::resolve_and_apply_proxy_policy(config.proxy.as_deref(), config.use_system_proxy);
    let mut activated =
        idis::transport::socket_activation::take_activated_sockets(config.web, config.wifi);
    let enable_web = config.web || activated.web.is_some();
    let enable_wifi = config.wifi || activated.has_wifi();
    let _sentry_guard = init_sentry(&config, &resolved_proxy);

    let debug_recorder = if let Some(raw_path) = config
        .debug_log
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(debug_trace::init_global(PathBuf::from(raw_path))?)
    } else {
        None
    };
    if config.debug {
        debug_trace::set_debug_logging(true);
    }

    let log_buffer = LogBuffer::new();
    // When `--debug` is set (or toggled live via `POST /api/admin/debug`), switch both terminal
    // (when `RUST_LOG` is unset) and Web console log levels to DEBUG dynamically via `reload::Layer`.
    let has_rust_log_env = std::env::var_os("RUST_LOG").is_some();
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        if config.debug {
            EnvFilter::new("idis=debug,info")
        } else {
            EnvFilter::new("warn")
        }
    });
    let web_log_filter = if config.debug {
        EnvFilter::new("idis=debug,info")
    } else {
        EnvFilter::new("info")
    };
    let (fmt_filter_layer, fmt_reload) = tracing_subscriber::reload::Layer::new(env_filter);
    let (web_filter_layer, web_reload) = tracing_subscriber::reload::Layer::new(web_log_filter);
    debug_trace::register_log_level_toggler(Arc::new(move |enabled: bool| {
        if !has_rust_log_env {
            let next_fmt = if enabled {
                EnvFilter::new("idis=debug,info")
            } else {
                EnvFilter::new("warn")
            };
            let _ = fmt_reload.reload(next_fmt);
        }
        let next_web = if enabled {
            EnvFilter::new("idis=debug,info")
        } else {
            EnvFilter::new("info")
        };
        let _ = web_reload.reload(next_web);
    }));
    let debug_layer = debug_recorder
        .as_ref()
        .map(|r| DebugTraceLayer::new(r.clone()).with_filter(EnvFilter::new("idis=debug,info")));
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_filter(fmt_filter_layer))
        .with(LogBufferLayer::new(log_buffer.clone()).with_filter(web_filter_layer))
        .with(debug_layer)
        .with(sentry::integrations::tracing::layer())
        .init();

    if config.debug || debug_recorder.is_some() {
        idis::platform::enable_platform_diagnostics();
    }
    if let Some(ref rec) = debug_recorder {
        println!("Debug log : {}", rec.path().display());
        info!(
            "Debug trace file enabled => {}",
            rec.path().display()
        );
    } else if config.debug {
        info!("DEBUG log level enabled in terminal and Web console");
    }

    if _sentry_guard.is_some() {
        info!("Sentry reporting enabled (env={})", config.sentry_env);
    }

    let backend = default_backend(config.mock);
    let registry = Arc::new(SessionRegistry::new(config.clone(), backend.clone()));

    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop_sig = stop.clone();
        let reg_sig = registry.clone();
        let ctrlc_hits = std::sync::atomic::AtomicUsize::new(0);
        ctrlc::set_handler(move || {
            let n = ctrlc_hits.fetch_add(1, Ordering::SeqCst) + 1;
            if n >= 2 {
                std::process::exit(130);
            }
            stop_sig.store(true, Ordering::SeqCst);
            reg_sig.notify_lifecycle_wakeup();
            eprintln!("\nShutting down... (press Ctrl-C again to force quit)");
            info!("Received Ctrl-C, shutting down... (press Ctrl-C again to force quit)");
        })?;
    }
    {
        let stop_term = stop.clone();
        let reg_term = registry.clone();
        idis::transport::install_sigterm_handler(Arc::new(move || {
            info!("Received SIGTERM (service manager stop), shutting down gracefully...");
            stop_term.store(true, Ordering::SeqCst);
            reg_term.notify_lifecycle_wakeup();
        }));
    }

    if let Some(src) = activated.source {
        info!(
            "OS socket activation active via {src} (web={}, wifi_telemetry={}, wifi_data={})",
            activated.web
                .as_ref()
                .and_then(|l| l.local_addr().ok())
                .map(|a| a.to_string())
                .unwrap_or_else(|| "none".to_string()),
            activated.wifi_telemetry
                .as_ref()
                .and_then(|l| l.local_addr().ok())
                .map(|a| a.to_string())
                .unwrap_or_else(|| "none".to_string()),
            activated.wifi_data
                .as_ref()
                .and_then(|l| l.local_addr().ok())
                .map(|a| a.to_string())
                .unwrap_or_else(|| "none".to_string()),
        );
    }

    if !enable_wifi && config.no_usb && !enable_web {
        anyhow::bail!(
            "No transport enabled: Wi-Fi and Web are disabled by default and --no-usb was passed. Pass --wifi, --web, or omit --no-usb for USB."
        );
    }

    let mut web_handle = if enable_web {
        match web::start_web_server_with_listener(
            &config.web_bind,
            config.web_admin_token.clone(),
            config.web_view_token.clone(),
            registry.clone(),
            log_buffer.clone(),
            stop.clone(),
            activated.web.take(),
        ) {
            Ok(h) => {
                let local_host = if h.addr.is_ipv6() { "[::1]" } else { "127.0.0.1" };
                if h.addr.ip().is_unspecified() {
                    info!(
                        "Web Admin Console listening on http://{}/ (Local: http://{}:{}/)",
                        h.addr, local_host, h.addr.port()
                    );
                } else {
                    info!("Web Admin Console listening on http://{}/", h.addr);
                }
                if let Some(vaddr) = h.viewer_addr() {
                    info!(
                        "Web Extended-Screen Viewer listening on http://{vaddr}/view (0.0.0.0 random port)"
                    );
                } else {
                    info!("Web Extended-Screen Viewer port is closed (opens automatically on 0.0.0.0:<random> when Web viewing is enabled)");
                }
                match (&h.admin_token, h.admin_token_generated) {
                    (Some(tok), true) => {
                        // Print one-time generated token directly to stdout, bypassing tracing/LogBuffer/Sentry.
                        println!(
                            "Generated random Web Admin token for LAN/remote access (one-time display): {tok}"
                        );
                        info!(
                            "Generated random Web Admin token for LAN/remote access (local http://{}:{}/ is passwordless by default; pass --web-admin-token to require login everywhere)",
                            local_host, h.addr.port()
                        );
                    }
                    (Some(_), false) => {
                        if h.addr.ip().is_loopback() {
                            info!("Web Admin token configured via --web-admin-token / IDIS_WEB_ADMIN_TOKEN");
                        } else {
                            info!(
                                "Web Admin token configured via --web-admin-token / IDIS_WEB_ADMIN_TOKEN for LAN/remote access (local http://{}:{}/ is passwordless)",
                                local_host, h.addr.port()
                            );
                        }
                    }
                    (None, _) => {
                        info!(
                            "Web Admin password is empty by default on loopback bind ({}); pass --web-admin-token to require login",
                            h.addr
                        );
                    }
                }
                if config
                    .web_view_token
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .is_some()
                {
                    info!("Web extended-screen viewer enabled via --web-view-token");
                } else {
                    info!("Web extended-screen viewer passcode is disabled by default (set via --web-view-token or in Web Admin Console)");
                }
                Some(h)
            }
            Err(e) => {
                error!("Failed to start Web control server: {e:#}");
                sentry::integrations::anyhow::capture_anyhow(&e);
                return Err(e.context("explicitly requested --web listener failed to bind"));
            }
        }
    } else {
        None
    };

    let wifi_ctrl = if let Some(wh) = web_handle.as_ref() {
        wh.wifi_controller()
    } else {
        Arc::new(wifi::WifiServerController::new(
            config.clone(),
            backend.clone(),
            registry.clone(),
            stop.clone(),
        ))
    };

    if enable_wifi {
        if let Err(e) = wifi_ctrl.start_with_prebound(
            activated.wifi_telemetry.take(),
            activated.wifi_data.take(),
        ) {
            error!("Failed to start Wi-Fi server: {e:#}");
            sentry::integrations::anyhow::capture_anyhow(&e);
            if let Some(mut wh) = web_handle.take() {
                wh.stop();
            }
            return Err(e.context("explicitly requested --wifi listener failed to bind"));
        }
    } else {
        info!("Wi-Fi listener disabled by default (USB-only mode; pass --wifi or toggle in Web Admin to enable LAN Wi-Fi)");
    }

    if web_handle.is_none() && !wifi_ctrl.is_running() && config.no_usb {
        anyhow::bail!("All requested transports failed to start; exiting.");
    }

    let lan_ips = netinfo::detect_lan_ipv4s();
    let wifi_addrs_now = wifi_ctrl.addrs();
    let conn_info = HostConnectionInfo::build_with_viewer(
        lan_ips,
        wifi_addrs_now.map(|(tel, _)| tel.ip()),
        wifi_addrs_now.map(|(tel, data)| (tel.port(), data.port())),
        web_handle.as_ref().map(|h| h.addr),
        web_handle.as_ref().and_then(|h| h.viewer_addr()),
    );
    let eff_video = registry.video_settings();
    let eff_allow_input = registry.is_input_allowed();
    let eff_low_power = registry.is_low_power();
    let eff_lock_ipad = registry.lock_action_ipad();
    let eff_lock_web = registry.lock_action_web();
    debug_trace::record(
        "lifecycle",
        "startup",
        serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "mode": format!("{:?}", config.mode),
            "quality": format!("{:?}", eff_video.quality),
            "width": eff_video.width,
            "height": eff_video.height,
            "hidpi": eff_video.hidpi,
            "integer_scale": eff_video.integer_scale,
            "max_pixel_edge": eff_video.max_pixel_edge,
            "fps": eff_video.fps,
            "bitrate_mbps": eff_video.bitrate_mbps,
            "wifi": enable_wifi,
            "usb": !config.no_usb,
            "web": enable_web,
            "web_bind": config.web_bind,
            "web_independent_screen": registry.is_web_independent_screen(),
            "web_screen_mode": registry.web_screen_mode(),
            "web_require_approval": registry.is_web_require_approval(),
            "allow_input": eff_allow_input,
            "low_power": eff_low_power,
            "lock_action_ipad": eff_lock_ipad,
            "lock_action_web": eff_lock_web,
            "lock_delay_secs": registry.lock_delay_secs(),
            "config_path": registry.config_path().map(|p| p.display().to_string()),
            "client_cursor": registry.is_client_cursor(),
            "half_fps_when_unfocused": eff_video.half_fps_when_unfocused,
            "max_extended_screens": registry.max_extended_screens(),
            "max_web_viewers": registry.max_web_viewers(),
            "auto_max_in_flight": registry.is_auto_max_in_flight(),
            "max_in_flight": registry.max_in_flight(),
            "ping_timeout_secs": config.ping_timeout_secs,
            "idle_exit_secs": config.idle_exit_secs,
            "proxy": resolved_proxy.summary(),
            "connection": conn_info,
        }),
    );
    print_connection_guide(
        &conn_info,
        &config,
        &registry,
        web_handle.as_ref().map(|h| h.addr),
        config.web_view_token.as_deref(),
        config.qr,
    );

    let mut usb_handle = if !config.no_usb {
        Some(usbmux::start_usbmux_watcher(
            config.usbmuxd_addr.clone(),
            registry.clone(),
            stop.clone(),
        ))
    } else {
        None
    };

    info!(
        "idis running on {} (mode={:?}, wifi={}, usb={}, web={}, web_independent_screen={}, input={}, fps={}, bitrate={}Mbps, hidpi={}x, integer_scale={}, cursor={}, proxy={}, max_extended_screens={}, max_web_viewers={}, idle_exit_secs={}, trusted_store={}). Press Ctrl-C to quit.",
        std::env::consts::OS,
        config.mode,
        enable_wifi,
        !config.no_usb,
        enable_web,
        registry.is_web_independent_screen(),
        if eff_allow_input { "enabled" } else { "view-only" },
        eff_video.fps,
        eff_video.bitrate_mbps,
        eff_video.hidpi,
        eff_video.integer_scale,
        if registry.is_client_cursor() { "client-telemetry" } else { "composited" },
        resolved_proxy.summary(),
        if registry.max_extended_screens() == 0 {
            "unlimited".to_string()
        } else {
            registry.max_extended_screens().to_string()
        },
        registry.max_web_viewers(),
        if config.idle_exit_secs == 0 {
            "disabled".to_string()
        } else {
            format!("{}s", config.idle_exit_secs)
        },
        registry
            .config_path()
            .map(|p| p.display().to_string())
            .or_else(|| {
                registry
                    .trust_store()
                    .path()
                    .map(|p| p.display().to_string())
            })
            .unwrap_or_else(|| "<memory-only>".to_string())
    );
    let caps = backend.capabilities();
    if eff_allow_input && caps.accessibility_permission_required && !caps.accessibility_granted {
        tracing::warn!(
            "Remote input is enabled (CLI or ~/.config/idis.yaml), but OS Accessibility permission is NOT granted — iPad touch/keyboard input will be ignored until granted in System Settings -> Privacy & Security -> Accessibility (add your Terminal app / idis)."
        );
    }

    let mut last_reap = std::time::Instant::now();
    let mut last_lock_check = std::time::Instant::now();
    let mut last_window_rule_tick = std::time::Instant::now();
    let mut last_tick_mono = std::time::Instant::now();
    let mut last_tick_wall = std::time::SystemTime::now();
    if platform::is_host_screen_locked() {
        registry.on_host_screen_lock_changed_with_grace(true, false);
    }
    let mut was_idle = true;
    while !stop.load(Ordering::SeqCst) {
        if !registry.has_any_sessions_or_viewers() {
            was_idle = true;
            // Zero-wakeup idle standby: skip WindowServer lock-screen IPC and session reaping
            // while 0 iPads and 0 Web viewers are connected so the CPU/OS can enter full deep sleep.
            // In CLI-only mode (without --web watchdog), enforce iPad Wi-Fi port idle auto-close here too.
            let wifi_port_wait = if web_handle.is_none() {
                let port_limit = registry.port_idle_close_secs();
                if port_limit > 0 {
                    wifi_ctrl.tick_idle_close(port_limit);
                    wifi_ctrl.remaining_idle_close(port_limit)
                } else {
                    None
                }
            } else {
                None
            };
            let max_wait = match (
                if config.idle_exit_secs > 0 {
                    let limit = Duration::from_secs(config.idle_exit_secs);
                    if let Some(idle) = registry.idle_duration() {
                        if idle >= limit {
                            info!(
                                "No screen connection or web access for {}s (limit={}s) — auto-exiting.",
                                idle.as_secs(),
                                config.idle_exit_secs
                            );
                            stop.store(true, Ordering::SeqCst);
                            break;
                        }
                        Some(limit.saturating_sub(idle))
                    } else {
                        Some(Duration::from_secs(1))
                    }
                } else {
                    None
                },
                wifi_port_wait,
            ) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            };
            let pre_mono = std::time::Instant::now();
            let pre_wall = std::time::SystemTime::now();
            registry.wait_idle(&stop, max_wait);
            let idle_mono_dt = pre_mono.elapsed();
            let idle_wall_dt = std::time::SystemTime::now()
                .duration_since(pre_wall)
                .unwrap_or_default();
            if idle_wall_dt >= idle_mono_dt.saturating_add(Duration::from_secs(5)) {
                info!(
                    "System sleep/wake detected during idle standby (wall_dt={}s, mono_dt={}s) — refreshing idle window",
                    idle_wall_dt.as_secs(),
                    idle_mono_dt.as_secs()
                );
                registry.on_system_wake();
            }
            last_tick_mono = std::time::Instant::now();
            last_tick_wall = std::time::SystemTime::now();
            continue;
        }

        if was_idle {
            was_idle = false;
            platform::pump_main_runloop();
            // Synchronize host screen-lock state immediately when transitioning out of idle standby.
            // If the host is already locked while waking from idle, enforce immediately (no grace window).
            let cur_locked = platform::is_host_screen_locked();
            if cur_locked != registry.is_host_screen_locked() {
                registry.on_host_screen_lock_changed_with_grace(cur_locked, false);
            } else if cur_locked {
                registry.refresh_host_lock_state_now(true);
            }
            last_lock_check = std::time::Instant::now();
            last_reap = std::time::Instant::now();
            last_tick_mono = std::time::Instant::now();
            last_tick_wall = std::time::SystemTime::now();
        }

        platform::pump_main_runloop();
        let loop_sleep = Duration::from_millis(registry.polling_config().main_loop_ms);
        registry.wait_active_tick(&stop, loop_sleep);
        platform::pump_main_runloop();
        registry.tick_pending_standalone_web_resume();
        // Detect host sleep/wake via monotonic jump (Windows/Dark Wake) or wall-vs-monotonic jump
        // (macOS/Linux deep sleep) and grant a clean post-wake grace period before reaping/idle-exit.
        let mono_dt = last_tick_mono.elapsed();
        let now_wall = std::time::SystemTime::now();
        let wall_dt = now_wall
            .duration_since(last_tick_wall)
            .unwrap_or_default();
        if mono_dt >= Duration::from_secs(5)
            || wall_dt >= mono_dt.saturating_add(Duration::from_secs(5))
        {
            info!(
                "System sleep/wake transition detected (wall_dt={}s, mono_dt={}s) — refreshing session grace window",
                wall_dt.as_secs(),
                mono_dt.as_secs()
            );
            registry.on_system_wake();
            last_reap = std::time::Instant::now();
        }
        last_tick_mono = std::time::Instant::now();
        last_tick_wall = now_wall;

        // Poll host screen lock/unlock transitions once per second (avoids unnecessary WindowServer IPC).
        // Compare directly against `registry.is_host_screen_locked()` so external unlock resets (e.g.
        // fresh handshake) never desynchronize a stale local bool.
        if last_lock_check.elapsed() >= Duration::from_secs(1) {
            last_lock_check = std::time::Instant::now();
            let cur_locked = platform::is_host_screen_locked();
            if cur_locked != registry.is_host_screen_locked() {
                registry.on_host_screen_lock_changed(cur_locked);
            } else if cur_locked {
                registry.tick_host_lock_policy();
            }
        }

        if last_window_rule_tick.elapsed() >= Duration::from_millis(1500) {
            last_window_rule_tick = std::time::Instant::now();
            if registry.has_active_window_routing_work() {
                let _ = registry.tick_window_rules();
            }
        }

        if last_reap.elapsed() >= Duration::from_secs(2) {
            registry.reap_timed_out_sessions();
            if web_handle.is_none() {
                let port_limit = registry.port_idle_close_secs();
                if port_limit > 0 {
                    wifi_ctrl.tick_idle_close(port_limit);
                }
            }
            // Also enforce `--idle-exit-secs` here so an idle pre-handshake USB iPad (which
            // keeps `has_any_sessions_or_viewers() == true` while `idle_duration()` still ticks)
            // cannot perpetually defeat idle auto-exit.
            if config.idle_exit_secs > 0 {
                if let Some(idle) = registry.idle_duration() {
                    if idle >= Duration::from_secs(config.idle_exit_secs) {
                        info!(
                            "No screen connection or web access for {}s (limit={}s) — auto-exiting.",
                            idle.as_secs(),
                            config.idle_exit_secs
                        );
                        stop.store(true, Ordering::SeqCst);
                        break;
                    }
                }
            }
            last_reap = std::time::Instant::now();
        }
    }

    // Stop all listeners/acceptors FIRST so no new connections, sessions, virtual displays,
    // or config writes can be initiated while `registry.close_all()` tears down active state.
    if let Some(mut h) = web_handle.take() {
        h.stop();
    }
    wifi_ctrl.stop();
    if let Some(mut h) = usb_handle.take() {
        h.stop();
    }
    registry.close_all();
    debug_trace::record("lifecycle", "shutdown", serde_json::json!({}));
    if let Some(ref rec) = debug_recorder {
        info!("Debug trace saved to: {}", rec.path().display());
    }
    info!("Shutdown complete.");
    debug_trace::flush_global();
    Ok(())
}

fn print_connection_guide(
    conn: &HostConnectionInfo,
    config: &AppConfig,
    registry: &SessionRegistry,
    web_addr: Option<std::net::SocketAddr>,
    view_token: Option<&str>,
    show_qr: bool,
) {
    let lock_ipad = registry.lock_action_ipad();
    let lock_web = registry.lock_action_web();
    let lock_desc = if lock_ipad == lock_web {
        format!("{lock_ipad:?}")
    } else {
        format!("iPad={lock_ipad:?}/Web={lock_web:?}")
    };
    println!(
        "idis v{} running (USB: {}, Wi-Fi: {}, Web: {}, mode: {:?}, on-lock: {}{}{})",
        env!("CARGO_PKG_VERSION"),
        if !config.no_usb { "ON" } else { "OFF" },
        if conn.wifi_enabled { "ON" } else { "OFF" },
        if web_addr.is_some() { "ON" } else { "OFF" },
        config.mode,
        lock_desc,
        if registry.is_input_allowed() { ", input: ON" } else { "" },
        if registry.is_low_power() { ", low-power: ON" } else { "" },
    );

    if !conn.lan_ips.is_empty() {
        info!("Detected host LAN IP(s): {}", conn.lan_ips.join(", "));
    } else {
        info!("No non-loopback LAN IPv4 detected (localhost/USB only).");
    }

    if conn.wifi_enabled {
        let data_port = conn.wifi_data_port.unwrap_or(0);
        println!(
            "Wi-Fi iPad : {} (data port={data_port})",
            conn.wifi_endpoints.join(" | ")
        );
        info!(
            "Wi-Fi iPad manual IP:port => {} (data port={data_port}, auto-sent after Handshake)",
            conn.wifi_endpoints.join(" | ")
        );
    }

    if !conn.web_admin_urls.is_empty() {
        if let Some(addr) = web_addr {
            if addr.ip().is_unspecified() {
                let local_host = if addr.is_ipv6() { "[::1]" } else { "127.0.0.1" };
                println!(
                    "Web Admin  : http://{}:{}/ (免密本机) | LAN: {}",
                    local_host,
                    addr.port(),
                    conn.web_admin_urls.join(" | ")
                );
            } else {
                println!("Web Admin  : {}", conn.web_admin_urls.join(" | "));
            }
        } else {
            println!("Web Admin  : {}", conn.web_admin_urls.join(" | "));
        }
        if conn.web_viewer_listening && !conn.web_viewer_urls.is_empty() {
            let viewer_display: Vec<String> = match view_token.map(str::trim).filter(|s| !s.is_empty()) {
                Some(tok) => {
                    let enc = web::percent_encode_query_val(tok);
                    conn.web_viewer_urls
                        .iter()
                        .map(|u| format!("{u}?token={enc}"))
                        .collect()
                }
                None => conn.web_viewer_urls.clone(),
            };
            let vport = conn.web_viewer_port.unwrap_or(0);
            println!(
                "Web Viewer : {} (独立随机端口 0.0.0.0:{vport})",
                viewer_display.join(" | ")
            );
            info!(
                "Web Extended-Screen Viewer URL => {} (bind=0.0.0.0:{vport})",
                conn.web_viewer_urls.join(" | ")
            );
        } else {
            println!("Web Viewer : 已关闭（在管理后台开启网页扩展屏并设置口令后，自动监听 0.0.0.0 随机端口）");
            info!("Web Extended-Screen Viewer port is closed until Web viewing is enabled");
        }
        info!("Web Admin Console URL => {}", conn.web_admin_urls.join(" | "));
    }

    if config.debug {
        println!("(DEBUG 日志级别已开启；按 Ctrl-C 退出)");
    } else if web_addr.is_some() {
        println!("(终端仅输出 WARN/ERROR，完整 INFO 日志见 Web 后台或设置 RUST_LOG=info；按 Ctrl-C 退出)");
    } else {
        println!("(终端仅输出 WARN/ERROR，完整日志请加 --debug 或设置 RUST_LOG=info；按 Ctrl-C 退出)");
    }

    if !show_qr {
        return;
    }

    let mut printed_any = false;
    if let Some(viewer_url) = conn.primary_web_viewer_url() {
        let qr_url = match view_token.map(str::trim).filter(|s| !s.is_empty()) {
            Some(tok) => format!("{viewer_url}?token={}", web::percent_encode_query_val(tok)),
            None => viewer_url.to_string(),
        };
        if let Ok(qr) = QrCode::encode(&qr_url) {
            println!("\n=== 网页扩展屏观看二维码 (Web Viewer) ===");
            println!("URL: {qr_url}");
            print!("{}", qr.to_terminal_string());
            printed_any = true;
        }
    }

    if let Some(wifi_ep) = conn.primary_wifi_endpoint() {
        if let Ok(qr) = QrCode::encode(wifi_ep) {
            println!("\n=== iPad Wi-Fi 连接地址二维码 (Telemetry IP:Port) ===");
            println!("IP:Port: {wifi_ep}");
            print!("{}", qr.to_terminal_string());
            printed_any = true;
        }
    }

    if !printed_any {
        println!("\n[QR] 当前为纯 USB 模式，未启用 --wifi 或 --web，无需 IP 连接二维码。");
    }
}
