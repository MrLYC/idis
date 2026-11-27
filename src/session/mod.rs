mod config_store;
mod data_channel;
mod flow_control;
mod handshake;
mod lock_policy;
mod web_screen;
mod window_routing;
#[cfg(test)]
mod tests;

pub use flow_control::{FlowControl, WebStreamSubscription};
pub use window_routing::{
    ApplyRulesReport, ScreenTargetInfo, StandaloneVirtualDisplayInfo,
    MAX_STANDALONE_VIRTUAL_DISPLAYS,
};

use crate::abr::AbrStatusSnapshot;
use crate::config::{AbrSensitivity, AppConfig, LockAction, MaxInFlight, QualityPreset, WebScreenMode};
use crate::platform::{
    DisplayBackend, EncodedFrame, HostSystemInfo, PlatformCapabilities, WEB_MAX_PIXEL_EDGE,
};
use crate::protocol::messages::ClientHandshake;
use crate::transport::SharedFrameWriter;
use crate::trust::{default_trusted_devices_path, TrustStore};
use crate::user_config::{
    default_config_path, load_yaml_file, ConfigPreset, PollingConfigSection, UserConfigFile,
    WindowRule,
};
use config_store::{has_cli_flag, load_persisted_settings, PersistedSettings};
use flow_control::{ActiveCapture, LowPowerSnapshot, WebAbrAccum, WebSubscriberEntry};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use window_routing::StandaloneVirtualDisplayEntry;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Instant;
use tracing::{info, warn};


/// Live diagnostic counters for incoming remote touch/mouse/keyboard events.
#[derive(Debug, Default)]
pub(super) struct InputCounters {
    pub(super) received: AtomicU64,
    pub(super) injected: AtomicU64,
    pub(super) dropped_view_only: AtomicU64,
    pub(super) dropped_locked: AtomicU64,
    pub(super) dropped_no_permission: AtomicU64,
    pub(super) decode_errors: AtomicU64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct InputStatsSnapshot {
    pub received: u64,
    pub injected: u64,
    pub dropped_view_only: u64,
    pub dropped_locked: u64,
    pub dropped_no_permission: u64,
    pub decode_errors: u64,
}

/// Decision returned when prompting the user about an untrusted incoming client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmDecision {
    /// Allow this connection and persist the device's SHA-256 handshake fingerprint to the trusted devices store.
    AllowAndTrust,
    /// Allow this session only without persisting to disk.
    AllowOnce,
    /// Reject the connection (`AccessConfirmed(isAccess=false, reason=4)`).
    Deny,
}

/// Metadata presented to the confirmation prompt/callback for an untrusted client.
#[derive(Debug, Clone)]
pub struct PendingDevice {
    pub session_id: u64,
    pub addr: String,
    pub fingerprint: String,
    pub uid: String,
    pub name: String,
    pub model: String,
    pub is_usb: bool,
    pub is_web: bool,
}

pub type ConfirmHandler = Arc<dyn Fn(&PendingDevice) -> ConfirmDecision + Send + Sync>;
pub type CancelPendingHandler = Arc<dyn Fn(Option<u64>, Option<&str>) + Send + Sync>;
pub type WebViewerLimitHandler = Arc<dyn Fn(usize) + Send + Sync>;

/// Serializable snapshot of an active iDisplay (Wi-Fi or USB) client session.
#[derive(Debug, Clone, Serialize)]
pub struct SessionSnapshot {
    pub id: u64,
    pub key: String,
    pub transport: String,
    pub fingerprint: Option<String>,
    pub uid: Option<String>,
    pub name: Option<String>,
    pub model: Option<String>,
    pub authorized: bool,
    pub awaiting_confirm: bool,
    pub streaming: bool,
    pub width: u32,
    pub height: u32,
    pub native_width: u32,
    pub native_height: u32,
    pub logical_width: u32,
    pub logical_height: u32,
    pub hidpi: u32,
    pub integer_scale: bool,
    pub is_pixel_exact: bool,
    pub connected_secs: u64,
    pub idle_secs: u64,
    pub in_flight: u32,
    pub max_in_flight: u32,
    pub auto_max_in_flight: bool,
    pub dropped_frames: u64,
    pub udp_cursor: bool,
    pub abr: Option<AbrStatusSnapshot>,
}

/// Serializable snapshot of an active browser WebSocket viewer.
#[derive(Debug, Clone, Serialize)]
pub struct WebViewerSnapshot {
    pub id: u64,
    pub peer: String,
    pub fingerprint: Option<String>,
    pub label: Option<String>,
    pub connected_secs: u64,
}

/// Serializable snapshot of the Web extended-screen mode and active stream source.
#[derive(Debug, Clone, Serialize)]
pub struct WebScreenSnapshot {
    pub mode: WebScreenMode,
    pub independent: bool,
    pub supported: bool,
    pub active: bool,
    /// `"main"` (host primary display), `"standalone"` (independent virtual display), `"ipad"` (reusing iPad screen), or `"idle"`.
    pub source: String,
    pub width: u32,
    pub height: u32,
    pub logical_width: u32,
    pub logical_height: u32,
    pub hidpi: u32,
}

struct ClientSession {
    id: u64,
    data_generation: u64,
    is_usb: bool,
    fingerprint: Option<String>,
    data_port: u16,
    telemetry_writer: SharedFrameWriter,
    pending_usb_data_writer: Option<SharedFrameWriter>,
    data_writer: Option<SharedFrameWriter>,
    handshake: Option<ClientHandshake>,
    authorized: bool,
    authorized_at: Option<Instant>,
    data_detached_at: Option<Instant>,
    awaiting_confirm: bool,
    connected_at: Instant,
    last_activity: Instant,
    flow: Arc<FlowControl>,
    udp_cursor_enabled: Arc<AtomicBool>,
    stream_paused: Arc<AtomicBool>,
    /// Tracks an in-progress left mouse drag `(x, y)` so abrupt disconnect / lock / view-only
    /// always synthesizes a safety `MouseUp` and never leaves the host mouse button stuck down.
    mouse_left_down: Option<(f64, f64)>,
    /// Suppresses trailing micro-drags and `MouseUp` after a right-click tap across all OSes.
    suppress_right_click_tail: bool,
    capture: Option<ActiveCapture>,
}

/// Runtime video quality & resolution configuration (hot-updatable via Web Admin Console).
/// iPad and standalone Web extended-screen settings are stored independently so adjusting one
/// never disrupts or flickers the other.
#[derive(Debug, Clone, Serialize)]
pub struct VideoSettings {
    /// Output width override for iPad (`0` = auto: iPad resolution).
    pub width: u32,
    /// Output height override for iPad (`0` = auto: iPad resolution).
    pub height: u32,
    pub fps: u32,
    pub bitrate_mbps: u32,
    pub hidpi: u32,
    /// When enabled, snap logical resolution to an exact integer divisor of physical stream pixels (1:1).
    pub integer_scale: bool,
    /// Maximum H.264 streaming long-edge pixels for iPad (`0` = auto per screen).
    pub max_pixel_edge: u32,
    /// Enable automatic network-adaptive bitrate & FPS scaling (ABR; constant pixel resolution, zero flash).
    pub adaptive_quality: bool,
    /// ABR sensitivity level (`conservative`, `balanced`, or `aggressive`).
    pub abr_sensitivity: AbrSensitivity,
    /// Halve iPad streaming FPS automatically when the host mouse cursor is not on the iPad display.
    pub half_fps_when_unfocused: bool,
    pub quality: QualityPreset,
    /// Dedicated standalone Web extended-screen logical width (default 1280; independent of iPad).
    pub web_width: u32,
    /// Dedicated standalone Web extended-screen logical height (default 720; independent of iPad).
    pub web_height: u32,
    /// Dedicated standalone Web extended-screen target FPS (default 30).
    pub web_fps: u32,
    /// Dedicated standalone Web extended-screen H.264 bitrate in Mbps (default 16).
    pub web_bitrate_mbps: u32,
    /// Dedicated standalone Web extended-screen HiDPI scale (1 or 2; default 1).
    pub web_hidpi: u32,
    /// Dedicated standalone Web extended-screen max streaming long edge (`0` = auto up to 3840).
    pub web_max_pixel_edge: u32,
    pub web_quality: QualityPreset,
}

/// Partial update applied to [`VideoSettings`].
#[derive(Debug, Default, Clone)]
pub struct VideoSettingsPatch {
    pub quality: Option<QualityPreset>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub fps: Option<u32>,
    pub bitrate_mbps: Option<u32>,
    pub hidpi: Option<u32>,
    pub integer_scale: Option<bool>,
    pub max_pixel_edge: Option<u32>,
    pub adaptive_quality: Option<bool>,
    pub abr_sensitivity: Option<AbrSensitivity>,
    pub half_fps_when_unfocused: Option<bool>,
    pub web_quality: Option<QualityPreset>,
    pub web_width: Option<u32>,
    pub web_height: Option<u32>,
    pub web_fps: Option<u32>,
    pub web_bitrate_mbps: Option<u32>,
    pub web_hidpi: Option<u32>,
    pub web_max_pixel_edge: Option<u32>,
}

/// Partial update patch for active-state polling intervals (all in milliseconds).
#[derive(Debug, Default, Clone)]
pub struct PollingPatch {
    pub main_loop_ms: Option<u64>,
    pub cursor_poll_ms: Option<u64>,
    pub usb_retry_ms: Option<u64>,
    pub admin_poll_ms: Option<u64>,
}

fn default_true() -> bool {
    true
}

fn default_max_in_flight() -> u32 {
    2
}

fn default_lock_delay_secs() -> u64 {
    10
}

fn default_max_extended_screens() -> usize {
    2
}

fn default_web_fps() -> u32 {
    30
}

fn default_web_bitrate_mbps() -> u32 {
    16
}

pub(super) fn default_web_hidpi() -> u32 {
    1
}

/// Central session coordinator shared by Wi-Fi, USB, and Web transports.
pub(super) type CachedWebFrameSlot = Arc<Mutex<Option<(u64, Arc<EncodedFrame>)>>>;

pub struct SessionRegistry {
    config: AppConfig,
    backend: Arc<dyn DisplayBackend>,
    trust_store: Arc<TrustStore>,
    config_path: Option<PathBuf>,
    config_read_only_corrupt: AtomicBool,
    config_parse_error: Mutex<Option<String>>,
    persisted_baseline: Mutex<UserConfigFile>,
    config_tx_lock: Mutex<()>,
    settings_save_lock: Mutex<()>,
    confirm_handler: Mutex<Option<ConfirmHandler>>,
    cancel_pending_handler: Mutex<Option<CancelPendingHandler>>,
    web_viewer_limit_handler: Mutex<Option<WebViewerLimitHandler>>,
    allow_input: AtomicBool,
    client_cursor: Arc<AtomicBool>,
    web_require_approval: AtomicBool,
    input_counters: InputCounters,
    low_power: Arc<AtomicBool>,
    low_power_snapshot: Mutex<Option<LowPowerSnapshot>>,
    p2p_relay_enabled: AtomicBool,
    max_extended_screens: AtomicUsize,
    max_web_viewers: AtomicUsize,
    auto_max_in_flight: Arc<AtomicBool>,
    max_in_flight: AtomicU32,
    video: Arc<Mutex<VideoSettings>>,
    polling: Arc<Mutex<PollingConfigSection>>,
    active_preset: Mutex<Option<String>>,
    presets: Mutex<Vec<ConfigPreset>>,
    window_rules: Mutex<Vec<WindowRule>>,
    next_window_rule_id: AtomicU64,
    next_virtual_display_id: AtomicU64,
    virtual_display_shutdown_epoch: AtomicU64,
    standalone_virtual_displays: Mutex<Vec<StandaloneVirtualDisplayEntry>>,
    applied_window_moves: Mutex<HashSet<(u32, String)>>,
    ipad_video_settings_gen: Arc<AtomicU64>,
    web_video_settings_gen: Arc<AtomicU64>,
    next_session_id: AtomicU64,
    next_capture_id: AtomicU64,
    sessions: Arc<Mutex<HashMap<String, ClientSession>>>,
    web_subscribers: Arc<Mutex<Vec<WebSubscriberEntry>>>,
    last_ipad_web_frame: CachedWebFrameSlot,
    last_standalone_web_frame: CachedWebFrameSlot,
    standalone_web_capture: Arc<Mutex<Option<ActiveCapture>>>,
    standalone_web_resume_after: Mutex<Option<Instant>>,
    web_abr_accum: Arc<Mutex<WebAbrAccum>>,
    web_screen_mode: Arc<AtomicU8>,
    /// Session ID of the single primary iPad streaming to `FollowIpad` Web viewers (prevents
    /// multi-iPad IPPP stream interleaving into one SharedWebMuxer).
    web_follow_ipad_session_id: Arc<AtomicU64>,
    /// Monotonic epoch bumped on every Web screen mode change, standalone capture lifecycle change,
    /// FollowIpad owner handover, or Web lock pause so stale in-flight frames are never mislabeled
    /// or muxed onto a different source's H.264 DPB (P1-B1).
    web_source_epoch: Arc<AtomicU64>,
    lock_action_ipad: Mutex<LockAction>,
    lock_action_web: Mutex<LockAction>,
    lock_delay_secs: AtomicU64,
    port_idle_close_secs: AtomicU64,
    host_lock_mutex: Mutex<()>,
    lock_apply_mutex: Mutex<()>,
    lock_state_epoch: AtomicU64,
    host_screen_locked: Arc<AtomicBool>,
    host_locked_since: Mutex<Option<Instant>>,
    host_lock_enforced: AtomicBool,
    host_lock_paused_ipad: Arc<AtomicBool>,
    host_lock_paused_web: Arc<AtomicBool>,
    web_lock_disconnecting: Arc<AtomicBool>,
    web_mode_lock: Mutex<()>,
    last_global_activity: Arc<Mutex<Instant>>,
    last_wifi_activity: Arc<Mutex<Instant>>,
    last_web_activity: Arc<Mutex<Instant>>,
    activity_signal: Arc<(Mutex<u64>, Condvar)>,
    wake_grace_until: Mutex<Option<Instant>>,
    confirm_lock: Mutex<()>,
    tty_prompt_tx: Arc<Mutex<Option<std::sync::mpsc::Sender<String>>>>,
    tty_reader_started: AtomicBool,
}

impl SessionRegistry {
    pub fn new(config: AppConfig, backend: Arc<dyn DisplayBackend>) -> Self {
        let explicit_legacy_trust = config
            .trusted_devices_file
            .as_deref()
            .map(str::trim);
        let legacy_none = explicit_legacy_trust
            .is_some_and(|p| p.is_empty() || p.eq_ignore_ascii_case("none"));
        let config_path = match config.config_file.as_deref().map(str::trim) {
            Some(p) if p.is_empty() || p.eq_ignore_ascii_case("none") => None,
            Some(p) => Some(PathBuf::from(p)),
            None if legacy_none => None,
            None => default_config_path(),
        };

        // Load unified YAML config (`~/.config/idis.yaml`), migrating legacy `trusted_devices.txt`
        // + `settings.json` automatically on first run if the YAML file does not exist yet.
        let (loaded_yaml, migrated_or_new, config_corrupt, config_parse_error) =
            if let Some(ref cp) = config_path {
                crate::user_config::sweep_stale_tmp_files(cp);
                if cp.exists() {
                    let within_cap = std::fs::metadata(cp)
                        .ok()
                        .is_some_and(|m| m.len() <= crate::user_config::MAX_YAML_CONFIG_BYTES as u64);
                    let had_legacy_mac_entries = within_cap
                        && std::fs::read_to_string(cp).ok().is_some_and(|raw| {
                            raw.lines().any(|line| {
                                line.trim_start().starts_with("- mac:")
                                    || line.trim_start().starts_with("mac:")
                            })
                        });
                    match load_yaml_file(cp) {
                        Ok(y) => {
                            info!(
                                "Loaded config from {} ({} trusted device(s))",
                                cp.display(),
                                y.trusted_devices.len()
                            );
                            (Some(y), had_legacy_mac_entries, false, None)
                        }
                        Err(e) => {
                            let err_msg = format!("{e:#}");
                            warn!(
                                "Failed to parse config file {}: {err_msg}; entering read-only fallback mode to protect existing file from being overwritten",
                                cp.display()
                            );
                            (None, false, true, Some(err_msg))
                        }
                    }
                } else {
                let mut migrated = UserConfigFile::default();
                let mut had_legacy = false;
                let legacy_trust_path = explicit_legacy_trust
                    .filter(|p| !p.is_empty() && !p.eq_ignore_ascii_case("none"))
                    .map(PathBuf::from)
                    .or_else(default_trusted_devices_path);
                if let Some(ref ltp) = legacy_trust_path {
                    if ltp.exists() {
                        let legacy_store = TrustStore::load(Some(ltp.clone()));
                        migrated.trusted_devices = legacy_store.list();
                        had_legacy = true;
                    }
                    if let Some(legacy_settings_path) = ltp.parent().map(|d| d.join("settings.json"))
                    {
                        if let Some(s) = load_persisted_settings(&legacy_settings_path) {
                            migrated.ipad.width = s.width;
                            migrated.ipad.height = s.height;
                            migrated.ipad.fps = s.fps;
                            migrated.ipad.bitrate_mbps = s.bitrate_mbps;
                            migrated.ipad.hidpi = s.hidpi;
                            migrated.ipad.integer_scale = s.integer_scale;
                            migrated.ipad.max_pixel_edge = s.max_pixel_edge;
                            migrated.ipad.adaptive_quality = s.adaptive_quality;
                            migrated.web.width = if s.web_width >= 320 { s.web_width } else { 1280 };
                            migrated.web.height = if s.web_height >= 240 { s.web_height } else { 720 };
                            migrated.web.fps = s.web_fps;
                            migrated.web.bitrate_mbps = s.web_bitrate_mbps;
                            migrated.web.hidpi = s.web_hidpi;
                            migrated.web.max_pixel_edge = s.web_max_pixel_edge;
                            migrated.web_independent_screen = s.web_independent_screen;
                            migrated.lock_action_ipad = s.lock_action_ipad;
                            migrated.lock_action_web = s.lock_action_web;
                            migrated.lock_delay_secs = s.lock_delay_secs;
                            migrated.auto_max_in_flight = s.auto_max_in_flight;
                            migrated.max_in_flight = s.max_in_flight;
                            migrated.max_extended_screens = s.max_extended_screens;
                            migrated.max_web_viewers = s.max_web_viewers;
                            migrated.low_power = s.low_power;
                            had_legacy = true;
                        }
                    }
                }
                let _ = migrated.validate_and_normalize();
                if had_legacy {
                    info!(
                        "Migrated legacy settings & {} trusted device(s) into {}",
                        migrated.trusted_devices.len(),
                        cp.display()
                    );
                }
                (Some(migrated), true, false, None)
            }
        } else {
            (None, false, false, None)
        };

        let saved: Option<PersistedSettings> = loaded_yaml.as_ref().map(|y| PersistedSettings {
            width: y.ipad.width,
            height: y.ipad.height,
            web_width: y.web.width,
            web_height: y.web.height,
            web_fps: y.web.fps,
            web_bitrate_mbps: y.web.bitrate_mbps,
            web_hidpi: y.web.hidpi,
            web_max_pixel_edge: y.web.max_pixel_edge,
            fps: y.ipad.fps,
            bitrate_mbps: y.ipad.bitrate_mbps,
            hidpi: y.ipad.hidpi,
            integer_scale: y.ipad.integer_scale,
            max_pixel_edge: y.ipad.max_pixel_edge,
            adaptive_quality: y.ipad.adaptive_quality,
            web_independent_screen: y.web_independent_screen,
            lock_action_ipad: y.lock_action_ipad,
            lock_action_web: y.lock_action_web,
            lock_delay_secs: y.lock_delay_secs,
            auto_max_in_flight: y.auto_max_in_flight,
            max_in_flight: y.max_in_flight,
            max_extended_screens: y.max_extended_screens,
            max_web_viewers: y.max_web_viewers,
            low_power: y.low_power,
        });

        let trust_store = if let Some(ref y) = loaded_yaml {
            Arc::new(TrustStore::from_devices(
                config_path.clone(),
                y.trusted_devices.clone(),
            ))
        } else if let Some(p) = explicit_legacy_trust.filter(|p| !p.is_empty() && !p.eq_ignore_ascii_case("none")) {
            Arc::new(TrustStore::load(Some(PathBuf::from(p))))
        } else {
            Arc::new(TrustStore::from_devices(None, Vec::new()))
        };

        let eff_low_power = if config.no_low_power || has_cli_flag("--no-low-power") {
            false
        } else if has_cli_flag("--low-power") || config.low_power {
            config.low_power
        } else {
            saved.as_ref().map(|s| s.low_power).unwrap_or(false)
        };
        let low_power = Arc::new(AtomicBool::new(eff_low_power));
        let eff_allow_input = if config.no_allow_input || has_cli_flag("--no-allow-input") {
            false
        } else if has_cli_flag("--allow-input") || config.allow_input {
            config.allow_input
        } else {
            loaded_yaml.as_ref().map(|y| y.allow_input).unwrap_or(false)
        };
        let allow_input = AtomicBool::new(eff_allow_input);
        let eff_client_cursor = if config.no_client_cursor || has_cli_flag("--no-client-cursor") {
            false
        } else if has_cli_flag("--client-cursor") || config.client_cursor {
            config.client_cursor
        } else {
            loaded_yaml
                .as_ref()
                .map(|y| y.client_cursor)
                .unwrap_or(false)
        };
        let client_cursor = Arc::new(AtomicBool::new(eff_client_cursor));
        let eff_web_require_approval =
            if config.no_web_require_approval || has_cli_flag("--no-web-require-approval") {
                false
            } else if has_cli_flag("--web-require-approval") || config.web_require_approval {
                config.web_require_approval
            } else {
                loaded_yaml
                    .as_ref()
                    .map(|y| y.web_require_approval)
                    .unwrap_or(false)
            };
        let web_require_approval = AtomicBool::new(eff_web_require_approval);
        let eff_p2p = if eff_low_power {
            false
        } else {
            loaded_yaml
                .as_ref()
                .map(|y| y.p2p_relay_enabled)
                .unwrap_or(true)
        };
        let p2p_relay_enabled = AtomicBool::new(eff_p2p);
        let eff_max_ext = if has_cli_flag("--max-extended-screens")
            || has_cli_flag("--max-screen-connections")
            || has_cli_flag("--max-connections")
            || config.max_extended_screens != 2
        {
            config.max_extended_screens
        } else {
            saved
                .as_ref()
                .map(|s| s.max_extended_screens)
                .unwrap_or(config.max_extended_screens)
        };
        let eff_max_web_viewers = if eff_low_power {
            0
        } else if has_cli_flag("--max-web-viewers") || config.max_web_viewers != 0 {
            config.max_web_viewers
        } else {
            saved
                .as_ref()
                .map(|s| s.max_web_viewers)
                .unwrap_or(config.max_web_viewers)
        };
        let max_extended_screens = AtomicUsize::new(eff_max_ext);
        let max_web_viewers = AtomicUsize::new(eff_max_web_viewers);
        let (eff_auto_mif, eff_fixed_mif) =
            if has_cli_flag("--max-in-flight") || config.max_in_flight != MaxInFlight::Auto {
                match config.max_in_flight {
                    MaxInFlight::Auto => (true, 2),
                    MaxInFlight::Fixed(n) => (false, n.min(12)),
                }
            } else if let Some(ref s) = saved {
                (s.auto_max_in_flight, s.max_in_flight.min(12))
            } else {
                (true, 2)
            };
        let auto_max_in_flight = Arc::new(AtomicBool::new(eff_auto_mif));
        let max_in_flight = AtomicU32::new(eff_fixed_mif);
        let can_web_independent =
            backend.supports_virtual_display() && config.mode == crate::config::CaptureMode::Extend;
        let requested_web_mode = if let Some(m) = config.web_screen_mode {
            m
        } else if config.web_independent_screen || has_cli_flag("--web-independent-screen") {
            if config.web_independent_screen {
                WebScreenMode::Independent
            } else {
                WebScreenMode::FollowIpad
            }
        } else if let Some(ref y) = loaded_yaml {
            if y.web_screen_mode == WebScreenMode::FollowIpad && y.web_independent_screen {
                WebScreenMode::Independent
            } else {
                y.web_screen_mode
            }
        } else if saved.as_ref().is_some_and(|s| s.web_independent_screen) {
            WebScreenMode::Independent
        } else {
            WebScreenMode::FollowIpad
        };
        let eff_web_mode = if requested_web_mode == WebScreenMode::Independent && !can_web_independent {
            warn!(
                "--web-independent-screen / --web-screen-mode independent ignored: independent virtual display is only supported in macOS Extend mode"
            );
            WebScreenMode::FollowIpad
        } else {
            requested_web_mode
        };
        let web_screen_mode = Arc::new(AtomicU8::new(eff_web_mode.as_u8()));
        let (init_fps, init_bitrate, init_quality) = match config.quality {
            Some(q) => {
                let (f, b) = q.defaults();
                (f, b, q)
            }
            None => {
                let explicit_fps = has_cli_flag("--fps") || config.fps != 30;
                let explicit_br = has_cli_flag("--bitrate-mbps") || config.bitrate_mbps != 16;
                let (eco_fps, eco_br) = QualityPreset::Eco.defaults();
                let eff_fps = if explicit_fps {
                    config.fps
                } else if eff_low_power {
                    eco_fps
                } else {
                    saved.as_ref().map(|s| s.fps).unwrap_or(config.fps)
                };
                let eff_br = if explicit_br {
                    config.bitrate_mbps
                } else if eff_low_power {
                    eco_br
                } else {
                    saved
                        .as_ref()
                        .map(|s| s.bitrate_mbps)
                        .unwrap_or(config.bitrate_mbps)
                };
                (
                    eff_fps.clamp(5, 120),
                    eff_br.clamp(2, 60),
                    QualityPreset::from_fps_bitrate(eff_fps, eff_br),
                )
            }
        };
        let raw_w = if has_cli_flag("--width") || config.width != 0 {
            config.width
        } else {
            saved.as_ref().map(|s| s.width).unwrap_or(0)
        };
        let raw_h = if has_cli_flag("--height") || config.height != 0 {
            config.height
        } else {
            saved.as_ref().map(|s| s.height).unwrap_or(0)
        };
        let (eff_w, eff_h) = if raw_w >= 320 && raw_h >= 240 {
            (raw_w.clamp(320, 3840) & !1, raw_h.clamp(240, 2160) & !1)
        } else {
            (0, 0)
        };
        let raw_hidpi = if eff_low_power {
            1
        } else if has_cli_flag("--hidpi") || config.hidpi != 1 {
            config.hidpi
        } else {
            saved.as_ref().map(|s| s.hidpi).unwrap_or(config.hidpi)
        };
        let eff_int_scale = if has_cli_flag("--integer-scale") || config.integer_scale {
            config.integer_scale
        } else {
            saved.as_ref().map(|s| s.integer_scale).unwrap_or(false)
        };
        let raw_edge = if has_cli_flag("--max-pixel-edge") || config.max_pixel_edge != 0 {
            config.max_pixel_edge
        } else {
            saved.as_ref().map(|s| s.max_pixel_edge).unwrap_or(0)
        };
        let eff_adaptive = if has_cli_flag("--no-adaptive-quality") || config.no_adaptive_quality {
            !config.no_adaptive_quality
        } else {
            saved.as_ref().map(|s| s.adaptive_quality).unwrap_or(true)
        };
        let eff_abr_sensitivity = config.abr_sensitivity.unwrap_or_else(|| {
            loaded_yaml
                .as_ref()
                .map(|y| y.ipad.abr_sensitivity)
                .unwrap_or(AbrSensitivity::Balanced)
        });
        let eff_half_fps_unfocused =
            if config.no_half_fps_unfocused || has_cli_flag("--no-half-fps-unfocused") {
                false
            } else if has_cli_flag("--half-fps-unfocused") || config.half_fps_unfocused {
                config.half_fps_unfocused
            } else {
                loaded_yaml
                    .as_ref()
                    .map(|y| y.ipad.half_fps_when_unfocused)
                    .unwrap_or(false)
            };
        let eff_lock_ipad = if let Some(la) = config.on_lock_ipad {
            la
        } else if has_cli_flag("--on-lock") || config.on_lock != LockAction::Pause {
            config.on_lock
        } else {
            saved
                .as_ref()
                .map(|s| s.lock_action_ipad)
                .unwrap_or(config.on_lock)
        };
        let eff_lock_web = if let Some(la) = config.on_lock_web {
            la
        } else if has_cli_flag("--on-lock") || config.on_lock != LockAction::Pause {
            config.on_lock
        } else {
            saved
                .as_ref()
                .map(|s| s.lock_action_web)
                .unwrap_or(config.on_lock)
        };
        let eff_lock_delay = if has_cli_flag("--on-lock-delay-secs") || config.on_lock_delay_secs != 10 {
            config.on_lock_delay_secs
        } else {
            saved
                .as_ref()
                .map(|s| s.lock_delay_secs)
                .unwrap_or(config.on_lock_delay_secs)
        }
        .min(3600);
        let eff_port_idle_close =
            if has_cli_flag("--port-idle-close-secs") || config.port_idle_close_secs != 300 {
                config.port_idle_close_secs
            } else {
                loaded_yaml
                    .as_ref()
                    .map(|y| y.port_idle_close_secs)
                    .unwrap_or(config.port_idle_close_secs)
            }
            .min(86_400);
        let raw_web_w = if has_cli_flag("--web-width") || config.web_width != 1280 {
            config.web_width
        } else {
            saved
                .as_ref()
                .map(|s| s.web_width)
                .filter(|&w| w >= 320)
                .unwrap_or(config.web_width)
        };
        let raw_web_h = if has_cli_flag("--web-height") || config.web_height != 720 {
            config.web_height
        } else {
            saved
                .as_ref()
                .map(|s| s.web_height)
                .filter(|&h| h >= 240)
                .unwrap_or(config.web_height)
        };
        let eff_web_w = raw_web_w.clamp(320, 3840) & !1;
        let eff_web_h = raw_web_h.clamp(240, 2160) & !1;
        let eff_web_fps = if has_cli_flag("--web-fps") || config.web_fps != 30 {
            config.web_fps
        } else {
            saved
                .as_ref()
                .map(|s| s.web_fps)
                .filter(|&f| f >= 5)
                .unwrap_or(config.web_fps)
        }
        .clamp(5, 120);
        let eff_web_br = if has_cli_flag("--web-bitrate-mbps") || config.web_bitrate_mbps != 16 {
            config.web_bitrate_mbps
        } else {
            saved
                .as_ref()
                .map(|s| s.web_bitrate_mbps)
                .filter(|&b| b >= 2)
                .unwrap_or(config.web_bitrate_mbps)
        }
        .clamp(2, 60);
        let eff_web_hidpi = if has_cli_flag("--web-hidpi") || config.web_hidpi != 1 {
            config.web_hidpi
        } else {
            saved.as_ref().map(|s| s.web_hidpi).unwrap_or(config.web_hidpi)
        };
        let eff_web_edge = if has_cli_flag("--web-max-pixel-edge") || config.web_max_pixel_edge != 0 {
            config.web_max_pixel_edge
        } else {
            saved.as_ref().map(|s| s.web_max_pixel_edge).unwrap_or(0)
        };
        let init_video = VideoSettings {
            width: eff_w,
            height: eff_h,
            fps: init_fps,
            bitrate_mbps: init_bitrate,
            hidpi: if raw_hidpi >= 2 { 2 } else { 1 },
            integer_scale: eff_int_scale,
            max_pixel_edge: if raw_edge >= 640 {
                raw_edge.clamp(640, WEB_MAX_PIXEL_EDGE) & !1
            } else {
                0
            },
            adaptive_quality: eff_adaptive,
            abr_sensitivity: eff_abr_sensitivity,
            half_fps_when_unfocused: eff_half_fps_unfocused,
            quality: init_quality,
            web_width: eff_web_w,
            web_height: eff_web_h,
            web_fps: eff_web_fps,
            web_bitrate_mbps: eff_web_br,
            web_hidpi: if eff_web_hidpi >= 2 { 2 } else { 1 },
            web_max_pixel_edge: if eff_web_edge >= 640 {
                eff_web_edge.clamp(640, WEB_MAX_PIXEL_EDGE) & !1
            } else {
                0
            },
            web_quality: QualityPreset::from_fps_bitrate(eff_web_fps, eff_web_br),
        };
        let mut init_polling = loaded_yaml
            .as_ref()
            .map(|y| y.polling.clone())
            .unwrap_or_default();
        if eff_low_power {
            init_polling = PollingConfigSection::low_power_defaults();
        }
        init_polling.normalize();
        let init_baseline = loaded_yaml.clone().unwrap_or_default();
        let init_active_preset = loaded_yaml.as_ref().and_then(|y| y.active_preset.clone());
        let init_presets = loaded_yaml
            .as_ref()
            .map(|y| y.presets.clone())
            .unwrap_or_default();
        let init_window_rules = loaded_yaml
            .as_ref()
            .map(|y| y.window_rules.clone())
            .unwrap_or_default();
        let reg = Self {
            config,
            backend,
            trust_store,
            config_path,
            config_read_only_corrupt: AtomicBool::new(config_corrupt),
            config_parse_error: Mutex::new(config_parse_error),
            persisted_baseline: Mutex::new(init_baseline),
            config_tx_lock: Mutex::new(()),
            settings_save_lock: Mutex::new(()),
            confirm_handler: Mutex::new(None),
            cancel_pending_handler: Mutex::new(None),
            web_viewer_limit_handler: Mutex::new(None),
            allow_input,
            client_cursor,
            web_require_approval,
            input_counters: InputCounters::default(),
            low_power,
            low_power_snapshot: Mutex::new(None),
            p2p_relay_enabled,
            max_extended_screens,
            max_web_viewers,
            auto_max_in_flight,
            max_in_flight,
            video: Arc::new(Mutex::new(init_video)),
            polling: Arc::new(Mutex::new(init_polling)),
            active_preset: Mutex::new(init_active_preset),
            presets: Mutex::new(init_presets),
            window_rules: Mutex::new(init_window_rules),
            next_window_rule_id: AtomicU64::new(1),
            next_virtual_display_id: AtomicU64::new(1),
            virtual_display_shutdown_epoch: AtomicU64::new(1),
            standalone_virtual_displays: Mutex::new(Vec::new()),
            applied_window_moves: Mutex::new(HashSet::new()),
            ipad_video_settings_gen: Arc::new(AtomicU64::new(1)),
            web_video_settings_gen: Arc::new(AtomicU64::new(1)),
            next_session_id: AtomicU64::new(1),
            next_capture_id: AtomicU64::new(1),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            web_subscribers: Arc::new(Mutex::new(Vec::new())),
            last_ipad_web_frame: Arc::new(Mutex::new(None)),
            last_standalone_web_frame: Arc::new(Mutex::new(None)),
            standalone_web_capture: Arc::new(Mutex::new(None)),
            standalone_web_resume_after: Mutex::new(None),
            web_abr_accum: Arc::new(Mutex::new(WebAbrAccum::default())),
            web_screen_mode,
            web_follow_ipad_session_id: Arc::new(AtomicU64::new(0)),
            web_source_epoch: Arc::new(AtomicU64::new(1)),
            lock_action_ipad: Mutex::new(eff_lock_ipad),
            lock_action_web: Mutex::new(eff_lock_web),
            lock_delay_secs: AtomicU64::new(eff_lock_delay),
            port_idle_close_secs: AtomicU64::new(eff_port_idle_close),
            host_lock_mutex: Mutex::new(()),
            lock_apply_mutex: Mutex::new(()),
            lock_state_epoch: AtomicU64::new(1),
            host_screen_locked: Arc::new(AtomicBool::new(false)),
            host_locked_since: Mutex::new(None),
            host_lock_enforced: AtomicBool::new(false),
            host_lock_paused_ipad: Arc::new(AtomicBool::new(false)),
            host_lock_paused_web: Arc::new(AtomicBool::new(false)),
            web_lock_disconnecting: Arc::new(AtomicBool::new(false)),
            web_mode_lock: Mutex::new(()),
            last_global_activity: Arc::new(Mutex::new(Instant::now())),
            last_wifi_activity: Arc::new(Mutex::new(Instant::now())),
            last_web_activity: Arc::new(Mutex::new(Instant::now())),
            activity_signal: Arc::new((Mutex::new(0), Condvar::new())),
            wake_grace_until: Mutex::new(None),
            confirm_lock: Mutex::new(()),
            tty_prompt_tx: Arc::new(Mutex::new(None)),
            tty_reader_started: AtomicBool::new(false),
        };
        if migrated_or_new {
            reg.persist_current_settings();
        }
        reg
    }

    pub fn config_path(&self) -> Option<&std::path::Path> {
        self.config_path.as_deref()
    }

    pub fn input_stats(&self) -> InputStatsSnapshot {
        InputStatsSnapshot {
            received: self.input_counters.received.load(Ordering::Relaxed),
            injected: self.input_counters.injected.load(Ordering::Relaxed),
            dropped_view_only: self
                .input_counters
                .dropped_view_only
                .load(Ordering::Relaxed),
            dropped_locked: self.input_counters.dropped_locked.load(Ordering::Relaxed),
            dropped_no_permission: self
                .input_counters
                .dropped_no_permission
                .load(Ordering::Relaxed),
            decode_errors: self.input_counters.decode_errors.load(Ordering::Relaxed),
        }
    }

    pub fn is_config_corrupt(&self) -> bool {
        self.config_read_only_corrupt.load(Ordering::Acquire)
    }

    pub fn config_parse_error(&self) -> Option<String> {
        self.config_parse_error.lock().unwrap().clone()
    }

    /// Read the verbatim disk config file contents (used to help the user repair corrupt YAML
    /// in Web Admin without overwriting their original file with an empty fallback template).
    pub fn read_raw_config_file(&self) -> Option<String> {
        let path = self.config_path.as_deref()?;
        std::fs::read_to_string(path).ok()
    }

    /// Structured platform capability matrix for Web Admin feature disclosure & diagnostic bundles.
    pub fn capabilities(&self) -> PlatformCapabilities {
        self.backend.capabilities()
    }

    /// Current monotonic Web video source epoch (bumped on every mode switch, owner failover,
    /// standalone capture start/stop, or lock pause).
    pub fn web_source_epoch(&self) -> u64 {
        self.web_source_epoch.load(Ordering::Acquire)
    }

    pub(super) fn bump_web_source_epoch(&self) -> u64 {
        self.web_source_epoch.fetch_add(1, Ordering::AcqRel) + 1
    }

    /// Return the latest cached IDR frame for the currently active Web stream source ONLY if its
    /// recorded `source_epoch` still matches `web_source_epoch()` (prevents dead-iPad or pre-lock
    /// cached frames from being re-stamped into `SharedWebMuxer` under a newer epoch; Iter-7 P1-B1).
    pub fn cached_web_idr_frame(&self) -> Option<(&'static str, u64, u32, Arc<EncodedFrame>)> {
        if self.is_host_lock_paused_web() || self.is_web_lock_disconnect_blocking() {
            return None;
        }
        let source = self.current_web_stream_source();
        let cur_epoch = self.web_source_epoch();
        let vs = self.video_settings();
        if matches!(source, "standalone" | "main") {
            let (ep, f) = self
                .last_standalone_web_frame
                .lock()
                .ok()
                .and_then(|g| g.clone())?;
            if ep != cur_epoch {
                return None;
            }
            Some((source, ep, vs.web_fps.max(1), f))
        } else if source == "ipad" {
            let (ep, f) = self.last_ipad_web_frame.lock().ok().and_then(|g| g.clone())?;
            if ep != cur_epoch {
                return None;
            }
            Some(("ipad", ep, vs.fps.max(1), f))
        } else {
            None
        }
    }

    pub fn is_auto_accept(&self) -> bool {
        self.config.auto_accept
    }

    pub fn is_p2p_relay_enabled(&self) -> bool {
        self.p2p_relay_enabled.load(Ordering::Acquire)
    }

    pub fn set_p2p_relay_enabled(&self, enabled: bool) {
        let low_power = self.is_low_power();
        let eff = if low_power { false } else { enabled };
        let prev = self.p2p_relay_enabled.swap(eff, Ordering::AcqRel);
        if low_power {
            // Keep runtime P2P disabled while low_power is active, but update persisted baseline
            // and low_power_snapshot so explicit user edits/resets survive exiting low_power (Iter-7 P2-C2).
            if let Ok(mut snap) = self.low_power_snapshot.lock() {
                if let Some(ref mut s) = *snap {
                    s.p2p_relay_enabled = enabled;
                }
            }
            self.persist_config_patch(|c| c.p2p_relay_enabled = enabled);
        } else if prev != eff {
            self.persist_config_patch(|c| c.p2p_relay_enabled = eff);
        }
    }

    pub fn config(&self) -> &AppConfig {
        &self.config
    }

    pub fn backend(&self) -> Arc<dyn DisplayBackend> {
        self.backend.clone()
    }

    pub fn port_idle_close_secs(&self) -> u64 {
        self.port_idle_close_secs.load(Ordering::Acquire)
    }

    pub fn set_port_idle_close_secs(&self, secs: u64) {
        let clamped = secs.min(86_400);
        let prev = self.port_idle_close_secs.swap(clamped, Ordering::AcqRel);
        if prev != clamped {
            info!("External port idle auto-close updated: {prev}s -> {clamped}s");
            self.persist_config_patch(|c| c.port_idle_close_secs = clamped);
        }
        self.notify_lifecycle_wakeup();
    }

    pub fn record_wifi_activity(&self) {
        if let Ok(mut ts) = self.last_wifi_activity.lock() {
            *ts = Instant::now();
        }
    }

    pub fn last_wifi_activity(&self) -> Instant {
        *self.last_wifi_activity.lock().unwrap()
    }

    pub fn record_web_activity(&self) {
        if let Ok(mut ts) = self.last_web_activity.lock() {
            *ts = Instant::now();
        }
    }

    pub fn last_web_activity(&self) -> Instant {
        *self.last_web_activity.lock().unwrap()
    }

    pub fn host_info(&self) -> HostSystemInfo {
        self.backend.host_system_info(&self.config.host_name)
    }

    pub fn trust_store(&self) -> Arc<TrustStore> {
        self.trust_store.clone()
    }

    /// Install a custom confirmation callback (primarily for tests or Web/GUI wrappers).
    pub fn set_confirm_handler(&self, handler: ConfirmHandler) {
        *self.confirm_handler.lock().unwrap() = Some(handler);
    }

    /// Install a hook invoked whenever a session is torn down/replaced so pending UI approvals
    /// for dead sessions are cancelled immediately instead of lingering for 60s.
    pub fn set_cancel_pending_handler(&self, handler: CancelPendingHandler) {
        *self.cancel_pending_handler.lock().unwrap() = Some(handler);
    }

    /// Install a hook invoked whenever the effective `max_web_viewers` limit changes
    /// (including low-power clamping, presets, YAML reload, and admin settings updates)
    /// so the dedicated external Web Viewer listener can open/close dynamically.
    pub fn set_web_viewer_limit_handler(&self, handler: WebViewerLimitHandler) {
        *self.web_viewer_limit_handler.lock().unwrap() = Some(handler);
    }

    fn notify_cancel_pending(&self, session_id: Option<u64>, addr: Option<&str>) {
        let cb = self.cancel_pending_handler.lock().ok().and_then(|g| g.clone());
        if let Some(f) = cb {
            f(session_id, addr);
        }
    }

    pub(crate) fn notify_web_viewer_limit_changed(&self, max_viewers: usize) {
        let cb = self.web_viewer_limit_handler.lock().ok().and_then(|g| g.clone());
        if let Some(f) = cb {
            f(max_viewers);
        }
    }

}

impl Drop for SessionRegistry {
    fn drop(&mut self) {
        self.shutdown_all_virtual_displays();
    }
}
