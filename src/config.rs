use anyhow::{anyhow, Result};
use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};

/// Quality presets combining FPS and H.264 bitrate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum QualityPreset {
    /// Power-saving / low-bandwidth (15 fps, 4 Mbps)
    #[value(alias = "4m", alias = "powersave")]
    Eco,
    /// Low bandwidth / smooth (30 fps, 8 Mbps)
    Low,
    /// Balanced default (30 fps, 16 Mbps)
    Balanced,
    /// Sharp high quality (60 fps, 24 Mbps)
    High,
    /// Ultra crisp text / Retina (60 fps, 36 Mbps)
    Ultra,
}

impl QualityPreset {
    pub fn defaults(self) -> (u32, u32) {
        match self {
            QualityPreset::Eco => (15, 4),
            QualityPreset::Low => (30, 8),
            QualityPreset::Balanced => (30, 16),
            QualityPreset::High => (60, 24),
            QualityPreset::Ultra => (60, 36),
        }
    }

    pub fn from_fps_bitrate(fps: u32, bitrate_mbps: u32) -> Self {
        if bitrate_mbps <= 5 && fps <= 20 {
            QualityPreset::Eco
        } else if bitrate_mbps <= 10 {
            QualityPreset::Low
        } else if bitrate_mbps <= 18 && fps <= 35 {
            QualityPreset::Balanced
        } else if bitrate_mbps <= 28 {
            QualityPreset::High
        } else {
            QualityPreset::Ultra
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CaptureMode {
    /// Extended display (macOS: CGVirtualDisplay; Linux/Windows: secondary monitor or --capture-rect)
    Extend,
    /// Mirror / capture an existing display (legacy typeCapture = 4)
    Mirror,
    /// Share the main display (legacy typeCapture = 5)
    Main,
}

impl CaptureMode {
    pub fn legacy_type_capture(self) -> i64 {
        match self {
            CaptureMode::Extend => 3,
            CaptureMode::Mirror => 4,
            CaptureMode::Main => 5,
        }
    }
}

/// Screen source mode for Web viewers (`/view`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebScreenMode {
    /// Reuse active iPad extended display when connected, otherwise spin up a standalone virtual screen
    #[default]
    #[value(alias = "follow_ipad", alias = "ipad")]
    FollowIpad,
    /// Always use a dedicated independent virtual extended display (macOS Extend mode)
    #[value(alias = "standalone")]
    Independent,
    /// Watch the host computer's primary display directly (macOS / Linux / Windows)
    Main,
}

impl WebScreenMode {
    pub fn as_u8(self) -> u8 {
        match self {
            Self::FollowIpad => 0,
            Self::Independent => 1,
            Self::Main => 2,
        }
    }

    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Independent,
            2 => Self::Main,
            _ => Self::FollowIpad,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::FollowIpad => "follow_ipad",
            Self::Independent => "independent",
            Self::Main => "main",
        }
    }
}

/// Network-adaptive quality (ABR) sensitivity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AbrSensitivity {
    /// Slow to step down on transient Wi-Fi jitter, fast to recover
    #[value(alias = "low")]
    Conservative,
    /// Balanced default (resilient to Wi-Fi PSM idle RTT)
    #[default]
    #[value(alias = "normal", alias = "medium")]
    Balanced,
    /// Reacts faster to sustained drops or send stalls on congested Wi-Fi
    #[value(alias = "high")]
    Aggressive,
}

impl AbrSensitivity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Conservative => "conservative",
            Self::Balanced => "balanced",
            Self::Aggressive => "aggressive",
        }
    }
}

/// Action taken automatically when the host screen locks (after `--on-lock-delay-secs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LockAction {
    /// Pause video transmission and hide Web preview while locked; auto-resume on unlock
    #[default]
    Pause,
    /// Disconnect all iPad sessions & Web viewers and release virtual displays on lock
    Disconnect,
    /// Keep active sessions running (native OS behavior)
    Keep,
}

/// In-flight video frame window policy (`auto` by default, or explicit fixed limit `0..=12`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(untagged)]
pub enum MaxInFlight {
    /// Automatically adapt per-session window (USB: 1..=2, Wi-Fi: 1..=4) from baseline RTT & queuing delay
    #[default]
    Auto,
    /// Explicit fixed max unacknowledged in-flight frames (0 = disable backpressure, 1..=12 = fixed)
    Fixed(u32),
}

impl MaxInFlight {
    pub fn parse(s: &str) -> Result<Self> {
        let trimmed = s.trim();
        if trimmed.eq_ignore_ascii_case("auto") {
            return Ok(Self::Auto);
        }
        let n: u32 = trimmed
            .parse()
            .map_err(|_| anyhow!("expected 'auto' or an integer 0..=12, got {s:?}"))?;
        if n > 12 {
            return Err(anyhow!("max-in-flight must be 'auto' or 0..=12, got {n}"));
        }
        Ok(Self::Fixed(n))
    }

    pub fn is_auto(self) -> bool {
        matches!(self, Self::Auto)
    }

    pub fn fixed_value(self) -> Option<u32> {
        match self {
            Self::Auto => None,
            Self::Fixed(n) => Some(n),
        }
    }
}

impl std::fmt::Display for MaxInFlight {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auto => f.write_str("auto"),
            Self::Fixed(n) => write!(f, "{n}"),
        }
    }
}

/// Optional capture region `X,Y,W,H` (useful on Linux/Windows to capture a specific monitor or virtual output).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureRect {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

impl CaptureRect {
    pub fn parse(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split(',').map(str::trim).collect();
        if parts.len() != 4 {
            return Err(anyhow!("expected X,Y,W,H (e.g. 1920,0,1024,768), got {s:?}"));
        }
        let x: i32 = parts[0].parse()?;
        let y: i32 = parts[1].parse()?;
        let width: u32 = parts[2].parse()?;
        let height: u32 = parts[3].parse()?;
        if width == 0 || height == 0 {
            return Err(anyhow!(
                "capture rect width and height must be non-zero, got {width}x{height}"
            ));
        }
        Ok(Self {
            x,
            y,
            width,
            height,
        })
    }
}

pub fn default_usbmuxd_addr() -> String {
    #[cfg(windows)]
    {
        "127.0.0.1:27015".to_string()
    }
    #[cfg(not(windows))]
    {
        "/var/run/usbmuxd".to_string()
    }
}

#[derive(Debug, Clone, Parser)]
#[command(
    name = "idis",
    version,
    about = "Cross-platform Web Extended Screen, macOS virtual display & window routing host (with optional legacy USB/Wi-Fi display client compatibility)"
)]
pub struct AppConfig {
    /// Display capture mode: extend, mirror, or main
    #[arg(long, value_enum, default_value_t = CaptureMode::Extend, help_heading = "Display & Capture")]
    pub mode: CaptureMode,

    /// Optional video quality preset (eco=4M/15fps, low=8M/30fps, balanced=16M/30fps, high=24M/60fps, ultra=36M/60fps)
    #[arg(long, value_enum, help_heading = "Video & Quality")]
    pub quality: Option<QualityPreset>,

    /// Target FPS for video capture and H.264 encoding
    #[arg(long, default_value_t = 30, help_heading = "Video & Quality")]
    pub fps: u32,

    /// Target H.264 average bitrate in Mbps (legacy default: 16)
    #[arg(long, default_value_t = 16, help_heading = "Video & Quality")]
    pub bitrate_mbps: u32,

    /// Override output video width (0 = use iPad reported resolution)
    #[arg(long, default_value_t = 0, help_heading = "Display & Capture")]
    pub width: u32,

    /// Override output video height (0 = use iPad reported resolution)
    #[arg(long, default_value_t = 0, help_heading = "Display & Capture")]
    pub height: u32,

    /// HiDPI / Retina scale factor for macOS virtual display (1 = standard, 2 = Retina)
    #[arg(long, default_value_t = 1, help_heading = "Display & Capture")]
    pub hidpi: u32,

    /// Snap virtual display logical resolution to an exact integer divisor of physical stream pixels (1:1 pixel-aligned, eliminates fractional blur)
    #[arg(long, default_value_t = false, help_heading = "Display & Capture")]
    pub integer_scale: bool,

    /// Maximum H.264 streaming long-edge pixels (0 = auto per screen: each iPad's native panel edge, Web up to 3840; or explicit e.g. 1024/1536/2048/2732/3840)
    #[arg(long, default_value_t = 0, help_heading = "Video & Quality")]
    pub max_pixel_edge: u32,

    /// Disable automatic network-adaptive bitrate & FPS scaling (ABR; enabled by default)
    #[arg(long, default_value_t = false, help_heading = "Video & Quality")]
    pub no_adaptive_quality: bool,

    /// Network-adaptive quality (ABR) sensitivity: conservative, balanced (default), or aggressive
    #[arg(long, value_enum, help_heading = "Video & Quality")]
    pub abr_sensitivity: Option<AbrSensitivity>,

    /// Automatically halve iPad streaming FPS when the host mouse cursor is not on the iPad display (instant full-FPS recovery on cursor entry)
    #[arg(long = "half-fps-unfocused", default_value_t = false, conflicts_with = "no_half_fps_unfocused", help_heading = "Video & Quality")]
    pub half_fps_unfocused: bool,

    /// Explicitly disable halving iPad FPS when cursor focus is outside the iPad (overrides ~/.config/idis.yaml)
    #[arg(long = "no-half-fps-unfocused", default_value_t = false, conflicts_with = "half_fps_unfocused", help_heading = "Video & Quality")]
    pub no_half_fps_unfocused: bool,

    /// Default action when the host screen locks (applies to both iPad & Web unless overridden by `--on-lock-ipad` / `--on-lock-web`): pause, disconnect, or keep
    #[arg(long, value_enum, default_value_t = LockAction::Pause, help_heading = "Security & Access")]
    pub on_lock: LockAction,

    /// Action for iPad sessions when the host screen locks: pause, disconnect, or keep (defaults to `--on-lock`)
    #[arg(long, value_enum, help_heading = "Security & Access")]
    pub on_lock_ipad: Option<LockAction>,

    /// Action for Web viewers when the host screen locks: pause, disconnect, or keep (defaults to `--on-lock`)
    #[arg(long, value_enum, help_heading = "Security & Access")]
    pub on_lock_web: Option<LockAction>,

    /// Grace delay in seconds before enforcing lock-screen pause/disconnect (default: 10s, 0 = immediate)
    #[arg(long, default_value_t = 10, help_heading = "Security & Access")]
    pub on_lock_delay_secs: u64,

    /// Monitor index (Linux/Windows: 0=primary, 1=second...) or macOS CGDirectDisplayID
    #[arg(long, default_value_t = 0, help_heading = "Display & Capture")]
    pub display_id: u32,

    /// Optional source capture region X,Y,W,H on Linux/Windows (e.g. "1920,0,1024,768")
    #[arg(long, value_parser = CaptureRect::parse, help_heading = "Display & Capture")]
    pub capture_rect: Option<CaptureRect>,

    /// FFmpeg H.264 encoder name on Linux/Windows (e.g. libx264, h264_nvenc, h264_vaapi, h264_qsv)
    #[arg(long, default_value = "libx264", help_heading = "Video & Quality")]
    pub encoder: String,

    /// Path to ffmpeg executable (used on Linux and Windows)
    #[arg(long, default_value = "ffmpeg", help_heading = "Video & Quality")]
    pub ffmpeg_path: String,

    /// TCP bind address or interface name for Wi-Fi listeners (e.g. 0.0.0.0, en0, lo0:56845)
    #[arg(long = "bind-addr", alias = "bind", default_value = "0.0.0.0", help_heading = "Network & Transport")]
    pub bind_addr: String,

    /// TCP port for Telemetry/Control service (0 = OS ephemeral port, advertised via Bonjour/mDNS)
    #[arg(long, default_value_t = 0, help_heading = "Network & Transport")]
    pub telemetry_port: u16,

    /// TCP port for Video/Data service (0 = OS ephemeral port, sent in VideoServiceAccessibleOnPort)
    #[arg(long, default_value_t = 0, help_heading = "Network & Transport")]
    pub data_port: u16,

    /// Advertised Bonjour/mDNS host name (empty = system hostname)
    #[arg(long, default_value = "", help_heading = "Network & Transport")]
    pub host_name: String,

    /// Enable Wi-Fi TCP listener (default: disabled for security; USB-only unless --wifi is passed)
    #[arg(long, default_value_t = false, help_heading = "Network & Transport")]
    pub wifi: bool,

    /// Disable Bonjour/mDNS LAN broadcast even when --wifi is enabled (use manual IP:port instead)
    #[arg(long, default_value_t = false, help_heading = "Network & Transport")]
    pub no_bonjour: bool,

    /// Disable USB (usbmuxd + PeerTalk port 2345) listener
    #[arg(long, default_value_t = false, help_heading = "Network & Transport")]
    pub no_usb: bool,

    /// Allow remote touch/mouse/keyboard input injection from the iPad (default: disabled / view-only)
    #[arg(long, default_value_t = false, conflicts_with = "no_allow_input", help_heading = "Security & Access")]
    pub allow_input: bool,

    /// Explicitly disable remote touch/mouse/keyboard input injection (overrides ~/.config/idis.yaml)
    #[arg(long = "no-allow-input", default_value_t = false, conflicts_with = "allow_input", help_heading = "Security & Access")]
    pub no_allow_input: bool,

    /// usbmuxd endpoint (Unix socket path on macOS/Linux, or host:port like 127.0.0.1:27015 on Windows)
    #[arg(long, default_value_t = default_usbmuxd_addr(), help_heading = "Network & Transport")]
    pub usbmuxd_addr: String,

    /// Render cursor on the iPad client via Telemetry instead of compositing it into the video stream
    #[arg(long, default_value_t = false, conflicts_with = "no_client_cursor", help_heading = "Display & Capture")]
    pub client_cursor: bool,

    /// Explicitly composite the OS cursor into video frames instead of client-side rendering (overrides ~/.config/idis.yaml)
    #[arg(long = "no-client-cursor", default_value_t = false, conflicts_with = "client_cursor", help_heading = "Display & Capture")]
    pub no_client_cursor: bool,

    /// Whitelist of allowed client device fingerprints (e.g. fp:a1b2c3d4e5f60718293a4b5c; can be specified multiple times)
    #[arg(long = "allow-fingerprint", help_heading = "Security & Access")]
    pub allow_fingerprints: Vec<String>,

    /// Whitelist of allowed source IP addresses for Wi-Fi connections (empty = allow any LAN IP subject to trust/confirm)
    #[arg(long = "allow-ip", help_heading = "Security & Access")]
    pub allow_ips: Vec<String>,

    /// Path to unified YAML config file (default: ~/.config/idis.yaml; pass "none" for memory-only)
    #[arg(long = "config", env = "IDIS_CONFIG", help_heading = "Security & Access")]
    pub config_file: Option<String>,

    /// Legacy path override for trusted devices file (deprecated: trusted devices now live in ~/.config/idis.yaml)
    #[arg(long, env = "IDIS_TRUSTED_DEVICES", hide = true)]
    pub trusted_devices_file: Option<String>,

    /// Maximum number of concurrent extended screens (iPad + standalone Web extended display; default: 2, 0 = unlimited)
    #[arg(
        long = "max-extended-screens",
        alias = "max-screen-connections",
        alias = "max-connections",
        default_value_t = 2,
        help_heading = "Security & Access"
    )]
    pub max_extended_screens: usize,

    /// Maximum number of concurrent Web extended-screen viewers (default: 0 = Web viewing disabled)
    #[arg(long = "max-web-viewers", default_value_t = 0, help_heading = "Web Console & P2P")]
    pub max_web_viewers: usize,

    /// Auto-exit if no screen connection or web access occurs within N seconds after startup/idle (default: 300s, 0 = disable)
    #[arg(long, default_value_t = 300, help_heading = "Diagnostics & Runtime")]
    pub idle_exit_secs: u64,

    /// Auto-close open external Web Viewer and iPad Wi-Fi listening ports after N seconds with no active clients on that port (default: 300s, 0 = disable)
    #[arg(long, default_value_t = 300, help_heading = "Diagnostics & Runtime")]
    pub port_idle_close_secs: u64,

    /// Auto-accept untrusted connections without interactive confirmation (insecure on shared networks)
    #[arg(long, default_value_t = false, help_heading = "Security & Access")]
    pub auto_accept: bool,

    /// Disable interactive confirmation prompt (immediately decline untrusted devices not in whitelist/trusted store)
    #[arg(long, default_value_t = false, help_heading = "Security & Access")]
    pub no_confirm: bool,

    /// Auto-trust physically connected USB devices without confirmation (enabled by default; kept for CLI compatibility)
    #[arg(long, default_value_t = false, conflicts_with = "require_usb_confirm", hide = true)]
    pub trust_usb: bool,

    /// Require manual confirmation even for physically connected USB devices (default: false; USB is auto-trusted)
    #[arg(long, default_value_t = false, conflicts_with = "trust_usb", help_heading = "Security & Access")]
    pub require_usb_confirm: bool,

    /// Low-power basic mode: allow only already-trusted devices with saved settings, disable Web viewing & P2P, use 4M/15fps eco preset unless overridden, and reduce background polling
    #[arg(long, default_value_t = false, conflicts_with = "no_low_power", help_heading = "Diagnostics & Runtime")]
    pub low_power: bool,

    /// Explicitly disable low-power mode (overrides ~/.config/idis.yaml)
    #[arg(long = "no-low-power", default_value_t = false, conflicts_with = "low_power", help_heading = "Diagnostics & Runtime")]
    pub no_low_power: bool,

    /// Disconnect inactive/sleeping clients and release virtual display after N seconds without Ping/activity (0 = disable)
    #[arg(long, default_value_t = 20, help_heading = "Network & Transport")]
    pub ping_timeout_secs: u64,

    /// Max unacknowledged in-flight video frames: "auto" (default, adapts to USB/Wi-Fi RTT & queuing delay) or fixed 0..=12 (0 = disable)
    #[arg(long, value_parser = MaxInFlight::parse, default_value = "auto", help_heading = "Video & Quality")]
    pub max_in_flight: MaxInFlight,

    /// Sentry DSN for automatic error and crash reporting (can also be set via SENTRY_DSN env)
    #[arg(long, env = "SENTRY_DSN", help_heading = "Diagnostics & Runtime")]
    pub sentry_dsn: Option<String>,

    /// Sentry environment tag (e.g. production, dev)
    #[arg(long, env = "SENTRY_ENV", default_value = "production", help_heading = "Diagnostics & Runtime")]
    pub sentry_env: String,

    /// Explicit HTTP/HTTPS proxy URL for outbound requests (e.g. http://127.0.0.1:7890; default: none / direct)
    #[arg(long, help_heading = "Network & Transport")]
    pub proxy: Option<String>,

    /// Allow using system/environment proxy settings (HTTP_PROXY/HTTPS_PROXY/ALL_PROXY or OS system proxy; default: disabled)
    #[arg(long, default_value_t = false, help_heading = "Network & Transport")]
    pub use_system_proxy: bool,

    /// Enable the Web admin control panel and browser extended-screen viewer (default: disabled)
    #[arg(long, default_value_t = false, help_heading = "Web Console & P2P")]
    pub web: bool,

    /// HTTP bind address:port or interface:port for the Web Admin Console (default: 127.0.0.1:8787; Web Viewer uses a separate dynamic 0.0.0.0 random port)
    #[arg(long, default_value = "127.0.0.1:8787", help_heading = "Web Console & P2P")]
    pub web_bind: String,

    /// Admin login token for the Web control panel (empty = no password on loopback bind, auto-generated random token on non-loopback bind)
    #[arg(long, env = "IDIS_WEB_ADMIN_TOKEN", help_heading = "Web Console & P2P")]
    pub web_admin_token: Option<String>,

    /// Passcode allowing browser viewers to watch the extended display (empty = disabled until set by admin)
    #[arg(long, env = "IDIS_WEB_VIEW_TOKEN", help_heading = "Web Console & P2P")]
    pub web_view_token: Option<String>,

    /// Default virtual display width for standalone Web viewer when no iPad is connected (default: 1280)
    #[arg(long, default_value_t = 1280, help_heading = "Web Console & P2P")]
    pub web_width: u32,

    /// Default virtual display height for standalone Web viewer when no iPad is connected (default: 720)
    #[arg(long, default_value_t = 720, help_heading = "Web Console & P2P")]
    pub web_height: u32,

    /// Default target FPS for standalone Web extended display (default: 30)
    #[arg(long, default_value_t = 30, help_heading = "Web Console & P2P")]
    pub web_fps: u32,

    /// Default target H.264 bitrate in Mbps for standalone Web extended display (default: 16)
    #[arg(long, default_value_t = 16, help_heading = "Web Console & P2P")]
    pub web_bitrate_mbps: u32,

    /// Default HiDPI scale factor for standalone Web extended display (1 or 2; default: 1)
    #[arg(long, default_value_t = 1, help_heading = "Web Console & P2P")]
    pub web_hidpi: u32,

    /// Maximum H.264 streaming long-edge pixels for standalone Web extended display (0 = auto up to 3840)
    #[arg(long, default_value_t = 0, help_heading = "Web Console & P2P")]
    pub web_max_pixel_edge: u32,

    /// Always create an independent virtual extended display for Web viewers instead of reusing the iPad's screen (macOS Extend mode)
    #[arg(long, default_value_t = false, help_heading = "Web Console & P2P")]
    pub web_independent_screen: bool,

    /// Screen source for Web viewers: follow-ipad (default), independent (virtual screen), or main (host primary display)
    #[arg(long, value_enum, help_heading = "Web Console & P2P")]
    pub web_screen_mode: Option<WebScreenMode>,

    /// Require explicit Admin approval / device trust before untrusted browsers can watch /view
    #[arg(long, default_value_t = false, conflicts_with = "no_web_require_approval", help_heading = "Web Console & P2P")]
    pub web_require_approval: bool,

    /// Explicitly disable Web viewer approval gate (overrides ~/.config/idis.yaml)
    #[arg(long = "no-web-require-approval", default_value_t = false, conflicts_with = "web_require_approval", help_heading = "Web Console & P2P")]
    pub no_web_require_approval: bool,

    /// Print connection QR code(s) in the terminal at startup (default: false)
    #[arg(long, default_value_t = false, help_heading = "Web Console & P2P")]
    pub qr: bool,

    /// Set log level to debug in both terminal and Web console (for troubleshooting & remote agent debugging)
    #[arg(long, default_value_t = false, help_heading = "Diagnostics & Runtime")]
    pub debug: bool,

    /// Optional output path to also write a JSONL trace file (disabled unless explicitly provided)
    #[arg(long, help_heading = "Diagnostics & Runtime")]
    pub debug_log: Option<String>,

    /// Force legacy all-intra (every frame IDR) H.264 encoding instead of default IPPP temporal compression
    #[arg(long = "all-intra", default_value_t = false, help_heading = "Video & Quality")]
    pub all_intra: bool,

    /// Use synthetic mock display backend (for protocol testing without screen capture)
    #[arg(long, default_value_t = false, help_heading = "Diagnostics & Runtime")]
    pub mock: bool,
}

impl AppConfig {
    /// Physically connected USB devices are trusted automatically unless `--require-usb-confirm` is set.
    pub fn is_usb_auto_trusted(&self) -> bool {
        !self.require_usb_confirm
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_most_secure() {
        let cfg = AppConfig::try_parse_from(["idis"]).unwrap();
        assert!(!cfg.wifi, "Wi-Fi must be disabled by default (opt-in via --wifi)");
        assert!(!cfg.no_usb, "USB must be enabled by default");
        assert!(!cfg.allow_input, "remote input injection must be disabled by default (opt-in via --allow-input)");
        assert!(!cfg.require_usb_confirm, "USB devices should be auto-trusted without confirmation by default");
        assert!(cfg.is_usb_auto_trusted(), "USB devices must be auto-trusted by default");
        assert!(!cfg.low_power, "low-power mode must be opt-in");
        assert!(!cfg.auto_accept, "auto-accept must be disabled by default");
        assert_eq!(cfg.max_extended_screens, 2, "default max_extended_screens must be 2");
        assert_eq!(cfg.max_web_viewers, 0, "default max_web_viewers must be 0 (disabled)");
        assert_eq!(cfg.idle_exit_secs, 300, "default idle_exit_secs must be 300s");
        assert_eq!(cfg.port_idle_close_secs, 300, "default port_idle_close_secs must be 300s");
        assert_eq!(cfg.ping_timeout_secs, 20);
        assert_eq!(cfg.max_in_flight, MaxInFlight::Auto);
        assert!(cfg.sentry_dsn.is_none());
        assert!(cfg.proxy.is_none(), "outbound proxy must be disabled by default");
        assert!(
            !cfg.use_system_proxy,
            "system/environment proxy must be disabled by default (opt-in via --use-system-proxy)"
        );
        assert!(!cfg.web, "Web control panel must be disabled by default");
        assert_eq!(cfg.web_bind, "127.0.0.1:8787", "Web panel must bind localhost by default");
        assert!(cfg.web_view_token.is_none(), "Web viewer passcode must be disabled by default");
        assert!(!cfg.qr, "terminal QR printing must be opt-in via --qr");
        assert!(!cfg.debug, "debug disk recording must be disabled by default (opt-in via --debug)");
        assert!(cfg.debug_log.is_none());
        assert!(!cfg.integer_scale);
        assert_eq!(cfg.max_pixel_edge, 0);
        assert!(!cfg.no_adaptive_quality);
        assert_eq!(cfg.on_lock, LockAction::Pause);
        assert!(cfg.on_lock_ipad.is_none());
        assert!(cfg.on_lock_web.is_none());
        assert_eq!(cfg.on_lock_delay_secs, 10);
        assert!(!cfg.web_independent_screen);
        assert_eq!(cfg.web_fps, 30);
        assert_eq!(cfg.web_bitrate_mbps, 16);
        assert_eq!(cfg.web_hidpi, 1);
        assert_eq!(cfg.web_max_pixel_edge, 0);
    }

    #[test]
    fn explicit_proxy_flags_parse() {
        let cfg = AppConfig::try_parse_from([
            "idis",
            "--proxy",
            "http://127.0.0.1:7890",
            "--qr",
            "--debug",
            "--debug-log",
            "/tmp/idis-trace.jsonl",
        ])
        .unwrap();
        assert_eq!(cfg.proxy.as_deref(), Some("http://127.0.0.1:7890"));
        assert!(!cfg.use_system_proxy);
        assert!(cfg.qr);
        assert!(cfg.debug);
        assert_eq!(cfg.debug_log.as_deref(), Some("/tmp/idis-trace.jsonl"));

        let sys_cfg = AppConfig::try_parse_from(["idis", "--use-system-proxy"]).unwrap();
        assert!(sys_cfg.proxy.is_none());
        assert!(sys_cfg.use_system_proxy);

        let mif_fixed = AppConfig::try_parse_from(["idis", "--max-in-flight", "4"]).unwrap();
        assert_eq!(mif_fixed.max_in_flight, MaxInFlight::Fixed(4));
        let mif_zero = AppConfig::try_parse_from(["idis", "--max-in-flight", "0"]).unwrap();
        assert_eq!(mif_zero.max_in_flight, MaxInFlight::Fixed(0));
        let mif_auto = AppConfig::try_parse_from(["idis", "--max-in-flight", "auto"]).unwrap();
        assert_eq!(mif_auto.max_in_flight, MaxInFlight::Auto);
    }

    #[test]
    fn capture_rect_and_max_in_flight_reject_invalid_inputs() {
        assert_eq!(
            CaptureRect::parse("1920, 0, 1024, 768").unwrap(),
            CaptureRect {
                x: 1920,
                y: 0,
                width: 1024,
                height: 768
            }
        );
        assert!(CaptureRect::parse("-1920,0,1280,720").is_ok());
        assert!(CaptureRect::parse("0,0,0,720").is_err(), "zero width must fail");
        assert!(CaptureRect::parse("0,0,1280,0").is_err(), "zero height must fail");
        assert!(CaptureRect::parse("0,0,1280").is_err(), "missing field must fail");
        assert!(CaptureRect::parse("0,0,-10,720").is_err(), "negative width must fail");
        assert!(CaptureRect::parse("abc,0,100,100").is_err());

        assert!(AppConfig::try_parse_from(["idis", "--max-in-flight", "invalid"]).is_err());
        assert!(AppConfig::try_parse_from(["idis", "--max-in-flight", "-1"]).is_err());
        assert!(AppConfig::try_parse_from(["idis", "--max-in-flight", "999999999999"]).is_err());
    }
}
