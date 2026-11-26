//! Unified YAML configuration file (`~/.config/idis.yaml`) storing trusted devices
//! (deterministic handshake fingerprint auth), per-device connection preferences, and global host settings.

use crate::config::{AbrSensitivity, LockAction, WebScreenMode};
use crate::platform::WindowMoveLayout;
use crate::trust::{normalize_fingerprint, TrustedDevice};
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

fn default_true() -> bool {
    true
}

fn default_max_extended_screens() -> usize {
    2
}

fn default_max_in_flight() -> u32 {
    2
}

fn default_lock_delay_secs() -> u64 {
    10
}

fn default_port_idle_close_secs() -> u64 {
    300
}

fn default_fps() -> u32 {
    30
}

fn default_bitrate_mbps() -> u32 {
    16
}

fn default_hidpi() -> u32 {
    1
}

fn default_web_width() -> u32 {
    1280
}

fn default_web_height() -> u32 {
    720
}

fn default_main_loop_ms() -> u64 {
    250
}

fn default_cursor_poll_ms() -> u64 {
    8
}

fn default_usb_retry_ms() -> u64 {
    1000
}

fn default_admin_poll_ms() -> u64 {
    2000
}

/// Active-state polling intervals persisted in `~/.config/idis.yaml` (all in milliseconds).
/// Note: idle standby (0 active connections) is event-driven with zero periodic wakeups regardless
/// of these values; these intervals govern active sessions, USB retries, and Web Admin polling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PollingConfigSection {
    #[serde(default = "default_main_loop_ms")]
    pub main_loop_ms: u64,
    #[serde(default = "default_cursor_poll_ms")]
    pub cursor_poll_ms: u64,
    #[serde(default = "default_usb_retry_ms")]
    pub usb_retry_ms: u64,
    #[serde(default = "default_admin_poll_ms")]
    pub admin_poll_ms: u64,
}

impl Default for PollingConfigSection {
    fn default() -> Self {
        Self {
            main_loop_ms: default_main_loop_ms(),
            cursor_poll_ms: default_cursor_poll_ms(),
            usb_retry_ms: default_usb_retry_ms(),
            admin_poll_ms: default_admin_poll_ms(),
        }
    }
}

impl PollingConfigSection {
    pub fn low_power_defaults() -> Self {
        Self {
            main_loop_ms: 500,
            cursor_poll_ms: 50,
            usb_retry_ms: 3000,
            admin_poll_ms: 5000,
        }
    }

    pub fn normalize(&mut self) {
        self.main_loop_ms = self.main_loop_ms.clamp(100, 5000);
        self.cursor_poll_ms = self.cursor_poll_ms.clamp(8, 200);
        self.usb_retry_ms = self.usb_retry_ms.clamp(250, 30_000);
        self.admin_poll_ms = self.admin_poll_ms.clamp(500, 30_000);
    }
}

pub const MAX_CUSTOM_PRESETS: usize = 32;
pub const MAX_WINDOW_RULES: usize = 64;

/// Target screen selector for an automatic window routing rule persisted in `~/.config/idis.yaml`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WindowRouteTarget {
    /// Route to any currently active ephemeral standalone virtual display.
    #[default]
    AnyVirtual,
    /// Route to an ephemeral standalone virtual display matching `name` (case-insensitive).
    VirtualName { name: String },
    /// Route to any connected iPad extended screen.
    AnyIpad,
    /// Route to a specific connected iPad identified by its handshake fingerprint.
    Device { fingerprint: String },
    /// Route to the standalone Web independent screen when active.
    WebScreen,
    /// Route to a specific OS display ID (e.g. a secondary physical monitor or Windows Virtual Display Driver).
    Display { display_id: u32 },
    /// Route back to the host primary display.
    MainDisplay,
}

/// Persistent automatic window-routing rule saved in `~/.config/idis.yaml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowRule {
    pub id: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub app_name: String,
    #[serde(default)]
    pub bundle_id: String,
    #[serde(default)]
    pub title_contains: String,
    /// When `true`, only matches floating overlay windows (`layer > 0`, e.g. Notion recording bar)
    /// while leaving normal app windows untouched.
    #[serde(default)]
    pub floating_only: bool,
    #[serde(default)]
    pub target: WindowRouteTarget,
    #[serde(default)]
    pub layout: WindowMoveLayout,
}

impl WindowRule {
    pub fn validate_and_normalize(&mut self) -> Result<()> {
        let clean = |s: &str, max: usize| -> String {
            s.chars()
                .filter(|c| !c.is_control())
                .collect::<String>()
                .trim()
                .chars()
                .take(max)
                .collect()
        };
        self.id = clean(&self.id, 64);
        if self.id.is_empty() {
            return Err(anyhow!("窗口规则 ID 不能为空"));
        }
        self.app_name = clean(&self.app_name, 128);
        self.bundle_id = clean(&self.bundle_id, 128);
        self.title_contains = clean(&self.title_contains, 128);
        if self.app_name.is_empty() && self.bundle_id.is_empty() && self.title_contains.is_empty() {
            return Err(anyhow!("窗口规则至少需要填写应用名、Bundle ID 或窗口标题关键字之一"));
        }
        match &mut self.target {
            WindowRouteTarget::VirtualName { name } => {
                *name = clean(name, 64);
                if name.is_empty() {
                    return Err(anyhow!("指定虚拟屏名称不能为空"));
                }
            }
            WindowRouteTarget::Device { fingerprint } => {
                let fp = normalize_fingerprint(fingerprint)
                    .ok_or_else(|| anyhow!("窗口规则中的目标设备指纹无效: {fingerprint:?}"))?;
                *fingerprint = fp;
            }
            WindowRouteTarget::Display { display_id } if *display_id == 0 => {
                return Err(anyhow!("目标显示器 ID 必须大于 0"));
            }
            _ => {}
        }
        Ok(())
    }
}

/// A named reusable configuration preset stored inside `~/.config/idis.yaml`.
/// Intentionally excludes `trusted_devices` so switching presets never modifies device trust.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigPreset {
    pub name: String,
    #[serde(default)]
    pub low_power: bool,
    #[serde(default)]
    pub allow_input: bool,
    #[serde(default)]
    pub client_cursor: bool,
    #[serde(default = "default_max_extended_screens")]
    pub max_extended_screens: usize,
    #[serde(default)]
    pub max_web_viewers: usize,
    #[serde(default = "default_true")]
    pub auto_max_in_flight: bool,
    #[serde(default = "default_max_in_flight")]
    pub max_in_flight: u32,
    #[serde(default)]
    pub lock_action_ipad: LockAction,
    #[serde(default)]
    pub lock_action_web: LockAction,
    #[serde(default = "default_lock_delay_secs")]
    pub lock_delay_secs: u64,
    #[serde(default)]
    pub web_independent_screen: bool,
    #[serde(default)]
    pub web_screen_mode: WebScreenMode,
    #[serde(default)]
    pub web_require_approval: bool,
    #[serde(default = "default_true")]
    pub p2p_relay_enabled: bool,
    #[serde(default)]
    pub ipad: IpadConfigSection,
    #[serde(default)]
    pub web: WebConfigSection,
    #[serde(default)]
    pub polling: PollingConfigSection,
}

impl ConfigPreset {
    pub fn sanitize_name(raw: &str) -> Result<String> {
        let cleaned: String = raw
            .chars()
            .filter(|c| !c.is_control())
            .collect::<String>()
            .trim()
            .to_string();
        if cleaned.is_empty() {
            return Err(anyhow!("预设名称不能为空"));
        }
        if cleaned.chars().count() > 64 {
            return Err(anyhow!("预设名称不能超过 64 个字符"));
        }
        Ok(cleaned)
    }

    pub fn from_user_config(name: String, cfg: &UserConfigFile) -> Self {
        Self {
            name,
            low_power: cfg.low_power,
            allow_input: cfg.allow_input,
            client_cursor: cfg.client_cursor,
            max_extended_screens: cfg.max_extended_screens,
            max_web_viewers: cfg.max_web_viewers,
            auto_max_in_flight: cfg.auto_max_in_flight,
            max_in_flight: cfg.max_in_flight,
            lock_action_ipad: cfg.lock_action_ipad,
            lock_action_web: cfg.lock_action_web,
            lock_delay_secs: cfg.lock_delay_secs,
            web_independent_screen: cfg.web_screen_mode == WebScreenMode::Independent,
            web_screen_mode: cfg.web_screen_mode,
            web_require_approval: cfg.web_require_approval,
            p2p_relay_enabled: cfg.p2p_relay_enabled,
            ipad: cfg.ipad.clone(),
            web: cfg.web.clone(),
            polling: cfg.polling.clone(),
        }
    }

    pub fn apply_into_config(&self, target: &mut UserConfigFile) {
        target.low_power = self.low_power;
        target.allow_input = self.allow_input;
        target.client_cursor = self.client_cursor;
        target.max_extended_screens = self.max_extended_screens;
        target.max_web_viewers = self.max_web_viewers;
        target.auto_max_in_flight = self.auto_max_in_flight;
        target.max_in_flight = self.max_in_flight;
        target.lock_action_ipad = self.lock_action_ipad;
        target.lock_action_web = self.lock_action_web;
        target.lock_delay_secs = self.lock_delay_secs;
        target.web_screen_mode = self.web_screen_mode;
        target.web_independent_screen = self.web_screen_mode == WebScreenMode::Independent;
        target.web_require_approval = self.web_require_approval;
        target.p2p_relay_enabled = self.p2p_relay_enabled;
        target.ipad = self.ipad.clone();
        target.web = self.web.clone();
        target.polling = self.polling.clone();
        target.active_preset = Some(self.name.clone());
    }

    pub fn validate_and_normalize(&mut self) -> Result<()> {
        self.name = Self::sanitize_name(&self.name)?;
        self.max_extended_screens = self.max_extended_screens.min(32);
        self.max_web_viewers = self.max_web_viewers.min(128);
        self.max_in_flight = self.max_in_flight.min(12);
        self.lock_delay_secs = self.lock_delay_secs.min(3600);
        self.ipad.fps = self.ipad.fps.clamp(5, 120);
        self.ipad.bitrate_mbps = self.ipad.bitrate_mbps.clamp(2, 60);
        self.ipad.hidpi = if self.ipad.hidpi >= 2 { 2 } else { 1 };
        if self.ipad.width >= 320 && self.ipad.height >= 240 {
            self.ipad.width = self.ipad.width.clamp(320, 3840) & !1;
            self.ipad.height = self.ipad.height.clamp(240, 2160) & !1;
        } else {
            self.ipad.width = 0;
            self.ipad.height = 0;
        }
        self.ipad.max_pixel_edge = if self.ipad.max_pixel_edge >= 640 {
            self.ipad.max_pixel_edge.clamp(640, 3840) & !1
        } else {
            0
        };
        self.web.width = self.web.width.clamp(320, 3840) & !1;
        self.web.height = self.web.height.clamp(240, 2160) & !1;
        self.web.fps = self.web.fps.clamp(5, 120);
        self.web.bitrate_mbps = self.web.bitrate_mbps.clamp(2, 60);
        self.web.hidpi = if self.web.hidpi >= 2 { 2 } else { 1 };
        self.web.max_pixel_edge = if self.web.max_pixel_edge >= 640 {
            self.web.max_pixel_edge.clamp(640, 3840) & !1
        } else {
            0
        };
        self.polling.normalize();
        if self.web_screen_mode == WebScreenMode::FollowIpad && self.web_independent_screen {
            self.web_screen_mode = WebScreenMode::Independent;
        }
        self.web_independent_screen = self.web_screen_mode == WebScreenMode::Independent;
        if self.low_power {
            self.p2p_relay_enabled = false;
            self.max_web_viewers = 0;
            self.ipad.fps = 15;
            self.ipad.bitrate_mbps = 4;
            self.ipad.hidpi = 1;
        }
        Ok(())
    }

    /// Built-in starter presets always available for one-click switching (can be overridden by
    /// saving a custom preset with the same name in `~/.config/idis.yaml`).
    pub fn builtin_presets() -> Vec<Self> {
        let mut balanced = Self::from_user_config("日常均衡".to_string(), &UserConfigFile::default());
        balanced.ipad.fps = 30;
        balanced.ipad.bitrate_mbps = 16;

        let mut hd = Self::from_user_config("高清副屏".to_string(), &UserConfigFile::default());
        hd.ipad.fps = 60;
        hd.ipad.bitrate_mbps = 24;
        hd.ipad.hidpi = 2;
        hd.ipad.integer_scale = true;

        let mut eco = Self::from_user_config("极简省电".to_string(), &UserConfigFile::default());
        eco.low_power = true;
        eco.p2p_relay_enabled = false;
        eco.max_web_viewers = 0;
        eco.ipad.fps = 15;
        eco.ipad.bitrate_mbps = 4;
        eco.ipad.hidpi = 1;
        eco.polling = PollingConfigSection::low_power_defaults();

        let mut web_share = Self::from_user_config("网页共享".to_string(), &UserConfigFile::default());
        web_share.max_web_viewers = 4;
        web_share.p2p_relay_enabled = true;
        web_share.web.width = 1920;
        web_share.web.height = 1080;
        web_share.web.fps = 30;
        web_share.web.bitrate_mbps = 16;

        vec![balanced, hd, eco, web_share]
    }
}

/// Global iPad display & streaming preferences persisted in `~/.config/idis.yaml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpadConfigSection {
    #[serde(default)]
    pub width: u32,
    #[serde(default)]
    pub height: u32,
    #[serde(default = "default_fps")]
    pub fps: u32,
    #[serde(default = "default_bitrate_mbps")]
    pub bitrate_mbps: u32,
    #[serde(default = "default_hidpi")]
    pub hidpi: u32,
    #[serde(default)]
    pub integer_scale: bool,
    #[serde(default)]
    pub max_pixel_edge: u32,
    #[serde(default = "default_true")]
    pub adaptive_quality: bool,
    #[serde(default)]
    pub abr_sensitivity: AbrSensitivity,
    #[serde(default)]
    pub half_fps_when_unfocused: bool,
}

impl Default for IpadConfigSection {
    fn default() -> Self {
        Self {
            width: 0,
            height: 0,
            fps: default_fps(),
            bitrate_mbps: default_bitrate_mbps(),
            hidpi: default_hidpi(),
            integer_scale: false,
            max_pixel_edge: 0,
            adaptive_quality: true,
            abr_sensitivity: AbrSensitivity::Balanced,
            half_fps_when_unfocused: false,
        }
    }
}

/// Global Web extended-screen preferences persisted in `~/.config/idis.yaml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebConfigSection {
    #[serde(default = "default_web_width")]
    pub width: u32,
    #[serde(default = "default_web_height")]
    pub height: u32,
    #[serde(default = "default_fps")]
    pub fps: u32,
    #[serde(default = "default_bitrate_mbps")]
    pub bitrate_mbps: u32,
    #[serde(default = "default_hidpi")]
    pub hidpi: u32,
    #[serde(default)]
    pub max_pixel_edge: u32,
}

impl Default for WebConfigSection {
    fn default() -> Self {
        Self {
            width: default_web_width(),
            height: default_web_height(),
            fps: default_fps(),
            bitrate_mbps: default_bitrate_mbps(),
            hidpi: default_hidpi(),
            max_pixel_edge: 0,
        }
    }
}

/// Unified YAML configuration model saved at `~/.config/idis.yaml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserConfigFile {
    #[serde(default)]
    pub low_power: bool,
    #[serde(default)]
    pub allow_input: bool,
    #[serde(default)]
    pub client_cursor: bool,
    #[serde(default = "default_max_extended_screens")]
    pub max_extended_screens: usize,
    #[serde(default)]
    pub max_web_viewers: usize,
    #[serde(default = "default_true")]
    pub auto_max_in_flight: bool,
    #[serde(default = "default_max_in_flight")]
    pub max_in_flight: u32,
    #[serde(default)]
    pub lock_action_ipad: LockAction,
    #[serde(default)]
    pub lock_action_web: LockAction,
    #[serde(default = "default_lock_delay_secs")]
    pub lock_delay_secs: u64,
    #[serde(default = "default_port_idle_close_secs")]
    pub port_idle_close_secs: u64,
    #[serde(default)]
    pub web_independent_screen: bool,
    #[serde(default)]
    pub web_screen_mode: WebScreenMode,
    #[serde(default)]
    pub web_require_approval: bool,
    #[serde(default = "default_true")]
    pub p2p_relay_enabled: bool,
    #[serde(default)]
    pub ipad: IpadConfigSection,
    #[serde(default)]
    pub web: WebConfigSection,
    #[serde(default)]
    pub polling: PollingConfigSection,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_preset: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub presets: Vec<ConfigPreset>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub window_rules: Vec<WindowRule>,
    #[serde(default)]
    pub trusted_devices: Vec<TrustedDevice>,
}

impl Default for UserConfigFile {
    fn default() -> Self {
        Self {
            low_power: false,
            allow_input: false,
            client_cursor: false,
            max_extended_screens: default_max_extended_screens(),
            max_web_viewers: 0,
            auto_max_in_flight: true,
            max_in_flight: default_max_in_flight(),
            lock_action_ipad: LockAction::Pause,
            lock_action_web: LockAction::Pause,
            lock_delay_secs: default_lock_delay_secs(),
            port_idle_close_secs: default_port_idle_close_secs(),
            web_independent_screen: false,
            web_screen_mode: WebScreenMode::FollowIpad,
            web_require_approval: false,
            p2p_relay_enabled: true,
            ipad: IpadConfigSection::default(),
            web: WebConfigSection::default(),
            polling: PollingConfigSection::default(),
            active_preset: None,
            presets: Vec::new(),
            window_rules: Vec::new(),
            trusted_devices: Vec::new(),
        }
    }
}

impl UserConfigFile {
    /// Parse YAML, validate every trusted device MAC address, deduplicate by normalized MAC,
    /// and clamp numeric ranges to safe bounds.
    pub fn from_yaml_str(raw: &str) -> Result<Self> {
        let trimmed = raw.trim();
        let mut cfg: Self = if trimmed.is_empty() {
            Self::default()
        } else {
            serde_yaml::from_str(trimmed).context("YAML 语法或字段格式错误")?
        };
        cfg.validate_and_normalize()?;
        Ok(cfg)
    }

    pub fn validate_and_normalize(&mut self) -> Result<()> {
        self.max_extended_screens = self.max_extended_screens.min(32);
        self.max_web_viewers = self.max_web_viewers.min(128);
        self.max_in_flight = self.max_in_flight.min(12);
        self.lock_delay_secs = self.lock_delay_secs.min(3600);
        if self.web_screen_mode == WebScreenMode::FollowIpad && self.web_independent_screen {
            self.web_screen_mode = WebScreenMode::Independent;
        }
        self.web_independent_screen = self.web_screen_mode == WebScreenMode::Independent;

        self.ipad.fps = self.ipad.fps.clamp(5, 120);
        self.ipad.bitrate_mbps = self.ipad.bitrate_mbps.clamp(2, 60);
        self.ipad.hidpi = if self.ipad.hidpi >= 2 { 2 } else { 1 };
        if self.ipad.width >= 320 && self.ipad.height >= 240 {
            self.ipad.width = self.ipad.width.clamp(320, 3840) & !1;
            self.ipad.height = self.ipad.height.clamp(240, 2160) & !1;
        } else {
            self.ipad.width = 0;
            self.ipad.height = 0;
        }
        self.ipad.max_pixel_edge = if self.ipad.max_pixel_edge >= 640 {
            self.ipad.max_pixel_edge.clamp(640, 3840) & !1
        } else {
            0
        };

        self.web.width = self.web.width.clamp(320, 3840) & !1;
        self.web.height = self.web.height.clamp(240, 2160) & !1;
        self.web.fps = self.web.fps.clamp(5, 120);
        self.web.bitrate_mbps = self.web.bitrate_mbps.clamp(2, 60);
        self.web.hidpi = if self.web.hidpi >= 2 { 2 } else { 1 };
        self.web.max_pixel_edge = if self.web.max_pixel_edge >= 640 {
            self.web.max_pixel_edge.clamp(640, 3840) & !1
        } else {
            0
        };
        self.polling.normalize();
        self.active_preset = self
            .active_preset
            .as_deref()
            .and_then(|s| ConfigPreset::sanitize_name(s).ok());
        let mut normalized_presets: Vec<ConfigPreset> = Vec::with_capacity(self.presets.len());
        for (idx, mut p) in std::mem::take(&mut self.presets).into_iter().enumerate() {
            p.validate_and_normalize()
                .with_context(|| format!("presets[{idx}] 配置无效"))?;
            normalized_presets.retain(|existing| existing.name != p.name);
            if normalized_presets.len() >= MAX_CUSTOM_PRESETS {
                return Err(anyhow!("自定义预设数量不能超过 {MAX_CUSTOM_PRESETS} 个"));
            }
            normalized_presets.push(p);
        }
        self.presets = normalized_presets;

        let mut normalized_rules: Vec<WindowRule> = Vec::with_capacity(self.window_rules.len());
        for (idx, mut rule) in std::mem::take(&mut self.window_rules)
            .into_iter()
            .enumerate()
        {
            if rule.id.trim().is_empty() {
                rule.id = format!("rule-{}", idx + 1);
            }
            rule.validate_and_normalize()
                .with_context(|| format!("window_rules[{idx}] 配置无效"))?;
            normalized_rules.retain(|existing| existing.id != rule.id);
            if normalized_rules.len() >= MAX_WINDOW_RULES {
                return Err(anyhow!("窗口规则数量不能超过 {MAX_WINDOW_RULES} 条"));
            }
            normalized_rules.push(rule);
        }
        self.window_rules = normalized_rules;

        let mut normalized: Vec<TrustedDevice> = Vec::with_capacity(self.trusted_devices.len());
        for (idx, mut dev) in std::mem::take(&mut self.trusted_devices)
            .into_iter()
            .enumerate()
        {
            let Some(fp) = normalize_fingerprint(&dev.fingerprint) else {
                if dev.fingerprint.trim().is_empty() && !dev.mac.trim().is_empty() {
                    tracing::warn!(
                        "Dropped legacy MAC-based trusted_devices[{}] entry (name={:?}); please re-approve device to bind its handshake fingerprint",
                        idx,
                        dev.name
                    );
                    continue;
                }
                return Err(anyhow!(
                    "trusted_devices[{}] 的设备指纹无效: {:?}（示例 fp:a1b2c3d4e5f60718293a4b5c）",
                    idx,
                    dev.fingerprint
                ));
            };
            dev.fingerprint = fp;
            dev.mac.clear();
            dev.name = dev.name.replace(['\t', '\r', '\n'], " ").trim().to_string();
            dev.model = dev.model.replace(['\t', '\r', '\n'], " ").trim().to_string();
            dev.uid = dev.uid.replace(['\t', '\r', '\n'], " ").trim().to_string();
            dev.prefs.normalize();
            normalized.retain(|d| d.fingerprint != dev.fingerprint);
            normalized.push(dev);
        }
        self.trusted_devices = normalized;
        Ok(())
    }

    pub fn to_yaml_string(&self) -> Result<String> {
        let body = serde_yaml::to_string(self).context("failed to serialize idis.yaml")?;
        Ok(format!(
            "# idis 配置文件 (~/.config/idis.yaml)\n\
             # 包含全局连接偏好、画质配置与受信设备列表（基于握手属性 SHA-256 指纹认证，每台设备可独立记录偏好）\n\n\
             {body}"
        ))
    }
}

/// Default unified config path: `~/.config/idis.yaml`.
pub fn default_config_path() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        if let Some(home) = std::env::var_os("USERPROFILE") {
            if !home.is_empty() {
                return Some(PathBuf::from(home).join(".config").join("idis.yaml"));
            }
        }
        std::env::var_os("APPDATA").map(|a| PathBuf::from(a).join("idis").join("idis.yaml"))
    }
    #[cfg(not(windows))]
    {
        std::env::var_os("HOME")
            .filter(|h| !h.is_empty())
            .map(|h| PathBuf::from(h).join(".config").join("idis.yaml"))
    }
}

pub fn load_yaml_file(path: &Path) -> Result<UserConfigFile> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read config file {}", path.display()))?;
    UserConfigFile::from_yaml_str(&raw)
}

static YAML_SAVE_SEQ: AtomicU64 = AtomicU64::new(1);

pub fn save_yaml_file(path: &Path, cfg: &UserConfigFile) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create config directory {}", parent.display()))?;
        }
    }
    let content = cfg.to_yaml_string()?;
    let seq = YAML_SAVE_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp_name = format!(
        "{}.{}.{}.tmp",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("idis.yaml"),
        std::process::id(),
        seq
    );
    let tmp_path = path.with_file_name(tmp_name);
    {
        let mut opts = fs::OpenOptions::new();
        opts.create(true).write(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(&tmp_path)
            .with_context(|| format!("failed to open temp config {}", tmp_path.display()))?;
        f.write_all(content.as_bytes())
            .with_context(|| format!("failed to write temp config {}", tmp_path.display()))?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600));
    }
    if let Err(e) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e).with_context(|| format!("failed to replace config {}", path.display()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust::DevicePreferences;

    #[test]
    fn yaml_config_roundtrip_and_mac_validation() {
        let mut cfg = UserConfigFile {
            low_power: true,
            max_web_viewers: 4,
            ..Default::default()
        };
        cfg.ipad.fps = 15;
        cfg.ipad.bitrate_mbps = 4;
        cfg.polling = PollingConfigSection {
            main_loop_ms: 400,
            cursor_poll_ms: 20,
            usb_retry_ms: 2500,
            admin_poll_ms: 4000,
        };
        cfg.trusted_devices.push(TrustedDevice {
            fingerprint: "FP:A1B2C3D4E5F60718293A4B5C".to_string(),
            mac: String::new(),
            uid: "uid-1".to_string(),
            name: "测试设备".to_string(),
            model: "iPad".to_string(),
            trusted_at: 1700000000,
            prefs: DevicePreferences {
                width: Some(1024),
                height: Some(768),
                fps: Some(15),
                bitrate_mbps: Some(4),
                hidpi: Some(2),
                max_pixel_edge: None,
                adaptive_quality: Some(true),
            },
        });
        cfg.validate_and_normalize().unwrap();
        let yaml = cfg.to_yaml_string().unwrap();
        let parsed = UserConfigFile::from_yaml_str(&yaml).unwrap();
        assert!(parsed.low_power);
        assert_eq!(parsed.max_web_viewers, 4);
        assert_eq!(parsed.trusted_devices.len(), 1);
        assert_eq!(
            parsed.trusted_devices[0].fingerprint,
            "fp:a1b2c3d4e5f60718293a4b5c"
        );
        assert_eq!(parsed.trusted_devices[0].prefs.hidpi, Some(2));
        assert_eq!(parsed.trusted_devices[0].prefs.fps, Some(15));
        assert_eq!(parsed.polling.main_loop_ms, 400);
        assert_eq!(parsed.polling.cursor_poll_ms, 20);
        assert_eq!(parsed.polling.usb_retry_ms, 2500);
        assert_eq!(parsed.polling.admin_poll_ms, 4000);

        // Out-of-range polling values are safely clamped on parse
        let clamped = UserConfigFile::from_yaml_str(
            "polling:\n  main_loop_ms: 1\n  cursor_poll_ms: 9999\n  usb_retry_ms: 10\n  admin_poll_ms: 999999\n",
        )
        .unwrap();
        assert_eq!(clamped.polling.main_loop_ms, 100);
        assert_eq!(clamped.polling.cursor_poll_ms, 200);
        assert_eq!(clamped.polling.usb_retry_ms, 250);
        assert_eq!(clamped.polling.admin_poll_ms, 30_000);

        // Named preset roundtrip, deduplication, and low_power normalization
        let mut preset_cfg = UserConfigFile::default();
        let mut p1 = ConfigPreset::from_user_config("会议模式".to_string(), &preset_cfg);
        p1.max_web_viewers = 6;
        p1.web.width = 1920;
        p1.web.height = 1080;
        p1.polling.admin_poll_ms = 3000;
        preset_cfg.presets.push(p1);
        preset_cfg.active_preset = Some("会议模式".to_string());
        let preset_yaml = preset_cfg.to_yaml_string().unwrap();
        let parsed_preset_cfg = UserConfigFile::from_yaml_str(&preset_yaml).unwrap();
        assert_eq!(parsed_preset_cfg.active_preset.as_deref(), Some("会议模式"));
        assert_eq!(parsed_preset_cfg.presets.len(), 1);
        assert_eq!(parsed_preset_cfg.presets[0].max_web_viewers, 6);
        assert_eq!(parsed_preset_cfg.presets[0].web.width, 1920);
        assert_eq!(parsed_preset_cfg.presets[0].polling.admin_poll_ms, 3000);

        let bad_yaml = "trusted_devices:\n  - fingerprint: \"-\"\n    name: bad\n";
        assert!(UserConfigFile::from_yaml_str(bad_yaml).is_err());

        // Legacy MAC-only entries in existing `~/.config/idis.yaml` must migrate cleanly
        // without marking the config file corrupt.
        let legacy_mac_yaml = "\
trusted_devices:
  - mac: \"02:00:00:00:00:01\"
    name: LegacyMacPad
  - fingerprint: \"FP:A1B2C3D4E5F60718293A4B5C\"
    name: FingerprintPad
";
        let migrated = UserConfigFile::from_yaml_str(legacy_mac_yaml).unwrap();
        assert_eq!(migrated.trusted_devices.len(), 1);
        assert_eq!(
            migrated.trusted_devices[0].fingerprint,
            "fp:a1b2c3d4e5f60718293a4b5c"
        );
    }
}
