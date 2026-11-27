//! Unified YAML configuration file (`~/.config/idis.yaml`) storing trusted devices
//! (deterministic handshake fingerprint auth), per-device connection preferences, and global host settings.

use crate::config::{AbrSensitivity, LockAction, WebScreenMode};
use crate::platform::WindowMoveLayout;
use crate::protocol::messages::{
    InputEvent, KEY_MOD_ALT, KEY_MOD_CTRL, KEY_MOD_META, KEY_MOD_SHIFT,
};
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

fn default_gesture_edge_zone_pct() -> u8 {
    8
}

fn default_gesture_min_swipe_pct() -> u8 {
    6
}

fn default_left_top_action() -> GestureAction {
    GestureAction::Hotkey {
        keys: "ctrl+left".to_string(),
    }
}

fn default_left_bottom_action() -> GestureAction {
    GestureAction::Hotkey {
        keys: "cmd+tab".to_string(),
    }
}

fn default_right_top_action() -> GestureAction {
    GestureAction::TogglePause
}

fn default_right_bottom_action() -> GestureAction {
    GestureAction::ToggleInput
}

/// The 4 supported iPad screen edge-swipe gesture slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeGestureSlot {
    LeftTopSwipeRight,
    LeftBottomSwipeRight,
    RightTopSwipeLeft,
    RightBottomSwipeLeft,
}

impl EdgeGestureSlot {
    pub const ALL: [Self; 4] = [
        Self::LeftTopSwipeRight,
        Self::LeftBottomSwipeRight,
        Self::RightTopSwipeLeft,
        Self::RightBottomSwipeLeft,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::LeftTopSwipeRight => "left_top_swipe_right",
            Self::LeftBottomSwipeRight => "left_bottom_swipe_right",
            Self::RightTopSwipeLeft => "right_top_swipe_left",
            Self::RightBottomSwipeLeft => "right_bottom_swipe_left",
        }
    }

    pub fn label_zh(self) -> &'static str {
        match self {
            Self::LeftTopSwipeRight => "左边缘上半向右短滑",
            Self::LeftBottomSwipeRight => "左边缘下半向右短滑",
            Self::RightTopSwipeLeft => "右边缘上半向左短滑",
            Self::RightBottomSwipeLeft => "右边缘下半向左短滑",
        }
    }

    pub fn is_left_edge(self) -> bool {
        matches!(self, Self::LeftTopSwipeRight | Self::LeftBottomSwipeRight)
    }
}

/// Parsed cross-platform keyboard shortcut ready for `CaptureHandle::inject_input`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedHotkey {
    pub canonical: String,
    pub key_code: Option<u16>,
    pub ch: Option<u16>,
    pub modifiers: u8,
}

impl ParsedHotkey {
    pub fn to_input_event(&self) -> InputEvent {
        if self.modifiers != 0 {
            InputEvent::KeyModified {
                key_code: self.key_code,
                ch: self.ch,
                modifiers: self.modifiers,
            }
        } else if let Some(key_code) = self.key_code {
            InputEvent::KeySpecial { key_code }
        } else {
            InputEvent::KeyUnicode {
                ch: self.ch.unwrap_or(b' ' as u16),
            }
        }
    }
}

/// Parse and canonicalize a hotkey string such as `"ctrl+left"`, `"cmd+shift+4"`, `"cmd+tab"`, or `"space"`.
pub fn parse_hotkey_spec(raw: &str) -> Result<ParsedHotkey> {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .to_string();
    if cleaned.is_empty() {
        return Err(anyhow!("快捷键不能为空（例如 ctrl+left、cmd+tab、space）"));
    }
    if cleaned.len() > 64 {
        return Err(anyhow!("快捷键长度不能超过 64 个字符"));
    }

    let mut modifiers = 0u8;
    let mut key_code: Option<u16> = None;
    let mut ch: Option<u16> = None;
    let mut canonical_key: Option<String> = None;

    for raw_part in cleaned.split('+') {
        let part = raw_part.trim().to_ascii_lowercase();
        if part.is_empty() {
            return Err(anyhow!("快捷键格式无效: {cleaned:?}（存在多余的 + 号）"));
        }
        match part.as_str() {
            "ctrl" | "control" => modifiers |= KEY_MOD_CTRL,
            "alt" | "opt" | "option" => modifiers |= KEY_MOD_ALT,
            "shift" => modifiers |= KEY_MOD_SHIFT,
            "cmd" | "command" | "meta" | "super" | "win" => modifiers |= KEY_MOD_META,
            other => {
                if canonical_key.is_some() {
                    return Err(anyhow!(
                        "快捷键只能包含一个主键，发现多个非修饰键: {cleaned:?}"
                    ));
                }
                let (kc, ch_val, name): (Option<u16>, Option<u16>, String) = match other {
                    "backspace" | "bs" => (Some(0x33), None, "backspace".to_string()),
                    "return" | "enter" => (Some(0x24), None, "return".to_string()),
                    "tab" => (Some(0x30), None, "tab".to_string()),
                    "esc" | "escape" => (Some(0x35), None, "esc".to_string()),
                    "delete" | "del" | "forwarddelete" => (Some(0x75), None, "delete".to_string()),
                    "up" | "arrowup" => (Some(0x7E), None, "up".to_string()),
                    "down" | "arrowdown" => (Some(0x7D), None, "down".to_string()),
                    "left" | "arrowleft" => (Some(0x7B), None, "left".to_string()),
                    "right" | "arrowright" => (Some(0x7C), None, "right".to_string()),
                    "home" => (Some(0x73), None, "home".to_string()),
                    "end" => (Some(0x77), None, "end".to_string()),
                    "pageup" | "pgup" => (Some(0x74), None, "pageup".to_string()),
                    "pagedown" | "pgdn" => (Some(0x79), None, "pagedown".to_string()),
                    "space" => (None, Some(b' ' as u16), "space".to_string()),
                    s if s.len() == 1 => {
                        let b = s.as_bytes()[0];
                        let supported = b.is_ascii_lowercase()
                            || b.is_ascii_digit()
                            || matches!(
                                b,
                                b'-' | b'='
                                    | b'['
                                    | b']'
                                    | b';'
                                    | b'\''
                                    | b','
                                    | b'.'
                                    | b'/'
                                    | b'\\'
                                    | b'`'
                            );
                        if !supported {
                            return Err(anyhow!("不支持的快捷键字符: {other:?}"));
                        }
                        (None, Some(b as u16), (b as char).to_string())
                    }
                    _ => {
                        return Err(anyhow!(
                            "不支持的按键名称: {other:?}（支持字母、数字、方向键 left/right/up/down、tab、space、esc、return、backspace、delete、home、end、pageup、pagedown）"
                        ));
                    }
                };
                key_code = kc;
                ch = ch_val;
                canonical_key = Some(name);
            }
        }
    }

    let Some(key_name) = canonical_key else {
        return Err(anyhow!("快捷键缺少主键（不能只有修饰键）: {cleaned:?}"));
    };

    let mut parts: Vec<&str> = Vec::with_capacity(5);
    if (modifiers & KEY_MOD_CTRL) != 0 {
        parts.push("ctrl");
    }
    if (modifiers & KEY_MOD_ALT) != 0 {
        parts.push("alt");
    }
    if (modifiers & KEY_MOD_SHIFT) != 0 {
        parts.push("shift");
    }
    if (modifiers & KEY_MOD_META) != 0 {
        parts.push("cmd");
    }
    parts.push(&key_name);

    Ok(ParsedHotkey {
        canonical: parts.join("+"),
        key_code,
        ch,
        modifiers,
    })
}

/// Action triggered by an iPad edge-swipe gesture.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GestureAction {
    /// Disabled; touches pass through directly as normal mouse input.
    #[default]
    None,
    /// Soft-toggle streaming pause/resume while keeping the session and virtual display alive.
    TogglePause,
    /// Completely disconnect the current iPad session and release its virtual display.
    Disconnect,
    /// Toggle remote touch/keyboard input (`allow_input`, acting as a touch-lock switch).
    ToggleInput,
    /// Toggle global low-power mode.
    ToggleLowPower,
    /// Cycle through available presets (built-in and custom).
    CyclePreset,
    /// Apply a specific named preset.
    ApplyPreset { preset: String },
    /// Request an immediate IDR keyframe refresh.
    RequestKeyframe,
    /// Capture a PNG screenshot of the iPad screen into `<screenshot_dir>/idis-YYYY-MM-DD/`.
    Screenshot,
    /// Inject a custom keyboard shortcut (e.g. `ctrl+left`, `cmd+tab`, `ctrl+up`).
    Hotkey { keys: String },
    /// Inject a mouse right-click at the swipe start location.
    RightClick,
    /// Inject a vertical mouse wheel scroll (`delta` clamped to `-1000..=1000`, non-zero).
    Scroll { delta: i32 },
}

impl GestureAction {
    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }

    /// Whether executing this action injects OS-level keyboard/mouse input (requires `allow_input`
    /// and OS Accessibility permission). Session-control actions (`TogglePause`, `Disconnect`,
    /// `ToggleInput`, `ToggleLowPower`, `CyclePreset`, `ApplyPreset`, `RequestKeyframe`) do not
    /// inject OS input and can operate even when touch-locked (`allow_input == false`).
    pub fn requires_host_input(&self) -> bool {
        matches!(
            self,
            Self::Hotkey { .. } | Self::RightClick | Self::Scroll { .. }
        )
    }

    pub fn validate_and_normalize(&mut self) -> Result<()> {
        match self {
            Self::ApplyPreset { preset } => {
                *preset = ConfigPreset::sanitize_name(preset)?;
            }
            Self::Hotkey { keys } => {
                let parsed = parse_hotkey_spec(keys)?;
                *keys = parsed.canonical;
            }
            Self::Scroll { delta } => {
                *delta = (*delta).clamp(-1000, 1000);
                if *delta == 0 {
                    *delta = -120;
                }
            }
            _ => {}
        }
        Ok(())
    }

    pub fn describe(&self) -> String {
        match self {
            Self::None => "无动作".to_string(),
            Self::TogglePause => "暂停/恢复投屏".to_string(),
            Self::Disconnect => "断开投屏".to_string(),
            Self::ToggleInput => "开关远程触控".to_string(),
            Self::ToggleLowPower => "开关省电模式".to_string(),
            Self::CyclePreset => "循环切换预设".to_string(),
            Self::ApplyPreset { preset } => format!("应用预设: {preset}"),
            Self::RequestKeyframe => "刷新关键帧".to_string(),
            Self::Screenshot => "截屏并保存".to_string(),
            Self::Hotkey { keys } => format!("快捷键: {keys}"),
            Self::RightClick => "模拟鼠标右键".to_string(),
            Self::Scroll { delta } => {
                if *delta > 0 {
                    format!("向上滚动 ({delta})")
                } else {
                    format!("向下滚动 ({delta})")
                }
            }
        }
    }
}

/// Persistent iPad edge-swipe gesture mapping configuration saved in `~/.config/idis.yaml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeGesturesConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Edge trigger zone width as a percentage of display width (`3..=25`, default `8`).
    #[serde(default = "default_gesture_edge_zone_pct")]
    pub edge_zone_pct: u8,
    /// Minimum inward horizontal swipe distance as a percentage of display width (`3..=30`, default `6`).
    #[serde(default = "default_gesture_min_swipe_pct")]
    pub min_swipe_pct: u8,
    /// Base directory where screenshot gestures save `idis-YYYY-MM-DD/` folders (empty = `~/Pictures`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub screenshot_dir: String,
    /// Left edge upper half -> swipe right.
    #[serde(default = "default_left_top_action")]
    pub left_top_swipe_right: GestureAction,
    /// Left edge lower half -> swipe right.
    #[serde(default = "default_left_bottom_action")]
    pub left_bottom_swipe_right: GestureAction,
    /// Right edge upper half -> swipe left.
    #[serde(default = "default_right_top_action")]
    pub right_top_swipe_left: GestureAction,
    /// Right edge lower half -> swipe left.
    #[serde(default = "default_right_bottom_action")]
    pub right_bottom_swipe_left: GestureAction,
}

impl Default for EdgeGesturesConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            edge_zone_pct: default_gesture_edge_zone_pct(),
            min_swipe_pct: default_gesture_min_swipe_pct(),
            screenshot_dir: String::new(),
            left_top_swipe_right: default_left_top_action(),
            left_bottom_swipe_right: default_left_bottom_action(),
            right_top_swipe_left: default_right_top_action(),
            right_bottom_swipe_left: default_right_bottom_action(),
        }
    }
}

impl EdgeGesturesConfig {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    pub fn action_for(&self, slot: EdgeGestureSlot) -> &GestureAction {
        match slot {
            EdgeGestureSlot::LeftTopSwipeRight => &self.left_top_swipe_right,
            EdgeGestureSlot::LeftBottomSwipeRight => &self.left_bottom_swipe_right,
            EdgeGestureSlot::RightTopSwipeLeft => &self.right_top_swipe_left,
            EdgeGestureSlot::RightBottomSwipeLeft => &self.right_bottom_swipe_left,
        }
    }

    pub fn has_any_active_action(&self) -> bool {
        self.enabled
            && EdgeGestureSlot::ALL
                .iter()
                .any(|&slot| !self.action_for(slot).is_none())
    }

    pub fn has_any_session_control_action(&self) -> bool {
        self.enabled
            && EdgeGestureSlot::ALL.iter().any(|&slot| {
                let a = self.action_for(slot);
                !a.is_none() && !a.requires_host_input()
            })
    }

    pub fn validate_and_normalize(&mut self) -> Result<()> {
        self.edge_zone_pct = self.edge_zone_pct.clamp(3, 25);
        self.min_swipe_pct = self.min_swipe_pct.clamp(3, 30);
        self.screenshot_dir = self
            .screenshot_dir
            .chars()
            .filter(|c| !c.is_control())
            .collect::<String>()
            .trim()
            .chars()
            .take(512)
            .collect();
        self.left_top_swipe_right
            .validate_and_normalize()
            .context("gestures.left_top_swipe_right 配置无效")?;
        self.left_bottom_swipe_right
            .validate_and_normalize()
            .context("gestures.left_bottom_swipe_right 配置无效")?;
        self.right_top_swipe_left
            .validate_and_normalize()
            .context("gestures.right_top_swipe_left 配置无效")?;
        self.right_bottom_swipe_left
            .validate_and_normalize()
            .context("gestures.right_bottom_swipe_left 配置无效")?;
        Ok(())
    }
}

/// Resolve the default base directory for saved screenshots (`~/Pictures`, or home/current dir fallback).
pub fn default_screenshot_base_dir() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
        let home_path = PathBuf::from(home);
        if !home_path.as_os_str().is_empty() {
            return home_path.join("Pictures");
        }
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

/// Resolve a user-configured screenshot base directory (empty -> default, leading `~` expanded).
pub fn resolve_screenshot_base_dir(configured: &str) -> PathBuf {
    let trimmed = configured.trim();
    if trimmed.is_empty() {
        return default_screenshot_base_dir();
    }
    if trimmed == "~" {
        if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
            if !home.is_empty() {
                return PathBuf::from(home);
            }
        }
    } else if let Some(rest) = trimmed
        .strip_prefix("~/")
        .or_else(|| trimmed.strip_prefix("~\\"))
    {
        if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
            if !home.is_empty() {
                return PathBuf::from(home).join(rest);
            }
        }
    }
    PathBuf::from(trimmed)
}

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
    #[serde(default, skip_serializing_if = "EdgeGesturesConfig::is_default")]
    pub gestures: EdgeGesturesConfig,
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
            gestures: EdgeGesturesConfig::default(),
            trusted_devices: Vec::new(),
        }
    }
}

pub const MAX_TRUSTED_DEVICES: usize = 256;
pub const MAX_YAML_CONFIG_BYTES: usize = 256 * 1024;

/// Reject YAML anchors (`&name`) and aliases (`*name`) outside quoted strings before passing
/// untrusted YAML to `serde_yaml::from_str`, preventing exponential "Billion Laughs" OOM bombs.
fn contains_yaml_anchor_or_alias(raw: &str) -> bool {
    for line in raw.lines() {
        let bytes = line.as_bytes();
        let mut i = 0usize;
        let mut in_single = false;
        let mut in_double = false;
        while i < bytes.len() {
            let b = bytes[i];
            if in_double {
                if b == b'\\' {
                    i += 2;
                    continue;
                }
                if b == b'"' {
                    in_double = false;
                }
                i += 1;
                continue;
            }
            if in_single {
                if b == b'\'' {
                    if i + 1 < bytes.len() && bytes[i + 1] == b'\'' {
                        i += 2;
                        continue;
                    }
                    in_single = false;
                }
                i += 1;
                continue;
            }
            match b {
                b'#' => break, // rest of line is YAML comment
                b'"' => in_double = true,
                b'\'' => in_single = true,
                b'&' | b'*' => {
                    let prev_delim = i == 0
                        || matches!(
                            bytes[i - 1],
                            b' ' | b'\t' | b':' | b'-' | b'[' | b'{' | b','
                        );
                    let next_ident = bytes
                        .get(i + 1)
                        .is_some_and(|&n| n.is_ascii_alphanumeric() || n == b'_' || n == b'-');
                    if prev_delim && next_ident {
                        return true;
                    }
                }
                _ => {}
            }
            i += 1;
        }
    }
    false
}

impl UserConfigFile {
    /// Parse YAML, validate every trusted device fingerprint, deduplicate,
    /// reject YAML anchor/alias bombs and oversized files, and clamp numeric ranges to safe bounds.
    pub fn from_yaml_str(raw: &str) -> Result<Self> {
        if raw.len() > MAX_YAML_CONFIG_BYTES {
            return Err(anyhow!(
                "YAML 配置文件过大（{} 字节，上限 {} 字节）",
                raw.len(),
                MAX_YAML_CONFIG_BYTES
            ));
        }
        if contains_yaml_anchor_or_alias(raw) {
            return Err(anyhow!("YAML 配置禁止使用锚点（&）或别名（*）引用"));
        }
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
        self.port_idle_close_secs = self.port_idle_close_secs.min(86_400);
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
        let mut normalized_presets: Vec<ConfigPreset> =
            Vec::with_capacity(self.presets.len().min(MAX_CUSTOM_PRESETS));
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

        let raw_rules = std::mem::take(&mut self.window_rules);
        let mut used_rule_ids: std::collections::HashSet<String> = raw_rules
            .iter()
            .map(|r| r.id.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let mut normalized_rules: Vec<WindowRule> =
            Vec::with_capacity(raw_rules.len().min(MAX_WINDOW_RULES));
        let mut auto_rule_seq = 1usize;
        for (idx, mut rule) in raw_rules.into_iter().enumerate() {
            if rule.id.trim().is_empty() {
                let mut candidate = format!("rule-{auto_rule_seq}");
                while !used_rule_ids.insert(candidate.clone()) {
                    auto_rule_seq += 1;
                    candidate = format!("rule-{auto_rule_seq}");
                }
                auto_rule_seq += 1;
                rule.id = candidate;
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
        self.gestures.validate_and_normalize()?;

        let raw_devices = std::mem::take(&mut self.trusted_devices);
        let mut normalized: Vec<TrustedDevice> =
            Vec::with_capacity(raw_devices.len().min(MAX_TRUSTED_DEVICES));
        let clean_field = |s: &str| -> String {
            s.chars()
                .map(|c| if c.is_control() { ' ' } else { c })
                .collect::<String>()
                .trim()
                .chars()
                .take(128)
                .collect()
        };
        for (idx, mut dev) in raw_devices.into_iter().enumerate() {
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
            dev.name = clean_field(&dev.name);
            dev.model = clean_field(&dev.model);
            dev.uid = clean_field(&dev.uid);
            dev.prefs.normalize();
            normalized.retain(|d| d.fingerprint != dev.fingerprint);
            if normalized.len() >= MAX_TRUSTED_DEVICES {
                return Err(anyhow!("受信设备数量不能超过 {MAX_TRUSTED_DEVICES} 台"));
            }
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
    let meta = fs::metadata(path)
        .with_context(|| format!("failed to stat config file {}", path.display()))?;
    if meta.len() > MAX_YAML_CONFIG_BYTES as u64 {
        return Err(anyhow!(
            "config file {} is too large ({} bytes, max {})",
            path.display(),
            meta.len(),
            MAX_YAML_CONFIG_BYTES
        ));
    }
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read config file {}", path.display()))?;
    if raw.trim().is_empty() {
        return Err(anyhow!(
            "config file {} is empty (0 bytes or whitespace only); refusing to overwrite with defaults",
            path.display()
        ));
    }
    UserConfigFile::from_yaml_str(&raw)
}

/// Best-effort startup cleanup of stale `{file_name}.{pid}.{seq}.tmp` files left behind by a
/// prior crashed/SIGKILLed process (never removes `.tmp` files owned by the current PID).
pub fn sweep_stale_tmp_files(target_path: &Path) {
    let Some(parent) = target_path.parent().filter(|p| !p.as_os_str().is_empty()) else {
        return;
    };
    let Some(base) = target_path.file_name().and_then(|n| n.to_str()) else {
        return;
    };
    let prefix = format!("{base}.");
    let my_pid = std::process::id().to_string();
    let Ok(entries) = fs::read_dir(parent) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if let Some(rest) = name_str
            .strip_prefix(&prefix)
            .and_then(|r| r.strip_suffix(".tmp"))
        {
            if let Some((pid_part, seq_part)) = rest.split_once('.') {
                if pid_part != my_pid
                    && !pid_part.is_empty()
                    && pid_part.bytes().all(|b| b.is_ascii_digit())
                    && !seq_part.is_empty()
                    && seq_part.bytes().all(|b| b.is_ascii_digit())
                {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
    }
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
    let base_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("idis.yaml");
    let pid = std::process::id();
    let (tmp_path, mut f) = loop {
        let seq = YAML_SAVE_SEQ.fetch_add(1, Ordering::Relaxed);
        let candidate = path.with_file_name(format!("{base_name}.{pid}.{seq}.tmp"));
        let mut opts = fs::OpenOptions::new();
        opts.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        match opts.open(&candidate) {
            Ok(file) => break (candidate, file),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("failed to open temp config {}", candidate.display()));
            }
        }
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = f.set_permissions(fs::Permissions::from_mode(0o600));
    }
    if let Err(e) = f.write_all(content.as_bytes()).and_then(|()| f.sync_all()) {
        drop(f);
        let _ = fs::remove_file(&tmp_path);
        return Err(e)
            .with_context(|| format!("failed to write/sync temp config {}", tmp_path.display()));
    }
    drop(f);
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

    #[test]
    fn edge_gestures_yaml_and_hotkey_validation_roundtrip() {
        let hk = parse_hotkey_spec("  Cmd + Shift + ArrowLeft ").unwrap();
        assert_eq!(hk.canonical, "shift+cmd+left");
        assert_eq!(hk.key_code, Some(0x7B));
        assert_eq!(hk.modifiers, KEY_MOD_SHIFT | KEY_MOD_META);

        assert!(parse_hotkey_spec("").is_err());
        assert!(parse_hotkey_spec("cmd+ctrl").is_err());
        assert!(parse_hotkey_spec("cmd+unknownkey").is_err());
        assert!(parse_hotkey_spec("cmd+a+b").is_err());

        // Default config omits `gestures:` to stay clean and backward-compatible.
        let default_yaml = UserConfigFile::default().to_yaml_string().unwrap();
        assert!(!default_yaml.contains("gestures:"));

        // Custom 4-slot config roundtrips and clamps percentages.
        let yaml = "\
gestures:
  enabled: true
  edge_zone_pct: 99
  min_swipe_pct: 1
  screenshot_dir: ~/Pictures/MyShots
  left_top_swipe_right:
    kind: hotkey
    keys: Command+Tab
  left_bottom_swipe_right:
    kind: screenshot
  right_top_swipe_left:
    kind: toggle_pause
  right_bottom_swipe_left:
    kind: disconnect
";
        let parsed = UserConfigFile::from_yaml_str(yaml).unwrap();
        assert!(parsed.gestures.enabled);
        assert_eq!(parsed.gestures.edge_zone_pct, 25);
        assert_eq!(parsed.gestures.min_swipe_pct, 3);
        assert_eq!(parsed.gestures.screenshot_dir, "~/Pictures/MyShots");
        assert_eq!(
            parsed.gestures.left_top_swipe_right,
            GestureAction::Hotkey {
                keys: "cmd+tab".to_string()
            }
        );
        assert_eq!(
            parsed.gestures.left_bottom_swipe_right,
            GestureAction::Screenshot
        );
        assert!(resolve_screenshot_base_dir("/tmp/custom-shots").ends_with("custom-shots"));
        assert!(resolve_screenshot_base_dir("~/Pictures/MyShots").ends_with("Pictures/MyShots"));
        assert_eq!(
            parsed.gestures.right_top_swipe_left,
            GestureAction::TogglePause
        );
        assert_eq!(
            parsed.gestures.right_bottom_swipe_left,
            GestureAction::Disconnect
        );

        let re_yaml = parsed.to_yaml_string().unwrap();
        assert!(re_yaml.contains("gestures:"));
        let re_parsed = UserConfigFile::from_yaml_str(&re_yaml).unwrap();
        assert_eq!(re_parsed.gestures, parsed.gestures);

        let bad_hotkey_yaml = "\
gestures:
  enabled: true
  left_top_swipe_right:
    kind: hotkey
    keys: ctrl+notakey
";
        assert!(UserConfigFile::from_yaml_str(bad_hotkey_yaml).is_err());
    }
}
