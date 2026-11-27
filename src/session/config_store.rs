use super::flow_control::LowPowerSnapshot;
use super::{
    default_lock_delay_secs, default_max_extended_screens, default_max_in_flight, default_true,
    default_web_bitrate_mbps, default_web_fps, default_web_hidpi, PollingPatch, SessionRegistry,
    VideoSettings, VideoSettingsPatch,
};
use crate::config::{LockAction, QualityPreset, WebScreenMode};
use crate::platform::{CaptureHandle, IPAD_MAX_PIXEL_EDGE, WEB_MAX_PIXEL_EDGE};
use crate::protocol::messages::ClientHandshake;
use crate::trust::{DevicePreferences, TrustedDevice};
use crate::user_config::{
    load_yaml_file, save_yaml_file, ConfigPreset, IpadConfigSection, PollingConfigSection,
    UserConfigFile, WebConfigSection, MAX_CUSTOM_PRESETS,
};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct PersistedSettings {
    #[serde(default)]
    pub(super) width: u32,
    #[serde(default)]
    pub(super) height: u32,
    #[serde(default)]
    pub(super) web_width: u32,
    #[serde(default)]
    pub(super) web_height: u32,
    #[serde(default = "default_web_fps")]
    pub(super) web_fps: u32,
    #[serde(default = "default_web_bitrate_mbps")]
    pub(super) web_bitrate_mbps: u32,
    #[serde(default = "default_web_hidpi")]
    pub(super) web_hidpi: u32,
    #[serde(default)]
    pub(super) web_max_pixel_edge: u32,
    #[serde(default = "default_web_fps")]
    pub(super) fps: u32,
    #[serde(default = "default_web_bitrate_mbps")]
    pub(super) bitrate_mbps: u32,
    #[serde(default = "default_web_hidpi")]
    pub(super) hidpi: u32,
    #[serde(default)]
    pub(super) integer_scale: bool,
    #[serde(default)]
    pub(super) max_pixel_edge: u32,
    #[serde(default = "default_true")]
    pub(super) adaptive_quality: bool,
    #[serde(default)]
    pub(super) web_independent_screen: bool,
    #[serde(default, alias = "lock_action")]
    pub(super) lock_action_ipad: LockAction,
    #[serde(default)]
    pub(super) lock_action_web: LockAction,
    #[serde(default = "default_lock_delay_secs")]
    pub(super) lock_delay_secs: u64,
    #[serde(default = "default_true")]
    pub(super) auto_max_in_flight: bool,
    #[serde(default = "default_max_in_flight")]
    pub(super) max_in_flight: u32,
    #[serde(default = "default_max_extended_screens")]
    pub(super) max_extended_screens: usize,
    #[serde(default)]
    pub(super) max_web_viewers: usize,
    #[serde(default)]
    pub(super) low_power: bool,
}

pub(super) fn has_cli_flag(flag: &str) -> bool {
    let prefix = format!("{flag}=");
    std::env::args().skip(1).any(|a| a == flag || a.starts_with(&prefix))
}

pub(super) fn load_persisted_settings(path: &std::path::Path) -> Option<PersistedSettings> {
    let content = std::fs::read_to_string(path).ok()?;
    match serde_json::from_str::<PersistedSettings>(&content) {
        Ok(s) => {
            info!(
                "Loaded persisted settings from {} (ipad={}x{} {}fps {}Mbps {}x, web={}x{} {}fps {}Mbps {}x, lock_ipad={:?}, lock_web={:?}, max_ext={}, max_web_viewers={})",
                path.display(),
                s.width,
                s.height,
                s.fps,
                s.bitrate_mbps,
                s.hidpi,
                s.web_width,
                s.web_height,
                s.web_fps,
                s.web_bitrate_mbps,
                s.web_hidpi,
                s.lock_action_ipad,
                s.lock_action_web,
                s.max_extended_screens,
                s.max_web_viewers
            );
            Some(s)
        }
        Err(e) => {
            warn!("Ignoring invalid persisted settings file {}: {e}", path.display());
            None
        }
    }
}

#[cfg(test)]
pub(super) fn save_persisted_settings(path: &std::path::Path, settings: &PersistedSettings) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(settings)?;
    let tmp_name = format!(
        "{}.{}.tmp",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("settings.json"),
        std::process::id()
    );
    let tmp_path = path.with_file_name(tmp_name);
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).write(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        use std::io::Write;
        let mut f = opts.open(&tmp_path)?;
        f.write_all(json.as_bytes())?;
    }
    if let Err(e) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e.into());
    }
    Ok(())
}


impl SessionRegistry {
    pub fn export_user_config(&self) -> UserConfigFile {
        let v = self.video_settings();
        UserConfigFile {
            low_power: self.is_low_power(),
            allow_input: self.is_input_allowed(),
            client_cursor: self.is_client_cursor(),
            max_extended_screens: self.max_extended_screens(),
            max_web_viewers: self.max_web_viewers(),
            auto_max_in_flight: self.is_auto_max_in_flight(),
            max_in_flight: self.max_in_flight(),
            lock_action_ipad: self.lock_action_ipad(),
            lock_action_web: self.lock_action_web(),
            lock_delay_secs: self.lock_delay_secs(),
            port_idle_close_secs: self.port_idle_close_secs(),
            web_independent_screen: self.is_web_independent_screen(),
            web_screen_mode: self.web_screen_mode(),
            web_require_approval: self.is_web_require_approval(),
            p2p_relay_enabled: self.is_p2p_relay_enabled(),
            ipad: IpadConfigSection {
                width: v.width,
                height: v.height,
                fps: v.fps,
                bitrate_mbps: v.bitrate_mbps,
                hidpi: v.hidpi,
                integer_scale: v.integer_scale,
                max_pixel_edge: v.max_pixel_edge,
                adaptive_quality: v.adaptive_quality,
                abr_sensitivity: v.abr_sensitivity,
                half_fps_when_unfocused: v.half_fps_when_unfocused,
            },
            web: WebConfigSection {
                width: v.web_width,
                height: v.web_height,
                fps: v.web_fps,
                bitrate_mbps: v.web_bitrate_mbps,
                hidpi: v.web_hidpi,
                max_pixel_edge: v.web_max_pixel_edge,
            },
            polling: self.polling_config(),
            active_preset: self.active_preset.lock().unwrap().clone(),
            presets: self.presets.lock().unwrap().clone(),
            window_rules: self.window_rules.lock().unwrap().clone(),
            gestures: self.gestures_config(),
            trusted_devices: self.trust_store.list(),
        }
    }

    /// Snapshot the persisted YAML baseline + current trusted devices (excluding temporary CLI overrides).
    pub fn export_persisted_config(&self) -> UserConfigFile {
        let mut cfg = self.persisted_baseline.lock().unwrap().clone();
        cfg.trusted_devices = self.trust_store.list();
        cfg
    }

    /// Update specific fields on the persisted baseline (never polluting disk with one-shot CLI
    /// flags like `--allow-input` or `--fps 60`) and atomically write `~/.config/idis.yaml`.
    pub(super) fn persist_config_patch(&self, mutate: impl FnOnce(&mut UserConfigFile)) {
        let Some(ref path) = self.config_path else {
            let mut base = self.persisted_baseline.lock().unwrap();
            mutate(&mut base);
            return;
        };
        if self.config_read_only_corrupt.load(Ordering::Acquire) {
            warn!(
                "Skipping automatic write to {} because the existing file failed to parse at startup (fix it and reload, or explicitly save valid YAML in Web Admin)",
                path.display()
            );
            return;
        }
        let _guard = self.settings_save_lock.lock().unwrap();
        let mut candidate = self.persisted_baseline.lock().unwrap().clone();
        mutate(&mut candidate);
        let mut snapshot = candidate.clone();
        snapshot.trusted_devices = self.trust_store.list();
        // Write to disk FIRST (CFG-3) so an I/O failure never leaves `persisted_baseline` ahead of disk.
        match save_yaml_file(path, &snapshot) {
            Ok(()) => {
                *self.persisted_baseline.lock().unwrap() = candidate;
            }
            Err(e) => {
                warn!("Failed to persist config to {}: {e:#}", path.display());
            }
        }
    }

    /// Persist the unified `~/.config/idis.yaml` atomically to disk from `persisted_baseline` +
    /// current `trusted_devices` (preserving disk baseline values for CLI-overridden fields).
    pub fn save_config_file(&self) -> Result<()> {
        let Some(ref path) = self.config_path else {
            return Ok(());
        };
        if self.config_read_only_corrupt.load(Ordering::Acquire) {
            return Err(anyhow!(
                "配置文件 {} 存在语法错误，当前处于只读保护模式；请先在「配置文件」修复并保存有效 YAML 后再修改受信设备",
                path.display()
            ));
        }
        let _guard = self.settings_save_lock.lock().unwrap();
        let mut snapshot = self.persisted_baseline.lock().unwrap().clone();
        snapshot.trusted_devices = self.trust_store.list();
        save_yaml_file(path, &snapshot)
    }

    /// Trust a device by handshake fingerprint and immediately persist `~/.config/idis.yaml`
    /// (rolling back memory on I/O failure, serialized under `settings_save_lock` so concurrent
    /// `persist_config_patch` calls never snapshot an uncommitted trust mutation).
    pub fn trust_device_and_save(
        &self,
        fingerprint: &str,
        uid: &str,
        name: &str,
        model: &str,
    ) -> Result<TrustedDevice> {
        let _tx = self.config_tx_lock.lock().unwrap();
        let _save = self.settings_save_lock.lock().unwrap();
        if let Some(ref path) = self.config_path {
            if self.config_read_only_corrupt.load(Ordering::Acquire) {
                return Err(anyhow!(
                    "配置文件 {} 存在语法错误，当前处于只读保护模式；请先在「配置文件」修复并保存有效 YAML 后再修改受信设备",
                    path.display()
                ));
            }
        }
        let prev_devices = self.trust_store.list();
        let rec = self.trust_store.trust_device(fingerprint, uid, name, model)?;
        if let Some(ref path) = self.config_path {
            let mut snapshot = self.persisted_baseline.lock().unwrap().clone();
            snapshot.trusted_devices = self.trust_store.list();
            if let Err(e) = save_yaml_file(path, &snapshot) {
                self.trust_store.replace_all_in_memory(prev_devices);
                return Err(e);
            }
        }
        Ok(rec)
    }

    /// Revoke a trusted device by fingerprint, disconnect active sessions for it, and persist `~/.config/idis.yaml`.
    pub fn revoke_trusted_device_and_save(&self, fingerprint: &str) -> Result<bool> {
        let removed = {
            let _tx = self.config_tx_lock.lock().unwrap();
            let _save = self.settings_save_lock.lock().unwrap();
            if let Some(ref path) = self.config_path {
                if self.config_read_only_corrupt.load(Ordering::Acquire) {
                    return Err(anyhow!(
                        "配置文件 {} 存在语法错误，当前处于只读保护模式；请先在「配置文件」修复并保存有效 YAML 后再修改受信设备",
                        path.display()
                    ));
                }
            }
            let prev_devices = self.trust_store.list();
            let removed = self.trust_store.revoke_device(fingerprint)?;
            if removed {
                if let Some(ref path) = self.config_path {
                    let mut snapshot = self.persisted_baseline.lock().unwrap().clone();
                    snapshot.trusted_devices = self.trust_store.list();
                    if let Err(e) = save_yaml_file(path, &snapshot) {
                        self.trust_store.replace_all_in_memory(prev_devices);
                        return Err(e);
                    }
                }
            }
            removed
        };
        if removed {
            // Release `config_tx_lock` before disconnecting/joining session capture threads.
            self.disconnect_sessions_matching(fingerprint);
        }
        Ok(removed)
    }

    /// Validate, hot-apply, and optionally persist a full `UserConfigFile` (from Web UI or disk reload).
    pub fn apply_user_config(&self, cfg: UserConfigFile, persist: bool) -> Result<UserConfigFile> {
        let tx = self.config_tx_lock.lock().unwrap();
        self.apply_user_config_locked(tx, cfg, persist)
    }

    fn apply_user_config_locked(
        &self,
        _tx: std::sync::MutexGuard<'_, ()>,
        mut cfg: UserConfigFile,
        persist: bool,
    ) -> Result<UserConfigFile> {
        cfg.validate_and_normalize()?;
        if !self.supports_independent_web_screen() && cfg.web_screen_mode == WebScreenMode::Independent {
            cfg.web_screen_mode = WebScreenMode::FollowIpad;
            cfg.web_independent_screen = false;
        }
        // Pre-validate Independent virtual-display quota BEFORE writing disk (P2-C6 / CFG-3).
        if cfg.web_screen_mode == WebScreenMode::Independent
            && !cfg.low_power
            && cfg.max_web_viewers > 0
            && cfg.max_extended_screens > 0
        {
            let has_viewers = !self.web_subscribers.lock().unwrap().is_empty();
            if has_viewers {
                let auth_ipads = self
                    .sessions
                    .lock()
                    .unwrap()
                    .values()
                    .filter(|s| s.authorized)
                    .count();
                if auth_ipads + 1 > cfg.max_extended_screens.min(32) {
                    anyhow::bail!(
                        "扩展屏数量已达上限 ({}/{})，无法切换为独立网页扩展屏（请先断开一台设备、调大最大扩展屏数或选择「电脑主屏幕」）",
                        auth_ipads,
                        cfg.max_extended_screens.min(32)
                    );
                }
            }
        }
        // Keep `baseline_cfg` with the user's pre-low-power settings intact on disk & in
        // `persisted_baseline` (CFG-4: reloading/saving YAML with `low_power: true` must remain
        // reversible when turning low-power OFF!), while deriving `eff_cfg` with low-power runtime
        // invariants enforced for active execution.
        let baseline_cfg = cfg.clone();
        let mut eff_cfg = cfg;
        if eff_cfg.low_power {
            eff_cfg.p2p_relay_enabled = false;
            eff_cfg.max_web_viewers = 0;
            let (eco_fps, eco_br) = QualityPreset::Eco.defaults();
            eff_cfg.ipad.fps = eco_fps;
            eff_cfg.ipad.bitrate_mbps = eco_br;
            eff_cfg.ipad.hidpi = 1;
            eff_cfg.polling = PollingConfigSection::low_power_defaults();
        }
        // Write to disk AND atomically update `persisted_baseline` + `trust_store` + corrupt flag
        // inside ONE `settings_save_lock` critical section BEFORE slow capture reconfigures so
        // concurrent `persist_config_patch` calls can never snapshot stale pre-revoke `trusted_devices`
        // back onto disk (Iter-6 P1-C2 / CFG-3).
        let prev_fps: Vec<String> = {
            let _guard = self.settings_save_lock.lock().unwrap();
            if persist {
                if let Some(ref path) = self.config_path {
                    save_yaml_file(path, &baseline_cfg)?;
                }
            }
            self.config_read_only_corrupt.store(false, Ordering::Release);
            *self.config_parse_error.lock().unwrap() = None;
            *self.persisted_baseline.lock().unwrap() = baseline_cfg;
            let prev: Vec<String> = self
                .trust_store
                .list()
                .into_iter()
                .map(|d| d.fingerprint)
                .collect();
            self.trust_store
                .replace_all_in_memory(eff_cfg.trusted_devices.clone());
            prev
        };

        let prev_allow = self.allow_input.swap(eff_cfg.allow_input, Ordering::AcqRel);
        if prev_allow && !eff_cfg.allow_input {
            self.release_all_stuck_mouse_buttons();
        }
        self.set_client_cursor_inner(eff_cfg.client_cursor, false);
        self.web_require_approval
            .store(eff_cfg.web_require_approval, Ordering::Release);
        self.low_power.store(eff_cfg.low_power, Ordering::Release);
        // Always clear any prior toggle snapshot when applying a full config or preset (ConfigAndPresets.tla).
        if let Ok(mut snap) = self.low_power_snapshot.lock() {
            *snap = None;
        }
        if eff_cfg.low_power {
            self.notify_cancel_pending(None, None);
        }
        self.p2p_relay_enabled
            .store(eff_cfg.p2p_relay_enabled, Ordering::Release);
        *self.polling.lock().unwrap() = eff_cfg.polling.clone();
        *self.active_preset.lock().unwrap() = eff_cfg.active_preset.clone();
        *self.presets.lock().unwrap() = eff_cfg.presets.clone();
        *self.window_rules.lock().unwrap() = eff_cfg.window_rules.clone();
        *self.gestures.lock().unwrap() = eff_cfg.gestures.clone();
        self.applied_window_moves.lock().unwrap().clear();
        self.max_extended_screens
            .store(eff_cfg.max_extended_screens.min(32), Ordering::Release);
        self.set_max_web_viewers_inner(eff_cfg.max_web_viewers, false);
        self.auto_max_in_flight
            .store(eff_cfg.auto_max_in_flight, Ordering::Release);
        let eff_mif = eff_cfg.max_in_flight.min(12);
        self.max_in_flight.store(eff_mif, Ordering::Release);
        if !eff_cfg.auto_max_in_flight {
            if let Ok(map) = self.sessions.lock() {
                for sess in map.values() {
                    sess.flow.set_max_in_flight(eff_mif);
                }
            }
        } else {
            self.reset_live_sessions_auto_in_flight();
        }
        *self.lock_action_ipad.lock().unwrap() = eff_cfg.lock_action_ipad;
        *self.lock_action_web.lock().unwrap() = eff_cfg.lock_action_web;
        self.lock_delay_secs
            .store(eff_cfg.lock_delay_secs.min(3600), Ordering::Release);
        self.port_idle_close_secs
            .store(eff_cfg.port_idle_close_secs.min(86_400), Ordering::Release);
        self.notify_lifecycle_wakeup();
        self.refresh_lock_policy_if_locked();
        let _ = self.set_web_screen_mode_inner(eff_cfg.web_screen_mode, false);

        // Do NOT overwrite per-device preferences when loading/applying the full YAML file, and do
        // NOT perform redundant disk writes here (already persisted cleanly above when `persist == true`).
        let _ = self.update_video_settings_inner(
            VideoSettingsPatch {
                width: Some(eff_cfg.ipad.width),
                height: Some(eff_cfg.ipad.height),
                fps: Some(eff_cfg.ipad.fps),
                bitrate_mbps: Some(eff_cfg.ipad.bitrate_mbps),
                hidpi: Some(eff_cfg.ipad.hidpi),
                integer_scale: Some(eff_cfg.ipad.integer_scale),
                max_pixel_edge: Some(eff_cfg.ipad.max_pixel_edge),
                adaptive_quality: Some(eff_cfg.ipad.adaptive_quality),
                abr_sensitivity: Some(eff_cfg.ipad.abr_sensitivity),
                half_fps_when_unfocused: Some(eff_cfg.ipad.half_fps_when_unfocused),
                web_width: Some(eff_cfg.web.width),
                web_height: Some(eff_cfg.web.height),
                web_fps: Some(eff_cfg.web.fps),
                web_bitrate_mbps: Some(eff_cfg.web.bitrate_mbps),
                web_hidpi: Some(eff_cfg.web.hidpi),
                web_max_pixel_edge: Some(eff_cfg.web.max_pixel_edge),
                ..Default::default()
            },
            false,
            false,
        );
        self.apply_low_power_to_captures(eff_cfg.low_power);

        let final_cfg = self.export_user_config();
        drop(_tx);

        // Disconnect any active sessions whose fingerprint was removed from `trusted_devices`
        // AFTER releasing `config_tx_lock` so teardown thread joins never block config updates.
        for old_fp in prev_fps {
            if !self.trust_store.is_trusted(Some(&old_fp)) {
                self.disconnect_sessions_matching(&old_fp);
            }
        }
        Ok(final_cfg)
    }

    /// Reload `~/.config/idis.yaml` from disk and hot-apply it to the running host.
    pub fn reload_user_config_from_disk(&self) -> Result<UserConfigFile> {
        let Some(ref path) = self.config_path else {
            anyhow::bail!("当前为纯内存配置模式（--config none），无磁盘配置文件可重载");
        };
        let cfg = load_yaml_file(path)?;
        self.apply_user_config(cfg, false)
    }

    pub fn video_settings(&self) -> VideoSettings {
        self.video.lock().unwrap().clone()
    }

    pub(super) fn persist_current_settings(&self) {
        if let Err(e) = self.save_config_file() {
            if let Some(ref p) = self.config_path {
                warn!("Failed to persist config to {}: {e:#}", p.display());
            }
        }
    }

    /// Reset iPad video quality & resolution settings back to safe defaults (without altering standalone Web screen settings).
    /// Also clears saved per-device overrides across trusted devices (including offline ones) atomically
    /// with disk persistence (rolling back on I/O error) and preserves low-power runtime caps (Iter-6 P2-C4).
    pub fn reset_video_settings(&self) -> Result<VideoSettings> {
        // Hold `config_tx_lock` across both disk persistence AND runtime low-power cap application
        // so a concurrent `set_low_power(true)` cannot race between disk save and runtime apply.
        let _tx = self.config_tx_lock.lock().unwrap();
        {
            let _save = self.settings_save_lock.lock().unwrap();
            if let Some(ref path) = self.config_path {
                if self.config_read_only_corrupt.load(Ordering::Acquire) {
                    return Err(anyhow!(
                        "配置文件 {} 存在语法错误，当前处于只读保护模式；请先在「配置文件」修复并保存有效 YAML 后再重置视频设置",
                        path.display()
                    ));
                }
            }
            let prev_devices = self.trust_store.list();
            let mut next_baseline = self.persisted_baseline.lock().unwrap().clone();
            next_baseline.active_preset = None;
            next_baseline.auto_max_in_flight = true;
            next_baseline.ipad.width = 0;
            next_baseline.ipad.height = 0;
            next_baseline.ipad.fps = 30;
            next_baseline.ipad.bitrate_mbps = 16;
            next_baseline.ipad.hidpi = 1;
            next_baseline.ipad.integer_scale = false;
            next_baseline.ipad.max_pixel_edge = 0;
            next_baseline.ipad.adaptive_quality = true;
            next_baseline.ipad.abr_sensitivity = crate::config::AbrSensitivity::Balanced;
            next_baseline.ipad.half_fps_when_unfocused = false;
            let _ = self.trust_store.clear_all_device_prefs();
            if let Some(ref path) = self.config_path {
                let mut snapshot = next_baseline.clone();
                snapshot.trusted_devices = self.trust_store.list();
                if let Err(e) = save_yaml_file(path, &snapshot) {
                    self.trust_store.replace_all_in_memory(prev_devices);
                    return Err(e);
                }
            }
            *self.persisted_baseline.lock().unwrap() = next_baseline;
        }
        *self.active_preset.lock().unwrap() = None;
        self.auto_max_in_flight.store(true, Ordering::Release);
        self.reset_live_sessions_auto_in_flight();
        let low_power = self.is_low_power();
        if low_power {
            if let Ok(mut snap) = self.low_power_snapshot.lock() {
                if let Some(ref mut s) = *snap {
                    s.fps = 30;
                    s.bitrate_mbps = 16;
                    s.hidpi = 1;
                }
            }
            let (eco_fps, eco_br) = QualityPreset::Eco.defaults();
            // Keep Eco runtime caps active while low_power is enabled; persisted_baseline &
            // low_power_snapshot already carry the reset Balanced defaults for when low_power ends.
            self.update_video_settings_inner(
                VideoSettingsPatch {
                    width: Some(0),
                    height: Some(0),
                    fps: Some(eco_fps),
                    bitrate_mbps: Some(eco_br),
                    hidpi: Some(1),
                    integer_scale: Some(false),
                    max_pixel_edge: Some(0),
                    adaptive_quality: Some(true),
                    abr_sensitivity: Some(crate::config::AbrSensitivity::Balanced),
                    half_fps_when_unfocused: Some(false),
                    ..Default::default()
                },
                false,
                false,
            )
        } else {
            // Pass `persist = false, record_device_prefs = false` because disk was already persisted
            // atomically above and online trusted iPads must NOT be re-stamped with DevicePreferences.
            self.update_video_settings_inner(
                VideoSettingsPatch {
                    quality: Some(QualityPreset::Balanced),
                    width: Some(0),
                    height: Some(0),
                    fps: Some(30),
                    bitrate_mbps: Some(16),
                    hidpi: Some(1),
                    integer_scale: Some(false),
                    max_pixel_edge: Some(0),
                    adaptive_quality: Some(true),
                    abr_sensitivity: Some(crate::config::AbrSensitivity::Balanced),
                    half_fps_when_unfocused: Some(false),
                    ..Default::default()
                },
                false,
                false,
            )
        }
    }

    /// Reset standalone Web extended-screen video settings back to defaults (without altering iPad settings).
    pub fn reset_web_video_settings(&self) -> Result<VideoSettings> {
        self.update_video_settings(VideoSettingsPatch {
            web_quality: Some(QualityPreset::Balanced),
            web_width: Some(1280),
            web_height: Some(720),
            web_fps: Some(30),
            web_bitrate_mbps: Some(16),
            web_hidpi: Some(1),
            web_max_pixel_edge: Some(0),
            ..Default::default()
        })
    }

    /// Compute the effective streaming long-edge pixel ceiling for a specific iPad session.
    /// In auto mode (`vs.max_pixel_edge == 0`), adapts per screen while respecting 2x Retina HiDPI
    /// (e.g. legacy iPad reporting `1024x768` logical points at `2x HiDPI` streams true `2048x1536`),
    /// and never oversamples beyond the connected iPad's actual physical panel long edge
    /// (preventing 3840x2880 streams onto a 2048x1536 panel when a user selects 2048x1536 @ 2x).
    pub fn effective_ipad_max_pixel_edge(hs: &ClientHandshake, vs: &VideoSettings) -> u32 {
        if vs.max_pixel_edge >= 640 {
            vs.max_pixel_edge.clamp(640, WEB_MAX_PIXEL_EDGE) & !1
        } else {
            let (pw, ph) = hs.effective_resolution();
            let panel_edge = pw.max(ph);
            let scale = if vs.hidpi >= 2 { 2 } else { 1 };
            let physical_panel_edge = if panel_edge >= 640 {
                if scale >= 2 && panel_edge <= 1400 {
                    // Legacy iDisplay on Retina iPads often reports 1x UIKit points (e.g. 1024x768);
                    // allow full 2x Retina pixels (2048x1536) in auto mode.
                    panel_edge.saturating_mul(2)
                } else {
                    panel_edge
                }
            } else {
                IPAD_MAX_PIXEL_EDGE
            };
            let target_edge = if vs.width >= 320 && vs.height >= 240 {
                vs.width
                    .max(vs.height)
                    .saturating_mul(scale)
                    .min(physical_panel_edge)
            } else {
                physical_panel_edge
            };
            if target_edge >= 640 {
                target_edge.clamp(640, WEB_MAX_PIXEL_EDGE) & !1
            } else {
                IPAD_MAX_PIXEL_EDGE
            }
        }
    }

    /// Compute the effective streaming long-edge pixel ceiling for the standalone Web extended screen.
    /// In auto mode (`vs.web_max_pixel_edge == 0`), allows full scaling up to `WEB_MAX_PIXEL_EDGE` (3840)
    /// independently of any connected iPad's panel limit.
    pub fn effective_web_max_pixel_edge(vs: &VideoSettings) -> u32 {
        if vs.web_max_pixel_edge >= 640 {
            vs.web_max_pixel_edge.clamp(640, WEB_MAX_PIXEL_EDGE) & !1
        } else {
            WEB_MAX_PIXEL_EDGE
        }
    }

    /// Update runtime video quality/resolution settings and hot-reconfigure only affected active captures.
    pub fn update_video_settings(&self, patch: VideoSettingsPatch) -> Result<VideoSettings> {
        self.update_video_settings_inner(patch, true, true)
    }

    fn update_video_settings_inner(
        &self,
        patch: VideoSettingsPatch,
        persist: bool,
        record_device_prefs: bool,
    ) -> Result<VideoSettings> {
        let affects_ipad = patch.quality.is_some()
            || patch.width.is_some()
            || patch.height.is_some()
            || patch.fps.is_some()
            || patch.bitrate_mbps.is_some()
            || patch.hidpi.is_some()
            || patch.integer_scale.is_some()
            || patch.max_pixel_edge.is_some();
        let affects_web = patch.web_quality.is_some()
            || patch.web_width.is_some()
            || patch.web_height.is_some()
            || patch.web_fps.is_some()
            || patch.web_bitrate_mbps.is_some()
            || patch.web_hidpi.is_some()
            || patch.web_max_pixel_edge.is_some();
        let low_power_enforce = persist && self.is_low_power();
        let (updated, persist_ipad_fps, persist_ipad_br, persist_ipad_hidpi) = {
            let mut v = self.video.lock().unwrap();
            let mut want_fps = v.fps;
            let mut want_br = v.bitrate_mbps;
            let mut want_hidpi = v.hidpi;
            if let Some(q) = patch.quality {
                let (f, b) = q.defaults();
                want_fps = f;
                want_br = b;
                if !low_power_enforce {
                    v.fps = f;
                    v.bitrate_mbps = b;
                    v.quality = q;
                }
            }
            if let Some(fps) = patch.fps {
                let clamped = fps.clamp(5, 120);
                want_fps = clamped;
                if !low_power_enforce {
                    v.fps = clamped;
                }
            }
            if let Some(br) = patch.bitrate_mbps {
                let clamped = br.clamp(2, 60);
                want_br = clamped;
                if !low_power_enforce {
                    v.bitrate_mbps = clamped;
                }
            }
            if let Some(h) = patch.hidpi {
                let clamped = if h >= 2 { 2 } else { 1 };
                want_hidpi = clamped;
                if !low_power_enforce {
                    v.hidpi = clamped;
                }
            }
            if low_power_enforce {
                // Keep Eco runtime caps enforced while low_power is active; user's requested
                // fps/bitrate/hidpi are saved into `persisted_baseline` + `low_power_snapshot`
                // so exiting low_power cleanly applies them without CFG-4 divergence (Iter-7 P2-C2).
                let (eco_fps, eco_br) = QualityPreset::Eco.defaults();
                v.fps = eco_fps;
                v.bitrate_mbps = eco_br;
                v.hidpi = 1;
                v.quality = QualityPreset::Eco;
            }
            if let Some(int_scale) = patch.integer_scale {
                v.integer_scale = int_scale;
            }
            if let Some(edge) = patch.max_pixel_edge {
                v.max_pixel_edge = if edge == 0 {
                    0
                } else {
                    edge.clamp(640, WEB_MAX_PIXEL_EDGE) & !1
                };
            }
            if let Some(adaptive) = patch.adaptive_quality {
                v.adaptive_quality = adaptive;
            }
            if let Some(sens) = patch.abr_sensitivity {
                v.abr_sensitivity = sens;
            }
            if let Some(half_fps) = patch.half_fps_when_unfocused {
                v.half_fps_when_unfocused = half_fps;
            }
            if let Some(w) = patch.width {
                v.width = if w == 0 { 0 } else { w.clamp(320, 3840) & !1 };
            }
            if let Some(h) = patch.height {
                v.height = if h == 0 { 0 } else { h.clamp(240, 2160) & !1 };
            }
            // If only one of width/height is zero, treat both as auto (0x0)
            if v.width == 0 || v.height == 0 {
                v.width = 0;
                v.height = 0;
            }
            if !low_power_enforce
                && patch.quality.is_none()
                && (patch.fps.is_some() || patch.bitrate_mbps.is_some())
            {
                v.quality = QualityPreset::from_fps_bitrate(v.fps, v.bitrate_mbps);
            }

            // Independent standalone Web extended-screen video settings
            if let Some(wq) = patch.web_quality {
                let (f, b) = wq.defaults();
                v.web_fps = f;
                v.web_bitrate_mbps = b;
                v.web_quality = wq;
            }
            if let Some(ww) = patch.web_width {
                if ww >= 320 {
                    v.web_width = ww.clamp(320, 3840) & !1;
                }
            }
            if let Some(wh) = patch.web_height {
                if wh >= 240 {
                    v.web_height = wh.clamp(240, 2160) & !1;
                }
            }
            if let Some(wfps) = patch.web_fps {
                v.web_fps = wfps.clamp(5, 120);
            }
            if let Some(wbr) = patch.web_bitrate_mbps {
                v.web_bitrate_mbps = wbr.clamp(2, 60);
            }
            if let Some(whidpi) = patch.web_hidpi {
                v.web_hidpi = if whidpi >= 2 { 2 } else { 1 };
            }
            if let Some(wedge) = patch.web_max_pixel_edge {
                v.web_max_pixel_edge = if wedge == 0 {
                    0
                } else {
                    wedge.clamp(640, WEB_MAX_PIXEL_EDGE) & !1
                };
            }
            if patch.web_quality.is_none()
                && (patch.web_fps.is_some() || patch.web_bitrate_mbps.is_some())
            {
                v.web_quality = QualityPreset::from_fps_bitrate(v.web_fps, v.web_bitrate_mbps);
            }
            (v.clone(), want_fps, want_br, want_hidpi)
        };
        if low_power_enforce {
            if let Ok(mut snap) = self.low_power_snapshot.lock() {
                if let Some(ref mut s) = *snap {
                    if patch.quality.is_some() || patch.fps.is_some() {
                        s.fps = persist_ipad_fps;
                    }
                    if patch.quality.is_some() || patch.bitrate_mbps.is_some() {
                        s.bitrate_mbps = persist_ipad_br;
                    }
                    if patch.hidpi.is_some() {
                        s.hidpi = persist_ipad_hidpi;
                    }
                }
            }
        }
        if affects_ipad {
            // Bump iPad generation so iPad ABR controllers reset cleanly to Tier 0 for the new target.
            self.ipad_video_settings_gen.fetch_add(1, Ordering::AcqRel);
        }
        if affects_web {
            // Bump Web generation independently so standalone Web ABR resets cleanly without cross-talk.
            self.web_video_settings_gen.fetch_add(1, Ordering::AcqRel);
        }

        info!(
            "Runtime video settings updated: ipad={}x{} {}fps {}Mbps {}x max_edge={} abr={}; web={}x{} {}fps {}Mbps {}x max_edge={}",
            updated.width,
            updated.height,
            updated.fps,
            updated.bitrate_mbps,
            updated.hidpi,
            updated.max_pixel_edge,
            updated.adaptive_quality,
            updated.web_width,
            updated.web_height,
            updated.web_fps,
            updated.web_bitrate_mbps,
            updated.web_hidpi,
            updated.web_max_pixel_edge,
        );
        crate::debug_trace::record(
            "video",
            "settings_updated",
            serde_json::json!({
                "width": updated.width,
                "height": updated.height,
                "fps": updated.fps,
                "bitrate_mbps": updated.bitrate_mbps,
                "hidpi": updated.hidpi,
                "integer_scale": updated.integer_scale,
                "max_pixel_edge": updated.max_pixel_edge,
                "adaptive_quality": updated.adaptive_quality,
                "half_fps_when_unfocused": updated.half_fps_when_unfocused,
                "quality": updated.quality,
                "web_width": updated.web_width,
                "web_height": updated.web_height,
                "web_fps": updated.web_fps,
                "web_bitrate_mbps": updated.web_bitrate_mbps,
                "web_hidpi": updated.web_hidpi,
                "web_max_pixel_edge": updated.web_max_pixel_edge,
                "web_quality": updated.web_quality,
            }),
        );

        let supports_hidpi = self.backend.supports_hidpi();
        // Record updated iPad preferences onto currently connected trusted devices so each device
        // reconnects with its saved preferences automatically in `~/.config/idis.yaml`.
        if (affects_ipad || patch.adaptive_quality.is_some()) && record_device_prefs {
            let connected_fps: Vec<String> = {
                let map = self.sessions.lock().unwrap();
                map.values()
                    .filter(|s| s.authorized)
                    .filter_map(|s| s.fingerprint.clone())
                    .collect()
            };
            let prefs = DevicePreferences {
                width: if patch.width.is_some() || patch.height.is_some() {
                    Some(updated.width)
                } else {
                    None
                },
                height: if patch.width.is_some() || patch.height.is_some() {
                    Some(updated.height)
                } else {
                    None
                },
                fps: if patch.quality.is_some() || patch.fps.is_some() {
                    Some(persist_ipad_fps)
                } else {
                    None
                },
                bitrate_mbps: if patch.quality.is_some() || patch.bitrate_mbps.is_some() {
                    Some(persist_ipad_br)
                } else {
                    None
                },
                hidpi: patch.hidpi.map(|_| persist_ipad_hidpi),
                max_pixel_edge: patch.max_pixel_edge.map(|_| updated.max_pixel_edge),
                adaptive_quality: patch.adaptive_quality.map(|_| updated.adaptive_quality),
            };
            if !prefs.is_empty() {
                for fp in connected_fps {
                    if let Err(e) = self.trust_store.update_device_prefs(&fp, prefs.clone()) {
                        warn!("Failed to persist device preferences for {fp}: {e:#}");
                    }
                }
            }
        }
        // Hot-reconfigure active iPad captures only when iPad-affecting parameters changed,
        // respecting each trusted device's persisted `DevicePreferences` overlay (P2-B2).
        if affects_ipad {
            if let Ok(mut lf) = self.last_ipad_web_frame.lock() {
                *lf = None;
            }
            let low_power = self.is_low_power();
            type SharedCapture = Arc<Mutex<Box<dyn CaptureHandle>>>;
            struct IpadReconfigureTarget {
                key: String,
                w: u32,
                h: u32,
                fps: u32,
                br: u32,
                eff_hidpi: u32,
                eff_edge: u32,
                hdl: SharedCapture,
            }
            let session_targets: Vec<IpadReconfigureTarget> = {
                let map = self.sessions.lock().unwrap();
                map.iter()
                    .filter_map(|(k, s)| {
                        let hdl = s.capture.as_ref()?.handle.clone();
                        let dev_prefs = s
                            .fingerprint
                            .as_deref()
                            .and_then(|fp| self.trust_store.get_device(fp))
                            .map(|d| d.prefs);
                        let eff_vs =
                            Self::overlay_device_prefs(updated.clone(), dev_prefs.as_ref(), low_power);
                        let eff_hidpi = if supports_hidpi { eff_vs.hidpi } else { 1 };
                        let (w, h, eff_edge) = if let Some(ref hs) = s.handshake {
                            let (rw, rh) =
                                Self::resolve_dimensions_for_settings(hs, &eff_vs, supports_hidpi);
                            (rw, rh, Self::effective_ipad_max_pixel_edge(hs, &eff_vs))
                        } else if eff_vs.width >= 320 && eff_vs.height >= 240 {
                            (
                                eff_vs.width,
                                eff_vs.height,
                                if eff_vs.max_pixel_edge >= 640 {
                                    eff_vs.max_pixel_edge
                                } else {
                                    IPAD_MAX_PIXEL_EDGE
                                },
                            )
                        } else {
                            (
                                1024,
                                768,
                                if eff_vs.max_pixel_edge >= 640 {
                                    eff_vs.max_pixel_edge
                                } else {
                                    IPAD_MAX_PIXEL_EDGE
                                },
                            )
                        };
                        Some(IpadReconfigureTarget {
                            key: k.clone(),
                            w,
                            h,
                            fps: eff_vs.fps,
                            br: eff_vs.bitrate_mbps,
                            eff_hidpi,
                            eff_edge,
                            hdl,
                        })
                    })
                    .collect()
            };
            for t in session_targets {
                self.notify_lifecycle_wakeup();
                if let Ok(mut g) = t.hdl.lock() {
                    if let Err(e) = g.reconfigure(t.w, t.h, t.fps, t.br, t.eff_hidpi, t.eff_edge) {
                        warn!("[{}] Live video reconfigure failed: {e:#}", t.key);
                    }
                }
                self.notify_lifecycle_wakeup();
            }
        }

        // Hot-reconfigure standalone Web capture only when Web-affecting parameters changed.
        if affects_web {
            let standalone_hdl = {
                let guard = self.standalone_web_capture.lock().unwrap();
                guard.as_ref().map(|c| c.handle.clone())
            };
            if let Some(hdl) = standalone_hdl {
                if let Ok(mut lf) = self.last_standalone_web_frame.lock() {
                    *lf = None;
                }
                let (w, h) = self.resolve_web_dimensions(&updated);
                let web_hidpi = if supports_hidpi { updated.web_hidpi } else { 1 };
                let web_edge = Self::effective_web_max_pixel_edge(&updated);
                self.notify_lifecycle_wakeup();
                if let Ok(mut g) = hdl.lock() {
                    if let Err(e) = g.reconfigure(
                        w,
                        h,
                        updated.web_fps,
                        updated.web_bitrate_mbps,
                        web_hidpi,
                        web_edge,
                    ) {
                        warn!("Live standalone Web capture reconfigure failed: {e:#}");
                    }
                }
                self.notify_lifecycle_wakeup();
            }
        }

        if persist {
            if affects_ipad
                || affects_web
                || patch.adaptive_quality.is_some()
                || patch.abr_sensitivity.is_some()
                || patch.half_fps_when_unfocused.is_some()
            {
                *self.active_preset.lock().unwrap() = None;
            }
            // Only patch fields explicitly included in `patch` so temporary CLI overrides
            // (e.g. `--fps 60` or `--bitrate-mbps 24`) never leak into `~/.config/idis.yaml`
            // when the user updates an unrelated field.
            self.persist_config_patch(|c| {
                if affects_ipad
                    || affects_web
                    || patch.adaptive_quality.is_some()
                    || patch.abr_sensitivity.is_some()
                    || patch.half_fps_when_unfocused.is_some()
                {
                    c.active_preset = None;
                }
                if patch.width.is_some() || patch.height.is_some() {
                    c.ipad.width = updated.width;
                    c.ipad.height = updated.height;
                }
                if patch.quality.is_some() || patch.fps.is_some() {
                    c.ipad.fps = persist_ipad_fps;
                }
                if patch.quality.is_some() || patch.bitrate_mbps.is_some() {
                    c.ipad.bitrate_mbps = persist_ipad_br;
                }
                if patch.hidpi.is_some() {
                    c.ipad.hidpi = persist_ipad_hidpi;
                }
                if patch.integer_scale.is_some() {
                    c.ipad.integer_scale = updated.integer_scale;
                }
                if patch.max_pixel_edge.is_some() {
                    c.ipad.max_pixel_edge = updated.max_pixel_edge;
                }
                if patch.adaptive_quality.is_some() {
                    c.ipad.adaptive_quality = updated.adaptive_quality;
                }
                if patch.abr_sensitivity.is_some() {
                    c.ipad.abr_sensitivity = updated.abr_sensitivity;
                }
                if patch.half_fps_when_unfocused.is_some() {
                    c.ipad.half_fps_when_unfocused = updated.half_fps_when_unfocused;
                }
                if patch.web_width.is_some() {
                    c.web.width = updated.web_width;
                }
                if patch.web_height.is_some() {
                    c.web.height = updated.web_height;
                }
                if patch.web_quality.is_some() || patch.web_fps.is_some() {
                    c.web.fps = updated.web_fps;
                }
                if patch.web_quality.is_some() || patch.web_bitrate_mbps.is_some() {
                    c.web.bitrate_mbps = updated.web_bitrate_mbps;
                }
                if patch.web_hidpi.is_some() {
                    c.web.hidpi = updated.web_hidpi;
                }
                if patch.web_max_pixel_edge.is_some() {
                    c.web.max_pixel_edge = updated.web_max_pixel_edge;
                }
            });
        }
        Ok(updated)
    }

    pub(super) fn resolve_web_dimensions(&self, v: &VideoSettings) -> (u32, u32) {
        let base_w = self.config.web_width.max(320) & !1;
        let base_h = self.config.web_height.max(240) & !1;
        if v.web_width >= 320 && v.web_height >= 240 {
            (v.web_width & !1, v.web_height & !1)
        } else {
            (base_w, base_h)
        }
    }


    pub fn polling_config(&self) -> PollingConfigSection {
        self.polling.lock().unwrap().clone()
    }

    pub fn update_polling_config(&self, patch: PollingPatch) -> PollingConfigSection {
        let low_power = self.is_low_power();
        if low_power {
            // Keep runtime polling clamped to low_power_defaults(), while persisting user edits
            // to `persisted_baseline` and updating `low_power_snapshot` so exiting low_power
            // applies them cleanly without CFG-4 divergence (Iter-7 P2-C2).
            let mut next_base = self
                .low_power_snapshot
                .lock()
                .ok()
                .and_then(|g| g.as_ref().map(|s| s.polling.clone()))
                .unwrap_or_else(|| self.persisted_baseline.lock().unwrap().polling.clone());
            if let Some(v) = patch.main_loop_ms {
                next_base.main_loop_ms = v;
            }
            if let Some(v) = patch.cursor_poll_ms {
                next_base.cursor_poll_ms = v;
            }
            if let Some(v) = patch.usb_retry_ms {
                next_base.usb_retry_ms = v;
            }
            if let Some(v) = patch.admin_poll_ms {
                next_base.admin_poll_ms = v;
            }
            next_base.normalize();
            if let Ok(mut snap) = self.low_power_snapshot.lock() {
                if let Some(ref mut s) = *snap {
                    s.polling = next_base.clone();
                }
            }
            self.persist_config_patch(|c| {
                if patch.main_loop_ms.is_some() {
                    c.polling.main_loop_ms = next_base.main_loop_ms;
                }
                if patch.cursor_poll_ms.is_some() {
                    c.polling.cursor_poll_ms = next_base.cursor_poll_ms;
                }
                if patch.usb_retry_ms.is_some() {
                    c.polling.usb_retry_ms = next_base.usb_retry_ms;
                }
                if patch.admin_poll_ms.is_some() {
                    c.polling.admin_poll_ms = next_base.admin_poll_ms;
                }
            });
            return self.polling.lock().unwrap().clone();
        }
        let updated = {
            let mut p = self.polling.lock().unwrap();
            if let Some(v) = patch.main_loop_ms {
                p.main_loop_ms = v;
            }
            if let Some(v) = patch.cursor_poll_ms {
                p.cursor_poll_ms = v;
            }
            if let Some(v) = patch.usb_retry_ms {
                p.usb_retry_ms = v;
            }
            if let Some(v) = patch.admin_poll_ms {
                p.admin_poll_ms = v;
            }
            p.normalize();
            p.clone()
        };
        info!(
            "Runtime polling config updated: main_loop={}ms, cursor={}ms, usb_retry={}ms, admin={}ms",
            updated.main_loop_ms,
            updated.cursor_poll_ms,
            updated.usb_retry_ms,
            updated.admin_poll_ms,
        );
        self.persist_config_patch(|c| {
            if patch.main_loop_ms.is_some() {
                c.polling.main_loop_ms = updated.main_loop_ms;
            }
            if patch.cursor_poll_ms.is_some() {
                c.polling.cursor_poll_ms = updated.cursor_poll_ms;
            }
            if patch.usb_retry_ms.is_some() {
                c.polling.usb_retry_ms = updated.usb_retry_ms;
            }
            if patch.admin_poll_ms.is_some() {
                c.polling.admin_poll_ms = updated.admin_poll_ms;
            }
        });
        updated
    }

    pub fn reset_polling_config(&self) -> PollingConfigSection {
        let std_default = PollingConfigSection::default();
        let target = if self.is_low_power() {
            PollingConfigSection::low_power_defaults()
        } else {
            std_default.clone()
        };
        *self.polling.lock().unwrap() = target.clone();
        if let Ok(mut snap) = self.low_power_snapshot.lock() {
            if let Some(ref mut s) = *snap {
                s.polling = std_default.clone();
            }
        }
        info!(
            "Runtime polling config reset: main_loop={}ms, cursor={}ms, usb_retry={}ms, admin={}ms",
            target.main_loop_ms, target.cursor_poll_ms, target.usb_retry_ms, target.admin_poll_ms,
        );
        // Always persist standard defaults to disk baseline (CFG-4: never clobber baseline with
        // low-power polling defaults when resetting while `low_power == true`; Iter-6 P2-C3).
        self.persist_config_patch(|c| c.polling = std_default);
        target
    }

    pub fn list_presets(&self) -> (Option<String>, Vec<ConfigPreset>) {
        let active = self.active_preset.lock().unwrap().clone();
        let list = self.presets.lock().unwrap().clone();
        (active, list)
    }

    /// Snapshot current runtime configuration into a named preset and persist to `~/.config/idis.yaml`.
    pub fn save_current_as_preset(&self, raw_name: &str) -> Result<ConfigPreset> {
        if self.is_config_corrupt() {
            return Err(anyhow!(
                "当前配置文件格式有误，请先在「配置文件」卡片中修复并保存后再管理预设"
            ));
        }
        let name = ConfigPreset::sanitize_name(raw_name)?;
        let _tx = self.config_tx_lock.lock().unwrap();
        let current = self.export_user_config();
        let mut preset = ConfigPreset::from_user_config(name.clone(), &current);
        preset.validate_and_normalize()?;

        let mut next_presets = self.presets.lock().unwrap().clone();
        if let Some(pos) = next_presets.iter().position(|p| p.name == name) {
            next_presets[pos] = preset.clone();
        } else {
            if next_presets.len() >= MAX_CUSTOM_PRESETS {
                return Err(anyhow!("自定义预设数量已达上限（{MAX_CUSTOM_PRESETS}）"));
            }
            next_presets.push(preset.clone());
        }

        if let Some(ref path) = self.config_path {
            let _guard = self.settings_save_lock.lock().unwrap();
            let mut to_write = self.persisted_baseline.lock().unwrap().clone();
            to_write.trusted_devices = self.trust_store.list();
            to_write.presets = next_presets.clone();
            to_write.active_preset = Some(name.clone());
            save_yaml_file(path, &to_write)?;
            *self.persisted_baseline.lock().unwrap() = to_write;
        } else {
            let mut base = self.persisted_baseline.lock().unwrap();
            base.presets = next_presets.clone();
            base.active_preset = Some(name.clone());
        }
        *self.presets.lock().unwrap() = next_presets;
        *self.active_preset.lock().unwrap() = Some(name.clone());
        info!("Saved current configuration as preset {:?}", name);
        Ok(preset)
    }

    /// Apply a named preset (custom YAML preset takes precedence over built-in starter presets),
    /// hot-updating all live settings and persisting while keeping `trusted_devices` untouched.
    pub fn apply_preset(&self, raw_name: &str) -> Result<UserConfigFile> {
        // Invariant CFG-2: never overwrite a corrupt disk YAML via preset switching.
        if self.is_config_corrupt() {
            return Err(anyhow!(
                "当前配置文件格式有误，请先在「配置文件」卡片中修复并保存后再切换预设"
            ));
        }
        let name = ConfigPreset::sanitize_name(raw_name)?;
        // Invariant CFG-3: hold `config_tx_lock` across preset lookup, baseline/trust snapshot,
        // and disk-first atomic commit so concurrent mutations cannot be clobbered.
        let tx = self.config_tx_lock.lock().unwrap();
        let (chosen, is_custom) = {
            let custom = self.presets.lock().unwrap();
            if let Some(p) = custom.iter().find(|p| p.name == name).cloned() {
                (p, true)
            } else if let Some(p) = ConfigPreset::builtin_presets()
                .into_iter()
                .find(|p| p.name == name)
            {
                (p, false)
            } else {
                return Err(anyhow!("未找到名为 {:?} 的配置预设", name));
            }
        };

        let mut next_cfg = self.export_persisted_config();
        let prev_baseline_allow_input = next_cfg.allow_input;
        next_cfg.presets = self.presets.lock().unwrap().clone();
        next_cfg.trusted_devices = self.trust_store.list();
        // Clear per-device overrides when explicitly applying a preset so stale per-device prefs
        // never silently defeat the chosen preset on the next ABR tick or device reconnect.
        for dev in &mut next_cfg.trusted_devices {
            dev.prefs = crate::trust::DevicePreferences::default();
        }
        chosen.apply_into_config(&mut next_cfg);
        if !is_custom {
            // Built-in starter presets only tune display/power/polling profiles; preserve the
            // user's persisted `allow_input` preference (matches `ConfigAndPresets.tla`).
            next_cfg.allow_input = prev_baseline_allow_input;
        }
        let applied = self.apply_user_config_locked(tx, next_cfg, true)?;
        info!("Applied configuration preset {:?}", name);
        Ok(applied)
    }

    /// Delete a custom preset from `~/.config/idis.yaml` by name.
    pub fn delete_preset(&self, raw_name: &str) -> Result<bool> {
        if self.is_config_corrupt() {
            return Err(anyhow!(
                "当前配置文件格式有误，请先在「配置文件」卡片中修复并保存后再管理预设"
            ));
        }
        let name = ConfigPreset::sanitize_name(raw_name)?;
        let _tx = self.config_tx_lock.lock().unwrap();
        let mut next_presets = self.presets.lock().unwrap().clone();
        let before = next_presets.len();
        next_presets.retain(|p| p.name != name);
        if next_presets.len() == before {
            return Ok(false);
        }
        let next_active = {
            let cur = self.active_preset.lock().unwrap().clone();
            if cur.as_deref() == Some(name.as_str()) {
                None
            } else {
                cur
            }
        };
        if let Some(ref path) = self.config_path {
            let _guard = self.settings_save_lock.lock().unwrap();
            let mut to_write = self.persisted_baseline.lock().unwrap().clone();
            to_write.trusted_devices = self.trust_store.list();
            to_write.presets = next_presets.clone();
            to_write.active_preset = next_active.clone();
            save_yaml_file(path, &to_write)?;
            *self.persisted_baseline.lock().unwrap() = to_write;
        } else {
            let mut base = self.persisted_baseline.lock().unwrap();
            base.presets = next_presets.clone();
            base.active_preset = next_active.clone();
        }
        *self.presets.lock().unwrap() = next_presets;
        *self.active_preset.lock().unwrap() = next_active;
        info!("Deleted custom configuration preset {:?}", name);
        Ok(true)
    }

    pub fn is_low_power(&self) -> bool {
        self.low_power.load(Ordering::Acquire)
    }

    pub fn set_low_power(&self, enabled: bool) {
        let _tx = self.config_tx_lock.lock().unwrap();
        let prev = self.low_power.load(Ordering::Acquire);
        if enabled && !prev {
            // Populate `low_power_snapshot` BEFORE publishing `low_power = true` so no concurrent
            // reader observes `low_power == true` with `low_power_snapshot == None`.
            let vs = self.video_settings();
            let pol = self.polling_config();
            let mut snap = self.low_power_snapshot.lock().unwrap();
            if snap.is_none() {
                *snap = Some(LowPowerSnapshot {
                    p2p_relay_enabled: self.is_p2p_relay_enabled(),
                    max_web_viewers: self.max_web_viewers(),
                    fps: vs.fps,
                    bitrate_mbps: vs.bitrate_mbps,
                    hidpi: vs.hidpi,
                    polling: pol,
                });
            }
        }
        self.low_power.store(enabled, Ordering::Release);
        if prev != enabled {
            info!("Runtime setting updated: low_power={enabled}");
        }
        if enabled {
            // Low-power basic mode: trusted devices only (cancel any pending approvals),
            // disable Web viewing & P2P, drop stream to 4M/15fps eco 1x, and switch active polling
            // intervals to low-power defaults without clobbering saved YAML baseline preferences.
            self.notify_cancel_pending(None, None);
            self.p2p_relay_enabled.store(false, Ordering::Release);
            self.set_max_web_viewers_inner(0, false);
            *self.polling.lock().unwrap() = PollingConfigSection::low_power_defaults();
            let _ = self.update_video_settings_inner(
                VideoSettingsPatch {
                    quality: Some(QualityPreset::Eco),
                    hidpi: Some(1),
                    ..Default::default()
                },
                false,
                false,
            );
            self.apply_low_power_to_captures(true);
        } else if prev {
            // Reversibly restore pre-low-power runtime settings (from snapshot, or from persisted YAML baseline).
            let restore = self.low_power_snapshot.lock().unwrap().take().unwrap_or_else(|| {
                let base = self.persisted_baseline.lock().unwrap();
                LowPowerSnapshot {
                    p2p_relay_enabled: base.p2p_relay_enabled,
                    max_web_viewers: base.max_web_viewers,
                    fps: base.ipad.fps,
                    bitrate_mbps: base.ipad.bitrate_mbps,
                    hidpi: base.ipad.hidpi,
                    polling: base.polling.clone(),
                }
            });
            self.p2p_relay_enabled
                .store(restore.p2p_relay_enabled, Ordering::Release);
            self.set_max_web_viewers_inner(restore.max_web_viewers, false);
            *self.polling.lock().unwrap() = restore.polling;
            let _ = self.update_video_settings_inner(
                VideoSettingsPatch {
                    fps: Some(restore.fps),
                    bitrate_mbps: Some(restore.bitrate_mbps),
                    hidpi: Some(restore.hidpi),
                    ..Default::default()
                },
                false,
                false,
            );
            self.apply_low_power_to_captures(false);
        }
        if prev != enabled {
            self.persist_config_patch(|c| {
                c.low_power = enabled;
            });
        }
    }

    pub fn is_input_allowed(&self) -> bool {
        self.allow_input.load(Ordering::Relaxed)
    }

    pub fn is_client_cursor(&self) -> bool {
        self.client_cursor.load(Ordering::Acquire)
    }

    /// Dynamically toggle client-side cursor rendering vs OS-composited cursor on all active iPad captures.
    pub fn set_client_cursor(&self, enabled: bool) {
        self.set_client_cursor_inner(enabled, true);
    }

    fn set_client_cursor_inner(&self, enabled: bool, persist: bool) {
        let prev = self.client_cursor.swap(enabled, Ordering::AcqRel);
        if prev != enabled {
            info!(
                "Runtime setting updated: client_cursor={enabled} ({})",
                if enabled { "client-telemetry" } else { "composited" }
            );
        }
        if persist
            && (prev != enabled || self.persisted_baseline.lock().unwrap().client_cursor != enabled)
        {
            self.persist_config_patch(|c| c.client_cursor = enabled);
        }
        let handles: Vec<_> = {
            let map = self.sessions.lock().unwrap();
            map.iter()
                .filter_map(|(k, s)| Some((k.clone(), s.capture.as_ref()?.handle.clone())))
                .collect()
        };
        for (key, hdl) in handles {
            if let Ok(mut g) = hdl.lock() {
                if let Err(e) = g.set_show_cursor(!enabled) {
                    warn!("[{key}] Live set_show_cursor({}) failed: {e:#}", !enabled);
                }
            }
        }
    }

    pub fn is_web_require_approval(&self) -> bool {
        self.web_require_approval.load(Ordering::Acquire)
    }

    pub fn set_web_require_approval(&self, enabled: bool) {
        let prev = self.web_require_approval.swap(enabled, Ordering::AcqRel);
        if prev != enabled {
            info!("Runtime setting updated: web_require_approval={enabled}");
        }
        if prev != enabled || self.persisted_baseline.lock().unwrap().web_require_approval != enabled
        {
            self.persist_config_patch(|c| c.web_require_approval = enabled);
        }
    }

    pub fn gestures_config(&self) -> crate::user_config::EdgeGesturesConfig {
        self.gestures.lock().unwrap().clone()
    }

    pub fn set_gestures_config(
        &self,
        mut cfg: crate::user_config::EdgeGesturesConfig,
    ) -> Result<crate::user_config::EdgeGesturesConfig> {
        cfg.validate_and_normalize()?;
        *self.gestures.lock().unwrap() = cfg.clone();
        if let Ok(mut map) = self.sessions.lock() {
            for sess in map.values_mut() {
                sess.edge_gesture.reset();
            }
        }
        let persisted = cfg.clone();
        self.persist_config_patch(|c| c.gestures = persisted);
        info!(
            "Runtime setting updated: gestures.enabled={} edge_zone={}% min_swipe={}%",
            cfg.enabled, cfg.edge_zone_pct, cfg.min_swipe_pct
        );
        Ok(cfg)
    }

    pub fn set_input_allowed(&self, allowed: bool) {
        let prev = self.allow_input.swap(allowed, Ordering::AcqRel);
        info!("Runtime setting updated: allow_input={allowed}");
        if prev != allowed {
            self.persist_config_patch(|c| c.allow_input = allowed);
            if !allowed {
                self.release_all_stuck_mouse_buttons();
            }
        }
        let caps = self.backend.capabilities();
        if allowed && caps.accessibility_permission_required && !caps.accessibility_granted {
            warn!(
                "Remote input enabled, but OS Accessibility permission is NOT granted — iPad touch/keyboard events will be ignored until granted in System Settings -> Privacy & Security -> Accessibility."
            );
        }
    }

    pub fn max_extended_screens(&self) -> usize {
        self.max_extended_screens.load(Ordering::Relaxed)
    }

    pub fn set_max_extended_screens(&self, max_screens: usize) {
        let clamped = max_screens.min(32);
        let prev = self.max_extended_screens.swap(clamped, Ordering::AcqRel);
        if prev != clamped {
            info!("Runtime setting updated: max_extended_screens={clamped}");
            self.persist_config_patch(|c| c.max_extended_screens = clamped);
        }
    }

    pub fn max_web_viewers(&self) -> usize {
        self.max_web_viewers.load(Ordering::Relaxed)
    }

    pub fn set_max_web_viewers(&self, max_viewers: usize) {
        let _tx = self.config_tx_lock.lock().unwrap();
        self.set_max_web_viewers_inner(max_viewers, true);
    }

    /// Update runtime `max_web_viewers` without overwriting persisted `idis.yaml` baseline
    /// (used by external port idle auto-close so the user's saved YAML limit is preserved).
    pub fn set_max_web_viewers_runtime(&self, max_viewers: usize) {
        let _tx = self.config_tx_lock.lock().unwrap();
        self.set_max_web_viewers_inner(max_viewers, false);
    }

    fn set_max_web_viewers_inner(&self, max_viewers: usize, persist: bool) {
        let low_power = self.is_low_power();
        let requested = max_viewers.min(128);
        let clamped = if low_power { 0 } else { requested };
        let prev = self.max_web_viewers.swap(clamped, Ordering::AcqRel);
        if persist && low_power {
            // Keep runtime Web viewers disabled while low_power is active, but update persisted
            // baseline & low_power_snapshot so explicit changes/resets survive exiting low_power (Iter-7 P2-C2).
            if let Ok(mut snap) = self.low_power_snapshot.lock() {
                if let Some(ref mut s) = *snap {
                    s.max_web_viewers = requested;
                }
            }
            self.persist_config_patch(|c| c.max_web_viewers = requested);
        } else if prev != clamped {
            info!("Runtime setting updated: max_web_viewers={clamped}");
            if persist {
                self.persist_config_patch(|c| c.max_web_viewers = clamped);
            }
        }
        if clamped == 0 {
            self.kick_all_web_viewers();
        } else {
            let kicked = {
                let mut subs = self.web_subscribers.lock().unwrap();
                if subs.len() > clamped {
                    let excess: Vec<_> = subs.drain(clamped..).collect();
                    let n = excess.len();
                    for s in excess {
                        s.kick();
                    }
                    n
                } else {
                    0
                }
            };
            if kicked > 0 {
                info!("Disconnected {kicked} excess Web viewer(s) after lowering max_web_viewers to {clamped}");
                self.stop_standalone_web_capture_if_no_viewers();
            }
        }
        self.notify_web_viewer_limit_changed(clamped);
    }

    /// Number of currently active extended screens (authorized iPad sessions + independent virtual Web extended screen if active).
    pub fn active_extended_screens(&self) -> usize {
        let standalone_n = usize::from(
            self.is_web_independent_screen()
                && self.standalone_web_capture.lock().unwrap().is_some(),
        );
        let sess_n = self
            .sessions
            .lock()
            .unwrap()
            .values()
            .filter(|s| s.authorized)
            .count();
        sess_n + standalone_n
    }

    pub fn active_web_viewers(&self) -> usize {
        self.web_subscribers.lock().unwrap().len()
    }

    pub fn is_auto_max_in_flight(&self) -> bool {
        self.auto_max_in_flight.load(Ordering::Acquire)
    }

    /// Restore live sessions' `flow.max_in_flight` to `2` when returning to auto mode if previously
    /// disabled (`0`) or above transport auto ceiling (`2` for USB, `8` for Wi-Fi; Iter-9 P2-C1).
    fn reset_live_sessions_auto_in_flight(&self) {
        if let Ok(map) = self.sessions.lock() {
            for sess in map.values() {
                let max_bound = crate::abr::InFlightController::max_window_for_transport(sess.is_usb);
                let cur = sess.flow.max_in_flight();
                if cur == 0 || cur > max_bound {
                    sess.flow.set_max_in_flight(2);
                }
            }
        }
    }

    pub fn set_auto_max_in_flight(&self, auto: bool) {
        let prev = self.auto_max_in_flight.swap(auto, Ordering::AcqRel);
        if auto {
            self.reset_live_sessions_auto_in_flight();
        } else {
            let fixed = self.max_in_flight();
            if let Ok(map) = self.sessions.lock() {
                for sess in map.values() {
                    sess.flow.set_max_in_flight(fixed);
                }
            }
        }
        if prev != auto {
            info!(
                "Runtime setting updated: auto_max_in_flight={auto} (manual_fallback={})",
                self.max_in_flight()
            );
            self.persist_config_patch(|c| c.auto_max_in_flight = auto);
        }
    }

    pub fn max_in_flight(&self) -> u32 {
        self.max_in_flight.load(Ordering::Relaxed)
    }

    /// Initial per-session in-flight limit (starts at 2 in auto mode, or fixed value when manual).
    pub(super) fn initial_session_max_in_flight(&self) -> u32 {
        if self.is_auto_max_in_flight() {
            2
        } else {
            self.max_in_flight()
        }
    }

    pub fn set_max_in_flight(&self, max_in_flight: u32) {
        let clamped = max_in_flight.min(12);
        self.auto_max_in_flight.store(false, Ordering::Release);
        self.max_in_flight.store(clamped, Ordering::Relaxed);
        if let Ok(map) = self.sessions.lock() {
            for sess in map.values() {
                sess.flow.set_max_in_flight(clamped);
            }
        }
        info!("Runtime setting updated: max_in_flight={clamped} (manual)");
        self.persist_config_patch(|c| {
            c.auto_max_in_flight = false;
            c.max_in_flight = clamped;
        });
    }

    /// Clear saved per-device display/quality overrides for a trusted device fingerprint and
    /// hot-apply global settings to any currently active session matching that fingerprint.
    pub fn clear_trusted_device_prefs_and_save(&self, fingerprint: &str) -> Result<bool> {
        let Some(norm_fp) = crate::trust::normalize_fingerprint(fingerprint) else {
            return Ok(false);
        };
        let cleared = {
            let _tx = self.config_tx_lock.lock().unwrap();
            let _save = self.settings_save_lock.lock().unwrap();
            if let Some(ref path) = self.config_path {
                if self.config_read_only_corrupt.load(Ordering::Acquire) {
                    return Err(anyhow!(
                        "配置文件 {} 存在语法错误，当前处于只读保护模式；请先在「配置文件」修复并保存有效 YAML 后再修改受信设备",
                        path.display()
                    ));
                }
            }
            let prev_devices = self.trust_store.list();
            let cleared = self.trust_store.clear_device_prefs(&norm_fp)?;
            if cleared {
                if let Some(ref path) = self.config_path {
                    let mut snapshot = self.persisted_baseline.lock().unwrap().clone();
                    snapshot.trusted_devices = self.trust_store.list();
                    if let Err(e) = save_yaml_file(path, &snapshot) {
                        self.trust_store.replace_all_in_memory(prev_devices);
                        return Err(e);
                    }
                }
            }
            cleared
        };
        if cleared {
            self.ipad_video_settings_gen.fetch_add(1, Ordering::AcqRel);
            let vs = self.video_settings();
            let supports_hidpi = self.backend.supports_hidpi();
            let eff_hidpi = if supports_hidpi { vs.hidpi } else { 1 };
            type SharedCapture = Arc<Mutex<Box<dyn CaptureHandle>>>;
            let targets: Vec<(String, u32, u32, u32, SharedCapture)> = {
                let map = self.sessions.lock().unwrap();
                map.iter()
                    .filter(|(_, s)| {
                        s.fingerprint
                            .as_deref()
                            .is_some_and(|fp| fp.eq_ignore_ascii_case(&norm_fp))
                    })
                    .filter_map(|(k, s)| {
                        let hdl = s.capture.as_ref()?.handle.clone();
                        let (w, h, edge) = if let Some(ref hs) = s.handshake {
                            let (rw, rh) =
                                Self::resolve_dimensions_for_settings(hs, &vs, supports_hidpi);
                            (rw, rh, Self::effective_ipad_max_pixel_edge(hs, &vs))
                        } else {
                            (1024, 768, IPAD_MAX_PIXEL_EDGE)
                        };
                        Some((k.clone(), w, h, edge, hdl))
                    })
                    .collect()
            };
            for (key, w, h, edge, hdl) in targets {
                self.notify_lifecycle_wakeup();
                if let Ok(mut g) = hdl.lock() {
                    if let Err(e) = g.reconfigure(w, h, vs.fps, vs.bitrate_mbps, eff_hidpi, edge) {
                        warn!("[{key}] Live reconfigure after clearing device prefs failed: {e:#}");
                    }
                }
                self.notify_lifecycle_wakeup();
            }
            info!("Cleared saved per-device preferences for {norm_fp}");
        }
        Ok(cleared)
    }

    /// Total active authorized screen connections (iPad Wi-Fi + USB sessions + Web extended-screen viewers).
    pub fn total_screen_connections(&self) -> usize {
        let sess_n = self
            .sessions
            .lock()
            .unwrap()
            .values()
            .filter(|s| s.authorized)
            .count();
        let web_n = self.web_subscribers.lock().unwrap().len();
        sess_n + web_n
    }

}
