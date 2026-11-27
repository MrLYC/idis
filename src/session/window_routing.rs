use super::SessionRegistry;
use crate::platform::{DesktopWindowInfo, StandaloneVirtualDisplayHandle, WindowMoveLayout};
use crate::user_config::{WindowRouteTarget, WindowRule, MAX_WINDOW_RULES};
use anyhow::{anyhow, Result};
use serde::Serialize;
use std::collections::HashSet;
use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

pub const MAX_STANDALONE_VIRTUAL_DISPLAYS: usize = 4;

pub(super) struct StandaloneVirtualDisplayEntry {
    pub id: u64,
    pub name: String,
    pub width: u32,
    pub height: u32,
    pub display_id: u32,
    pub created_at_unix: u64,
    pub handle: Box<dyn StandaloneVirtualDisplayHandle>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StandaloneVirtualDisplayInfo {
    pub id: u64,
    pub name: String,
    pub width: u32,
    pub height: u32,
    pub display_id: u32,
    pub created_at_unix: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScreenTargetInfo {
    pub id: String,
    pub kind: String,
    pub name: String,
    pub display_id: u32,
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
    pub is_main: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ApplyRulesReport {
    pub moved: usize,
    pub skipped: usize,
    pub failed: usize,
    pub errors: Vec<String>,
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn sanitize_virtual_display_name(raw: &str, seq: u64) -> String {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .chars()
        .take(48)
        .collect();
    if cleaned.is_empty() {
        format!("虚拟屏 {seq}")
    } else {
        cleaned
    }
}

pub(crate) fn rule_matches_window(rule: &WindowRule, win: &DesktopWindowInfo) -> bool {
    if !rule.enabled {
        return false;
    }
    if rule.floating_only && !win.is_floating {
        return false;
    }
    if !rule.bundle_id.is_empty()
        && !win.bundle_id.eq_ignore_ascii_case(rule.bundle_id.trim())
    {
        return false;
    }
    if !rule.app_name.is_empty() {
        let needle = rule.app_name.trim().to_lowercase();
        let app_lc = win.app_name.to_lowercase();
        if !app_lc.contains(&needle) {
            return false;
        }
    }
    if !rule.title_contains.is_empty() {
        let needle = rule.title_contains.trim().to_lowercase();
        let title_lc = win.title.to_lowercase();
        if !title_lc.contains(&needle) {
            return false;
        }
    }
    true
}

impl SessionRegistry {
    pub fn list_standalone_virtual_displays(&self) -> Vec<StandaloneVirtualDisplayInfo> {
        self.standalone_virtual_displays
            .lock()
            .unwrap()
            .iter()
            .map(|e| StandaloneVirtualDisplayInfo {
                id: e.id,
                name: e.name.clone(),
                width: e.width,
                height: e.height,
                display_id: e.display_id,
                created_at_unix: e.created_at_unix,
            })
            .collect()
    }

    pub fn has_standalone_virtual_displays(&self) -> bool {
        !self.standalone_virtual_displays.lock().unwrap().is_empty()
    }

    /// Create an ephemeral zero-encode standalone virtual display (destroyed on manual removal or process exit).
    pub fn create_standalone_virtual_display(
        &self,
        raw_name: &str,
        width: u32,
        height: u32,
    ) -> Result<StandaloneVirtualDisplayInfo> {
        if !self.backend.supports_virtual_display() {
            return Err(anyhow!("当前平台不支持创建独立虚拟屏（仅 macOS 支持）"));
        }
        let w = if width >= 320 {
            width.clamp(320, 3840) & !1
        } else {
            1280
        };
        let h = if height >= 240 {
            height.clamp(240, 2160) & !1
        } else {
            720
        };
        let shutdown_epoch = {
            let list = self.standalone_virtual_displays.lock().unwrap();
            if list.len() >= MAX_STANDALONE_VIRTUAL_DISPLAYS {
                return Err(anyhow!(
                    "临时虚拟屏数量已达上限（最多 {MAX_STANDALONE_VIRTUAL_DISPLAYS} 块）"
                ));
            }
            self.virtual_display_shutdown_epoch.load(Ordering::Acquire)
        };
        let seq = self
            .next_virtual_display_id
            .fetch_add(1, Ordering::AcqRel);
        let name = sanitize_virtual_display_name(raw_name, seq);
        let serial_num = 0x4944_8000u32.wrapping_add((seq as u32) & 0x7FFF);

        let mut handle = self
            .backend
            .create_standalone_virtual_display(&name, w, h, serial_num)?;
        let display_id = handle.display_id();
        let created_at_unix = unix_now_secs();
        let info_out = StandaloneVirtualDisplayInfo {
            id: seq,
            name: name.clone(),
            width: w,
            height: h,
            display_id,
            created_at_unix,
        };
        {
            let mut list = self.standalone_virtual_displays.lock().unwrap();
            let epoch_changed =
                self.virtual_display_shutdown_epoch.load(Ordering::Acquire) != shutdown_epoch;
            if epoch_changed || list.len() >= MAX_STANDALONE_VIRTUAL_DISPLAYS {
                drop(list);
                handle.stop();
                drop(handle);
                return Err(anyhow!(if epoch_changed {
                    "临时虚拟屏创建期间触发了全量关闭，已自动清理"
                } else {
                    "临时虚拟屏数量已达上限（最多 4 块）"
                }));
            }
            list.push(StandaloneVirtualDisplayEntry {
                id: seq,
                name: name.clone(),
                width: w,
                height: h,
                display_id,
                created_at_unix,
                handle,
            });
        }
        info!("Created ephemeral standalone virtual display #{seq} '{name}' ({w}x{h}, display_id={display_id})");
        // Clear prior dedup entries for virtual-display rules so existing matching windows move immediately.
        self.clear_applied_moves_for_virtual_targets();
        self.record_external_activity();
        let _ = self.tick_window_rules();
        Ok(info_out)
    }

    /// Destroy an ephemeral standalone virtual display by its runtime ID.
    pub fn remove_standalone_virtual_display(&self, id: u64) -> bool {
        let removed = {
            let mut list = self.standalone_virtual_displays.lock().unwrap();
            list.iter().position(|e| e.id == id).map(|pos| list.remove(pos))
        };
        if let Some(mut entry) = removed {
            info!(
                "Destroying ephemeral standalone virtual display #{} '{}' (display_id={})",
                entry.id, entry.name, entry.display_id
            );
            entry.handle.stop();
            drop(entry);
            self.record_external_activity();
            true
        } else {
            false
        }
    }

    /// Destroy all ephemeral standalone virtual displays cleanly during process shutdown.
    pub fn shutdown_all_virtual_displays(&self) {
        let entries: Vec<StandaloneVirtualDisplayEntry> = {
            let mut list = self.standalone_virtual_displays.lock().unwrap();
            self.virtual_display_shutdown_epoch
                .fetch_add(1, Ordering::AcqRel);
            std::mem::take(&mut *list)
        };
        for mut entry in entries {
            entry.handle.stop();
        }
    }

    /// Enumerate all currently available target screens (Main, ephemeral virtual displays, connected iPads, standalone Web screen).
    pub fn list_target_screens(&self) -> Vec<ScreenTargetInfo> {
        let mut out = Vec::new();
        let mut seen_display_ids = HashSet::new();

        let main_id = self.backend.main_display_id();
        if main_id != 0 {
            let (x, y, w, h) = self
                .backend
                .display_bounds(main_id)
                .unwrap_or((0, 0, 0, 0));
            seen_display_ids.insert(main_id);
            out.push(ScreenTargetInfo {
                id: "main".to_string(),
                kind: "main".to_string(),
                name: "电脑主屏幕".to_string(),
                display_id: main_id,
                x,
                y,
                width: w,
                height: h,
                is_main: true,
                device_fingerprint: None,
            });
        }

        let vds = self.list_standalone_virtual_displays();
        for vd in vds {
            if vd.display_id == 0 || !seen_display_ids.insert(vd.display_id) {
                continue;
            }
            let (x, y, w, h) = self
                .backend
                .display_bounds(vd.display_id)
                .unwrap_or((0, 0, vd.width, vd.height));
            out.push(ScreenTargetInfo {
                id: format!("vd:{}", vd.id),
                kind: "virtual".to_string(),
                name: vd.name,
                display_id: vd.display_id,
                x,
                y,
                width: w,
                height: h,
                is_main: false,
                device_fingerprint: None,
            });
        }

        let ipad_caps: Vec<(String, Option<String>, super::flow_control::SharedCaptureHandle)> = {
            let map = self.sessions.lock().unwrap();
            map.iter()
                .filter_map(|(k, s)| {
                    let cap = s.capture.as_ref()?;
                    let name = s
                        .handshake
                        .as_ref()
                        .map(|h| h.name.trim())
                        .filter(|n| !n.is_empty())
                        .map(|n| n.to_string())
                        .unwrap_or_else(|| k.clone());
                    Some((name, s.fingerprint.clone(), cap.handle.clone()))
                })
                .collect()
        };
        for (name, fp, hdl) in ipad_caps {
            let (did, handle_bounds) = hdl
                .lock()
                .ok()
                .map(|g| (g.display_id().unwrap_or(0), g.display_bounds()))
                .unwrap_or((0, None));
            if did == 0 || !seen_display_ids.insert(did) {
                continue;
            }
            let (x, y, w, h) = self
                .backend
                .display_bounds(did)
                .or(handle_bounds)
                .unwrap_or((0, 0, 0, 0));
            out.push(ScreenTargetInfo {
                id: format!("ipad:{}", fp.as_deref().unwrap_or(&name)),
                kind: "ipad".to_string(),
                name,
                display_id: did,
                x,
                y,
                width: w,
                height: h,
                is_main: false,
                device_fingerprint: fp,
            });
        }

        let web_hdl = self
            .standalone_web_capture
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|c| c.handle.clone()));
        if let Some(hdl) = web_hdl {
            let (did, handle_bounds) = hdl
                .lock()
                .ok()
                .map(|g| (g.display_id().unwrap_or(0), g.display_bounds()))
                .unwrap_or((0, None));
            if did != 0 && seen_display_ids.insert(did) {
                let (x, y, w, h) = self
                    .backend
                    .display_bounds(did)
                    .or(handle_bounds)
                    .unwrap_or((0, 0, 0, 0));
                out.push(ScreenTargetInfo {
                    id: "web:independent".to_string(),
                    kind: "web".to_string(),
                    name: "网页独立屏".to_string(),
                    display_id: did,
                    x,
                    y,
                    width: w,
                    height: h,
                    is_main: false,
                    device_fingerprint: None,
                });
            }
        }

        for (did, name, x, y, w, h) in self.backend.list_additional_displays() {
            if did == 0 || !seen_display_ids.insert(did) {
                continue;
            }
            out.push(ScreenTargetInfo {
                id: format!("display:{did}"),
                kind: "display".to_string(),
                name,
                display_id: did,
                x,
                y,
                width: w,
                height: h,
                is_main: false,
                device_fingerprint: None,
            });
        }

        out
    }

    pub fn list_desktop_windows(&self) -> Result<Vec<DesktopWindowInfo>> {
        self.backend.list_desktop_windows()
    }

    pub fn move_desktop_window(
        &self,
        window_id: u32,
        pid: i32,
        target_display_id: u32,
        layout: WindowMoveLayout,
    ) -> Result<()> {
        self.backend
            .move_desktop_window(window_id, pid, target_display_id, layout)
    }

    pub fn list_window_rules(&self) -> Vec<WindowRule> {
        self.window_rules.lock().unwrap().clone()
    }

    pub fn upsert_window_rule(&self, mut rule: WindowRule) -> Result<WindowRule> {
        if rule.id.trim().is_empty() {
            let seq = self.next_window_rule_id.fetch_add(1, Ordering::AcqRel);
            rule.id = format!("rule-{}-{seq}", unix_now_secs());
        }
        rule.validate_and_normalize()?;
        let saved = {
            let mut rules = self.window_rules.lock().unwrap();
            if let Some(existing) = rules.iter_mut().find(|r| r.id == rule.id) {
                *existing = rule.clone();
            } else {
                if rules.len() >= MAX_WINDOW_RULES {
                    return Err(anyhow!("窗口规则数量不能超过 {MAX_WINDOW_RULES} 条"));
                }
                rules.push(rule.clone());
            }
            rules.clone()
        };
        self.persist_config_patch(|c| c.window_rules = saved);
        // Clear dedup for this rule so newly added/edited enabled rule takes effect immediately.
        self.applied_window_moves
            .lock()
            .unwrap()
            .retain(|(_, rid)| rid != &rule.id);
        self.record_external_activity();
        let _ = self.tick_window_rules();
        Ok(rule)
    }

    pub fn delete_window_rule(&self, id: &str) -> bool {
        let needle = id.trim();
        let (removed, snapshot) = {
            let mut rules = self.window_rules.lock().unwrap();
            let before = rules.len();
            rules.retain(|r| r.id != needle);
            (rules.len() != before, rules.clone())
        };
        if removed {
            self.persist_config_patch(|c| c.window_rules = snapshot);
            self.applied_window_moves
                .lock()
                .unwrap()
                .retain(|(_, rid)| rid != needle);
        }
        removed
    }

    fn resolve_target_display_id(
        target: &WindowRouteTarget,
        screens: &[ScreenTargetInfo],
    ) -> Option<u32> {
        match target {
            WindowRouteTarget::AnyVirtual => screens
                .iter()
                .find(|s| s.kind == "virtual")
                .map(|s| s.display_id),
            WindowRouteTarget::VirtualName { name } => {
                let needle = name.trim();
                screens
                    .iter()
                    .find(|s| s.kind == "virtual" && s.name.eq_ignore_ascii_case(needle))
                    .map(|s| s.display_id)
            }
            WindowRouteTarget::AnyIpad => screens
                .iter()
                .find(|s| s.kind == "ipad")
                .map(|s| s.display_id),
            WindowRouteTarget::Device { fingerprint } => {
                let needle = fingerprint.trim();
                screens
                    .iter()
                    .find(|s| {
                        s.kind == "ipad"
                            && s.device_fingerprint
                                .as_deref()
                                .is_some_and(|fp| fp.eq_ignore_ascii_case(needle))
                    })
                    .map(|s| s.display_id)
            }
            WindowRouteTarget::WebScreen => screens
                .iter()
                .find(|s| s.kind == "web")
                .map(|s| s.display_id),
            WindowRouteTarget::Display { display_id } => screens
                .iter()
                .find(|s| s.display_id == *display_id)
                .map(|s| s.display_id),
            WindowRouteTarget::MainDisplay => screens
                .iter()
                .find(|s| s.is_main)
                .map(|s| s.display_id),
        }
    }

    fn clear_applied_moves_for_virtual_targets(&self) {
        let virtual_rule_ids: HashSet<String> = self
            .window_rules
            .lock()
            .unwrap()
            .iter()
            .filter(|r| {
                matches!(
                    r.target,
                    WindowRouteTarget::AnyVirtual | WindowRouteTarget::VirtualName { .. }
                )
            })
            .map(|r| r.id.clone())
            .collect();
        if !virtual_rule_ids.is_empty() {
            self.applied_window_moves
                .lock()
                .unwrap()
                .retain(|(_, rid)| !virtual_rule_ids.contains(rid));
        }
    }

    /// Clear prior dedup entries for iPad targets when an iPad capture starts so auto-rules run once.
    pub(super) fn on_ipad_screen_online_for_window_rules(&self) {
        let ipad_rule_ids: HashSet<String> = self
            .window_rules
            .lock()
            .unwrap()
            .iter()
            .filter(|r| {
                matches!(
                    r.target,
                    WindowRouteTarget::AnyIpad | WindowRouteTarget::Device { .. }
                )
            })
            .map(|r| r.id.clone())
            .collect();
        if !ipad_rule_ids.is_empty() {
            self.applied_window_moves
                .lock()
                .unwrap()
                .retain(|(_, rid)| !ipad_rule_ids.contains(rid));
        }
    }

    /// Returns true only when window routing is supported AND at least one enabled rule exists.
    pub fn has_active_window_routing_work(&self) -> bool {
        if !self.backend.supports_window_routing() {
            return false;
        }
        let rules = self.window_rules.lock().unwrap();
        if !rules.iter().any(|r| r.enabled) {
            return false;
        }
        // Only wake/poll if there is at least one target screen (virtual display, iPad, or Web screen)
        // OR an enabled MainDisplay rule.
        let has_non_main = self.has_standalone_virtual_displays()
            || !self.sessions.lock().unwrap().is_empty()
            || self.standalone_web_capture.lock().unwrap().is_some();
        has_non_main
            || rules.iter().any(|r| {
                r.enabled
                    && matches!(
                        r.target,
                        WindowRouteTarget::MainDisplay | WindowRouteTarget::Display { .. }
                    )
            })
    }

    /// Force-apply all enabled rules right now (ignoring prior anti-fighting dedup).
    pub fn apply_window_rules_now(&self) -> Result<ApplyRulesReport> {
        self.applied_window_moves.lock().unwrap().clear();
        self.tick_window_rules_inner(true)
    }

    /// Lightweight periodic tick called from the main loop (~1.5s when active).
    pub fn tick_window_rules(&self) -> Result<ApplyRulesReport> {
        self.tick_window_rules_inner(false)
    }

    fn tick_window_rules_inner(&self, force: bool) -> Result<ApplyRulesReport> {
        if !self.backend.supports_window_routing() {
            return Ok(ApplyRulesReport::default());
        }
        if !force && self.is_host_screen_locked() {
            return Ok(ApplyRulesReport::default());
        }
        let rules: Vec<WindowRule> = self
            .window_rules
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.enabled)
            .cloned()
            .collect();
        if rules.is_empty() {
            return Ok(ApplyRulesReport::default());
        }
        let screens = self.list_target_screens();
        let active_rules: Vec<(WindowRule, u32)> = rules
            .into_iter()
            .filter_map(|r| {
                let did = Self::resolve_target_display_id(&r.target, &screens)?;
                Some((r, did))
            })
            .collect();
        if active_rules.is_empty() {
            return Ok(ApplyRulesReport::default());
        }

        let windows = self.backend.list_desktop_windows()?;
        let live_wids: HashSet<u32> = windows.iter().map(|w| w.window_id).collect();
        {
            let mut applied = self.applied_window_moves.lock().unwrap();
            applied.retain(|(wid, _)| live_wids.contains(wid));
        }

        let mut report = ApplyRulesReport::default();
        for win in &windows {
            let Some((rule, target_did)) = active_rules
                .iter()
                .find(|(r, _)| rule_matches_window(r, win))
            else {
                continue;
            };
            let key = (win.window_id, rule.id.clone());
            if win.display_id == *target_did {
                self.applied_window_moves.lock().unwrap().insert(key);
                report.skipped += 1;
                continue;
            }
            if !force && self.applied_window_moves.lock().unwrap().contains(&key) {
                report.skipped += 1;
                continue;
            }
            match self
                .backend
                .move_desktop_window(win.window_id, win.pid, *target_did, rule.layout)
            {
                Ok(()) => {
                    debug!(
                        "Window rule '{}' moved '{}' ({}) wid={} -> display {}",
                        rule.id, win.app_name, win.title, win.window_id, target_did
                    );
                    self.applied_window_moves.lock().unwrap().insert(key);
                    report.moved += 1;
                }
                Err(e) => {
                    warn!(
                        "Window rule '{}' failed to move wid={} ('{}'): {e:#}",
                        rule.id, win.window_id, win.app_name
                    );
                    report.failed += 1;
                    if report.errors.len() < 8 {
                        report.errors.push(format!("{}: {e}", win.app_name));
                    }
                }
            }
        }
        Ok(report)
    }
}
