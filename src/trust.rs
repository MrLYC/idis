use crate::protocol::messages::ClientHandshake;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

/// Optional per-device display & streaming preferences stored directly on a trusted device entry.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevicePreferences {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fps: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bitrate_mbps: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hidpi: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_pixel_edge: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adaptive_quality: Option<bool>,
}

impl DevicePreferences {
    pub fn is_empty(&self) -> bool {
        self.width.is_none()
            && self.height.is_none()
            && self.fps.is_none()
            && self.bitrate_mbps.is_none()
            && self.hidpi.is_none()
            && self.max_pixel_edge.is_none()
            && self.adaptive_quality.is_none()
    }

    pub fn normalize(&mut self) {
        match (self.width, self.height) {
            (Some(w), Some(h)) if w >= 320 && h >= 240 => {
                self.width = Some(w.clamp(320, 3840) & !1);
                self.height = Some(h.clamp(240, 2160) & !1);
            }
            (Some(0), Some(0)) => {
                self.width = Some(0);
                self.height = Some(0);
            }
            (None, None) => {}
            _ => {
                self.width = None;
                self.height = None;
            }
        }
        if let Some(fps) = self.fps {
            self.fps = Some(fps.clamp(5, 120));
        }
        if let Some(br) = self.bitrate_mbps {
            self.bitrate_mbps = Some(br.clamp(2, 60));
        }
        if let Some(h) = self.hidpi {
            self.hidpi = Some(if h >= 2 { 2 } else { 1 });
        }
        if let Some(edge) = self.max_pixel_edge {
            self.max_pixel_edge = Some(if edge >= 640 {
                edge.clamp(640, 3840) & !1
            } else {
                0
            });
        }
    }

    /// Merge any `Some(...)` fields from `patch` into `self` without clobbering unspecified fields.
    pub fn merge_from(&mut self, patch: &DevicePreferences) {
        if let (Some(w), Some(h)) = (patch.width, patch.height) {
            self.width = Some(w);
            self.height = Some(h);
        }
        if let Some(fps) = patch.fps {
            self.fps = Some(fps);
        }
        if let Some(br) = patch.bitrate_mbps {
            self.bitrate_mbps = Some(br);
        }
        if let Some(h) = patch.hidpi {
            self.hidpi = Some(h);
        }
        if let Some(edge) = patch.max_pixel_edge {
            self.max_pixel_edge = Some(edge);
        }
        if let Some(aq) = patch.adaptive_quality {
            self.adaptive_quality = Some(aq);
        }
        self.normalize();
    }
}

/// A persisted trusted client device record bound to a deterministic SHA-256 handshake fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedDevice {
    /// Deterministic SHA-256 device fingerprint (`fp:<24-hex>`) computed from stable handshake
    /// attributes plus the device name.
    #[serde(default)]
    pub fingerprint: String,
    /// Legacy MAC field accepted only when reading older `~/.config/idis.yaml` files for smooth migration.
    #[serde(default, skip_serializing)]
    pub mac: String,
    /// Client-reported iDisplay `uniqueIdentifier` (informational metadata; hashed into `fingerprint`).
    #[serde(default)]
    pub uid: String,
    /// Human-readable device name (e.g. `iPad Air`; hashed into `fingerprint`).
    #[serde(default)]
    pub name: String,
    /// Device model (e.g. `iPad`).
    #[serde(default)]
    pub model: String,
    /// Unix timestamp (seconds) when the device was trusted.
    #[serde(default)]
    pub trusted_at: u64,
    /// Optional per-device display & streaming preferences (fall back to global iPad settings when omitted).
    #[serde(flatten, default)]
    pub prefs: DevicePreferences,
}

type PersistHook = Arc<dyn Fn() -> Result<()> + Send + Sync>;

/// Thread-safe persistent store of trusted client devices keyed by deterministic device fingerprint.
pub struct TrustStore {
    path: Option<PathBuf>,
    legacy_file_persist: bool,
    devices: Mutex<Vec<TrustedDevice>>,
    save_lock: Mutex<()>,
    persist_hook: Mutex<Option<PersistHook>>,
}

impl TrustStore {
    /// Load trusted devices from a legacy `.txt` path (or start empty if the file does not exist yet).
    /// If `path` is `None`, operates in-memory only (or delegates persistence to a YAML persist hook).
    pub fn load(path: Option<PathBuf>) -> Self {
        let mut devices = Vec::new();
        if let Some(ref p) = path {
            match fs::read_to_string(p) {
                Ok(content) => {
                    devices = parse_trusted_file(&content);
                    info!(
                        "Loaded {} trusted device(s) from {}",
                        devices.len(),
                        p.display()
                    );
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    debug!("Trusted devices file not found yet: {}", p.display());
                }
                Err(e) => {
                    warn!("Failed to read trusted devices file {}: {e}", p.display());
                }
            }
        }
        Self {
            path,
            legacy_file_persist: true,
            devices: Mutex::new(devices),
            save_lock: Mutex::new(()),
            persist_hook: Mutex::new(None),
        }
    }

    /// Construct a `TrustStore` backed by `~/.config/idis.yaml` with pre-loaded devices.
    /// Does NOT write legacy TSV files directly — persistence is coordinated by `SessionRegistry`.
    pub fn from_devices(display_path: Option<PathBuf>, devices: Vec<TrustedDevice>) -> Self {
        Self {
            path: display_path,
            legacy_file_persist: false,
            devices: Mutex::new(devices),
            save_lock: Mutex::new(()),
            persist_hook: Mutex::new(None),
        }
    }

    /// Install a unified persistence callback (used when backed by `~/.config/idis.yaml`).
    pub fn set_persist_hook(&self, hook: PersistHook) {
        *self.persist_hook.lock().unwrap() = Some(hook);
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    pub fn list(&self) -> Vec<TrustedDevice> {
        self.devices.lock().unwrap().clone()
    }

    /// Look up a trusted device record by device fingerprint.
    pub fn get_device(&self, fingerprint: &str) -> Option<TrustedDevice> {
        let norm = normalize_fingerprint(fingerprint)?;
        let guard = self.devices.lock().unwrap();
        guard.iter().find(|d| d.fingerprint == norm).cloned()
    }

    /// Replace all trusted device records in memory (used when reloading/saving `~/.config/idis.yaml`).
    pub fn replace_all_in_memory(&self, devices: Vec<TrustedDevice>) {
        *self.devices.lock().unwrap() = devices;
    }

    /// Check whether a connecting device matches a persisted trusted fingerprint record.
    pub fn is_trusted(&self, fingerprint: Option<&str>) -> bool {
        let Some(actual) = fingerprint.and_then(normalize_fingerprint) else {
            return false;
        };
        let guard = self.devices.lock().unwrap();
        guard.iter().any(|d| d.fingerprint == actual)
    }

    fn persist_devices(&self, next: &[TrustedDevice]) -> Result<()> {
        let hook = self.persist_hook.lock().unwrap().clone();
        if let Some(cb) = hook {
            return cb();
        }
        if self.legacy_file_persist {
            if let Some(ref p) = self.path {
                save_trusted_file(p, next)?;
            }
        }
        Ok(())
    }

    /// Add or update a trusted device by fingerprint and persist the store atomically to disk (if configured).
    /// Preserves any existing per-device connection preferences when updating metadata.
    pub fn trust_device(
        &self,
        fingerprint: &str,
        uid: &str,
        name: &str,
        model: &str,
    ) -> Result<TrustedDevice> {
        let Some(norm_fp) = normalize_fingerprint(fingerprint) else {
            anyhow::bail!("cannot trust device without a valid device fingerprint");
        };
        let clean_uid = sanitize_field(uid);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let _save_guard = self.save_lock.lock().unwrap();
        let prev = self.devices.lock().unwrap().clone();
        let existing_prefs = prev
            .iter()
            .find(|d| d.fingerprint == norm_fp)
            .map(|d| d.prefs.clone())
            .unwrap_or_default();
        let record = TrustedDevice {
            fingerprint: norm_fp.clone(),
            mac: String::new(),
            uid: clean_uid,
            name: sanitize_field(name),
            model: sanitize_field(model),
            trusted_at: now,
            prefs: existing_prefs,
        };
        let mut next = prev.clone();
        next.retain(|d| d.fingerprint != norm_fp);
        next.push(record.clone());

        *self.devices.lock().unwrap() = next.clone();
        if let Err(e) = self.persist_devices(&next) {
            *self.devices.lock().unwrap() = prev;
            return Err(e);
        }
        if let Some(ref p) = self.path {
            info!(
                "Saved trusted device (fingerprint={}, name={:?}) to {}",
                record.fingerprint,
                record.name,
                p.display()
            );
        }
        Ok(record)
    }

    /// Merge non-`None` per-device connection preferences into an already-trusted device fingerprint
    /// without clobbering unrelated saved fields.
    pub fn update_device_prefs(
        &self,
        fingerprint: &str,
        mut prefs: DevicePreferences,
    ) -> Result<bool> {
        let Some(norm_fp) = normalize_fingerprint(fingerprint) else {
            return Ok(false);
        };
        prefs.normalize();
        if prefs.is_empty() {
            return Ok(false);
        }
        let _save_guard = self.save_lock.lock().unwrap();
        let prev = self.devices.lock().unwrap().clone();
        let mut next = prev.clone();
        let Some(dev) = next.iter_mut().find(|d| d.fingerprint == norm_fp) else {
            return Ok(false);
        };
        let mut merged = dev.prefs.clone();
        merged.merge_from(&prefs);
        if dev.prefs == merged {
            return Ok(false);
        }
        dev.prefs = merged;
        *self.devices.lock().unwrap() = next.clone();
        if let Err(e) = self.persist_devices(&next) {
            *self.devices.lock().unwrap() = prev;
            return Err(e);
        }
        Ok(true)
    }

    /// Clear all per-device preference overrides for a single trusted fingerprint so it inherits
    /// global/preset settings cleanly. Returns `true` if any preference fields were cleared.
    pub fn clear_device_prefs(&self, fingerprint: &str) -> Result<bool> {
        let Some(norm_fp) = normalize_fingerprint(fingerprint) else {
            return Ok(false);
        };
        let _save_guard = self.save_lock.lock().unwrap();
        let prev = self.devices.lock().unwrap().clone();
        let mut next = prev.clone();
        let Some(dev) = next.iter_mut().find(|d| d.fingerprint == norm_fp) else {
            return Ok(false);
        };
        if dev.prefs.is_empty() {
            return Ok(false);
        }
        dev.prefs = DevicePreferences::default();
        *self.devices.lock().unwrap() = next.clone();
        if let Err(e) = self.persist_devices(&next) {
            *self.devices.lock().unwrap() = prev;
            return Err(e);
        }
        Ok(true)
    }

    /// Clear per-device preference overrides across ALL trusted devices (used by full iPad reset).
    pub fn clear_all_device_prefs(&self) -> Result<bool> {
        let _save_guard = self.save_lock.lock().unwrap();
        let prev = self.devices.lock().unwrap().clone();
        let mut next = prev.clone();
        let mut changed = false;
        for dev in &mut next {
            if !dev.prefs.is_empty() {
                dev.prefs = DevicePreferences::default();
                changed = true;
            }
        }
        if !changed {
            return Ok(false);
        }
        *self.devices.lock().unwrap() = next.clone();
        if let Err(e) = self.persist_devices(&next) {
            *self.devices.lock().unwrap() = prev;
            return Err(e);
        }
        Ok(true)
    }

    /// Remove trusted device matching the given normalized fingerprint and persist to disk.
    /// Returns `true` if at least one entry was removed.
    pub fn revoke_device(&self, fingerprint: &str) -> Result<bool> {
        let Some(norm_fp) = normalize_fingerprint(fingerprint) else {
            return Ok(false);
        };

        let _save_guard = self.save_lock.lock().unwrap();
        let prev = self.devices.lock().unwrap().clone();
        let mut next = prev.clone();
        let before = next.len();
        next.retain(|d| d.fingerprint != norm_fp);
        let removed = next.len() < before;

        if removed {
            *self.devices.lock().unwrap() = next.clone();
            if let Err(e) = self.persist_devices(&next) {
                *self.devices.lock().unwrap() = prev;
                return Err(e);
            }
            if let Some(ref p) = self.path {
                info!(
                    "Revoked trusted device (fingerprint={}) from {}",
                    norm_fp,
                    p.display()
                );
            }
        }
        Ok(removed)
    }
}

/// Default per-user path for storing legacy trusted client devices across macOS, Linux, and Windows.
pub fn default_trusted_devices_path() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        std::env::var_os("HOME").map(|h| {
            PathBuf::from(h)
                .join("Library")
                .join("Application Support")
                .join("idis")
                .join("trusted_devices.txt")
        })
    }
    #[cfg(target_os = "windows")]
    {
        if let Some(appdata) = std::env::var_os("APPDATA") {
            return Some(
                PathBuf::from(appdata)
                    .join("idis")
                    .join("trusted_devices.txt"),
            );
        }
        std::env::var_os("USERPROFILE").map(|h| {
            PathBuf::from(h)
                .join(".idis")
                .join("trusted_devices.txt")
        })
    }
    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    {
        if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
            if !xdg.is_empty() {
                return Some(
                    PathBuf::from(xdg)
                        .join("idis")
                        .join("trusted_devices.txt"),
                );
            }
        }
        std::env::var_os("HOME").map(|h| {
            PathBuf::from(h)
                .join(".config")
                .join("idis")
                .join("trusted_devices.txt")
        })
    }
}

fn sanitize_field(s: &str) -> String {
    s.replace(['\t', '\r', '\n'], " ").trim().to_string()
}

fn format_trusted_file(devices: &[TrustedDevice]) -> String {
    let mut out = String::from(
        "# idis trusted devices (handshake SHA-256 fingerprint; delete a line to revoke trust)\n\
         # Format: <fingerprint>\\t<uid_meta>\\t<name>\\t<model>\\t<trusted_unix_ts>\n",
    );
    for d in devices {
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\n",
            d.fingerprint, d.uid, d.name, d.model, d.trusted_at
        ));
    }
    out
}

fn parse_trusted_file(content: &str) -> Vec<TrustedDevice> {
    let mut out = Vec::new();
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.is_empty() {
            continue;
        }
        let Some(fingerprint) = normalize_fingerprint(parts[0]) else {
            warn!(
                "Skipping legacy/invalid trust entry without a valid device fingerprint: {:?}",
                parts[0]
            );
            continue;
        };
        let uid = parts.get(1).copied().unwrap_or("").trim().to_string();
        let name = parts.get(2).copied().unwrap_or("").trim().to_string();
        let model = parts.get(3).copied().unwrap_or("").trim().to_string();
        let trusted_at = parts
            .get(4)
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0);
        out.push(TrustedDevice {
            fingerprint,
            mac: String::new(),
            uid,
            name,
            model,
            trusted_at,
            prefs: DevicePreferences::default(),
        });
    }
    out
}

static TMP_SAVE_SEQ: AtomicU64 = AtomicU64::new(1);

fn save_trusted_file(path: &Path, devices: &[TrustedDevice]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }
    let content = format_trusted_file(devices);
    let base_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("trusted_devices.txt");
    let pid = std::process::id();
    let (tmp_path, mut f) = loop {
        let seq = TMP_SAVE_SEQ.fetch_add(1, Ordering::Relaxed);
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
                return Err(e).with_context(|| format!("failed to open {}", candidate.display()));
            }
        }
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = f.set_permissions(fs::Permissions::from_mode(0o600));
    }
    {
        use std::io::Write as _;
        if let Err(e) = f.write_all(content.as_bytes()).and_then(|()| f.sync_all()) {
            drop(f);
            let _ = fs::remove_file(&tmp_path);
            return Err(e)
                .with_context(|| format!("failed to write/sync {}", tmp_path.display()));
        }
    }
    drop(f);

    if let Err(e) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e).with_context(|| format!("failed to atomically replace {}", path.display()));
    }
    Ok(())
}

/// Normalize a device fingerprint string (`fp:<16..64 hex>` or bare `<16..64 hex>`) into canonical
/// lowercase `fp:<hex>` form. Rejects empty, non-hex, odd-length, or all-zero strings.
pub fn normalize_fingerprint(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let hex_part = trimmed
        .strip_prefix("fp:")
        .or_else(|| trimmed.strip_prefix("FP:"))
        .unwrap_or(trimmed);
    if hex_part.len() < 16 || hex_part.len() > 64 || !hex_part.len().is_multiple_of(2) {
        return None;
    }
    if !hex_part.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    if hex_part.bytes().all(|b| b == b'0') {
        return None;
    }
    Some(format!("fp:{}", hex_part.to_ascii_lowercase()))
}

/// Compute a deterministic SHA-256 device fingerprint (`fp:<24-hex>`) from stable `ClientHandshake`
/// attributes plus the device name.
///
/// Uses length-prefixed canonical framing with a versioned domain prefix (`idis-fp-v1`) over:
/// - `uid` (`uniqueIdentifier`, trimmed)
/// - `name` (device name, trimmed — renaming the device yields a new fingerprint requiring re-trust)
/// - `model` (normalized device model)
/// - `system_name` (`systemName`, trimmed)
/// - `system_version` (`systemVersion`, trimmed)
/// - `client_version` (`clientVersion`, trimmed)
/// - `panel_short x panel_long` (`min(w, h) x max(w, h)` — invariant to portrait/landscape rotation)
/// - `data_protocol_version`
pub fn compute_device_fingerprint(hs: &ClientHandshake) -> String {
    let mut payload = Vec::with_capacity(256);
    payload.extend_from_slice(b"idis-fp-v1\0");
    let push_field = |buf: &mut Vec<u8>, s: &str| {
        let bytes = s.as_bytes();
        buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(bytes);
    };
    let panel_short = hs.screen_width.min(hs.screen_height);
    let panel_long = hs.screen_width.max(hs.screen_height);
    let panel_dims = format!("{panel_short}x{panel_long}");
    let proto = hs.data_protocol_version.to_string();

    push_field(&mut payload, hs.uid.trim());
    push_field(&mut payload, hs.name.trim());
    push_field(&mut payload, hs.model.trim());
    push_field(&mut payload, hs.system_name.trim());
    push_field(&mut payload, hs.system_version.trim());
    push_field(&mut payload, hs.client_version.trim());
    push_field(&mut payload, &panel_dims);
    push_field(&mut payload, &proto);

    let digest = sha256(&payload);
    let mut out = String::with_capacity(3 + 24);
    out.push_str("fp:");
    for b in &digest[..12] {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

/// Extract a concise, stable human-readable Browser / OS label from an HTTP `User-Agent` header
/// (used both as the default display name and as part of the Web viewer fingerprint).
pub fn parse_web_client_label(user_agent: &str) -> String {
    let ua = user_agent.trim();
    let lower = ua.to_ascii_lowercase();
    let browser = if lower.contains("edg/") || lower.contains("edga/") || lower.contains("edgios/") {
        "Edge"
    } else if lower.contains("opr/") || lower.contains("opera") {
        "Opera"
    } else if lower.contains("firefox/") || lower.contains("fxios/") {
        "Firefox"
    } else if lower.contains("chrome/") || lower.contains("crios/") {
        "Chrome"
    } else if lower.contains("safari/") {
        "Safari"
    } else {
        "Browser"
    };
    let os = if lower.contains("ipad") {
        "iPadOS"
    } else if lower.contains("iphone") {
        "iOS"
    } else if lower.contains("android") {
        "Android"
    } else if lower.contains("mac os x") || lower.contains("macintosh") {
        "macOS"
    } else if lower.contains("windows") {
        "Windows"
    } else if lower.contains("linux") {
        "Linux"
    } else {
        "Web"
    };
    format!("{browser} / {os}")
}

/// Compute a deterministic SHA-256 device fingerprint (`fp:<24-hex>`) for a Web viewer browser
/// from its persistent server-issued `idis_vid` cookie and normalized browser/OS label.
pub fn compute_web_viewer_fingerprint(viewer_id: &str, client_label: &str) -> String {
    let mut payload = Vec::with_capacity(128);
    payload.extend_from_slice(b"idis-web-fp-v1\0");
    let push_field = |buf: &mut Vec<u8>, s: &str| {
        let bytes = s.as_bytes();
        buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(bytes);
    };
    push_field(&mut payload, viewer_id.trim());
    push_field(&mut payload, client_label.trim());

    let digest = sha256(&payload);
    let mut out = String::with_capacity(3 + 24);
    out.push_str("fp:");
    for b in &digest[..12] {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

/// Zero-dependency FIPS 180-4 SHA-256 implementation for deterministic device fingerprinting.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity((data.len() + 9 + 63) & !63);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for (i, word) in chunk.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(*word);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_hs(uid: &str, name: &str, w: u32, h: u32, orient: i32) -> ClientHandshake {
        ClientHandshake {
            uid: uid.to_string(),
            name: name.to_string(),
            model: "iPad".to_string(),
            system_name: "iPhone OS".to_string(),
            system_version: "12.5.8".to_string(),
            client_version: "6.2.0".to_string(),
            data_protocol_version: 5,
            orientation: orient,
            screen_width: w,
            screen_height: h,
            udp_port: 0,
            supports_telemetry_cursor: true,
            supports_mirror_mode: false,
            supports_shared_main_mode: false,
            max_compression: None,
            preferred_compression: Some(10),
            preferred_fps: None,
        }
    }

    #[test]
    fn sha256_matches_nist_vectors() {
        let hex = |d: [u8; 32]| {
            d.iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };
        assert_eq!(
            hex(sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn device_fingerprint_is_deterministic_rotation_invariant_and_name_sensitive() {
        let landscape = sample_hs("00000000-0001", "测试设备", 2048, 1536, 1);
        let portrait = sample_hs("00000000-0001", "测试设备", 1536, 2048, 0);
        let renamed = sample_hs("00000000-0001", "重命名平板", 2048, 1536, 1);
        let other_uid = sample_hs("DEADBEEF-0001", "测试设备", 2048, 1536, 1);

        let fp1 = compute_device_fingerprint(&landscape);
        let fp2 = compute_device_fingerprint(&portrait);
        let fp_renamed = compute_device_fingerprint(&renamed);
        let fp_other = compute_device_fingerprint(&other_uid);

        assert!(fp1.starts_with("fp:") && fp1.len() == 27);
        assert_eq!(fp1, fp2, "rotating portrait/landscape must keep fingerprint identical");
        assert_ne!(fp1, fp_renamed, "renaming device must produce a new fingerprint requiring re-trust");
        assert_ne!(fp1, fp_other, "different uid must produce a different fingerprint");
        assert_eq!(normalize_fingerprint(&fp1.to_uppercase()), Some(fp1));
        assert_eq!(normalize_fingerprint("0000000000000000"), None);
        assert_eq!(normalize_fingerprint("not-a-fp"), None);
    }

    #[test]
    fn trust_store_persists_and_enforces_fingerprint_binding() {
        let tmp = std::env::temp_dir().join(format!(
            "idisplay_trust_test_{}.txt",
            std::process::id()
        ));
        let _ = fs::remove_file(&tmp);

        let fp_a = "fp:a1b2c3d4e5f60718293a4b5c";
        let fp_b = "fp:11223344556677889900aabb";
        let store = TrustStore::load(Some(tmp.clone()));
        assert!(!store.is_trusted(Some(fp_a)));

        // Trusting without a valid fingerprint must fail
        assert!(store.trust_device("", "uid-1", "Bad", "iPad").is_err());
        assert!(store.trust_device("-", "uid-1", "Bad", "iPad").is_err());
        assert!(store.trust_device("aa:bb:cc:dd:ee:ff", "uid-1", "OldMac", "iPad").is_err());

        store
            .trust_device(&fp_a.to_uppercase(), "uid-1", "iPad Air", "iPad")
            .unwrap();
        assert!(store.is_trusted(Some(fp_a)));
        assert!(!store.is_trusted(Some(fp_b)));
        assert!(!store.is_trusted(None));

        // Append a legacy MAC row to verify it is skipped cleanly on reload
        {
            use std::io::Write as _;
            let mut f = fs::OpenOptions::new().append(true).open(&tmp).unwrap();
            writeln!(f, "aa:bb:cc:dd:ee:ff\tlegacy-mac\tOld iPad\tiPad\t12345").unwrap();
        }

        let reloaded = TrustStore::load(Some(tmp.clone()));
        assert_eq!(reloaded.list().len(), 1);
        assert!(reloaded.is_trusted(Some(fp_a)));
        assert!(!reloaded.is_trusted(Some(fp_b)));

        assert!(reloaded.revoke_device(fp_a).unwrap());
        assert!(!reloaded.is_trusted(Some(fp_a)));

        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn update_device_prefs_merges_partial_patch_without_clobbering() {
        let fp = "fp:a1b2c3d4e5f60718293a4b5c";
        let store = TrustStore::load(None);
        store
            .trust_device(fp, "uid-1", "iPad Pro", "iPad")
            .unwrap();
        let initial = DevicePreferences {
            width: Some(1920),
            height: Some(1080),
            fps: Some(60),
            bitrate_mbps: Some(24),
            hidpi: Some(2),
            max_pixel_edge: Some(2048),
            adaptive_quality: Some(true),
        };
        assert!(store.update_device_prefs(fp, initial).unwrap());

        let partial = DevicePreferences {
            adaptive_quality: Some(false),
            ..Default::default()
        };
        assert!(store.update_device_prefs(fp, partial.clone()).unwrap());
        assert!(!store.update_device_prefs(fp, partial).unwrap());

        let saved = store.get_device(fp).unwrap().prefs;
        assert_eq!(saved.width, Some(1920));
        assert_eq!(saved.height, Some(1080));
        assert_eq!(saved.fps, Some(60));
        assert_eq!(saved.bitrate_mbps, Some(24));
        assert_eq!(saved.hidpi, Some(2));
        assert_eq!(saved.max_pixel_edge, Some(2048));
        assert_eq!(saved.adaptive_quality, Some(false));
    }
}
