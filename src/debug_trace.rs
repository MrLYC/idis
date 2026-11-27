//! Opt-in structured JSONL debug recorder (`--debug` / `--debug-log <PATH>`).
//!
//! When enabled, records a chronological, privacy-sanitized timeline of:
//! - Startup environment & configuration (tokens/passwords stripped)
//! - All `idis` tracing logs down to `DEBUG` level
//! - iPad Wi-Fi/USB handshakes, orientation/resolution changes, stream stats & drops
//! - Web Admin actions & browser MSE viewer telemetry
//!
//! Disabled by default (zero disk writes, zero overhead).

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tracing_subscriber::Layer;

const MAX_DEBUG_LOG_BYTES: usize = 20 * 1024 * 1024; // 20 MiB cap
const MAX_RECENT_EVENTS: usize = 200;

type LogLevelToggler = Arc<dyn Fn(bool) + Send + Sync>;

static GLOBAL_RECORDER: OnceLock<Arc<DebugRecorder>> = OnceLock::new();
static DEBUG_LOG_ENABLED: AtomicBool = AtomicBool::new(false);
static LOG_LEVEL_TOGGLER: OnceLock<LogLevelToggler> = OnceLock::new();
static RECENT_EVENTS: OnceLock<Mutex<VecDeque<Value>>> = OnceLock::new();

fn recent_events_buf() -> &'static Mutex<VecDeque<Value>> {
    RECENT_EVENTS.get_or_init(|| Mutex::new(VecDeque::with_capacity(MAX_RECENT_EVENTS)))
}

struct RecorderInner {
    writer: BufWriter<File>,
    bytes_written: usize,
    truncated: bool,
}

pub struct DebugRecorder {
    path: PathBuf,
    started_at: Instant,
    inner: Mutex<RecorderInner>,
}

impl DebugRecorder {
    pub fn open(path: PathBuf) -> Result<Arc<Self>> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).with_context(|| {
                    format!("failed to create debug log directory {}", parent.display())
                })?;
            }
        }
        // Preserve one previous non-empty debug trace across crash-restarts (`<path>.prev`)
        // instead of unconditionally truncating pre-crash diagnostics.
        if fs::metadata(&path).ok().is_some_and(|m| m.len() > 0) {
            let prev_name = format!(
                "{}.prev",
                path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("debug.jsonl")
            );
            let _ = fs::rename(&path, path.with_file_name(prev_name));
        }
        let mut opts = OpenOptions::new();
        opts.create(true).write(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts
            .open(&path)
            .with_context(|| format!("failed to open debug log file {}", path.display()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
        }

        Ok(Arc::new(Self {
            path,
            started_at: Instant::now(),
            inner: Mutex::new(RecorderInner {
                writer: BufWriter::new(file),
                bytes_written: 0,
                truncated: false,
            }),
        }))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn write_event(&self, category: &str, event: &str, data: Value) {
        let ts_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let elapsed_ms = self.started_at.elapsed().as_millis() as u64;
        let clean_data = sanitize_json_value(data);
        let line = json!({
            "ts_unix_ms": ts_unix_ms,
            "elapsed_ms": elapsed_ms,
            "cat": category,
            "event": event,
            "data": clean_data,
        });
        let Ok(mut encoded) = serde_json::to_string(&line) else {
            return;
        };
        encoded.push('\n');

        let Ok(mut guard) = self.inner.lock() else {
            return;
        };
        if guard.truncated {
            return;
        }
        if guard.bytes_written + encoded.len() > MAX_DEBUG_LOG_BYTES {
            guard.truncated = true;
            let note = format!(
                "{{\"ts_unix_ms\":{ts_unix_ms},\"elapsed_ms\":{elapsed_ms},\"cat\":\"debug\",\"event\":\"truncated\",\"data\":{{\"max_bytes\":{MAX_DEBUG_LOG_BYTES}}}}}\n"
            );
            let _ = guard.writer.write_all(note.as_bytes());
            let _ = guard.writer.flush();
            return;
        }
        if guard.writer.write_all(encoded.as_bytes()).is_ok()
            && guard.writer.flush().is_ok()
        {
            guard.bytes_written += encoded.len();
        }
    }

    pub fn flush(&self) {
        if let Ok(mut guard) = self.inner.lock() {
            let _ = guard.writer.flush();
        }
    }
}

/// Generate a default timestamped debug log path in the current working directory.
pub fn default_debug_log_path() -> PathBuf {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (y, mo, d, h, mi, s) = unix_secs_to_utc_ymdhms(secs);
    PathBuf::from(format!(
        "idis-debug-{y:04}{mo:02}{d:02}-{h:02}{mi:02}{s:02}Z.jsonl"
    ))
}

/// Initialize the global debug recorder. Must be called once near process startup.
pub fn init_global(path: PathBuf) -> Result<Arc<DebugRecorder>> {
    let rec = DebugRecorder::open(path)?;
    let _ = GLOBAL_RECORDER.set(rec.clone());
    Ok(rec)
}

/// Register the live `tracing_subscriber::reload` callback so Web Admin can hot-toggle DEBUG logs.
pub fn register_log_level_toggler(cb: Arc<dyn Fn(bool) + Send + Sync>) {
    let _ = LOG_LEVEL_TOGGLER.set(cb);
}

/// Enable or disable debug-level tracing for structured diagnostic events (`--debug`).
pub fn set_debug_logging(enabled: bool) {
    DEBUG_LOG_ENABLED.store(enabled, Ordering::Release);
}

/// Hot-toggle runtime debug mode (updates tracing `reload::Layer` filters + structured tracing).
pub fn set_runtime_debug_enabled(enabled: bool) {
    DEBUG_LOG_ENABLED.store(enabled, Ordering::Release);
    if let Some(cb) = LOG_LEVEL_TOGGLER.get() {
        cb(enabled);
    }
    if enabled {
        crate::platform::enable_platform_diagnostics();
    }
}

/// Return a snapshot of up to the 200 most recent sanitized in-memory structured trace events.
pub fn recent_events() -> Vec<Value> {
    recent_events_buf()
        .lock()
        .map(|g| g.iter().cloned().collect())
        .unwrap_or_default()
}

/// Returns `true` if runtime DEBUG logging is enabled (reflects `--debug` and `POST /api/admin/debug`
/// independently of `--debug-log` file recording so the Web Admin toggle never gets stuck).
pub fn is_debug_logging_enabled() -> bool {
    DEBUG_LOG_ENABLED.load(Ordering::Acquire)
}

pub fn is_enabled() -> bool {
    DEBUG_LOG_ENABLED.load(Ordering::Acquire) || GLOBAL_RECORDER.get().is_some()
}

pub fn active_path() -> Option<PathBuf> {
    GLOBAL_RECORDER.get().map(|r| r.path().to_path_buf())
}

/// Record a structured debug event:
/// - Appends sanitized event to the 200-entry in-memory ring buffer (always available for `/api/admin/debug/bundle`).
/// - Writes sanitized JSONL event when `--debug-log <PATH>` is active.
/// - Emits a standard `tracing::debug!` log entry when `--debug` or runtime debug is active.
pub fn record(category: &str, event: &str, data: Value) {
    let clean_data = sanitize_json_value(data);
    if category != "log" {
        let ts_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        if let Ok(mut buf) = recent_events_buf().lock() {
            if buf.len() >= MAX_RECENT_EVENTS {
                buf.pop_front();
            }
            buf.push_back(json!({
                "ts_unix_ms": ts_unix_ms,
                "cat": category,
                "event": event,
                "data": clean_data,
            }));
        }
    }
    if let Some(rec) = GLOBAL_RECORDER.get() {
        rec.write_event(category, event, clean_data.clone());
    }
    if category != "log" && DEBUG_LOG_ENABLED.load(Ordering::Acquire) {
        tracing::debug!(target: "idis::debug", "[{category}] {event}: {clean_data}");
    }
}

fn is_sensitive_json_key(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    matches!(
        k.as_str(),
        "token"
            | "cookie"
            | "set-cookie"
            | "authorization"
            | "password"
            | "secret"
            | "uid"
            | "fingerprint"
            | "mac"
            | "peer_mac"
            | "name"
            | "session_id"
            | "idis_admin"
            | "idis_view"
            | "idis_vid"
            | "idisplay_admin"
            | "idisplay_view"
            | "idisplay_vid"
    ) || k.ends_with("_token")
        || k.ends_with("token")
        || k.ends_with("_secret")
        || k.ends_with("_password")
}

fn sanitize_json_with_parent(val: Value, parent_key: Option<&str>) -> Value {
    let in_preset_list = matches!(parent_key, Some("presets" | "builtin_presets"));
    match val {
        Value::String(s) => Value::String(sanitize_log_message(&s)),
        Value::Array(arr) => Value::Array(
            arr.into_iter()
                .map(|item| sanitize_json_with_parent(item, parent_key))
                .collect(),
        ),
        Value::Object(map) => {
            let mut out = serde_json::Map::with_capacity(map.len());
            for (k, v) in map {
                let clean_k = sanitize_log_message(&k);
                let preserve_preset_name =
                    in_preset_list && clean_k.eq_ignore_ascii_case("name");
                let clean_v = if is_sensitive_json_key(&clean_k) && !preserve_preset_name {
                    match v {
                        Value::Bool(_) | Value::Null => v,
                        _ => Value::String("<redacted>".to_string()),
                    }
                } else {
                    sanitize_json_with_parent(v, Some(clean_k.as_str()))
                };
                out.insert(clean_k, clean_v);
            }
            Value::Object(out)
        }
        other => other,
    }
}

/// Recursively sanitize all keys and strings in a JSON payload (redacting sensitive key values,
/// tokens, cookies, paths, MACs, and stripping control/ANSI escape characters).
pub fn sanitize_json_value(val: Value) -> Value {
    sanitize_json_with_parent(val, None)
}

pub fn flush_global() {
    if let Some(rec) = GLOBAL_RECORDER.get() {
        rec.flush();
    }
}

/// `tracing_subscriber::Layer` forwarding tracing events into the debug JSONL file.
pub struct DebugTraceLayer {
    recorder: Arc<DebugRecorder>,
}

impl DebugTraceLayer {
    pub fn new(recorder: Arc<DebugRecorder>) -> Self {
        Self { recorder }
    }
}

struct TraceVisitor(String);

impl tracing::field::Visit for TraceVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        } else if self.0.is_empty() {
            self.0 = format!("{}={value:?}", field.name());
        } else {
            self.0.push_str(&format!(" {}={value:?}", field.name()));
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.0 = value.to_string();
        } else if self.0.is_empty() {
            self.0 = format!("{}={value}", field.name());
        } else {
            self.0.push_str(&format!(" {}={value}", field.name()));
        }
    }
}

/// Redact PII (MAC addresses, UIDs, device names, tokens, Unix & Windows home usernames)
/// from raw tracing strings before writing them to `--debug` JSONL or Sentry breadcrumbs.
pub fn sanitize_log_message(input: &str) -> String {
    if input.contains("Generated random Web Admin token") {
        return "Generated random Web Admin token: <redacted>".to_string();
    }

    // 1) Redact Unix (`/Users/<user>`, `/home/<user>`) and Windows (`\Users\<user>`) home paths
    //    using earliest-match order and bounded username spans (never truncating past whitespace).
    let mut path_redacted = String::with_capacity(input.len());
    let mut rest = input;
    loop {
        let lower = rest.to_ascii_lowercase();
        let candidates = [
            lower.find("/users/").map(|i| (i, 7usize, '/')),
            lower.find("/home/").map(|i| (i, 6usize, '/')),
            lower.find("\\users\\").map(|i| (i, 7usize, '\\')),
        ];
        let Some((idx, plen, sep)) = candidates.into_iter().flatten().min_by_key(|c| c.0) else {
            path_redacted.push_str(rest);
            break;
        };
        // Strip preceding drive letter like `C:` for `\Users\`
        let keep_end = if sep == '\\'
            && idx >= 2
            && rest.as_bytes()[idx - 1] == b':'
            && rest.as_bytes()[idx - 2].is_ascii_alphabetic()
        {
            idx - 2
        } else {
            idx
        };
        path_redacted.push_str(&rest[..keep_end]);
        path_redacted.push('~');
        let after_prefix = &rest[idx + plen..];
        let user_end = after_prefix
            .find(|c: char| {
                c == '/' || c == '\\' || c.is_whitespace() || matches!(c, '"' | '\'' | ')' | ',')
            })
            .unwrap_or(after_prefix.len());
        rest = &after_prefix[user_end..];
    }

    // 2) Case-insensitive, quote-aware redaction of `uid=`, `mac=`, `name=`, `token=` fields.
    let bytes = path_redacted.as_bytes();
    let lower_bytes = path_redacted.to_ascii_lowercase();
    let lb = lower_bytes.as_bytes();
    let mut kv_redacted = String::with_capacity(path_redacted.len());
    let mut i = 0usize;
    while i < bytes.len() {
        let at_boundary = i == 0
            || !bytes[i - 1].is_ascii_alphanumeric() && bytes[i - 1] != b'_';
        let matched_key = if at_boundary {
            if lb[i..].starts_with(b"uid=") {
                Some(("uid=", 4usize))
            } else if lb[i..].starts_with(b"mac=") {
                Some(("mac=", 4usize))
            } else if lb[i..].starts_with(b"fp=") {
                Some(("fp=", 3usize))
            } else if lb[i..].starts_with(b"fingerprint=") {
                Some(("fingerprint=", 12usize))
            } else if lb[i..].starts_with(b"name=") {
                Some(("name=", 5usize))
            } else if lb[i..].starts_with(b"view_token=") {
                Some(("view_token=", 11usize))
            } else if lb[i..].starts_with(b"admin_token=") {
                Some(("admin_token=", 12usize))
            } else if lb[i..].starts_with(b"idis_admin=") {
                Some(("idis_admin=", 11usize))
            } else if lb[i..].starts_with(b"idis_view=") {
                Some(("idis_view=", 10usize))
            } else if lb[i..].starts_with(b"idis_vid=") {
                Some(("idis_vid=", 9usize))
            } else if lb[i..].starts_with(b"idisplay_admin=") {
                Some(("idisplay_admin=", 15usize))
            } else if lb[i..].starts_with(b"idisplay_view=") {
                Some(("idisplay_view=", 14usize))
            } else if lb[i..].starts_with(b"idisplay_vid=") {
                Some(("idisplay_vid=", 13usize))
            } else if lb[i..].starts_with(b"cookie=") {
                Some(("cookie=", 7usize))
            } else if lb[i..].starts_with(b"token=") {
                Some(("token=", 6usize))
            } else {
                None
            }
        } else {
            None
        };

        if let Some((key, klen)) = matched_key {
            let val_start = i + klen;
            let (val_end, keep_as_is) = if val_start < bytes.len() && bytes[val_start] == b'"' {
                // Quoted string value: consume until matching unescaped quote
                let mut j = val_start + 1;
                while j < bytes.len() {
                    if bytes[j] == b'\\' && j + 1 < bytes.len() && bytes[j + 1].is_ascii() {
                        j += 2;
                        continue;
                    }
                    if bytes[j] == b'"' {
                        j += 1;
                        break;
                    }
                    j += 1;
                }
                (j, false)
            } else {
                let mut j = val_start;
                while j < bytes.len()
                    && !bytes[j].is_ascii_whitespace()
                    && !matches!(bytes[j], b',' | b')' | b']' | b'&' | b';')
                {
                    j += 1;
                }
                let val = &path_redacted[val_start..j];
                let benign = val.is_empty()
                    || val == "<none>"
                    || val == "<unknown>"
                    || val == "<unavailable>"
                    || (key.ends_with("token=") && matches!(val, "true" | "false" | "none"));
                (j, benign)
            };
            if keep_as_is {
                kv_redacted.push_str(&path_redacted[i..val_end]);
            } else {
                kv_redacted.push_str(&path_redacted[i..val_start]);
                kv_redacted.push_str("<redacted>");
            }
            i = val_end;
        } else {
            let ch = path_redacted[i..].chars().next().unwrap();
            kv_redacted.push(ch);
            i += ch.len_utf8();
        }
    }

    // 3) Scan for remaining bare colon/hyphen-separated MAC addresses and strip ANSI/control chars.
    let mac_redacted = redact_bare_colon_macs(&kv_redacted);
    mac_redacted
        .chars()
        .filter(|&c| c == '\n' || c == '\t' || !c.is_control())
        .collect()
}

fn redact_bare_colon_macs(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    while i < b.len() {
        let prev_ok = i == 0 || !b[i - 1].is_ascii_hexdigit();
        if prev_ok && i + 11 <= b.len() && b[i].is_ascii_hexdigit() {
            // Match 6 hex octets (1-2 hex digits each) separated by uniform ':' or '-'
            let mut sep: Option<u8> = None;
            let mut pos = i;
            let mut octets = 0usize;
            let mut valid = true;
            while octets < 6 && pos < b.len() {
                let start = pos;
                while pos < b.len() && pos - start < 2 && b[pos].is_ascii_hexdigit() {
                    pos += 1;
                }
                if pos == start {
                    valid = false;
                    break;
                }
                octets += 1;
                if octets < 6 {
                    if pos >= b.len() {
                        valid = false;
                        break;
                    }
                    let ch = b[pos];
                    if ch != b':' && ch != b'-' {
                        valid = false;
                        break;
                    }
                    if let Some(expected) = sep {
                        if ch != expected {
                            valid = false;
                            break;
                        }
                    } else {
                        sep = Some(ch);
                    }
                    pos += 1;
                }
            }
            if valid && octets == 6 {
                let next_ok = pos == b.len() || (!b[pos].is_ascii_hexdigit() && Some(b[pos]) != sep);
                if next_ok {
                    if let Ok(cand) = std::str::from_utf8(&b[i..pos]) {
                        let sep_ch = sep.unwrap_or(b':') as char;
                        let parts: Vec<&str> = cand.split(sep_ch).collect();
                        if parts.len() == 6
                            && parts
                                .iter()
                                .all(|p| !p.is_empty() && p.len() <= 2 && u8::from_str_radix(p, 16).is_ok())
                        {
                            out.push_str("<mac>");
                            i = pos;
                            continue;
                        }
                    }
                }
            }
        }
        let ch = s[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

impl<S: tracing::Subscriber> Layer<S> for DebugTraceLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let meta = event.metadata();
        let mut visitor = TraceVisitor(String::new());
        event.record(&mut visitor);
        let msg = sanitize_log_message(&visitor.0);
        self.recorder.write_event(
            "log",
            meta.level().as_str(),
            json!({
                "target": meta.target(),
                "message": msg,
            }),
        );
    }
}

/// Convert Unix epoch seconds to UTC (year, month, day, hour, minute, second) without extra crates.
fn unix_secs_to_utc_ymdhms(secs: u64) -> (i64, u32, u32, u32, u32, u32) {
    let s = (secs % 60) as u32;
    let total_mins = secs / 60;
    let mi = (total_mins % 60) as u32;
    let total_hours = total_mins / 60;
    let h = (total_hours % 24) as u32;
    let days = (total_hours / 24) as i64;

    // Howard Hinnant's civil_from_days algorithm
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let mo = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let year = y + if mo <= 2 { 1 } else { 0 };
    (year, mo, d, h, mi, s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_unix_timestamp_and_writes_valid_jsonl() {
        assert_eq!(unix_secs_to_utc_ymdhms(0), (1970, 1, 1, 0, 0, 0));
        assert_eq!(unix_secs_to_utc_ymdhms(1_700_000_000), (2023, 11, 14, 22, 13, 20));

        let path = std::env::temp_dir().join(format!(
            "idis_debug_trace_test_{}.jsonl",
            std::process::id()
        ));
        let rec = DebugRecorder::open(path.clone()).unwrap();
        rec.write_event("test", "hello", json!({"n": 42}));
        rec.flush();

        let content = fs::read_to_string(&path).unwrap();
        let _ = fs::remove_file(&path);
        let parsed: Value = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(parsed["cat"], "test");
        assert_eq!(parsed["event"], "hello");
        assert_eq!(parsed["data"]["n"], 42);

        let sanitized = sanitize_log_message(
            r#"Handshake from /home/bob/x and C:\Users\Alice\idis (name="My Tablet", uid="0000 0001", fp=fp:11223344556677889900aabb, fingerprint=fp:aabbccddeeff001122334455, idis_vid=deadbeef01234567, peer=aa:bb:cc:dd:ee:ff) /view?token=secret123 view_token=false"#,
        );
        assert!(!sanitized.contains("bob"));
        assert!(!sanitized.contains("Alice"));
        assert!(!sanitized.contains("My Tablet"));
        assert!(!sanitized.contains("0000 0001"));
        assert!(!sanitized.contains("11223344556677889900aabb"));
        assert!(!sanitized.contains("aabbccddeeff001122334455"));
        assert!(!sanitized.contains("deadbeef01234567"));
        assert!(!sanitized.contains("aa:bb:cc:dd:ee:ff"));
        assert!(!sanitized.contains("secret123"));
        assert!(sanitized.contains("~/x"));
        assert!(sanitized.contains("~\\idis"));
        assert!(sanitized.contains("view_token=false"));

        // Regression test: multi-byte UTF-8 (Chinese device names & emojis) must never panic in MAC scanner
        let cjk = sanitize_log_message(
            r#"[198.51.100.77] Handshake from name="测试设备" (uid="00000000-0001", mac=<none>, 🎉) aa:bb:cc:dd:ee:ff"#,
        );
        assert!(!cjk.contains("测试设备"));
        assert!(!cjk.contains("00000000-0001"));
        assert!(!cjk.contains("aa:bb:cc:dd:ee:ff"));
        assert!(cjk.contains("<mac>"));
        assert!(cjk.contains("🎉"));

        // Preset profile names are preserved consistently with `active_preset`, while client
        // device names inside `sessions` and `trusted_devices` remain redacted.
        let bundle = sanitize_json_value(json!({
            "active_preset": "iPad Air WIFI",
            "presets": [{ "name": "iPad Air WIFI" }],
            "trusted_devices": [{ "name": "Alice's iPad", "mac": "aa:bb:cc:dd:ee:ff" }],
            "sessions": [{ "name": "Alice's iPad" }],
        }));
        assert_eq!(bundle["active_preset"], "iPad Air WIFI");
        assert_eq!(bundle["presets"][0]["name"], "iPad Air WIFI");
        assert_eq!(bundle["trusted_devices"][0]["name"], "<redacted>");
        assert_eq!(bundle["trusted_devices"][0]["mac"], "<redacted>");
        assert_eq!(bundle["sessions"][0]["name"], "<redacted>");
    }
}
