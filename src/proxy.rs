use std::process::Command;

/// All proxy-related environment variables cleared by default so neither
/// third-party HTTP clients (e.g. Sentry/ureq) nor child processes (e.g. ffmpeg)
/// silently route traffic through an inherited proxy.
pub const PROXY_ENV_VARS: &[&str] = &[
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
    "FTP_PROXY",
    "ftp_proxy",
    "NO_PROXY",
    "no_proxy",
];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedProxy {
    pub http_proxy: Option<String>,
    pub https_proxy: Option<String>,
}

impl ResolvedProxy {
    pub fn is_enabled(&self) -> bool {
        self.http_proxy.is_some() || self.https_proxy.is_some()
    }

    pub fn summary(&self) -> String {
        match (&self.http_proxy, &self.https_proxy) {
            (None, None) => "direct".to_string(),
            (Some(http), Some(https)) if http == https => mask_proxy_credentials(http),
            (Some(http), Some(https)) => format!(
                "http={}, https={}",
                mask_proxy_credentials(http),
                mask_proxy_credentials(https)
            ),
            (Some(http), None) => format!("http={}", mask_proxy_credentials(http)),
            (None, Some(https)) => format!("https={}", mask_proxy_credentials(https)),
        }
    }
}

/// Remove all proxy environment variables from the current process.
///
/// Must be called early in `main()` before spawning background threads or initializing Sentry.
pub fn sanitize_proxy_env() {
    for key in PROXY_ENV_VARS {
        std::env::remove_var(key);
    }
}

/// Strip proxy environment variables from a child `Command` (defense-in-depth).
pub fn strip_proxy_env_on_command(cmd: &mut Command) {
    for key in PROXY_ENV_VARS {
        cmd.env_remove(key);
    }
}

/// Resolve and apply the process proxy policy according to CLI flags:
///
/// - Default (`explicit_proxy = None`, `use_system_proxy = false`):
///   Strips all proxy environment variables and never reads OS system proxies.
/// - Explicit `--proxy <URL>`:
///   Strips inherited environment proxies and routes outbound HTTP/HTTPS strictly through `<URL>`.
/// - Explicit `--use-system-proxy`:
///   Preserves environment proxies (`HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`), and falls back
///   to OS system proxy settings (macOS `scutil --proxy` / Windows Internet Settings) if unset.
pub fn resolve_and_apply_proxy_policy(
    explicit_proxy: Option<&str>,
    use_system_proxy: bool,
) -> ResolvedProxy {
    let explicit = explicit_proxy.map(str::trim).filter(|s| !s.is_empty());

    if explicit.is_some() || !use_system_proxy {
        sanitize_proxy_env();
    }

    resolve_policy_with(
        explicit,
        use_system_proxy,
        |k| std::env::var(k).ok(),
        detect_os_system_proxy,
    )
}

fn resolve_policy_with<E, O>(
    explicit_proxy: Option<&str>,
    use_system_proxy: bool,
    env_lookup: E,
    os_lookup: O,
) -> ResolvedProxy
where
    E: Fn(&str) -> Option<String>,
    O: Fn() -> Option<ResolvedProxy>,
{
    if let Some(url) = explicit_proxy.map(str::trim).filter(|s| !s.is_empty()) {
        let normalized = normalize_proxy_url(url);
        return ResolvedProxy {
            http_proxy: Some(normalized.clone()),
            https_proxy: Some(normalized),
        };
    }

    if !use_system_proxy {
        return ResolvedProxy::default();
    }

    let env_resolved = resolve_from_env_lookup(env_lookup);
    if env_resolved.is_enabled() {
        return env_resolved;
    }

    os_lookup().unwrap_or_default()
}

fn resolve_from_env_lookup<F>(lookup: F) -> ResolvedProxy
where
    F: Fn(&str) -> Option<String>,
{
    let get = |keys: &[&str]| -> Option<String> {
        keys.iter()
            .find_map(|k| lookup(k))
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .map(|v| normalize_proxy_url(&v))
    };

    let all = get(&["ALL_PROXY", "all_proxy"]);
    let http_proxy = get(&["HTTP_PROXY", "http_proxy"]).or_else(|| all.clone());
    let https_proxy = get(&["HTTPS_PROXY", "https_proxy"])
        .or(all)
        .or_else(|| http_proxy.clone());

    ResolvedProxy {
        http_proxy,
        https_proxy,
    }
}

fn normalize_proxy_url(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("http://{trimmed}")
    }
}

fn format_host_port(host: &str, port: &str) -> String {
    let host = host.trim();
    let port = port.trim();
    if host.contains(':') && !host.starts_with('[') {
        format!("http://[{host}]:{port}")
    } else {
        format!("http://{host}:{port}")
    }
}

/// Mask `user:pass@` inside proxy URLs before writing them to logs.
pub fn mask_proxy_credentials(url: &str) -> String {
    if let Some(scheme_end) = url.find("://") {
        let after_scheme = &url[scheme_end + 3..];
        let authority_end = after_scheme.find('/').unwrap_or(after_scheme.len());
        let authority = &after_scheme[..authority_end];
        if let Some(at_pos) = authority.rfind('@') {
            return format!(
                "{}://***@{}",
                &url[..scheme_end],
                &after_scheme[at_pos + 1..]
            );
        }
    }
    url.to_string()
}

/// Parse output of macOS `scutil --proxy`.
pub fn parse_macos_scutil_proxy(output: &str) -> ResolvedProxy {
    let mut http_enable = false;
    let mut http_host = None;
    let mut http_port = None;

    let mut https_enable = false;
    let mut https_host = None;
    let mut https_port = None;

    for line in output.lines() {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let key = k.trim();
        let val = v.trim();
        match key {
            "HTTPEnable" => http_enable = val == "1",
            "HTTPProxy" if !val.is_empty() => http_host = Some(val.to_string()),
            "HTTPPort" if !val.is_empty() && val != "0" => http_port = Some(val.to_string()),
            "HTTPSEnable" => https_enable = val == "1",
            "HTTPSProxy" if !val.is_empty() => https_host = Some(val.to_string()),
            "HTTPSPort" if !val.is_empty() && val != "0" => https_port = Some(val.to_string()),
            _ => {}
        }
    }

    let http_proxy = match (http_enable, http_host, http_port) {
        (true, Some(h), Some(p)) => Some(format_host_port(&h, &p)),
        _ => None,
    };
    let https_proxy = match (https_enable, https_host, https_port) {
        (true, Some(h), Some(p)) => Some(format_host_port(&h, &p)),
        _ => None,
    };

    ResolvedProxy {
        http_proxy,
        https_proxy,
    }
}

/// Parse output of Windows `reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"`.
pub fn parse_windows_internet_settings_proxy(output: &str) -> ResolvedProxy {
    let mut enabled = false;
    let mut server: Option<String> = None;

    for line in output.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() < 3 {
            continue;
        }
        if tokens[0].eq_ignore_ascii_case("ProxyEnable") {
            let val = tokens[2];
            enabled = val == "0x1" || val == "1";
        } else if tokens[0].eq_ignore_ascii_case("ProxyServer") {
            server = Some(tokens[2..].join(" "));
        }
    }

    if !enabled {
        return ResolvedProxy::default();
    }
    let Some(raw) = server.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) else {
        return ResolvedProxy::default();
    };

    if raw.contains('=') {
        let mut http_proxy = None;
        let mut https_proxy = None;
        for entry in raw.split(';') {
            let Some((scheme, addr)) = entry.split_once('=') else {
                continue;
            };
            let addr = addr.trim();
            if addr.is_empty() {
                continue;
            }
            if scheme.trim().eq_ignore_ascii_case("http") {
                http_proxy = Some(normalize_proxy_url(addr));
            } else if scheme.trim().eq_ignore_ascii_case("https") {
                https_proxy = Some(normalize_proxy_url(addr));
            }
        }
        ResolvedProxy {
            http_proxy,
            https_proxy,
        }
    } else {
        let normalized = normalize_proxy_url(&raw);
        ResolvedProxy {
            http_proxy: Some(normalized.clone()),
            https_proxy: Some(normalized),
        }
    }
}

#[cfg(target_os = "macos")]
fn detect_os_system_proxy() -> Option<ResolvedProxy> {
    let output = Command::new("scutil").arg("--proxy").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let parsed = parse_macos_scutil_proxy(&text);
    parsed.is_enabled().then_some(parsed)
}

#[cfg(target_os = "windows")]
fn detect_os_system_proxy() -> Option<ResolvedProxy> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let output = Command::new("reg")
        .args([
            "query",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let parsed = parse_windows_internet_settings_proxy(&text);
    parsed.is_enabled().then_some(parsed)
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn detect_os_system_proxy() -> Option<ResolvedProxy> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn env_lookup_prefers_specific_then_all_proxy() {
        let map: HashMap<&str, &str> = [
            ("HTTP_PROXY", "127.0.0.1:7890"),
            ("HTTPS_PROXY", "http://127.0.0.1:7891"),
        ]
        .into_iter()
        .collect();
        let resolved = resolve_from_env_lookup(|k| map.get(k).map(|v| (*v).to_string()));
        assert_eq!(resolved.http_proxy.as_deref(), Some("http://127.0.0.1:7890"));
        assert_eq!(
            resolved.https_proxy.as_deref(),
            Some("http://127.0.0.1:7891")
        );

        let all_only: HashMap<&str, &str> = [("all_proxy", "http://127.0.0.1:8080")]
            .into_iter()
            .collect();
        let resolved_all = resolve_from_env_lookup(|k| all_only.get(k).map(|v| (*v).to_string()));
        assert_eq!(
            resolved_all.http_proxy.as_deref(),
            Some("http://127.0.0.1:8080")
        );
        assert_eq!(
            resolved_all.https_proxy.as_deref(),
            Some("http://127.0.0.1:8080")
        );
    }

    #[test]
    fn parse_macos_scutil_proxy_enabled_and_disabled() {
        let enabled = r#"
<dictionary> {
  HTTPEnable : 1
  HTTPPort : 7890
  HTTPProxy : 127.0.0.1
  HTTPSEnable : 1
  HTTPSPort : 7890
  HTTPSProxy : 127.0.0.1
}
"#;
        let parsed = parse_macos_scutil_proxy(enabled);
        assert_eq!(parsed.http_proxy.as_deref(), Some("http://127.0.0.1:7890"));
        assert_eq!(parsed.https_proxy.as_deref(), Some("http://127.0.0.1:7890"));
        assert_eq!(parsed.summary(), "http://127.0.0.1:7890");

        let disabled = r#"
<dictionary> {
  HTTPEnable : 0
  HTTPPort : 7890
  HTTPProxy : 127.0.0.1
  HTTPSEnable : 0
  HTTPSPort : 7890
  HTTPSProxy : 127.0.0.1
}
"#;
        let parsed_disabled = parse_macos_scutil_proxy(disabled);
        assert!(!parsed_disabled.is_enabled());
        assert_eq!(parsed_disabled.summary(), "direct");
    }

    #[test]
    fn parse_windows_registry_proxy_formats() {
        let single = r#"
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings
    ProxyEnable    REG_DWORD    0x1
    ProxyServer    REG_SZ    127.0.0.1:7890
"#;
        let parsed = parse_windows_internet_settings_proxy(single);
        assert_eq!(parsed.http_proxy.as_deref(), Some("http://127.0.0.1:7890"));
        assert_eq!(parsed.https_proxy.as_deref(), Some("http://127.0.0.1:7890"));

        let per_scheme = r#"
    ProxyEnable    REG_DWORD    0x1
    ProxyServer    REG_SZ    http=127.0.0.1:8080;https=127.0.0.1:8443
"#;
        let parsed_split = parse_windows_internet_settings_proxy(per_scheme);
        assert_eq!(
            parsed_split.http_proxy.as_deref(),
            Some("http://127.0.0.1:8080")
        );
        assert_eq!(
            parsed_split.https_proxy.as_deref(),
            Some("http://127.0.0.1:8443")
        );

        let disabled = r#"
    ProxyEnable    REG_DWORD    0x0
    ProxyServer    REG_SZ    127.0.0.1:7890
"#;
        assert!(!parse_windows_internet_settings_proxy(disabled).is_enabled());
    }

    #[test]
    fn masks_credentials_in_proxy_urls() {
        assert_eq!(
            mask_proxy_credentials("http://alice:secret@127.0.0.1:7890"),
            "http://***@127.0.0.1:7890"
        );
        assert_eq!(
            mask_proxy_credentials("http://127.0.0.1:7890"),
            "http://127.0.0.1:7890"
        );
    }

    #[test]
    fn policy_is_direct_by_default_even_with_env_and_os_proxy() {
        let env_map: HashMap<&str, &str> = [
            ("HTTP_PROXY", "http://127.0.0.1:7890"),
            ("HTTPS_PROXY", "http://127.0.0.1:7890"),
        ]
        .into_iter()
        .collect();
        let os_proxy = || {
            Some(ResolvedProxy {
                http_proxy: Some("http://127.0.0.1:9999".to_string()),
                https_proxy: Some("http://127.0.0.1:9999".to_string()),
            })
        };

        // Default: direct (neither env nor OS system proxy used)
        let default_res = resolve_policy_with(
            None,
            false,
            |k| env_map.get(k).map(|v| (*v).to_string()),
            os_proxy,
        );
        assert!(!default_res.is_enabled());
        assert_eq!(default_res.summary(), "direct");

        // Explicit --proxy overrides both env and OS proxy
        let explicit_res = resolve_policy_with(
            Some("127.0.0.1:8888"),
            true,
            |k| env_map.get(k).map(|v| (*v).to_string()),
            os_proxy,
        );
        assert_eq!(
            explicit_res.http_proxy.as_deref(),
            Some("http://127.0.0.1:8888")
        );
        assert_eq!(
            explicit_res.https_proxy.as_deref(),
            Some("http://127.0.0.1:8888")
        );

        // --use-system-proxy prefers env, then falls back to OS proxy
        let env_res = resolve_policy_with(
            None,
            true,
            |k| env_map.get(k).map(|v| (*v).to_string()),
            os_proxy,
        );
        assert_eq!(env_res.http_proxy.as_deref(), Some("http://127.0.0.1:7890"));

        let os_fallback = resolve_policy_with(None, true, |_| None, os_proxy);
        assert_eq!(
            os_fallback.https_proxy.as_deref(),
            Some("http://127.0.0.1:9999")
        );
    }
}
