use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};

/// Runtime connection details exposed in startup logs, terminal QR codes, and the Web Admin UI.
#[derive(Debug, Clone, Default, Serialize)]
pub struct HostConnectionInfo {
    pub lan_ips: Vec<String>,
    pub primary_ip: Option<String>,
    pub wifi_enabled: bool,
    pub wifi_telemetry_port: Option<u16>,
    pub wifi_data_port: Option<u16>,
    pub wifi_endpoints: Vec<String>,
    pub web_bind: Option<String>,
    pub web_localhost_only: bool,
    pub web_admin_urls: Vec<String>,
    pub web_viewer_bind: Option<String>,
    pub web_viewer_port: Option<u16>,
    pub web_viewer_listening: bool,
    pub web_viewer_urls: Vec<String>,
}

impl HostConnectionInfo {
    pub fn build(
        lan_ips: Vec<String>,
        wifi_bind_ip: Option<IpAddr>,
        wifi_ports: Option<(u16, u16)>,
        web_addr: Option<SocketAddr>,
    ) -> Self {
        Self::build_with_viewer(lan_ips, wifi_bind_ip, wifi_ports, web_addr, web_addr)
    }

    pub fn build_with_viewer(
        lan_ips: Vec<String>,
        wifi_bind_ip: Option<IpAddr>,
        wifi_ports: Option<(u16, u16)>,
        web_admin_addr: Option<SocketAddr>,
        web_viewer_addr: Option<SocketAddr>,
    ) -> Self {
        let primary_ip = lan_ips.first().cloned();
        let (wifi_enabled, wifi_telemetry_port, wifi_data_port, wifi_endpoints) =
            if let Some((tel_port, data_port)) = wifi_ports {
                let endpoints = resolve_host_list(wifi_bind_ip, &lan_ips)
                    .into_iter()
                    .map(|ip| format!("{ip}:{tel_port}"))
                    .collect();
                (true, Some(tel_port), Some(data_port), endpoints)
            } else {
                (false, None, None, Vec::new())
            };

        let (web_bind, web_localhost_only, web_admin_urls) =
            if let Some(addr) = web_admin_addr {
                let localhost_only = addr.ip().is_loopback();
                let hosts = resolve_host_list(Some(addr.ip()), &lan_ips);
                let port = addr.port();
                let admin_urls: Vec<String> =
                    hosts.iter().map(|h| format!("http://{h}:{port}/")).collect();
                (Some(addr.to_string()), localhost_only, admin_urls)
            } else {
                (None, true, Vec::new())
            };

        let (web_viewer_bind, web_viewer_port, web_viewer_listening, web_viewer_urls) =
            if let Some(addr) = web_viewer_addr {
                let hosts = resolve_host_list(Some(addr.ip()), &lan_ips);
                let port = addr.port();
                let viewer_urls: Vec<String> = hosts
                    .iter()
                    .map(|h| format!("http://{h}:{port}/view"))
                    .collect();
                (Some(addr.to_string()), Some(port), true, viewer_urls)
            } else {
                (None, None, false, Vec::new())
            };

        Self {
            lan_ips,
            primary_ip,
            wifi_enabled,
            wifi_telemetry_port,
            wifi_data_port,
            wifi_endpoints,
            web_bind,
            web_localhost_only,
            web_admin_urls,
            web_viewer_bind,
            web_viewer_port,
            web_viewer_listening,
            web_viewer_urls,
        }
    }

    /// Preferred Wi-Fi `IP:port` string for QR code / quick-connect display.
    pub fn primary_wifi_endpoint(&self) -> Option<&str> {
        self.wifi_endpoints.first().map(String::as_str)
    }

    /// Preferred Web Viewer URL (`http://<IP>:<port>/view`) for QR code / quick-connect display.
    pub fn primary_web_viewer_url(&self) -> Option<&str> {
        self.web_viewer_urls.first().map(String::as_str)
    }
}

fn resolve_host_list(bind_ip: Option<IpAddr>, lan_ips: &[String]) -> Vec<String> {
    match bind_ip {
        Some(ip) if !ip.is_unspecified() => vec![format_url_host(ip)],
        _ => {
            if !lan_ips.is_empty() {
                lan_ips.to_vec()
            } else {
                vec!["127.0.0.1".to_string()]
            }
        }
    }
}

fn format_url_host(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{v6}]"),
    }
}

/// Detect the host's non-loopback LAN IPv4 addresses, ordered with the primary outbound
/// interface first and private RFC1918 LAN addresses prioritized ahead of virtual/other IPs.
pub fn detect_lan_ipv4s() -> Vec<String> {
    let mut ips: Vec<Ipv4Addr> = Vec::new();

    // 1) Secondary enumeration of physical local interfaces first (filtered by interface name/flags)
    //    so virtual TUN/VPN interfaces (Clash/Sing-box utun, Tailscale, Docker, Parallels) do not hijack primary_ip.
    let mut iface_entries = enumerate_os_ipv4s();
    iface_entries.sort_by_key(|(ip, is_virtual)| (u8::from(*is_virtual), lan_rank(*ip)));

    // 2) Primary route probe via UDP connect (does not transmit any packet).
    let mut probed: Vec<Ipv4Addr> = Vec::new();
    for target in [
        "192.168.255.254:80",
        "10.255.255.254:80",
        "172.16.0.1:80",
        "8.8.8.8:80",
    ] {
        if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
            if sock.connect(target).is_ok() {
                if let Ok(SocketAddr::V4(local)) = sock.local_addr() {
                    let ip = *local.ip();
                    if is_usable_lan_ipv4(ip) && !probed.contains(&ip) {
                        probed.push(ip);
                    }
                }
            }
        }
    }

    // Prefer probed IPs that belong to a physical (non-virtual) interface.
    let is_known_virtual = |ip: Ipv4Addr| -> bool {
        iface_entries
            .iter()
            .find(|(eip, _)| *eip == ip)
            .map(|(_, virt)| *virt)
            .unwrap_or(false)
    };
    for ip in &probed {
        if !is_known_virtual(*ip) && lan_rank(*ip) <= 2 && !ips.contains(ip) {
            ips.push(*ip);
        }
    }
    // Add all physical interface IPs ranked by LAN preference.
    for (ip, is_virtual) in &iface_entries {
        if !is_virtual && is_usable_lan_ipv4(*ip) && !ips.contains(ip) {
            ips.push(*ip);
        }
    }
    // Fall back to remaining probed/virtual IPs only if still useful (e.g. Tailscale/VPN when no LAN exists).
    for ip in probed {
        if !ips.contains(&ip) {
            ips.push(ip);
        }
    }
    for (ip, _) in iface_entries {
        if is_usable_lan_ipv4(ip) && !ips.contains(&ip) {
            ips.push(ip);
        }
    }

    ips.into_iter().map(|ip| ip.to_string()).collect()
}

fn is_virtual_iface_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let prefixes = [
        "lo", "utun", "tun", "tap", "tailscale", "wg", "docker", "br-", "veth", "bridge",
        "vmnet", "vnic", "virbr", "awdl", "llw", "anpi", "ap", "gif", "stf", "ipsec", "ppp",
        "vboxnet", "zt", "ham", "clash", "meta", "mihomo", "sing", "flclash", "nordlynx",
        "mullvad", "proton", "cscotun", "podman", "cni", "flannel", "cali", "cilium", "feth",
    ];
    prefixes.iter().any(|p| lower.starts_with(p))
}

fn is_usable_lan_ipv4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    // Exclude RFC 2544 benchmark range 198.18.0.0/15 (commonly used by Clash/Surge TUN Fake-IP).
    let is_fake_ip_tun = o[0] == 198 && (o[1] == 18 || o[1] == 19);
    !ip.is_loopback()
        && !ip.is_unspecified()
        && !ip.is_link_local()
        && !ip.is_multicast()
        && !is_fake_ip_tun
}

fn lan_rank(ip: Ipv4Addr) -> u8 {
    let o = ip.octets();
    if o[0] == 192 && o[1] == 168 {
        0
    } else if o[0] == 10 {
        1
    } else if o[0] == 172 && (16..=31).contains(&o[1]) {
        // Common Docker/OrbStack bridges use 172.17-19.x.x — rank below real LANs.
        if (17..=19).contains(&o[1]) {
            4
        } else {
            2
        }
    } else if o[0] == 100 && (64..=127).contains(&o[1]) {
        // RFC 6598 CGNAT (Tailscale / ZeroTier / ISP CGNAT) — keep reachable as fallback, below LAN.
        5
    } else {
        3
    }
}

#[cfg(target_os = "macos")]
fn enumerate_os_ipv4s() -> Vec<(Ipv4Addr, bool)> {
    for bin in ["/sbin/ifconfig", "ifconfig"] {
        if let Ok(out) = std::process::Command::new(bin).output() {
            if out.status.success() {
                return parse_ifconfig_entries(&String::from_utf8_lossy(&out.stdout));
            }
        }
    }
    Vec::new()
}

#[cfg(target_os = "linux")]
fn enumerate_os_ipv4s() -> Vec<(Ipv4Addr, bool)> {
    if let Ok(out) = std::process::Command::new("ip")
        .args(["-4", "-o", "addr", "show", "up", "scope", "global"])
        .output()
    {
        if out.status.success() {
            return parse_ip_addr_entries(&String::from_utf8_lossy(&out.stdout));
        }
    }
    if let Ok(out) = std::process::Command::new("ifconfig").output() {
        return parse_ifconfig_entries(&String::from_utf8_lossy(&out.stdout));
    }
    Vec::new()
}

#[cfg(target_os = "windows")]
struct WinAdapterInfo {
    friendly_name: String,
    description: String,
    if_type: u32,
    ipv4s: Vec<Ipv4Addr>,
    ipv6s: Vec<Ipv6Addr>,
}

#[cfg(target_os = "windows")]
unsafe fn pwstr_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while len < 1024 && *ptr.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
}

#[cfg(target_os = "windows")]
fn enumerate_windows_adapters() -> Vec<WinAdapterInfo> {
    use std::mem::size_of;
    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
        GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6,
    };

    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut buf_bytes: u32 = 16 * 1024;
    let mut buf: Vec<u64> = Vec::new();
    let mut ok = false;
    for _ in 0..4 {
        let cap_bytes = (buf_bytes as usize).min(4 * 1024 * 1024);
        buf.resize(cap_bytes.div_ceil(8), 0);
        buf_bytes = (buf.len() * 8) as u32;
        let rc = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                flags,
                std::ptr::null(),
                buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                &mut buf_bytes,
            )
        };
        if rc == NO_ERROR {
            ok = true;
            break;
        }
        if rc != ERROR_BUFFER_OVERFLOW || buf_bytes == 0 || buf_bytes > 4 * 1024 * 1024 {
            return Vec::new();
        }
    }
    if !ok {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut cur = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !cur.is_null() {
        let adapter = unsafe { &*cur };
        if adapter.OperStatus == IfOperStatusUp {
            let friendly_name = unsafe { pwstr_to_string(adapter.FriendlyName.cast_const()) };
            let description = unsafe { pwstr_to_string(adapter.Description.cast_const()) };
            let mut ipv4s = Vec::new();
            let mut ipv6s = Vec::new();
            let mut ua = adapter.FirstUnicastAddress;
            while !ua.is_null() {
                let u = unsafe { &*ua };
                let sa = u.Address.lpSockaddr;
                let sa_len = u.Address.iSockaddrLength;
                if !sa.is_null() && sa_len >= 2 {
                    let family = unsafe { (*sa).sa_family };
                    if family == AF_INET && sa_len >= size_of::<SOCKADDR_IN>() as i32 {
                        let sin = unsafe { &*(sa as *const SOCKADDR_IN) };
                        let b = unsafe { sin.sin_addr.S_un.S_un_b };
                        let ip = Ipv4Addr::new(b.s_b1, b.s_b2, b.s_b3, b.s_b4);
                        if !ipv4s.contains(&ip) {
                            ipv4s.push(ip);
                        }
                    } else if family == AF_INET6 && sa_len >= size_of::<SOCKADDR_IN6>() as i32 {
                        let sin6 = unsafe { &*(sa as *const SOCKADDR_IN6) };
                        let ip = Ipv6Addr::from(unsafe { sin6.sin6_addr.u.Byte });
                        if !ipv6s.contains(&ip) {
                            ipv6s.push(ip);
                        }
                    }
                }
                ua = u.Next;
            }
            if !ipv4s.is_empty() || !ipv6s.is_empty() {
                out.push(WinAdapterInfo {
                    friendly_name,
                    description,
                    if_type: adapter.IfType,
                    ipv4s,
                    ipv6s,
                });
            }
        }
        cur = adapter.Next;
    }
    out
}

#[allow(dead_code)]
fn is_windows_virtual_adapter(friendly_name: &str, description: &str, if_type: u32) -> bool {
    const IF_TYPE_PPP: u32 = 23;
    const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
    const IF_TYPE_TUNNEL: u32 = 131;
    if matches!(
        if_type,
        IF_TYPE_PPP | IF_TYPE_SOFTWARE_LOOPBACK | IF_TYPE_TUNNEL
    ) {
        return true;
    }
    if is_virtual_iface_name(friendly_name.trim()) {
        return true;
    }
    let hay = format!(
        "{} {}",
        friendly_name.to_lowercase(),
        description.to_lowercase()
    );
    let markers = [
        "vethernet",
        "wsl",
        "vmware",
        "virtualbox",
        "tailscale",
        "wireguard",
        "wintun",
        "docker",
        "clash",
        "mihomo",
        "flclash",
        "sing-box",
        "singbox",
        "openvpn",
        "zerotier",
        "hyper-v",
        "radmin",
        "vpn",
        "tap-windows",
        "loopback",
        "teredo",
        "isatap",
        "6to4",
        "bluetooth",
        "npcap",
        "hamachi",
        "nordlynx",
        "mullvad",
        "proton",
        "km-test",
        "virtual",
        "unknown adapter",
        "未知适配器",
    ];
    markers.iter().any(|m| hay.contains(m))
}

#[allow(dead_code)]
fn windows_adapter_matches_iface(
    friendly_name: &str,
    description: &str,
    target: &str,
    exact_only: bool,
) -> bool {
    let needle = target.trim().to_lowercase();
    if needle.is_empty() {
        return false;
    }
    let friendly = friendly_name.trim().to_lowercase();
    if exact_only {
        return friendly == needle;
    }
    friendly.contains(&needle) || description.to_lowercase().contains(&needle)
}

#[cfg(target_os = "windows")]
fn enumerate_os_ipv4s() -> Vec<(Ipv4Addr, bool)> {
    let mut out = Vec::new();
    for adapter in enumerate_windows_adapters() {
        let is_virt = is_windows_virtual_adapter(
            &adapter.friendly_name,
            &adapter.description,
            adapter.if_type,
        );
        for ip in adapter.ipv4s {
            if !out.iter().any(|(existing, _)| *existing == ip) {
                out.push((ip, is_virt));
            }
        }
    }
    out
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn enumerate_os_ipv4s() -> Vec<(Ipv4Addr, bool)> {
    Vec::new()
}

/// Resolve a network interface name (e.g. `lo0`, `en0`, `eth0`, `utun4`) to its primary IP address
/// (prefers IPv4, falls back to IPv6).
pub fn resolve_interface_ip(iface_name: &str) -> Result<IpAddr> {
    let iface = iface_name.trim();
    if iface.is_empty() {
        return Err(anyhow!("network interface name cannot be empty"));
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(ip) = crate::platform::macos::resolve_interface_ip_native(iface) {
            return Ok(ip);
        }
        for bin in ["/sbin/ifconfig", "ifconfig"] {
            if let Ok(out) = std::process::Command::new(bin).arg(iface).output() {
                if out.status.success() {
                    let text = String::from_utf8_lossy(&out.stdout);
                    if let Some(ip) = parse_ifconfig_single_iface_ip(&text) {
                        return Ok(ip);
                    }
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(out) = std::process::Command::new("ip")
            .args(["-o", "addr", "show", "dev", iface])
            .output()
        {
            if out.status.success() {
                let text = String::from_utf8_lossy(&out.stdout);
                if let Some(ip) = parse_ip_addr_single_iface_ip(&text) {
                    return Ok(ip);
                }
            }
        }
        if let Ok(out) = std::process::Command::new("ifconfig").arg(iface).output() {
            if out.status.success() {
                let text = String::from_utf8_lossy(&out.stdout);
                if let Some(ip) = parse_ifconfig_single_iface_ip(&text) {
                    return Ok(ip);
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        if iface.eq_ignore_ascii_case("lo")
            || iface.eq_ignore_ascii_case("lo0")
            || iface.eq_ignore_ascii_case("loopback")
        {
            return Ok(IpAddr::V4(Ipv4Addr::LOCALHOST));
        }
        let adapters = enumerate_windows_adapters();
        let pick_ip = |a: &WinAdapterInfo| -> Option<IpAddr> {
            if let Some(&v4) = a.ipv4s.first() {
                return Some(IpAddr::V4(v4));
            }
            a.ipv6s
                .iter()
                .copied()
                .find(|v6| (v6.segments()[0] & 0xffc0) != 0xfe80)
                .or_else(|| a.ipv6s.first().copied())
                .map(IpAddr::V6)
        };
        for exact_only in [true, false] {
            for adapter in &adapters {
                if windows_adapter_matches_iface(
                    &adapter.friendly_name,
                    &adapter.description,
                    iface,
                    exact_only,
                ) {
                    if let Some(ip) = pick_ip(adapter) {
                        return Ok(ip);
                    }
                }
            }
        }
    }

    Err(anyhow!(
        "network interface {iface:?} not found or has no assigned IP address"
    ))
}

/// Split `host:port` safely while respecting bracketed IPv6 (`[::1]:8787`) and bare IPv6 (`::1`).
fn split_host_and_port(spec: &str) -> Result<(&str, Option<u16>)> {
    let s = spec.trim();
    if s.is_empty() {
        return Err(anyhow!("bind address cannot be empty"));
    }
    if let Some(rest) = s.strip_prefix('[') {
        let Some((host, after)) = rest.split_once(']') else {
            return Err(anyhow!("invalid bracketed IPv6 bind address {spec:?}"));
        };
        if after.is_empty() {
            return Ok((host, None));
        }
        if let Some(port_str) = after.strip_prefix(':') {
            let port: u16 = port_str
                .parse()
                .with_context(|| format!("invalid port in bind address {spec:?}"))?;
            return Ok((host, Some(port)));
        }
        return Err(anyhow!("invalid bind address {spec:?}"));
    }
    // Bare IPv6 address (contains 2+ colons) without port
    if s.matches(':').count() >= 2 {
        return Ok((s, None));
    }
    if let Some((host, port_str)) = s.rsplit_once(':') {
        let port: u16 = port_str
            .parse()
            .with_context(|| format!("invalid port in bind address {spec:?}"))?;
        return Ok((host.trim(), Some(port)));
    }
    Ok((s, None))
}

/// Resolve a bind specification supporting `IP:port`, `[IPv6]:port`, `hostname:port`, or `<iface>:<port>`
/// (e.g. `127.0.0.1:8787`, `lo0:8787`, `en0:8787`, `0.0.0.0:8787`).
pub fn resolve_bind_socket_addr(spec: &str, default_port: Option<u16>) -> Result<SocketAddr> {
    let trimmed = spec.trim();
    if let Ok(sa) = trimmed.parse::<SocketAddr>() {
        return Ok(sa);
    }
    let (host, parsed_port) = split_host_and_port(trimmed)?;
    let port = parsed_port
        .or(default_port)
        .ok_or_else(|| anyhow!("missing port in bind specification {spec:?} (expected e.g. 127.0.0.1:8787 or lo0:8787)"))?;

    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    if let Ok(ip) = resolve_interface_ip(host) {
        return Ok(SocketAddr::new(ip, port));
    }
    // Fall back to standard DNS / localhost resolution (e.g. `localhost:8787`).
    let mut addrs = (host, port)
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve bind address {spec:?} (neither an IP, local interface, nor hostname)"))?;
    // Prefer IPv4 when resolving hostnames like `localhost`.
    let all: Vec<SocketAddr> = addrs.by_ref().collect();
    if let Some(v4) = all.iter().find(|a| a.is_ipv4()) {
        return Ok(*v4);
    }
    all.into_iter()
        .next()
        .ok_or_else(|| anyhow!("bind address {spec:?} resolved to no socket addresses"))
}

/// Resolve Wi-Fi control/telemetry bind address (`--bind-addr` / `--bind`) + `--telemetry-port`.
/// Supports bare IPs (`0.0.0.0`), interface names (`en0`, `lo0`), or `iface:port` / `ip:port` (`lo0:56845`).
pub fn resolve_control_bind(bind_addr: &str, default_port: u16) -> Result<(IpAddr, u16)> {
    let sa = resolve_bind_socket_addr(bind_addr, Some(default_port))?;
    Ok((sa.ip(), sa.port()))
}

#[allow(dead_code)]
fn parse_ifconfig_single_iface_ip(text: &str) -> Option<IpAddr> {
    let mut fallback_v6: Option<Ipv6Addr> = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("inet ") {
            let token = rest
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim_start_matches("addr:");
            if let Ok(v4) = token.parse::<Ipv4Addr>() {
                return Some(IpAddr::V4(v4));
            }
        } else if let Some(rest) = trimmed.strip_prefix("inet6 ") {
            let token = rest
                .split_whitespace()
                .next()
                .unwrap_or("")
                .split('%')
                .next()
                .unwrap_or("")
                .split('/')
                .next()
                .unwrap_or("");
            if let Ok(v6) = token.parse::<Ipv6Addr>() {
                let is_ll = (v6.segments()[0] & 0xffc0) == 0xfe80;
                if fallback_v6.is_none() || !is_ll {
                    fallback_v6 = Some(v6);
                }
            }
        }
    }
    fallback_v6.map(IpAddr::V6)
}

#[allow(dead_code)]
fn parse_ip_addr_single_iface_ip(text: &str) -> Option<IpAddr> {
    let mut fallback_v6: Option<Ipv6Addr> = None;
    for line in text.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if let Some(pos) = tokens.iter().position(|t| *t == "inet") {
            if let Some(cidr) = tokens.get(pos + 1) {
                if let Ok(v4) = cidr.split('/').next().unwrap_or("").parse::<Ipv4Addr>() {
                    return Some(IpAddr::V4(v4));
                }
            }
        } else if let Some(pos) = tokens.iter().position(|t| *t == "inet6") {
            if let Some(cidr) = tokens.get(pos + 1) {
                if let Ok(v6) = cidr.split('/').next().unwrap_or("").parse::<Ipv6Addr>() {
                    let is_ll = (v6.segments()[0] & 0xffc0) == 0xfe80;
                    if fallback_v6.is_none() || !is_ll {
                        fallback_v6 = Some(v6);
                    }
                }
            }
        }
    }
    fallback_v6.map(IpAddr::V6)
}

#[allow(dead_code)]
fn parse_ipconfig_iface_ip(text: &str, iface: &str) -> Option<IpAddr> {
    let target = iface.to_ascii_lowercase();
    let mut in_section = false;
    for line in text.lines() {
        if !line.starts_with(char::is_whitespace) && line.trim_end().ends_with(':') {
            in_section = line.to_ascii_lowercase().contains(&target);
            continue;
        }
        if !in_section || !line.contains("IPv4") {
            continue;
        }
        if let Some((_, rhs)) = line.rsplit_once(':') {
            let clean = rhs.trim().split('(').next().unwrap_or("").trim();
            if let Ok(v4) = clean.parse::<Ipv4Addr>() {
                return Some(IpAddr::V4(v4));
            }
        }
    }
    None
}

#[allow(dead_code)]
fn parse_ifconfig_entries(text: &str) -> Vec<(Ipv4Addr, bool)> {
    let mut out = Vec::new();
    let mut cur_virtual = false;
    let mut cur_active = true;
    for line in text.lines() {
        if !line.starts_with(char::is_whitespace) && line.contains(':') {
            let iface = line.split(':').next().unwrap_or("").trim();
            cur_virtual = is_virtual_iface_name(iface) || line.contains("POINTOPOINT");
            if let (Some(lb), Some(rb)) = (line.find('<'), line.find('>')) {
                let flags = &line[lb + 1..rb];
                cur_active = flags.split(',').any(|f| f == "UP")
                    && flags.split(',').any(|f| f == "RUNNING");
            } else {
                cur_active = true;
            }
            continue;
        }
        if !cur_active {
            continue;
        }
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("inet ") {
            let token = rest
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim_start_matches("addr:");
            if let Ok(ip) = token.parse::<Ipv4Addr>() {
                if !out.iter().any(|(existing, _)| *existing == ip) {
                    out.push((ip, cur_virtual));
                }
            }
        }
    }
    out
}

#[allow(dead_code)]
fn parse_ifconfig_ipv4s(text: &str) -> Vec<Ipv4Addr> {
    parse_ifconfig_entries(text).into_iter().map(|(ip, _)| ip).collect()
}

#[allow(dead_code)]
fn parse_ip_addr_entries(text: &str) -> Vec<(Ipv4Addr, bool)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let iface = tokens.get(1).copied().unwrap_or("");
        let is_virt = is_virtual_iface_name(iface);
        if let Some(pos) = tokens.iter().position(|t| *t == "inet") {
            if let Some(cidr) = tokens.get(pos + 1) {
                let ip_str = cidr.split('/').next().unwrap_or("");
                if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                    if !out.iter().any(|(existing, _)| *existing == ip) {
                        out.push((ip, is_virt));
                    }
                }
            }
        }
    }
    out
}

#[allow(dead_code)]
fn parse_ip_addr_ipv4s(text: &str) -> Vec<Ipv4Addr> {
    parse_ip_addr_entries(text).into_iter().map(|(ip, _)| ip).collect()
}

#[allow(dead_code)]
fn parse_ipconfig_entries(text: &str) -> Vec<(Ipv4Addr, bool)> {
    let mut out = Vec::new();
    let mut cur_virtual = false;
    for line in text.lines() {
        if !line.starts_with(char::is_whitespace) && line.trim_end().ends_with(':') {
            let lower = line.to_ascii_lowercase();
            cur_virtual = lower.contains("vethernet")
                || lower.contains("wsl")
                || lower.contains("vmware")
                || lower.contains("virtualbox")
                || lower.contains("tailscale")
                || lower.contains("wireguard")
                || lower.contains("docker")
                || lower.contains("clash")
                || lower.contains("mihomo")
                || lower.contains("meta")
                || lower.contains("sing")
                || lower.contains("openvpn")
                || lower.contains("zerotier")
                || lower.contains("hyper-v")
                || lower.contains("radmin")
                || lower.contains("vpn")
                || lower.contains("unknown adapter")
                || line.contains("未知适配器")
                || lower.contains("tap")
                || lower.contains("tun");
            continue;
        }
        if !line.contains("IPv4") {
            continue;
        }
        if let Some((_, rhs)) = line.rsplit_once(':') {
            let clean = rhs.trim().split('(').next().unwrap_or("").trim();
            if let Ok(ip) = clean.parse::<Ipv4Addr>() {
                if !out.iter().any(|(existing, _)| *existing == ip) {
                    out.push((ip, cur_virtual));
                }
            }
        }
    }
    out
}

#[allow(dead_code)]
fn parse_ipconfig_ipv4s(text: &str) -> Vec<Ipv4Addr> {
    parse_ipconfig_entries(text).into_iter().map(|(ip, _)| ip).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_platform_interface_outputs() {
        let mac = "en0: flags=8863\n\tinet 192.0.2.100 netmask 0xffffff00\nlo0:\n\tinet 127.0.0.1 netmask 0xff000000\n";
        assert_eq!(
            parse_ifconfig_ipv4s(mac),
            vec![Ipv4Addr::new(192, 0, 2, 100), Ipv4Addr::LOCALHOST]
        );

        let linux = "2: eth0    inet 192.0.2.50/24 brd 192.0.2.255 scope global eth0\n";
        assert_eq!(
            parse_ip_addr_ipv4s(linux),
            vec![Ipv4Addr::new(192, 0, 2, 50)]
        );

        let win = "   IPv4 Address. . . . . . . . . . . : 198.51.100.18(Preferred)\r\n";
        assert_eq!(parse_ipconfig_ipv4s(win), vec![Ipv4Addr::new(198, 51, 100, 18)]);

        assert!(!is_windows_virtual_adapter(
            "以太网",
            "Realtek PCIe GbE Family Controller",
            6
        ));
        assert!(!is_windows_virtual_adapter(
            "WLAN",
            "Intel(R) Wi-Fi 6E AX211 160MHz",
            71
        ));
        assert!(is_windows_virtual_adapter(
            "vEthernet (WSL)",
            "Hyper-V Virtual Ethernet Adapter",
            6
        ));
        assert!(is_windows_virtual_adapter(
            "Meta",
            "Wintun Userspace Tunnel",
            53
        ));
        assert!(is_windows_virtual_adapter(
            "Tailscale",
            "Tailscale Tunnel",
            131
        ));
        assert!(windows_adapter_matches_iface(
            "以太网",
            "Realtek PCIe GbE Family Controller",
            "以太网",
            true
        ));
        assert!(!windows_adapter_matches_iface(
            "以太网 2",
            "Realtek PCIe GbE Family Controller",
            "以太网",
            true
        ));
        assert!(windows_adapter_matches_iface(
            "以太网 2",
            "Realtek PCIe GbE Family Controller",
            "Realtek",
            false
        ));

        let mac_multi = "\
utun3: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500
\tinet 100.64.0.10 --> 100.64.0.10 netmask 0xffffffff
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 192.0.2.140 netmask 0xffffff00 broadcast 192.0.2.255
";
        let entries = parse_ifconfig_entries(mac_multi);
        assert_eq!(
            entries,
            vec![
                (Ipv4Addr::new(100, 64, 0, 10), true),
                (Ipv4Addr::new(192, 0, 2, 140), false),
            ]
        );
    }

    #[test]
    fn builds_connection_endpoints_for_unspecified_and_loopback_binds() {
        let lan = vec!["192.0.2.100".to_string()];
        let info = HostConnectionInfo::build(
            lan.clone(),
            Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            Some((5026, 5027)),
            Some(SocketAddr::from(([0, 0, 0, 0], 8787))),
        );
        assert_eq!(info.wifi_endpoints, vec!["192.0.2.100:5026"]);
        assert_eq!(info.web_admin_urls, vec!["http://192.0.2.100:8787/"]);
        assert_eq!(info.web_viewer_urls, vec!["http://192.0.2.100:8787/view"]);
        assert!(!info.web_localhost_only);

        let local = HostConnectionInfo::build(
            lan.clone(),
            None,
            None,
            Some(SocketAddr::from(([127, 0, 0, 1], 8787))),
        );
        assert!(local.web_localhost_only);
        assert_eq!(local.web_viewer_urls, vec!["http://127.0.0.1:8787/view"]);

        let split_open = HostConnectionInfo::build_with_viewer(
            lan.clone(),
            None,
            None,
            Some(SocketAddr::from(([127, 0, 0, 1], 8787))),
            Some(SocketAddr::from(([0, 0, 0, 0], 54321))),
        );
        assert!(split_open.web_localhost_only);
        assert_eq!(split_open.web_admin_urls, vec!["http://127.0.0.1:8787/"]);
        assert!(split_open.web_viewer_listening);
        assert_eq!(split_open.web_viewer_port, Some(54321));
        assert_eq!(split_open.web_viewer_bind.as_deref(), Some("0.0.0.0:54321"));
        assert_eq!(split_open.web_viewer_urls, vec!["http://192.0.2.100:54321/view"]);

        let split_closed = HostConnectionInfo::build_with_viewer(
            lan,
            None,
            None,
            Some(SocketAddr::from(([127, 0, 0, 1], 8787))),
            None,
        );
        assert!(!split_closed.web_viewer_listening);
        assert_eq!(split_closed.web_viewer_port, None);
        assert!(split_closed.web_viewer_urls.is_empty());
    }

    #[test]
    fn resolves_bind_socket_addr_and_iface_formats() {
        assert_eq!(
            resolve_bind_socket_addr("127.0.0.1:8787", None).unwrap(),
            SocketAddr::from(([127, 0, 0, 1], 8787))
        );
        assert_eq!(
            resolve_bind_socket_addr("[::1]:8787", None).unwrap(),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8787)
        );
        assert_eq!(
            resolve_control_bind("0.0.0.0", 56845).unwrap(),
            (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 56845)
        );
        assert_eq!(
            resolve_control_bind("127.0.0.1:56845", 0).unwrap(),
            (IpAddr::V4(Ipv4Addr::LOCALHOST), 56845)
        );
        let mac_lo = "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\n\tinet 127.0.0.1 netmask 0xff000000\n\tinet6 ::1 prefixlen 128\n";
        assert_eq!(
            parse_ifconfig_single_iface_ip(mac_lo),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
        let linux_lo = "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever\n";
        assert_eq!(
            parse_ip_addr_single_iface_ip(linux_lo),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
        #[cfg(target_os = "linux")]
        {
            assert_eq!(
                resolve_bind_socket_addr("lo:8787", None).unwrap(),
                SocketAddr::from(([127, 0, 0, 1], 8787))
            );
            assert_eq!(
                resolve_control_bind("lo:56845", 0).unwrap(),
                (IpAddr::V4(Ipv4Addr::LOCALHOST), 56845)
            );
        }
    }
}
