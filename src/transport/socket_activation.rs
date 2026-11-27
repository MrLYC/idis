//! OS-level socket activation for zero-process background hosting:
//! - **macOS (`launchd`)**: calls `launch_activate_socket` for named sockets `"web"`,
//!   `"telemetry"`, and `"data"` defined in a LaunchAgent plist (`<key>Sockets</key>`).
//! - **Linux (`systemd`)**: parses standard `LISTEN_PID`, `LISTEN_FDS`, and optional
//!   `LISTEN_FDNAMES` (`web`, `telemetry`, `data`, or positional fallback), marks all inherited
//!   FDs `FD_CLOEXEC`, and unsets `LISTEN_*` env vars so child processes (e.g. `ffmpeg`) never
//!   inherit listening sockets.
//!
//! When not launched by `launchd`/`systemd`, `take_activated_sockets` cleanly returns empty
//! slots and `idis` binds its own sockets normally.

use std::net::TcpListener;
#[cfg(target_os = "macos")]
use tracing::warn;

/// Pre-bound listening sockets handed over by an OS service manager (`launchd` / `systemd`).
#[derive(Default)]
pub struct ActivatedSockets {
    pub web: Option<TcpListener>,
    pub wifi_telemetry: Option<TcpListener>,
    pub wifi_data: Option<TcpListener>,
    pub source: Option<&'static str>,
}

impl ActivatedSockets {
    pub fn has_any(&self) -> bool {
        self.web.is_some() || self.wifi_telemetry.is_some() || self.wifi_data.is_some()
    }

    pub fn has_wifi(&self) -> bool {
        self.wifi_telemetry.is_some() || self.wifi_data.is_some()
    }
}

/// Adopt any OS-activated TCP listeners for `web`, `telemetry`, and `data`.
///
/// `want_web` / `want_wifi` are used only as tie-breakers when `systemd` passes unnamed
/// positional sockets without `LISTEN_FDNAMES`.
pub fn take_activated_sockets(want_web: bool, want_wifi: bool) -> ActivatedSockets {
    #[cfg(target_os = "macos")]
    {
        let _ = (want_web, want_wifi);
        take_launchd_sockets()
    }
    #[cfg(target_os = "linux")]
    {
        take_systemd_sockets(want_web, want_wifi)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (want_web, want_wifi);
        ActivatedSockets::default()
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn set_cloexec(fd: i32) {
    extern "C" {
        fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    }
    const F_GETFD: i32 = 1;
    const F_SETFD: i32 = 2;
    const FD_CLOEXEC: i32 = 1;
    unsafe {
        let flags = fcntl(fd, F_GETFD);
        if flags >= 0 {
            let _ = fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
        }
    }
}

#[cfg(target_os = "linux")]
fn close_fd(fd: i32) {
    extern "C" {
        fn close(fd: i32) -> i32;
    }
    unsafe {
        let _ = close(fd);
    }
}

#[cfg(target_os = "macos")]
fn take_launchd_sockets() -> ActivatedSockets {
    use std::ffi::CString;
    use std::os::unix::io::FromRawFd;

    extern "C" {
        fn launch_activate_socket(
            name: *const std::ffi::c_char,
            fds: *mut *mut i32,
            cnt: *mut usize,
        ) -> i32;
        fn free(ptr: *mut std::ffi::c_void);
    }

    const ENOENT: i32 = 2;
    const ESRCH: i32 = 3;

    let activate_one = |name: &str| -> Option<TcpListener> {
        let c_name = CString::new(name).ok()?;
        let mut fds: *mut i32 = std::ptr::null_mut();
        let mut cnt: usize = 0;
        let rc = unsafe { launch_activate_socket(c_name.as_ptr(), &mut fds, &mut cnt) };
        if rc != 0 {
            if rc != ENOENT && rc != ESRCH {
                warn!("launch_activate_socket({name:?}) failed with errno={rc}");
            }
            return None;
        }
        if fds.is_null() || cnt == 0 {
            if !fds.is_null() {
                unsafe { free(fds.cast()) };
            }
            return None;
        }
        let slice = unsafe { std::slice::from_raw_parts(fds, cnt) };
        let mut raw_fds: Vec<i32> = slice.to_vec();
        unsafe { free(fds.cast()) };
        for &fd in &raw_fds {
            set_cloexec(fd);
        }
        // If launchd handed over dual-stack sockets (e.g. wildcard without SockFamily=IPv4),
        // prefer the IPv4 listener so LAN IPv4 iPads are not dropped, and warn clearly.
        let mut listeners: Vec<TcpListener> = raw_fds
            .drain(..)
            .map(|fd| unsafe { TcpListener::from_raw_fd(fd) })
            .collect();
        let chosen_idx = listeners
            .iter()
            .position(|l| l.local_addr().is_ok_and(|a| a.is_ipv4()))
            .unwrap_or(0);
        let listener = listeners.swap_remove(chosen_idx);
        if !listeners.is_empty() {
            warn!(
                "launchd passed {} sockets for {:?}; kept {} and closed {} extra socket(s) — set <key>SockFamily</key><string>IPv4</string> in your LaunchAgent plist to avoid dual-stack duplicates",
                listeners.len() + 1,
                name,
                listener
                    .local_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|_| "unknown".to_string()),
                listeners.len()
            );
            drop(listeners);
        }
        let _ = listener.set_nonblocking(false);
        Some(listener)
    };

    let web = activate_one("web");
    let wifi_telemetry = activate_one("telemetry");
    let wifi_data = activate_one("data");
    let source = if web.is_some() || wifi_telemetry.is_some() || wifi_data.is_some() {
        Some("launchd")
    } else {
        None
    };
    ActivatedSockets {
        web,
        wifi_telemetry,
        wifi_data,
        source,
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SocketSlot {
    Web,
    WifiTelemetry,
    WifiData,
}

#[cfg(target_os = "linux")]
fn classify_systemd_fd_name(name: &str) -> Option<SocketSlot> {
    match name.trim().to_ascii_lowercase().as_str() {
        "web" | "idis-web" | "idis-web.socket" | "http" => Some(SocketSlot::Web),
        "telemetry" | "wifi" | "control" | "idis-telemetry" | "idis-telemetry.socket" => {
            Some(SocketSlot::WifiTelemetry)
        }
        "data" | "video" | "idis-data" | "idis-data.socket" => Some(SocketSlot::WifiData),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn assign_systemd_slots(
    fd_count: usize,
    fd_names: &[String],
    want_web: bool,
    want_wifi: bool,
) -> Vec<Option<SocketSlot>> {
    let mut slots = vec![None; fd_count];
    let mut has_web = false;
    let mut has_tel = false;
    let mut has_data = false;

    // Pass 1: assign explicitly named FDs (`LISTEN_FDNAMES`).
    for (idx, name) in fd_names.iter().enumerate().take(fd_count) {
        if let Some(slot) = classify_systemd_fd_name(name) {
            match slot {
                SocketSlot::Web if !has_web => {
                    slots[idx] = Some(slot);
                    has_web = true;
                }
                SocketSlot::WifiTelemetry if !has_tel => {
                    slots[idx] = Some(slot);
                    has_tel = true;
                }
                SocketSlot::WifiData if !has_data => {
                    slots[idx] = Some(slot);
                    has_data = true;
                }
                _ => {}
            }
        }
    }

    // Pass 2: positional fallback for genuinely unnamed/unclassified sockets ONLY.
    // Explicitly named duplicates (e.g. two `"web"` FDs in `LISTEN_FDNAMES`) stay `None` so
    // the caller closes the duplicate instead of misassigning it to Wi-Fi telemetry/data.
    let unassigned: Vec<usize> = slots
        .iter()
        .enumerate()
        .filter_map(|(i, s)| {
            let is_known_name = fd_names
                .get(i)
                .and_then(|n| classify_systemd_fd_name(n))
                .is_some();
            if s.is_none() && !is_known_name {
                Some(i)
            } else {
                None
            }
        })
        .collect();
    if !unassigned.is_empty() {
        let mut remaining_roles = Vec::new();
        if !has_web && (want_web || !want_wifi || unassigned.len() >= 3) {
            remaining_roles.push(SocketSlot::Web);
        }
        if !has_tel && (want_wifi || !want_web || unassigned.len() >= 2) {
            remaining_roles.push(SocketSlot::WifiTelemetry);
        }
        if !has_data && (want_wifi || unassigned.len() >= 2) {
            remaining_roles.push(SocketSlot::WifiData);
        }
        for (idx, role) in unassigned.into_iter().zip(remaining_roles) {
            slots[idx] = Some(role);
        }
    }
    slots
}

#[cfg(target_os = "linux")]
fn take_systemd_sockets(want_web: bool, want_wifi: bool) -> ActivatedSockets {
    use std::os::unix::io::FromRawFd;

    const SD_LISTEN_FDS_START: i32 = 3;

    let listen_pid = std::env::var("LISTEN_PID")
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok());
    let listen_fds = std::env::var("LISTEN_FDS")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok());
    let listen_fdnames: Vec<String> = std::env::var("LISTEN_FDNAMES")
        .ok()
        .map(|v| v.split(':').map(ToString::to_string).collect())
        .unwrap_or_default();

    // Always clear LISTEN_* so spawned children (e.g. ffmpeg) never misinterpret inherited env.
    std::env::remove_var("LISTEN_PID");
    std::env::remove_var("LISTEN_FDS");
    std::env::remove_var("LISTEN_FDNAMES");

    let my_pid = std::process::id();
    let Some(pid) = listen_pid else {
        return ActivatedSockets::default();
    };
    if pid != my_pid {
        return ActivatedSockets::default();
    }
    let count = listen_fds.unwrap_or(0);
    if count == 0 || count > 64 {
        return ActivatedSockets::default();
    }

    // Mark every inherited FD CLOEXEC immediately.
    for i in 0..count {
        set_cloexec(SD_LISTEN_FDS_START + i as i32);
    }

    let assignments = assign_systemd_slots(count, &listen_fdnames, want_web, want_wifi);
    let mut out = ActivatedSockets::default();

    for (i, slot) in assignments.into_iter().enumerate() {
        let fd = SD_LISTEN_FDS_START + i as i32;
        match slot {
            Some(role) => {
                let listener = unsafe { TcpListener::from_raw_fd(fd) };
                let _ = listener.set_nonblocking(false);
                match role {
                    SocketSlot::Web => out.web = Some(listener),
                    SocketSlot::WifiTelemetry => out.wifi_telemetry = Some(listener),
                    SocketSlot::WifiData => out.wifi_data = Some(listener),
                }
            }
            None => {
                close_fd(fd);
            }
        }
    }

    if out.has_any() {
        out.source = Some("systemd");
    }
    out
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn systemd_slot_assignment_supports_named_and_positional_sockets() {
        // Named sockets in arbitrary order
        let names = vec![
            "data".to_string(),
            "web".to_string(),
            "telemetry".to_string(),
        ];
        let assigned = assign_systemd_slots(3, &names, true, true);
        assert_eq!(
            assigned,
            vec![
                Some(SocketSlot::WifiData),
                Some(SocketSlot::Web),
                Some(SocketSlot::WifiTelemetry),
            ]
        );

        // Positional fallback when systemd emits unit name `idis.socket:idis.socket:idis.socket`
        let generic = vec![
            "idis.socket".to_string(),
            "idis.socket".to_string(),
            "idis.socket".to_string(),
        ];
        let assigned_pos = assign_systemd_slots(3, &generic, true, true);
        assert_eq!(
            assigned_pos,
            vec![
                Some(SocketSlot::Web),
                Some(SocketSlot::WifiTelemetry),
                Some(SocketSlot::WifiData),
            ]
        );

        // 2 unnamed sockets in Wi-Fi-only mode -> telemetry + data
        let assigned_wifi = assign_systemd_slots(2, &[], false, true);
        assert_eq!(
            assigned_wifi,
            vec![Some(SocketSlot::WifiTelemetry), Some(SocketSlot::WifiData)]
        );

        // 1 unnamed socket in Web-only mode -> web
        let assigned_web = assign_systemd_slots(1, &[], true, false);
        assert_eq!(assigned_web, vec![Some(SocketSlot::Web)]);

        // P1-A5: Duplicate explicitly named FDs must remain None (closed), NEVER steal WifiTelemetry/WifiData!
        let dup_web = vec!["web".to_string(), "web".to_string()];
        assert_eq!(
            assign_systemd_slots(2, &dup_web, true, true),
            vec![Some(SocketSlot::Web), None]
        );
        let dup_tel = vec!["telemetry".to_string(), "telemetry".to_string()];
        assert_eq!(
            assign_systemd_slots(2, &dup_tel, true, true),
            vec![Some(SocketSlot::WifiTelemetry), None]
        );
        let tri_web = vec!["web".to_string(), "web".to_string(), "web".to_string()];
        assert_eq!(
            assign_systemd_slots(3, &tri_web, true, true),
            vec![Some(SocketSlot::Web), None, None]
        );

        // Excess unnamed FDs (>3) leave surplus as None so caller closes them
        assert_eq!(
            assign_systemd_slots(5, &[], true, true),
            vec![
                Some(SocketSlot::Web),
                Some(SocketSlot::WifiTelemetry),
                Some(SocketSlot::WifiData),
                None,
                None,
            ]
        );

        // Mixed named + unnamed + duplicate named
        let mixed = vec![
            "data".to_string(),
            "data".to_string(),
            "idis.socket".to_string(),
            "idis.socket".to_string(),
        ];
        assert_eq!(
            assign_systemd_slots(4, &mixed, true, true),
            vec![
                Some(SocketSlot::WifiData),
                None,
                Some(SocketSlot::Web),
                Some(SocketSlot::WifiTelemetry),
            ]
        );
    }
}
