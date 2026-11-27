use crate::config::CaptureRect;
use crate::platform::ffmpeg_capture::{
    build_windows_ddagrab_input_args, build_windows_gdigrab_input_args, FfmpegPipelineSpec,
    FfmpegProcess,
};
use crate::platform::mdns::publish_mdns;
use crate::platform::{
    bounded_frame_channel, clamp_pixel_dimensions, compute_window_move_rect, latest_frame_channel,
    BonjourHandle,
    CaptureHandle, CaptureParams, CursorState, DesktopWindowInfo, DisplayBackend, FrameReceiver,
    FrameSender, HostSystemInfo, WindowMoveLayout,
};
use crate::protocol::messages::{
    InputEvent, KEY_MOD_ALT, KEY_MOD_CTRL, KEY_MOD_META, KEY_MOD_SHIFT,
};
use anyhow::{anyhow, Result};
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tracing::{debug, info};
use windows_sys::Win32::Foundation::{CloseHandle, BOOL, HWND, LPARAM, POINT, RECT};
use windows_sys::Win32::Graphics::Dwm::{DwmGetWindowAttribute, DWMWA_CLOAKED};
use windows_sys::Win32::Graphics::Gdi::{
    EnumDisplayMonitors, GetMonitorInfoW, MonitorFromWindow, HDC, HMONITOR, MONITORINFO,
    MONITORINFOEXW, MONITOR_DEFAULTTONEAREST,
};
use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows_sys::Win32::UI::HiDpi::{
    SetProcessDpiAwarenessContext, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT, KEYEVENTF_KEYUP,
    KEYEVENTF_UNICODE, MOUSEEVENTF_ABSOLUTE, MOUSEEVENTF_HWHEEL, MOUSEEVENTF_LEFTDOWN,
    MOUSEEVENTF_LEFTUP, MOUSEEVENTF_MOVE, MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP,
    MOUSEEVENTF_VIRTUALDESK, MOUSEEVENTF_WHEEL, MOUSEINPUT, VK_BACK, VK_CONTROL, VK_DELETE,
    VK_DOWN, VK_END, VK_ESCAPE, VK_HOME, VK_LEFT, VK_LWIN, VK_MENU, VK_NEXT, VK_PRIOR, VK_RETURN,
    VK_RIGHT, VK_SHIFT, VK_SPACE, VK_TAB, VK_UP,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetCursorPos, GetShellWindow, GetSystemMetrics, GetWindowLongW, GetWindowRect,
    GetWindowTextW, GetWindowThreadProcessId, IsIconic, IsWindow, IsWindowVisible, IsZoomed,
    SetProcessDPIAware, SetWindowPos, ShowWindow, GWL_EXSTYLE, MONITORINFOF_PRIMARY, SM_CXSCREEN,
    SM_CXVIRTUALSCREEN, SM_CYSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN,
    SWP_NOACTIVATE, SWP_NOZORDER, SW_RESTORE, WS_EX_TOPMOST,
};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Native Windows backend:
/// - Per-Monitor DPI Awareness v2 for accurate physical-pixel capture, cursor, and window geometry
/// - Pure-Rust `mdns-sd` Bonjour advertisement
/// - `ffmpeg` DXGI Desktop Duplication (`ddagrab`) with automatic `gdigrab` fallback
///   (supports `libx264`, `h264_nvenc`, `h264_qsv`, `h264_amf`) and true pause/resume
/// - Direct Win32 `SendInput`, `GetCursorPos`, `EnumDisplayMonitors`, `EnumWindows`, and `SetWindowPos`
pub struct WindowsBackend;

/// Enable Per-Monitor DPI Awareness v2 early on startup so `EnumDisplayMonitors`, `GetSystemMetrics`,
/// `GetCursorPos`, `SendInput`, `GetWindowRect`, and `SetWindowPos` all operate in consistent
/// physical pixel coordinates on 125%/150%/200% DPI-scaled displays.
pub fn init_process_dpi_awareness() {
    unsafe {
        if SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) == 0 {
            let _ = SetProcessDPIAware();
        }
    }
}

/// Native zero-subprocess Windows lock-screen detection via `OpenInputDesktop(DESKTOP_SWITCHDESKTOP)`.
/// Returns `true` only after an interactive unlocked desktop has been observed at least once,
/// preventing false positives in headless/service CI environments.
pub fn is_screen_locked() -> bool {
    use std::sync::atomic::{AtomicBool, Ordering};
    const DESKTOP_SWITCHDESKTOP: u32 = 0x0100;
    #[link(name = "user32")]
    extern "system" {
        fn OpenInputDesktop(dw_flags: u32, f_inherit: i32, dw_desired_access: u32) -> isize;
        fn CloseDesktop(h_desktop: isize) -> i32;
    }
    static SEEN_UNLOCKED: AtomicBool = AtomicBool::new(false);
    let h = unsafe { OpenInputDesktop(0, 0, DESKTOP_SWITCHDESKTOP) };
    if h != 0 {
        unsafe {
            CloseDesktop(h);
        }
        SEEN_UNLOCKED.store(true, Ordering::Relaxed);
        false
    } else {
        SEEN_UNLOCKED.load(Ordering::Relaxed)
    }
}

impl WindowsBackend {
    pub fn new() -> Self {
        Self
    }
}

impl Default for WindowsBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct WinMonitorInfo {
    display_id: u32,
    hmon: HMONITOR,
    rect: CaptureRect,
    work_rect: RECT,
    is_primary: bool,
    device_name: String,
    name: String,
}

unsafe extern "system" fn enum_monitor_cb(
    hmon: HMONITOR,
    _hdc: HDC,
    rect_ptr: *mut RECT,
    lparam: LPARAM,
) -> BOOL {
    if lparam == 0 {
        return 1;
    }
    let list = &mut *(lparam as *mut Vec<WinMonitorInfo>);
    let mut mi: MONITORINFOEXW = zeroed();
    mi.monitorInfo.cbSize = size_of::<MONITORINFOEXW>() as u32;
    let (r, work_rect, is_primary, device_name) =
        if GetMonitorInfoW(hmon, &mut mi.monitorInfo as *mut MONITORINFO) != 0 {
            let nul = mi
                .szDevice
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(mi.szDevice.len());
            let raw_dev = String::from_utf16_lossy(&mi.szDevice[..nul]);
            let clean_dev = raw_dev.strip_prefix(r"\\.\").unwrap_or(&raw_dev).to_string();
            (
                mi.monitorInfo.rcMonitor,
                mi.monitorInfo.rcWork,
                (mi.monitorInfo.dwFlags & MONITORINFOF_PRIMARY) != 0,
                clean_dev,
            )
        } else if !rect_ptr.is_null() {
            let r = *rect_ptr;
            (r, r, r.left == 0 && r.top == 0, String::new())
        } else {
            return 1;
        };

    let w = (r.right - r.left).max(320) as u32 & !1;
    let h = (r.bottom - r.top).max(240) as u32 & !1;
    list.push(WinMonitorInfo {
        display_id: 0,
        hmon,
        rect: CaptureRect {
            x: r.left,
            y: r.top,
            width: w,
            height: h,
        },
        work_rect,
        is_primary,
        device_name,
        name: String::new(),
    });
    1
}

/// Enumerate active monitors sorted deterministically with the primary display first (`display_id = 1`,
/// matching DXGI `output_idx = 0`), followed by secondary displays (`display_id = 2, 3, ...`).
fn enumerate_monitors() -> Vec<WinMonitorInfo> {
    let mut monitors: Vec<WinMonitorInfo> = Vec::new();
    unsafe {
        EnumDisplayMonitors(
            std::ptr::null_mut(),
            std::ptr::null(),
            Some(enum_monitor_cb),
            (&mut monitors as *mut Vec<WinMonitorInfo>) as LPARAM,
        );
    }
    if monitors.is_empty() {
        let w = unsafe { GetSystemMetrics(SM_CXSCREEN) }.max(320) as u32 & !1;
        let h = unsafe { GetSystemMetrics(SM_CYSCREEN) }.max(240) as u32 & !1;
        monitors.push(WinMonitorInfo {
            display_id: 1,
            hmon: std::ptr::null_mut(),
            rect: CaptureRect {
                x: 0,
                y: 0,
                width: w,
                height: h,
            },
            work_rect: RECT {
                left: 0,
                top: 0,
                right: w as i32,
                bottom: h as i32,
            },
            is_primary: true,
            device_name: "DISPLAY1".to_string(),
            name: "电脑主屏幕".to_string(),
        });
        return monitors;
    }

    monitors.sort_by(|a, b| {
        b.is_primary
            .cmp(&a.is_primary)
            .then_with(|| a.rect.x.cmp(&b.rect.x))
            .then_with(|| a.rect.y.cmp(&b.rect.y))
            .then_with(|| a.device_name.cmp(&b.device_name))
    });
    for (idx, m) in monitors.iter_mut().enumerate() {
        m.display_id = (idx + 1) as u32;
        m.name = if m.is_primary {
            "电脑主屏幕".to_string()
        } else if m.device_name.is_empty() {
            format!("显示器 {}", idx + 1)
        } else {
            format!("显示器 {} ({})", idx + 1, m.device_name)
        };
    }
    monitors
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowsCaptureSource {
    Ddagrab { output_idx: u32 },
    Gdigrab,
}

/// Fast one-shot probe verifying that the local FFmpeg build supports `ddagrab` AND DXGI Desktop
/// Duplication can acquire a frame for `output_idx` in the active desktop session (not RDP/headless).
fn probe_ddagrab(ffmpeg_path: &str, output_idx: u32) -> bool {
    let mut cmd = Command::new(ffmpeg_path);
    crate::proxy::strip_proxy_env_on_command(&mut cmd);
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd.args([
        "-hide_banner",
        "-loglevel",
        "error",
        "-nostdin",
        "-f",
        "lavfi",
        "-i",
        &format!("ddagrab=output_idx={output_idx}:framerate=15:draw_mouse=0"),
        "-frames:v",
        "1",
        "-f",
        "null",
        "-",
    ])
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::null());

    let Ok(mut child) = cmd.spawn() else {
        return false;
    };
    let deadline = Instant::now() + Duration::from_millis(2500);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return false;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    }
}

fn send_mouse_input(dx: i32, dy: i32, flags: u32, mouse_data: u32) {
    let input = INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT {
                dx,
                dy,
                mouseData: mouse_data,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    };
    unsafe {
        SendInput(1, &input, size_of::<INPUT>() as i32);
    }
}

fn map_special_key_to_vk(key_code: u16) -> Option<u16> {
    match key_code {
        0x33 => Some(VK_BACK),
        0x24 => Some(VK_RETURN),
        0x30 => Some(VK_TAB),
        0x35 => Some(VK_ESCAPE),
        0x75 => Some(VK_DELETE),
        0x7E => Some(VK_UP),
        0x7D => Some(VK_DOWN),
        0x7B => Some(VK_LEFT),
        0x7C => Some(VK_RIGHT),
        0x73 => Some(VK_HOME),
        0x77 => Some(VK_END),
        0x74 => Some(VK_PRIOR),
        0x79 => Some(VK_NEXT),
        _ => None,
    }
}

fn send_vk_with_mods(vk: u16, modifiers: u8) {
    let mut mods = Vec::with_capacity(4);
    if (modifiers & KEY_MOD_CTRL) != 0 {
        mods.push(VK_CONTROL);
    }
    if (modifiers & KEY_MOD_ALT) != 0 {
        mods.push(VK_MENU);
    }
    if (modifiers & KEY_MOD_META) != 0 {
        mods.push(VK_LWIN);
    }
    if (modifiers & KEY_MOD_SHIFT) != 0 {
        mods.push(VK_SHIFT);
    }
    let make_vk = |code: u16, up: bool| INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: code,
                wScan: 0,
                dwFlags: if up { KEYEVENTF_KEYUP } else { 0 },
                time: 0,
                dwExtraInfo: 0,
            },
        },
    };
    let mut inputs = Vec::with_capacity(mods.len() * 2 + 2);
    for &m in &mods {
        inputs.push(make_vk(m, false));
    }
    inputs.push(make_vk(vk, false));
    inputs.push(make_vk(vk, true));
    for &m in mods.iter().rev() {
        inputs.push(make_vk(m, true));
    }
    unsafe {
        SendInput(inputs.len() as u32, inputs.as_ptr(), size_of::<INPUT>() as i32);
    }
}

fn send_vk(vk: u16) {
    send_vk_with_mods(vk, 0);
}

fn send_unicode(ch: u16) {
    let inputs = [
        INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: 0,
                    wScan: ch,
                    dwFlags: KEYEVENTF_UNICODE,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        },
        INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: 0,
                    wScan: ch,
                    dwFlags: KEYEVENTF_UNICODE | KEYEVENTF_KEYUP,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        },
    ];
    unsafe {
        SendInput(inputs.len() as u32, inputs.as_ptr(), size_of::<INPUT>() as i32);
    }
}

struct WindowsCaptureHandle {
    os_display_id: u32,
    capture_source: WindowsCaptureSource,
    src_rect: CaptureRect,
    out_w: u32,
    out_h: u32,
    max_pixel_edge: u32,
    fps: u32,
    bitrate_mbps: u32,
    encoder: String,
    ffmpeg_path: String,
    all_intra: bool,
    show_cursor: bool,
    paused: bool,
    tx: FrameSender,
    proc: Option<FfmpegProcess>,
}

impl WindowsCaptureHandle {
    /// Convert local client display coordinates `(x, y)` into Win32 normalized virtual desktop `[0..65535]`.
    fn map_to_win32_abs(&self, x: f64, y: f64) -> (i32, i32) {
        let cx = x.clamp(0.0, self.out_w.max(1) as f64);
        let cy = y.clamp(0.0, self.out_h.max(1) as f64);
        let px = self.src_rect.x as f64
            + cx * (self.src_rect.width as f64 / self.out_w.max(1) as f64);
        let py = self.src_rect.y as f64
            + cy * (self.src_rect.height as f64 / self.out_h.max(1) as f64);

        let vx = unsafe { GetSystemMetrics(SM_XVIRTUALSCREEN) } as f64;
        let vy = unsafe { GetSystemMetrics(SM_YVIRTUALSCREEN) } as f64;
        let vw = unsafe { GetSystemMetrics(SM_CXVIRTUALSCREEN) }.max(1) as f64;
        let vh = unsafe { GetSystemMetrics(SM_CYVIRTUALSCREEN) }.max(1) as f64;

        let nx = (((px - vx) * 65535.0) / vw).clamp(0.0, 65535.0).round() as i32;
        let ny = (((py - vy) * 65535.0) / vh).clamp(0.0, 65535.0).round() as i32;
        (nx, ny)
    }

    fn build_spec(&self, w: u32, h: u32) -> FfmpegPipelineSpec {
        let (input_args, video_filter_prefix) = match self.capture_source {
            WindowsCaptureSource::Ddagrab { output_idx } => (
                build_windows_ddagrab_input_args(output_idx, self.fps, self.show_cursor),
                Some("hwdownload,format=bgra".to_string()),
            ),
            WindowsCaptureSource::Gdigrab => (
                build_windows_gdigrab_input_args(self.src_rect, self.fps, self.show_cursor),
                None,
            ),
        };
        FfmpegPipelineSpec {
            ffmpeg_path: self.ffmpeg_path.clone(),
            input_args,
            video_filter_prefix,
            out_width: w,
            out_height: h,
            max_pixel_edge: self.max_pixel_edge,
            fps: self.fps,
            bitrate_mbps: self.bitrate_mbps,
            encoder: self.encoder.clone(),
            all_intra: self.all_intra,
        }
    }
}

impl CaptureHandle for WindowsCaptureHandle {
    fn display_id(&self) -> Option<u32> {
        (self.os_display_id != 0).then_some(self.os_display_id)
    }

    fn resize(&mut self, width: u32, height: u32) -> Result<()> {
        self.reconfigure(
            width,
            height,
            self.fps,
            self.bitrate_mbps,
            1,
            self.max_pixel_edge,
        )
    }

    fn set_paused(&mut self, paused: bool) -> Result<()> {
        if self.paused == paused {
            return Ok(());
        }
        self.paused = paused;
        if paused {
            if let Some(mut p) = self.proc.take() {
                p.stop();
            }
            info!("Windows capture paused (FFmpeg stopped)");
            Ok(())
        } else {
            let spec = self.build_spec(self.out_w, self.out_h);
            match FfmpegProcess::spawn(&spec, self.tx.clone()) {
                Ok(p) => {
                    self.proc = Some(p);
                    info!("Windows capture resumed (FFmpeg restarted)");
                    Ok(())
                }
                Err(e) => {
                    self.paused = true;
                    Err(e)
                }
            }
        }
    }

    fn set_show_cursor(&mut self, show_cursor: bool) -> Result<()> {
        if self.show_cursor == show_cursor && (self.paused || self.proc.is_some()) {
            return Ok(());
        }
        let prev = self.show_cursor;
        self.show_cursor = show_cursor;
        if self.paused {
            return Ok(());
        }
        if let Some(mut p) = self.proc.take() {
            p.stop();
        }
        let spec = self.build_spec(self.out_w, self.out_h);
        match FfmpegProcess::spawn(&spec, self.tx.clone()) {
            Ok(p) => {
                self.proc = Some(p);
                Ok(())
            }
            Err(e) => {
                self.show_cursor = prev;
                Err(e)
            }
        }
    }

    fn reconfigure(
        &mut self,
        width: u32,
        height: u32,
        fps: u32,
        bitrate_mbps: u32,
        _hidpi: u32,
        max_pixel_edge: u32,
    ) -> Result<()> {
        if max_pixel_edge >= 320 {
            self.max_pixel_edge = max_pixel_edge;
        }
        let (w, h) = clamp_pixel_dimensions(width, height, self.max_pixel_edge);
        self.out_w = w;
        self.out_h = h;
        if fps > 0 {
            self.fps = fps;
        }
        if bitrate_mbps > 0 {
            self.bitrate_mbps = bitrate_mbps;
        }
        if self.paused {
            return Ok(());
        }
        if let Some(mut p) = self.proc.take() {
            p.stop();
        }
        let spec = self.build_spec(w, h);
        self.proc = Some(FfmpegProcess::spawn(&spec, self.tx.clone())?);
        Ok(())
    }

    fn inject_input(&self, event: &InputEvent) -> Result<()> {
        let abs = MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK | MOUSEEVENTF_MOVE;
        match *event {
            InputEvent::MouseDown {
                x,
                y,
                right_click,
                ..
            } => {
                let (nx, ny) = self.map_to_win32_abs(x, y);
                if right_click {
                    send_mouse_input(nx, ny, abs | MOUSEEVENTF_RIGHTDOWN, 0);
                    send_mouse_input(nx, ny, abs | MOUSEEVENTF_RIGHTUP, 0);
                } else {
                    send_mouse_input(nx, ny, abs | MOUSEEVENTF_LEFTDOWN, 0);
                }
            }
            InputEvent::MouseDragged { x, y } => {
                let (nx, ny) = self.map_to_win32_abs(x, y);
                send_mouse_input(nx, ny, abs, 0);
            }
            InputEvent::MouseUp {
                x,
                y,
                double_click: _,
            } => {
                let (nx, ny) = self.map_to_win32_abs(x, y);
                send_mouse_input(nx, ny, abs | MOUSEEVENTF_LEFTUP, 0);
            }
            InputEvent::Scroll { dx, dy } => {
                if dy.is_finite() && dy != 0.0 {
                    let delta = (dy.clamp(-500.0, 500.0).round() as i32).saturating_mul(12);
                    send_mouse_input(0, 0, MOUSEEVENTF_WHEEL, delta as u32);
                }
                if dx.is_finite() && dx != 0.0 {
                    let delta = (dx.clamp(-500.0, 500.0).round() as i32).saturating_mul(12);
                    send_mouse_input(0, 0, MOUSEEVENTF_HWHEEL, delta as u32);
                }
            }
            InputEvent::KeySpecial { key_code } => {
                if let Some(vk) = map_special_key_to_vk(key_code) {
                    send_vk(vk);
                }
            }
            InputEvent::KeyUnicode { ch } => {
                send_unicode(ch);
            }
            InputEvent::KeyText { ref text } => {
                let mut units: Vec<u16> = text.encode_utf16().take(64).collect();
                if units.last().is_some_and(|&u| (0xD800..=0xDBFF).contains(&u)) {
                    units.pop();
                }
                for unit in units {
                    send_unicode(unit);
                }
            }
            InputEvent::KeyModified {
                key_code,
                ch,
                modifiers,
            } => {
                if let Some(vk) = key_code.and_then(map_special_key_to_vk) {
                    send_vk_with_mods(vk, modifiers);
                } else if let Some(u) = ch {
                    let ascii = (u as u8).to_ascii_uppercase();
                    if u == 0x20 {
                        send_vk_with_mods(VK_SPACE, modifiers);
                    } else if u < 0x80 && (ascii.is_ascii_uppercase() || ascii.is_ascii_digit()) {
                        send_vk_with_mods(ascii as u16, modifiers);
                    } else {
                        send_unicode(u);
                    }
                }
            }
        }
        Ok(())
    }

    fn query_cursor(&self) -> Option<CursorState> {
        let mut pt = POINT { x: 0, y: 0 };
        let ok = unsafe { GetCursorPos(&mut pt) };
        if ok == 0 {
            return None;
        }
        let inside = pt.x >= self.src_rect.x
            && pt.x < self.src_rect.x + self.src_rect.width as i32
            && pt.y >= self.src_rect.y
            && pt.y < self.src_rect.y + self.src_rect.height as i32;
        if inside {
            let lx = ((pt.x - self.src_rect.x) as f64 * self.out_w as f64
                / self.src_rect.width.max(1) as f64) as u32;
            let ly = ((pt.y - self.src_rect.y) as f64 * self.out_h as f64
                / self.src_rect.height.max(1) as f64) as u32;
            Some(CursorState {
                x: lx,
                y: ly,
                visible: true,
            })
        } else {
            Some(CursorState {
                x: 0,
                y: 0,
                visible: false,
            })
        }
    }

    fn stop(&mut self) {
        self.paused = true;
        if let Some(mut p) = self.proc.take() {
            p.stop();
        }
        self.tx.close();
    }
}

impl Drop for WindowsCaptureHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

fn query_process_app_names(pid: u32) -> (String, String) {
    let hproc = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if hproc.is_null() {
        return (String::new(), String::new());
    }
    let mut buf = [0u16; 512];
    let mut len = buf.len() as u32;
    let ok = unsafe { QueryFullProcessImageNameW(hproc, 0, buf.as_mut_ptr(), &mut len) };
    unsafe {
        CloseHandle(hproc);
    }
    if ok == 0 || len == 0 {
        return (String::new(), String::new());
    }
    let full = String::from_utf16_lossy(&buf[..len as usize]);
    let p = Path::new(&full);
    let exe_name = p
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_lowercase();
    let app_name = p
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(&exe_name)
        .to_string();
    (app_name, exe_name)
}

struct EnumWindowsCtx<'a> {
    shell_hwnd: HWND,
    monitors: &'a [WinMonitorInfo],
    main_display_id: u32,
    windows: Vec<DesktopWindowInfo>,
}

unsafe extern "system" fn enum_windows_cb(hwnd: HWND, lparam: LPARAM) -> BOOL {
    if lparam == 0 {
        return 1;
    }
    let ctx = &mut *(lparam as *mut EnumWindowsCtx<'_>);
    if hwnd == ctx.shell_hwnd || IsWindowVisible(hwnd) == 0 {
        return 1;
    }

    // Skip cloaked UWP / virtual-desktop background windows.
    let mut cloaked: u32 = 0;
    let hr = DwmGetWindowAttribute(
        hwnd,
        DWMWA_CLOAKED as u32,
        (&mut cloaked as *mut u32).cast::<c_void>(),
        size_of::<u32>() as u32,
    );
    if hr == 0 && cloaked != 0 {
        return 1;
    }

    let mut rect: RECT = zeroed();
    if GetWindowRect(hwnd, &mut rect) == 0 {
        return 1;
    }
    let w = rect.right - rect.left;
    let h = rect.bottom - rect.top;
    if w < 30 || h < 20 {
        return 1;
    }

    let mut title_buf = [0u16; 256];
    let title_len = GetWindowTextW(hwnd, title_buf.as_mut_ptr(), title_buf.len() as i32);
    let title = if title_len > 0 {
        String::from_utf16_lossy(&title_buf[..title_len as usize])
            .trim()
            .to_string()
    } else {
        String::new()
    };

    let ex_style = GetWindowLongW(hwnd, GWL_EXSTYLE) as u32;
    let is_topmost = (ex_style & WS_EX_TOPMOST) != 0;
    if title.is_empty() && !is_topmost {
        return 1;
    }

    let mut pid: u32 = 0;
    GetWindowThreadProcessId(hwnd, &mut pid);
    if pid == 0 {
        return 1;
    }

    let (app_name, bundle_id) = query_process_app_names(pid);
    if title.is_empty()
        && matches!(
            bundle_id.as_str(),
            "" | "textinputhost.exe"
                | "shellexperiencehost.exe"
                | "startmenuexperiencehost.exe"
                | "searchhost.exe"
                | "applicationframehost.exe"
                | "explorer.exe"
        )
    {
        return 1;
    }

    let hmon = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
    let cx = rect.left + w / 2;
    let cy = rect.top + h / 2;
    let display_id = ctx
        .monitors
        .iter()
        .find(|m| !m.hmon.is_null() && m.hmon == hmon)
        .or_else(|| {
            ctx.monitors.iter().find(|m| {
                cx >= m.rect.x
                    && cx < m.rect.x + m.rect.width as i32
                    && cy >= m.rect.y
                    && cy < m.rect.y + m.rect.height as i32
            })
        })
        .map(|m| m.display_id)
        .unwrap_or(ctx.main_display_id);

    // Win32 HWND handles are guaranteed to fit in 32 bits (WOW64 sign-extended on 64-bit).
    let window_id = hwnd as usize as u32;
    if window_id == 0 {
        return 1;
    }

    ctx.windows.push(DesktopWindowInfo {
        window_id,
        pid: pid as i32,
        app_name: if app_name.is_empty() {
            format!("PID {pid}")
        } else {
            app_name
        },
        bundle_id,
        title,
        x: rect.left,
        y: rect.top,
        width: w as u32,
        height: h as u32,
        layer: if is_topmost { 1 } else { 0 },
        is_floating: is_topmost,
        display_id,
    });
    1
}

fn read_windows_mem_bytes() -> u64 {
    unsafe {
        let mut st: MEMORYSTATUSEX = zeroed();
        st.dwLength = size_of::<MEMORYSTATUSEX>() as u32;
        if GlobalMemoryStatusEx(&mut st) != 0 {
            return st.ullTotalPhys;
        }
    }
    16 * 1024 * 1024 * 1024
}

impl DisplayBackend for WindowsBackend {
    fn supports_window_routing(&self) -> bool {
        true
    }

    fn capabilities(&self) -> crate::platform::PlatformCapabilities {
        crate::platform::PlatformCapabilities {
            hidpi: false,
            virtual_display: false,
            window_routing: true,
            screen_lock_detection: true,
            live_abr_quality: false,
            true_capture_pause: true,
            accessibility_permission_required: false,
            accessibility_granted: true,
        }
    }

    fn main_display_id(&self) -> u32 {
        enumerate_monitors()
            .into_iter()
            .find(|m| m.is_primary)
            .map(|m| m.display_id)
            .unwrap_or(1)
    }

    fn display_bounds(&self, display_id: u32) -> Option<(i32, i32, u32, u32)> {
        enumerate_monitors()
            .into_iter()
            .find(|m| m.display_id == display_id)
            .map(|m| (m.rect.x, m.rect.y, m.rect.width, m.rect.height))
    }

    fn list_additional_displays(&self) -> Vec<(u32, String, i32, i32, u32, u32)> {
        enumerate_monitors()
            .into_iter()
            .filter(|m| !m.is_primary)
            .map(|m| {
                (
                    m.display_id,
                    m.name,
                    m.rect.x,
                    m.rect.y,
                    m.rect.width,
                    m.rect.height,
                )
            })
            .collect()
    }

    fn list_desktop_windows(&self) -> Result<Vec<DesktopWindowInfo>> {
        let monitors = enumerate_monitors();
        let main_display_id = monitors
            .iter()
            .find(|m| m.is_primary)
            .map(|m| m.display_id)
            .unwrap_or(1);
        let mut ctx = EnumWindowsCtx {
            shell_hwnd: unsafe { GetShellWindow() },
            monitors: &monitors,
            main_display_id,
            windows: Vec::new(),
        };
        unsafe {
            EnumWindows(
                Some(enum_windows_cb),
                (&mut ctx as *mut EnumWindowsCtx<'_>) as LPARAM,
            );
        }
        Ok(ctx.windows)
    }

    fn move_desktop_window(
        &self,
        window_id: u32,
        pid: i32,
        target_display_id: u32,
        layout: WindowMoveLayout,
    ) -> Result<()> {
        let monitors = enumerate_monitors();
        let target = monitors
            .iter()
            .find(|m| m.display_id == target_display_id)
            .ok_or_else(|| anyhow!("未找到目标显示器 (display_id={target_display_id})"))?;

        let hwnd = window_id as usize as HWND;
        if hwnd.is_null() || unsafe { IsWindow(hwnd) } == 0 {
            return Err(anyhow!("目标窗口已关闭或无效 (window_id={window_id})"));
        }

        // Fail-closed PID verification to prevent moving a recycled HWND belonging to another process.
        let mut actual_pid: u32 = 0;
        unsafe {
            GetWindowThreadProcessId(hwnd, &mut actual_pid);
        }
        if pid > 0 && actual_pid as i32 != pid {
            return Err(anyhow!(
                "目标窗口所属进程已变更 (expected pid={pid}, actual={actual_pid})"
            ));
        }

        if unsafe { IsIconic(hwnd) != 0 || IsZoomed(hwnd) != 0 } {
            unsafe {
                ShowWindow(hwnd, SW_RESTORE);
            }
        }

        let mut cur_rect: RECT = unsafe { zeroed() };
        if unsafe { GetWindowRect(hwnd, &mut cur_rect) } == 0 {
            return Err(anyhow!("无法读取目标窗口坐标 (window_id={window_id})"));
        }
        let cur_w = cur_rect.right - cur_rect.left;
        let cur_h = cur_rect.bottom - cur_rect.top;
        let work = target.work_rect;
        let work_w = (work.right - work.left).max(320);
        let work_h = (work.bottom - work.top).max(240);

        let (nx, ny, nw, nh) =
            compute_window_move_rect(cur_w, cur_h, work.left, work.top, work_w, work_h, layout);
        let ok = unsafe {
            SetWindowPos(
                hwnd,
                std::ptr::null_mut(),
                nx,
                ny,
                nw,
                nh,
                SWP_NOZORDER | SWP_NOACTIVATE,
            )
        };
        if ok == 0 {
            return Err(anyhow!(
                "SetWindowPos 移动窗口失败（若目标应用以管理员权限运行，请以管理员身份运行 idis）"
            ));
        }
        debug!(
            "Moved Windows hwnd={window_id} (pid={actual_pid}) -> display {} ({nx},{ny} {nw}x{nh})",
            target.display_id
        );
        Ok(())
    }

    fn host_system_info(&self, override_host_name: &str) -> HostSystemInfo {
        let host_name = if override_host_name.is_empty() {
            std::env::var("COMPUTERNAME").unwrap_or_else(|_| "WindowsHost".to_string())
        } else {
            override_host_name.to_string()
        };
        let cpu_count = std::thread::available_parallelism()
            .map(|n| n.get() as u64)
            .unwrap_or(4);
        HostSystemInfo {
            user_name: std::env::var("USERNAME").unwrap_or_else(|_| "user".to_string()),
            host_name,
            os_version: "Windows".to_string(),
            physical_memory: read_windows_mem_bytes(),
            cpu_count,
        }
    }

    fn publish_bonjour(
        &self,
        service_name: &str,
        telemetry_port: u16,
        data_port: u16,
    ) -> Result<Box<dyn BonjourHandle>> {
        let host = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "WindowsHost".to_string());
        publish_mdns(service_name, &host, telemetry_port, data_port)
    }

    fn start_capture(
        &self,
        params: &CaptureParams,
    ) -> Result<(Box<dyn CaptureHandle>, FrameReceiver)> {
        let monitors = enumerate_monitors();
        let mon_idx = (params.display_id as usize).min(monitors.len().saturating_sub(1));
        let chosen_mon = &monitors[mon_idx];
        let src_rect = params.capture_rect.unwrap_or(chosen_mon.rect);
        let (out_w, out_h) =
            clamp_pixel_dimensions(params.width, params.height, params.max_pixel_edge);

        let capture_source = if params.capture_rect.is_some() {
            WindowsCaptureSource::Gdigrab
        } else if probe_ddagrab(&params.ffmpeg_path, mon_idx as u32) {
            WindowsCaptureSource::Ddagrab {
                output_idx: mon_idx as u32,
            }
        } else {
            info!(
                "Windows ddagrab unavailable for output_idx={}, falling back to gdigrab",
                mon_idx
            );
            WindowsCaptureSource::Gdigrab
        };

        let source_label = match capture_source {
            WindowsCaptureSource::Ddagrab { output_idx } => {
                format!("DXGI ddagrab (output_idx={output_idx})")
            }
            WindowsCaptureSource::Gdigrab => "GDI gdigrab".to_string(),
        };
        info!(
            "Windows capture source [{}]: monitor #{} (display_id={}) rect=({},{} {}x{}) -> output={}x{}",
            source_label,
            mon_idx,
            chosen_mon.display_id,
            src_rect.x,
            src_rect.y,
            src_rect.width,
            src_rect.height,
            out_w,
            out_h
        );

        let (tx, rx) = if params.all_intra {
            latest_frame_channel()
        } else {
            bounded_frame_channel(4)
        };
        let mut handle = WindowsCaptureHandle {
            os_display_id: chosen_mon.display_id,
            capture_source,
            src_rect,
            out_w,
            out_h,
            max_pixel_edge: params.max_pixel_edge,
            fps: params.fps,
            bitrate_mbps: params.bitrate_mbps,
            encoder: params.encoder.clone(),
            ffmpeg_path: params.ffmpeg_path.clone(),
            all_intra: params.all_intra,
            show_cursor: params.show_cursor,
            paused: false,
            tx: tx.clone(),
            proc: None,
        };
        let spec = handle.build_spec(out_w, out_h);
        handle.proc = Some(FfmpegProcess::spawn(&spec, tx)?);
        Ok((Box::new(handle), rx))
    }
}
