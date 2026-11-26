use crate::config::CaptureRect;
use crate::platform::ffmpeg_capture::{FfmpegPipelineSpec, FfmpegProcess};
use crate::platform::mdns::publish_mdns;
use crate::platform::{
    clamp_pixel_dimensions, latest_frame_channel, BonjourHandle, CaptureHandle, CaptureParams,
    CursorState, DisplayBackend, FrameReceiver, FrameSender, HostSystemInfo,
};
use crate::protocol::messages::InputEvent;
use anyhow::Result;
use std::mem::{size_of, zeroed};
use tracing::info;
use windows_sys::Win32::Foundation::{BOOL, LPARAM, POINT, RECT};
use windows_sys::Win32::Graphics::Gdi::{EnumDisplayMonitors, HDC, HMONITOR};
use windows_sys::Win32::System::SystemInformation::{
    GlobalMemoryStatusEx, MEMORYSTATUSEX,
};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT, KEYEVENTF_KEYUP,
    KEYEVENTF_UNICODE, MOUSEEVENTF_ABSOLUTE, MOUSEEVENTF_HWHEEL, MOUSEEVENTF_LEFTDOWN,
    MOUSEEVENTF_LEFTUP, MOUSEEVENTF_MOVE, MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP,
    MOUSEEVENTF_VIRTUALDESK, MOUSEEVENTF_WHEEL, MOUSEINPUT, VK_BACK, VK_DELETE, VK_ESCAPE,
    VK_RETURN, VK_TAB,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GetCursorPos, GetSystemMetrics, SM_CXSCREEN, SM_CXVIRTUALSCREEN, SM_CYSCREEN,
    SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN,
};

/// Native Windows backend:
/// - Pure-Rust `mdns-sd` Bonjour advertisement
/// - `ffmpeg` `gdigrab` -> Baseline CAVLC intra-only H.264 Annex-B (supports `libx264`, `h264_nvenc`, `h264_qsv`, `h264_amf`)
/// - Direct Win32 `SendInput`, `GetCursorPos`, `EnumDisplayMonitors` (supports multi-monitor & Virtual Display Driver)
pub struct WindowsBackend;

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

unsafe extern "system" fn enum_monitor_cb(
    _hmon: HMONITOR,
    _hdc: HDC,
    rect_ptr: *mut RECT,
    lparam: LPARAM,
) -> BOOL {
    if !rect_ptr.is_null() && lparam != 0 {
        let list = &mut *(lparam as *mut Vec<CaptureRect>);
        let r = *rect_ptr;
        let w = (r.right - r.left).max(320) as u32 & !1;
        let h = (r.bottom - r.top).max(240) as u32 & !1;
        list.push(CaptureRect {
            x: r.left,
            y: r.top,
            width: w,
            height: h,
        });
    }
    1
}

fn enumerate_monitors() -> Vec<CaptureRect> {
    let mut rects: Vec<CaptureRect> = Vec::new();
    unsafe {
        EnumDisplayMonitors(
            std::ptr::null_mut(),
            std::ptr::null(),
            Some(enum_monitor_cb),
            (&mut rects as *mut Vec<CaptureRect>) as LPARAM,
        );
    }
    if rects.is_empty() {
        let w = unsafe { GetSystemMetrics(SM_CXSCREEN) }.max(320) as u32 & !1;
        let h = unsafe { GetSystemMetrics(SM_CYSCREEN) }.max(240) as u32 & !1;
        rects.push(CaptureRect {
            x: 0,
            y: 0,
            width: w,
            height: h,
        });
    }
    rects
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

fn send_vk(vk: u16) {
    let inputs = [
        INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: vk,
                    wScan: 0,
                    dwFlags: 0,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        },
        INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: vk,
                    wScan: 0,
                    dwFlags: KEYEVENTF_KEYUP,
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
    tx: FrameSender,
    proc: Option<FfmpegProcess>,
}

impl WindowsCaptureHandle {
    /// Convert local iPad display coordinates `(x, y)` into Win32 normalized virtual desktop `[0..65535]`.
    fn map_to_win32_abs(&self, x: f64, y: f64) -> (i32, i32) {
        let cx = x.clamp(0.0, self.out_w.max(1) as f64);
        let cy = y.clamp(0.0, self.out_h.max(1) as f64);
        let px = self.src_rect.x as f64 + cx * (self.src_rect.width as f64 / self.out_w.max(1) as f64);
        let py = self.src_rect.y as f64 + cy * (self.src_rect.height as f64 / self.out_h.max(1) as f64);

        let vx = unsafe { GetSystemMetrics(SM_XVIRTUALSCREEN) } as f64;
        let vy = unsafe { GetSystemMetrics(SM_YVIRTUALSCREEN) } as f64;
        let vw = unsafe { GetSystemMetrics(SM_CXVIRTUALSCREEN) }.max(1) as f64;
        let vh = unsafe { GetSystemMetrics(SM_CYVIRTUALSCREEN) }.max(1) as f64;

        let nx = (((px - vx) * 65535.0) / vw).clamp(0.0, 65535.0).round() as i32;
        let ny = (((py - vy) * 65535.0) / vh).clamp(0.0, 65535.0).round() as i32;
        (nx, ny)
    }

    fn build_spec(&self, w: u32, h: u32) -> FfmpegPipelineSpec {
        FfmpegPipelineSpec {
            ffmpeg_path: self.ffmpeg_path.clone(),
            input_args: vec![
                "-f".to_string(),
                "gdigrab".to_string(),
                "-draw_mouse".to_string(),
                if self.show_cursor { "1" } else { "0" }.to_string(),
                "-framerate".to_string(),
                self.fps.max(1).to_string(),
                "-offset_x".to_string(),
                self.src_rect.x.to_string(),
                "-offset_y".to_string(),
                self.src_rect.y.to_string(),
                "-video_size".to_string(),
                format!("{}x{}", self.src_rect.width, self.src_rect.height),
                "-i".to_string(),
                "desktop".to_string(),
            ],
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
    fn resize(&mut self, width: u32, height: u32) -> Result<()> {
        self.reconfigure(width, height, self.fps, self.bitrate_mbps, 1, self.max_pixel_edge)
    }

    fn set_show_cursor(&mut self, show_cursor: bool) -> Result<()> {
        if self.show_cursor == show_cursor && self.proc.is_some() {
            return Ok(());
        }
        let prev = self.show_cursor;
        self.show_cursor = show_cursor;
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
            InputEvent::MouseDown { x, y, right_click, .. } => {
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
            InputEvent::MouseUp { x, y, double_click: _ } => {
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
            InputEvent::KeySpecial { key_code } => match key_code {
                0x33 => send_vk(VK_BACK),
                0x24 => send_vk(VK_RETURN),
                0x30 => send_vk(VK_TAB),
                0x35 => send_vk(VK_ESCAPE),
                0x75 => send_vk(VK_DELETE),
                _ => {}
            },
            InputEvent::KeyUnicode { ch } => {
                send_unicode(ch);
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
    fn capabilities(&self) -> crate::platform::PlatformCapabilities {
        crate::platform::PlatformCapabilities {
            hidpi: false,
            virtual_display: false,
            window_routing: false,
            screen_lock_detection: true,
            live_abr_quality: false,
            true_capture_pause: false,
            accessibility_permission_required: false,
            accessibility_granted: true,
        }
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
        let src_rect = params.capture_rect.unwrap_or_else(|| {
            monitors
                .get(params.display_id as usize)
                .copied()
                .unwrap_or(monitors[0])
        });
        let (out_w, out_h) = clamp_pixel_dimensions(params.width, params.height, params.max_pixel_edge);
        info!(
            "Windows GDI capture source: monitor #{} rect=({},{} {}x{}) -> output={}x{}",
            params.display_id,
            src_rect.x,
            src_rect.y,
            src_rect.width,
            src_rect.height,
            out_w,
            out_h
        );

        let (tx, rx) = latest_frame_channel();
        let mut handle = WindowsCaptureHandle {
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
            tx: tx.clone(),
            proc: None,
        };
        let spec = handle.build_spec(out_w, out_h);
        handle.proc = Some(FfmpegProcess::spawn(&spec, tx)?);
        Ok((Box::new(handle), rx))
    }
}
