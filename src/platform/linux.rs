use crate::config::CaptureRect;
use crate::platform::ffmpeg_capture::{FfmpegPipelineSpec, FfmpegProcess};
use crate::platform::mdns::publish_mdns;
use crate::platform::{
    bounded_frame_channel, clamp_pixel_dimensions, latest_frame_channel, BonjourHandle,
    CaptureHandle, CaptureParams,
    CursorState, DisplayBackend, FrameReceiver, FrameSender, HostSystemInfo,
};
use crate::protocol::messages::{
    InputEvent, KEY_MOD_ALT, KEY_MOD_CTRL, KEY_MOD_META, KEY_MOD_SHIFT,
};
use anyhow::Result;
use std::fs;
use std::sync::Mutex;
use tracing::{info, warn};
use x11rb::connection::Connection;
use x11rb::protocol::randr::ConnectionExt as RandrExt;
use x11rb::protocol::xproto::{ConnectionExt as XprotoExt, Window};
use x11rb::protocol::xtest::ConnectionExt as XtestExt;
use x11rb::rust_connection::RustConnection;

/// Native Linux backend:
/// - Pure-Rust `mdns-sd` Bonjour advertisement
/// - `ffmpeg` `x11grab` -> Baseline CAVLC intra-only H.264 Annex-B
/// - Pure-Rust `x11rb` (RandR + XTEST) for monitor geometry, cursor query, and touch/mouse/keyboard injection
fn map_special_key_to_x11_keysym(key_code: u16) -> Option<u32> {
    match key_code {
        0x33 => Some(0xFF08), // XK_BackSpace
        0x24 => Some(0xFF0D), // XK_Return
        0x30 => Some(0xFF09), // XK_Tab
        0x35 => Some(0xFF1B), // XK_Escape
        0x75 => Some(0xFFFF), // XK_Delete
        0x7E => Some(0xFF52), // XK_Up
        0x7D => Some(0xFF54), // XK_Down
        0x7B => Some(0xFF51), // XK_Left
        0x7C => Some(0xFF53), // XK_Right
        0x73 => Some(0xFF50), // XK_Home
        0x77 => Some(0xFF57), // XK_End
        0x74 => Some(0xFF55), // XK_Page_Up
        0x79 => Some(0xFF56), // XK_Page_Down
        _ => None,
    }
}

pub struct LinuxBackend;

impl LinuxBackend {
    pub fn new() -> Self {
        Self
    }
}

impl Default for LinuxBackend {
    fn default() -> Self {
        Self::new()
    }
}

struct X11Handle {
    conn: RustConnection,
    root: Window,
    key_min: u8,
    keysyms_per_keycode: u8,
    keysyms: Vec<u32>,
}

impl X11Handle {
    fn connect() -> Option<Self> {
        let (conn, screen_num) = RustConnection::connect(None).ok()?;
        let setup = conn.setup();
        let root = setup.roots.get(screen_num)?.root;
        let key_min = setup.min_keycode;
        let key_max = setup.max_keycode;
        let count = key_max.saturating_sub(key_min).saturating_add(1);
        let (keysyms_per_keycode, keysyms) = conn
            .get_keyboard_mapping(key_min, count)
            .ok()
            .and_then(|c| c.reply().ok())
            .map(|r| (r.keysyms_per_keycode, r.keysyms))
            .unwrap_or((0, Vec::new()));
        Some(Self {
            conn,
            root,
            key_min,
            keysyms_per_keycode,
            keysyms,
        })
    }

    fn resolve_monitor_rect(&self, display_id: u32) -> CaptureRect {
        if let Ok(cookie) = self.conn.randr_get_monitors(self.root, true) {
            if let Ok(reply) = cookie.reply() {
                let idx = display_id as usize;
                let chosen = reply
                    .monitors
                    .get(idx)
                    .or_else(|| reply.monitors.first());
                if let Some(m) = chosen {
                    return CaptureRect {
                        x: m.x as i32,
                        y: m.y as i32,
                        width: (m.width as u32 & !1).max(320),
                        height: (m.height as u32 & !1).max(240),
                    };
                }
            }
        }
        let s = &self.conn.setup().roots[0];
        CaptureRect {
            x: 0,
            y: 0,
            width: (s.width_in_pixels as u32 & !1).max(320),
            height: (s.height_in_pixels as u32 & !1).max(240),
        }
    }

    fn find_keycode_for_keysym(&self, target_sym: u32) -> Option<(u8, bool)> {
        if self.keysyms_per_keycode == 0 {
            return None;
        }
        let stride = self.keysyms_per_keycode as usize;
        for (i, chunk) in self.keysyms.chunks(stride).enumerate() {
            if chunk.first().copied() == Some(target_sym) {
                return Some((self.key_min.saturating_add(i as u8), false));
            }
            if chunk.get(1).copied() == Some(target_sym) {
                return Some((self.key_min.saturating_add(i as u8), true));
            }
        }
        None
    }

    fn move_pointer(&self, abs_x: i16, abs_y: i16) {
        let _ = self
            .conn
            .xtest_fake_input(6 /* MotionNotify */, 0, 0, self.root, abs_x, abs_y, 0);
        let _ = self.conn.flush();
    }

    fn button(&self, btn: u8, press: bool) {
        let ev_type = if press { 4 /* ButtonPress */ } else { 5 /* ButtonRelease */ };
        let _ = self.conn.xtest_fake_input(ev_type, btn, 0, self.root, 0, 0, 0);
        let _ = self.conn.flush();
    }

    fn tap_key_with_mods(&self, keycode: u8, shift: bool, modifiers: u8) {
        let mut mod_kcs: Vec<u8> = Vec::with_capacity(4);
        if (modifiers & KEY_MOD_CTRL) != 0 {
            if let Some((kc, _)) = self.find_keycode_for_keysym(0xFFE3 /* XK_Control_L */) {
                mod_kcs.push(kc);
            }
        }
        if (modifiers & KEY_MOD_ALT) != 0 {
            if let Some((kc, _)) = self.find_keycode_for_keysym(0xFFE9 /* XK_Alt_L */) {
                mod_kcs.push(kc);
            }
        }
        if (modifiers & KEY_MOD_META) != 0 {
            if let Some((kc, _)) = self.find_keycode_for_keysym(0xFFEB /* XK_Super_L */) {
                mod_kcs.push(kc);
            }
        }
        if shift || (modifiers & KEY_MOD_SHIFT) != 0 {
            if let Some((kc, _)) = self.find_keycode_for_keysym(0xFFE1 /* XK_Shift_L */) {
                mod_kcs.push(kc);
            }
        }
        for &mk in &mod_kcs {
            let _ = self.conn.xtest_fake_input(2 /* KeyPress */, mk, 0, self.root, 0, 0, 0);
        }
        let _ = self.conn.xtest_fake_input(2, keycode, 0, self.root, 0, 0, 0);
        let _ = self.conn.xtest_fake_input(3 /* KeyRelease */, keycode, 0, self.root, 0, 0, 0);
        for &mk in mod_kcs.iter().rev() {
            let _ = self.conn.xtest_fake_input(3, mk, 0, self.root, 0, 0, 0);
        }
        let _ = self.conn.flush();
    }

    fn tap_key(&self, keycode: u8, shift: bool) {
        self.tap_key_with_mods(keycode, shift, 0);
    }

    fn query_cursor(&self, rect: CaptureRect, out_w: u32, out_h: u32) -> Option<CursorState> {
        let rep = self.conn.query_pointer(self.root).ok()?.reply().ok()?;
        let rx = rep.root_x as i32;
        let ry = rep.root_y as i32;
        let inside = rx >= rect.x
            && rx < rect.x + rect.width as i32
            && ry >= rect.y
            && ry < rect.y + rect.height as i32;
        if inside {
            let lx = ((rx - rect.x) as f64 * out_w as f64 / rect.width.max(1) as f64) as u32;
            let ly = ((ry - rect.y) as f64 * out_h as f64 / rect.height.max(1) as f64) as u32;
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
}

struct LinuxCaptureHandle {
    x11: Option<Mutex<X11Handle>>,
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
    display_env: String,
    tx: FrameSender,
    proc: Option<FfmpegProcess>,
}

impl LinuxCaptureHandle {
    fn map_point(&self, x: f64, y: f64) -> (i16, i16) {
        let cx = x.clamp(0.0, self.out_w.max(1) as f64);
        let cy = y.clamp(0.0, self.out_h.max(1) as f64);
        let sx = self.src_rect.x as f64 + cx * (self.src_rect.width as f64 / self.out_w.max(1) as f64);
        let sy = self.src_rect.y as f64 + cy * (self.src_rect.height as f64 / self.out_h.max(1) as f64);
        let min_x = self.src_rect.x as f64;
        let max_x = (self.src_rect.x + self.src_rect.width.saturating_sub(1) as i32) as f64;
        let min_y = self.src_rect.y as f64;
        let max_y = (self.src_rect.y + self.src_rect.height.saturating_sub(1) as i32) as f64;
        (
            sx.clamp(min_x, max_x).round().clamp(i16::MIN as f64, i16::MAX as f64) as i16,
            sy.clamp(min_y, max_y).round().clamp(i16::MIN as f64, i16::MAX as f64) as i16,
        )
    }

    fn build_spec(&self, w: u32, h: u32) -> FfmpegPipelineSpec {
        let input = format!("{}+{},{}", self.display_env, self.src_rect.x, self.src_rect.y);
        FfmpegPipelineSpec {
            ffmpeg_path: self.ffmpeg_path.clone(),
            input_args: vec![
                "-f".to_string(),
                "x11grab".to_string(),
                "-draw_mouse".to_string(),
                if self.show_cursor { "1" } else { "0" }.to_string(),
                "-framerate".to_string(),
                self.fps.max(1).to_string(),
                "-video_size".to_string(),
                format!("{}x{}", self.src_rect.width, self.src_rect.height),
                "-i".to_string(),
                input,
            ],
            video_filter_prefix: None,
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

impl CaptureHandle for LinuxCaptureHandle {
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
        let Some(ref x11_mtx) = self.x11 else {
            return Ok(());
        };
        let Ok(x11) = x11_mtx.lock() else {
            return Ok(());
        };
        match *event {
            InputEvent::MouseDown { x, y, right_click, .. } => {
                let (ax, ay) = self.map_point(x, y);
                x11.move_pointer(ax, ay);
                if right_click {
                    x11.button(3, true);
                    x11.button(3, false);
                } else {
                    x11.button(1, true);
                }
            }
            InputEvent::MouseDragged { x, y } => {
                let (ax, ay) = self.map_point(x, y);
                x11.move_pointer(ax, ay);
            }
            InputEvent::MouseUp { x, y, double_click: _ } => {
                let (ax, ay) = self.map_point(x, y);
                x11.move_pointer(ax, ay);
                x11.button(1, false);
            }
            InputEvent::Scroll { dx, dy } => {
                if dy > 0.0 {
                    x11.button(4, true);
                    x11.button(4, false);
                } else if dy < 0.0 {
                    x11.button(5, true);
                    x11.button(5, false);
                }
                if dx > 0.0 {
                    x11.button(6, true);
                    x11.button(6, false);
                } else if dx < 0.0 {
                    x11.button(7, true);
                    x11.button(7, false);
                }
            }
            InputEvent::KeySpecial { key_code } => {
                let Some(sym) = map_special_key_to_x11_keysym(key_code) else {
                    return Ok(());
                };
                if let Some((kc, sh)) = x11.find_keycode_for_keysym(sym) {
                    x11.tap_key(kc, sh);
                }
            }
            InputEvent::KeyUnicode { ch } => {
                let sym = if ch < 0x100 {
                    ch as u32
                } else {
                    0x0100_0000 | (ch as u32)
                };
                if let Some((kc, sh)) = x11.find_keycode_for_keysym(sym) {
                    x11.tap_key(kc, sh);
                }
            }
            InputEvent::KeyText { ref text } => {
                for ch in text.chars().take(64) {
                    let cp = ch as u32;
                    let sym = if cp < 0x100 { cp } else { 0x0100_0000 | cp };
                    if let Some((kc, sh)) = x11.find_keycode_for_keysym(sym) {
                        x11.tap_key(kc, sh);
                    }
                }
            }
            InputEvent::KeyModified {
                key_code,
                ch,
                modifiers,
            } => {
                let sym = key_code.and_then(map_special_key_to_x11_keysym).or_else(|| {
                    ch.map(|c| {
                        let low = if c < 0x80 {
                            (c as u8).to_ascii_lowercase() as u32
                        } else {
                            c as u32
                        };
                        if low < 0x100 { low } else { 0x0100_0000 | low }
                    })
                });
                if let Some(sym) = sym {
                    if let Some((kc, sh)) = x11.find_keycode_for_keysym(sym) {
                        x11.tap_key_with_mods(kc, sh, modifiers);
                    }
                }
            }
        }
        Ok(())
    }

    fn query_cursor(&self) -> Option<CursorState> {
        let x11 = self.x11.as_ref()?.lock().ok()?;
        x11.query_cursor(self.src_rect, self.out_w, self.out_h)
    }

    fn save_screenshot_png(&self, dest: &std::path::Path) -> Result<()> {
        let input = format!("{}+{},{}", self.display_env, self.src_rect.x, self.src_rect.y);
        let status = std::process::Command::new(&self.ffmpeg_path)
            .args([
                "-y",
                "-loglevel",
                "error",
                "-f",
                "x11grab",
                "-video_size",
                &format!("{}x{}", self.src_rect.width, self.src_rect.height),
                "-i",
                &input,
                "-frames:v",
                "1",
            ])
            .arg(dest)
            .status()?;
        if !status.success() {
            return Err(anyhow::anyhow!("ffmpeg x11grab 截屏失败: {status}"));
        }
        Ok(())
    }

    fn stop(&mut self) {
        if let Some(mut p) = self.proc.take() {
            p.stop();
        }
        self.tx.close();
    }
}

impl Drop for LinuxCaptureHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

fn read_linux_hostname() -> String {
    fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "LinuxHost".to_string())
}

fn read_linux_os_version() -> String {
    if let Ok(text) = fs::read_to_string("/etc/os-release") {
        for line in text.lines() {
            if let Some(val) = line.strip_prefix("PRETTY_NAME=") {
                return val.trim_matches('"').to_string();
            }
        }
    }
    "Linux".to_string()
}

fn read_linux_mem_bytes() -> u64 {
    if let Ok(text) = fs::read_to_string("/proc/meminfo") {
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("MemTotal:") {
                if let Some(kb_str) = rest.split_whitespace().next() {
                    if let Ok(kb) = kb_str.parse::<u64>() {
                        return kb * 1024;
                    }
                }
            }
        }
    }
    8 * 1024 * 1024 * 1024
}

impl DisplayBackend for LinuxBackend {
    fn capabilities(&self) -> crate::platform::PlatformCapabilities {
        crate::platform::PlatformCapabilities {
            hidpi: false,
            virtual_display: false,
            window_routing: false,
            screen_lock_detection: false,
            live_abr_quality: false,
            true_capture_pause: false,
            accessibility_permission_required: false,
            accessibility_granted: true,
            screen_recording_permission_required: false,
            screen_recording_granted: true,
        }
    }

    fn lock_host_screen(&self) -> Result<()> {
        if let Ok(st) = std::process::Command::new("loginctl")
            .arg("lock-session")
            .status()
        {
            if st.success() {
                return Ok(());
            }
        }
        if let Ok(st) = std::process::Command::new("xdg-screensaver")
            .arg("lock")
            .status()
        {
            if st.success() {
                return Ok(());
            }
        }
        Err(anyhow::anyhow!(
            "Linux 锁屏失败（未检测到可用的 loginctl 或 xdg-screensaver）"
        ))
    }

    fn host_system_info(&self, override_host_name: &str) -> HostSystemInfo {
        let host_name = if override_host_name.is_empty() {
            read_linux_hostname()
        } else {
            override_host_name.to_string()
        };
        let cpu_count = std::thread::available_parallelism()
            .map(|n| n.get() as u64)
            .unwrap_or(4);
        HostSystemInfo {
            user_name: std::env::var("USER").unwrap_or_else(|_| "user".to_string()),
            host_name,
            os_version: read_linux_os_version(),
            physical_memory: read_linux_mem_bytes(),
            cpu_count,
        }
    }

    fn publish_bonjour(
        &self,
        service_name: &str,
        telemetry_port: u16,
        data_port: u16,
    ) -> Result<Box<dyn BonjourHandle>> {
        let host = read_linux_hostname();
        publish_mdns(service_name, &host, telemetry_port, data_port)
    }

    fn start_capture(
        &self,
        params: &CaptureParams,
    ) -> Result<(Box<dyn CaptureHandle>, FrameReceiver)> {
        let x11 = X11Handle::connect();
        let src_rect = if let Some(r) = params.capture_rect {
            r
        } else if let Some(ref x) = x11 {
            x.resolve_monitor_rect(params.display_id)
        } else {
            warn!("X11 connection unavailable (Wayland without XWayland?); defaulting to 1920x1080 capture");
            CaptureRect {
                x: 0,
                y: 0,
                width: 1920,
                height: 1080,
            }
        };

        let (out_w, out_h) = clamp_pixel_dimensions(params.width, params.height, params.max_pixel_edge);
        let display_env = std::env::var("DISPLAY").unwrap_or_else(|_| ":0".to_string());
        info!(
            "Linux X11 capture source: DISPLAY={display_env} rect=({},{} {}x{}) -> output={}x{}",
            src_rect.x, src_rect.y, src_rect.width, src_rect.height, out_w, out_h
        );

        let (tx, rx) = if params.all_intra {
            latest_frame_channel()
        } else {
            bounded_frame_channel(4)
        };
        let mut handle = LinuxCaptureHandle {
            x11: x11.map(Mutex::new),
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
            display_env,
            tx: tx.clone(),
            proc: None,
        };
        let spec = handle.build_spec(out_w, out_h);
        handle.proc = Some(FfmpegProcess::spawn(&spec, tx)?);
        Ok((Box::new(handle), rx))
    }
}
