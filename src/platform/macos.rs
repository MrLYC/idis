use crate::config::CaptureMode;
use crate::platform::{
    bounded_frame_channel, latest_frame_channel, BonjourHandle, CaptureHandle, CaptureParams,
    CursorState,
    DesktopWindowInfo, DisplayBackend, EncodedFrame, FrameReceiver, FrameSender, HostSystemInfo,
    StandaloneVirtualDisplayHandle, WindowMoveLayout,
};
use crate::protocol::messages::InputEvent;
use anyhow::{anyhow, Result};
use std::ffi::{c_char, c_void, CStr, CString};

type FrameCallback = extern "C" fn(
    ctx: *mut c_void,
    width: u32,
    height: u32,
    bytes_per_row: u32,
    is_keyframe: i32,
    data: *const u8,
    len: usize,
);

type DiagCallback = extern "C" fn(event: *const c_char, detail: *const c_char);

extern "C" fn diag_trampoline(event: *const c_char, detail: *const c_char) {
    if event.is_null() {
        return;
    }
    let ev = unsafe { CStr::from_ptr(event) }.to_string_lossy();
    let msg = if detail.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(detail) }
            .to_string_lossy()
            .into_owned()
    };
    tracing::debug!("[macos] {ev}: {msg}");
    crate::debug_trace::record("macos", &ev, serde_json::json!({ "detail": msg }));
}

/// Enable native macOS Objective-C bridge diagnostics into `debug_trace` when `--debug` is active.
pub fn enable_native_diagnostics() {
    unsafe {
        id_macos_set_diag_callback(Some(diag_trampoline));
    }
}

#[repr(C)]
struct CHostInfo {
    user_name: [c_char; 128],
    host_name: [c_char; 256],
    os_version: [c_char; 256],
    physical_memory: u64,
    cpu_count: u64,
}

extern "C" {
    fn id_macos_set_diag_callback(cb: Option<DiagCallback>);
    fn id_macos_get_host_info(out: *mut CHostInfo);

    fn id_macos_bonjour_start(
        service_name: *const c_char,
        telemetry_port: u16,
        data_port: u16,
    ) -> *mut c_void;
    fn id_macos_bonjour_stop(handle: *mut c_void);

    fn id_macos_capture_start(
        use_virtual_display: i32,
        display_id: u32,
        width: u32,
        height: u32,
        hidpi: u32,
        max_pixel_edge: u32,
        fps: u32,
        bitrate_mbps: u32,
        show_cursor: i32,
        all_intra: i32,
        display_serial: u32,
        display_name: *const c_char,
        cb: FrameCallback,
        ctx: *mut c_void,
    ) -> *mut c_void;
    fn id_macos_capture_resize(handle: *mut c_void, width: u32, height: u32) -> i32;
    fn id_macos_capture_reconfigure(
        handle: *mut c_void,
        width: u32,
        height: u32,
        fps: u32,
        bitrate_mbps: u32,
        hidpi: u32,
        max_pixel_edge: u32,
    ) -> i32;
    fn id_macos_capture_update_stream_quality(
        handle: *mut c_void,
        fps: u32,
        bitrate_mbps: u32,
        max_pixel_edge: u32,
    ) -> i32;
    fn id_macos_capture_request_keyframe(handle: *mut c_void);
    fn id_macos_capture_set_paused(handle: *mut c_void, paused: i32) -> i32;
    fn id_macos_capture_set_low_power(handle: *mut c_void, enabled: i32) -> i32;
    fn id_macos_capture_set_show_cursor(handle: *mut c_void, show_cursor: i32) -> i32;
    fn id_macos_capture_stop(handle: *mut c_void);
    fn id_macos_capture_size(handle: *mut c_void, out_w: *mut u32, out_h: *mut u32);

    fn id_macos_inject_mouse(
        handle: *mut c_void,
        video_w: u32,
        video_h: u32,
        kind: i32,
        x: f64,
        y: f64,
    );
    fn id_macos_inject_scroll(handle: *mut c_void, dx: f64, dy: f64);
    fn id_macos_inject_key_code(key_code: u16);
    fn id_macos_inject_key_code_mods(key_code: u16, mods: u8);
    fn id_macos_inject_unicode(ch: u16);
    fn id_macos_inject_unicode_mods(ch: u16, mods: u8);
    fn id_macos_inject_text(units: *const u16, len: usize);
    fn id_macos_is_accessibility_trusted() -> i32;
    fn id_macos_is_screen_capture_granted() -> i32;
    fn id_macos_probe_screen_capture_permission() -> i32;
    fn id_macos_request_permission(kind: i32) -> i32;
    fn id_macos_is_screen_locked() -> i32;
    fn id_macos_lock_screen() -> i32;
    fn id_macos_pump_main_runloop();
    fn id_macos_resolve_iface_ip(
        iface_name: *const c_char,
        out_addr: *mut u8,
        out_is_v6: *mut i32,
    ) -> i32;
    fn id_macos_query_cursor(
        handle: *mut c_void,
        video_w: u32,
        video_h: u32,
        out_x: *mut u32,
        out_y: *mut u32,
        out_visible: *mut i32,
    ) -> i32;
    fn id_macos_cursor_png(
        handle: *mut c_void,
        video_w: u32,
        video_h: u32,
        out_ptr: *mut *mut u8,
        out_len: *mut usize,
    ) -> i32;
    fn id_macos_cursor_png_if_changed(
        handle: *mut c_void,
        video_w: u32,
        video_h: u32,
        in_out_hash: *mut u64,
        out_ptr: *mut *mut u8,
        out_len: *mut usize,
    ) -> i32;
    fn id_macos_capture_screenshot_png(
        handle: *mut c_void,
        out_ptr: *mut *mut u8,
        out_len: *mut usize,
    ) -> i32;
    fn id_macos_free_bytes(ptr: *mut u8);
    fn id_macos_helper_set_display_mode(
        display_id: u32,
        logical_w: u32,
        logical_h: u32,
        pixel_w: u32,
        pixel_h: u32,
    ) -> i32;
    fn id_macos_capture_display_id(handle: *mut c_void) -> u32;
    fn id_macos_capture_display_bounds(
        handle: *mut c_void,
        out_x: *mut i32,
        out_y: *mut i32,
        out_w: *mut u32,
        out_h: *mut u32,
    ) -> i32;
    fn id_macos_main_display_id() -> u32;
    fn id_macos_display_bounds(
        display_id: u32,
        out_x: *mut i32,
        out_y: *mut i32,
        out_w: *mut u32,
        out_h: *mut u32,
    ) -> i32;
    fn id_macos_virtual_display_create(
        name: *const c_char,
        width: u32,
        height: u32,
        serial_num: u32,
    ) -> *mut c_void;
    fn id_macos_virtual_display_id(handle: *mut c_void) -> u32;
    fn id_macos_virtual_display_destroy(handle: *mut c_void);
    fn id_macos_list_windows_json(out_ptr: *mut *mut u8, out_len: *mut usize) -> i32;
    fn id_macos_move_window(
        window_id: u32,
        pid: i32,
        target_display_id: u32,
        fill_screen: i32,
        err_buf: *mut c_char,
        err_cap: usize,
    ) -> i32;
}

/// Internal subprocess entrypoint invoked by `macos/bridge.m` to set a virtual display's exact
/// HiDPI mode from a fresh process (bypassing CoreGraphics's creator-process mode cache quirk).
pub fn run_set_display_mode_helper(
    display_id: u32,
    logical_w: u32,
    logical_h: u32,
    pixel_w: u32,
    pixel_h: u32,
) -> i32 {
    unsafe { id_macos_helper_set_display_mode(display_id, logical_w, logical_h, pixel_w, pixel_h) }
}

/// Returns `true` if macOS Accessibility permission (`AXIsProcessTrusted`) is granted for this process.
/// Without Accessibility permission, `CGEventPost` silently drops all injected mouse & keyboard events.
pub fn is_accessibility_trusted() -> bool {
    unsafe { id_macos_is_accessibility_trusted() != 0 }
}

/// Returns `true` while the macOS console session is locked (`CGSSessionScreenIsLocked`).
pub fn is_screen_locked() -> bool {
    unsafe { id_macos_is_screen_locked() != 0 }
}

/// Non-blocking pump of the macOS main `CFRunLoop` so CoreGraphics refreshes its cached
/// display bounds & display modes across virtual display reconnects/recreates.
pub fn pump_main_runloop() {
    unsafe { id_macos_pump_main_runloop() };
}

/// Resolve a macOS network interface name (e.g. `lo0`, `en0`, `utun4`) to its IP address via `getifaddrs`.
pub fn resolve_interface_ip_native(iface: &str) -> Option<std::net::IpAddr> {
    let c_name = CString::new(iface).ok()?;
    let mut buf = [0u8; 16];
    let mut is_v6 = 0i32;
    let ok = unsafe { id_macos_resolve_iface_ip(c_name.as_ptr(), buf.as_mut_ptr(), &mut is_v6) };
    if ok == 0 {
        return None;
    }
    if is_v6 != 0 {
        Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(buf)))
    } else {
        Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            buf[0], buf[1], buf[2], buf[3],
        )))
    }
}

extern "C" fn frame_trampoline(
    ctx: *mut c_void,
    width: u32,
    height: u32,
    bytes_per_row: u32,
    is_keyframe: i32,
    data: *const u8,
    len: usize,
) {
    if ctx.is_null() || data.is_null() || len == 0 {
        return;
    }
    let tx = unsafe { &*(ctx as *const FrameSender) };
    let slice = unsafe { std::slice::from_raw_parts(data, len) };
    let _ = tx.send_latest(EncodedFrame {
        width,
        height,
        bytes_per_row,
        annex_b: slice.to_vec(),
        is_keyframe: is_keyframe != 0,
    });
}

fn cbuf_to_string(buf: &[c_char]) -> String {
    unsafe { CStr::from_ptr(buf.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

pub struct MacOsBackend;

impl MacOsBackend {
    pub fn new() -> Self {
        // Run one non-blocking ScreenCaptureKit permission probe at startup so Web Admin
        // immediately knows whether Screen Recording permission is granted without any
        // `CGPreflightScreenCaptureAccess()` false-negatives.
        std::thread::spawn(|| {
            let granted = unsafe { id_macos_probe_screen_capture_permission() } != 0;
            if !granted {
                tracing::warn!(
                    "macOS Screen Recording permission is NOT granted — open System Settings -> Privacy & Security -> Screen Recording, enable your Terminal app or `idis` (after upgrading, toggle off & on), then restart `idis`."
                );
            }
        });
        Self
    }
}

impl Default for MacOsBackend {
    fn default() -> Self {
        Self::new()
    }
}

struct MacBonjourHandle {
    ptr: *mut c_void,
}

unsafe impl Send for MacBonjourHandle {}

impl BonjourHandle for MacBonjourHandle {
    fn stop(&mut self) {
        if !self.ptr.is_null() {
            unsafe { id_macos_bonjour_stop(self.ptr) };
            self.ptr = std::ptr::null_mut();
        }
    }
}

impl Drop for MacBonjourHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

struct MacCaptureHandle {
    ptr: *mut c_void,
    tx_box: *mut FrameSender,
}

unsafe impl Send for MacCaptureHandle {}

struct MacStandaloneVirtualDisplay {
    ptr: *mut c_void,
    display_id: u32,
}

unsafe impl Send for MacStandaloneVirtualDisplay {}

impl StandaloneVirtualDisplayHandle for MacStandaloneVirtualDisplay {
    fn display_id(&self) -> u32 {
        self.display_id
    }

    fn stop(&mut self) {
        if !self.ptr.is_null() {
            unsafe { id_macos_virtual_display_destroy(self.ptr) };
            self.ptr = std::ptr::null_mut();
        }
    }
}

impl Drop for MacStandaloneVirtualDisplay {
    fn drop(&mut self) {
        self.stop();
    }
}

impl CaptureHandle for MacCaptureHandle {
    fn display_id(&self) -> Option<u32> {
        if self.ptr.is_null() {
            return None;
        }
        let id = unsafe { id_macos_capture_display_id(self.ptr) };
        if id != 0 {
            Some(id)
        } else {
            None
        }
    }

    fn display_bounds(&self) -> Option<(i32, i32, u32, u32)> {
        if self.ptr.is_null() {
            return None;
        }
        let (mut x, mut y, mut w, mut h) = (0i32, 0i32, 0u32, 0u32);
        let ok = unsafe { id_macos_capture_display_bounds(self.ptr, &mut x, &mut y, &mut w, &mut h) };
        (ok != 0 && w > 0 && h > 0).then_some((x, y, w, h))
    }

    fn resize(&mut self, width: u32, height: u32) -> Result<()> {
        if self.ptr.is_null() {
            return Err(anyhow!("capture handle already stopped"));
        }
        let rc = unsafe { id_macos_capture_resize(self.ptr, width, height) };
        if rc != 0 {
            return Err(anyhow!("failed to resize macOS virtual display/encoder"));
        }
        Ok(())
    }

    fn reconfigure(
        &mut self,
        width: u32,
        height: u32,
        fps: u32,
        bitrate_mbps: u32,
        hidpi: u32,
        max_pixel_edge: u32,
    ) -> Result<()> {
        if self.ptr.is_null() {
            return Err(anyhow!("capture handle already stopped"));
        }
        let rc = unsafe {
            id_macos_capture_reconfigure(
                self.ptr,
                width,
                height,
                fps,
                bitrate_mbps,
                hidpi,
                max_pixel_edge,
            )
        };
        if rc != 0 {
            return Err(anyhow!(
                "failed to reconfigure macOS virtual display/encoder"
            ));
        }
        Ok(())
    }

    fn update_stream_quality(
        &mut self,
        fps: u32,
        bitrate_mbps: u32,
        max_pixel_edge: u32,
    ) -> Result<()> {
        if self.ptr.is_null() {
            return Err(anyhow!("capture handle already stopped"));
        }
        let rc = unsafe {
            id_macos_capture_update_stream_quality(self.ptr, fps, bitrate_mbps, max_pixel_edge)
        };
        if rc != 0 {
            return Err(anyhow!(
                "failed to update macOS stream quality (fps={fps}, bitrate={bitrate_mbps}Mbps, max_edge={max_pixel_edge})"
            ));
        }
        Ok(())
    }

    fn request_keyframe(&self) {
        if !self.ptr.is_null() {
            unsafe { id_macos_capture_request_keyframe(self.ptr) };
        }
    }

    fn set_paused(&mut self, paused: bool) -> Result<()> {
        if self.ptr.is_null() {
            return Ok(());
        }
        let rc = unsafe { id_macos_capture_set_paused(self.ptr, if paused { 1 } else { 0 }) };
        if rc != 0 {
            return Err(anyhow!("failed to set macOS capture paused={paused}"));
        }
        Ok(())
    }

    fn set_low_power(&mut self, enabled: bool) -> Result<()> {
        if self.ptr.is_null() {
            return Ok(());
        }
        let rc = unsafe { id_macos_capture_set_low_power(self.ptr, if enabled { 1 } else { 0 }) };
        if rc != 0 {
            return Err(anyhow!("failed to set macOS capture low_power={enabled}"));
        }
        Ok(())
    }

    fn set_show_cursor(&mut self, show_cursor: bool) -> Result<()> {
        if self.ptr.is_null() {
            return Ok(());
        }
        let rc = unsafe {
            id_macos_capture_set_show_cursor(self.ptr, if show_cursor { 1 } else { 0 })
        };
        if rc != 0 {
            return Err(anyhow!("failed to set macOS capture show_cursor={show_cursor}"));
        }
        Ok(())
    }

    fn inject_input(&self, event: &InputEvent) -> Result<()> {
        if self.ptr.is_null() {
            return Ok(());
        }
        static WARNED_NO_AX: std::sync::atomic::AtomicBool =
            std::sync::atomic::AtomicBool::new(false);
        if !is_accessibility_trusted() {
            if !WARNED_NO_AX.swap(true, std::sync::atomic::Ordering::AcqRel) {
                tracing::warn!(
                    "macOS Accessibility permission is NOT granted — CGEventPost mouse/keyboard input from iPad is silently ignored by macOS! Grant permission in: System Settings -> Privacy & Security -> Accessibility (add your Terminal app / idis)."
                );
            }
            return Ok(());
        }
        let (mut vw, mut vh) = (0u32, 0u32);
        unsafe { id_macos_capture_size(self.ptr, &mut vw, &mut vh) };
        match *event {
            InputEvent::MouseDown {
                x,
                y,
                right_click,
                tap_count,
            } => {
                let kind = if right_click {
                    4
                } else if tap_count >= 2 {
                    5
                } else {
                    0
                };
                unsafe { id_macos_inject_mouse(self.ptr, vw, vh, kind, x, y) };
            }
            InputEvent::MouseDragged { x, y } => {
                unsafe { id_macos_inject_mouse(self.ptr, vw, vh, 1, x, y) };
            }
            InputEvent::MouseUp { x, y, double_click } => {
                let kind = if double_click { 3 } else { 2 };
                unsafe { id_macos_inject_mouse(self.ptr, vw, vh, kind, x, y) };
            }
            InputEvent::KeySpecial { key_code } => {
                unsafe { id_macos_inject_key_code(key_code) };
            }
            InputEvent::KeyUnicode { ch } => {
                unsafe { id_macos_inject_unicode(ch) };
            }
            InputEvent::KeyText { ref text } => {
                let mut units: Vec<u16> = text.encode_utf16().take(64).collect();
                if units.last().is_some_and(|&u| (0xD800..=0xDBFF).contains(&u)) {
                    units.pop();
                }
                if !units.is_empty() {
                    unsafe { id_macos_inject_text(units.as_ptr(), units.len()) };
                }
            }
            InputEvent::KeyModified {
                key_code,
                ch,
                modifiers,
            } => {
                if let Some(kc) = key_code {
                    unsafe { id_macos_inject_key_code_mods(kc, modifiers) };
                } else if let Some(u) = ch {
                    unsafe { id_macos_inject_unicode_mods(u, modifiers) };
                }
            }
            InputEvent::Scroll { dx, dy } => {
                unsafe { id_macos_inject_scroll(self.ptr, dx, dy) };
            }
        }
        Ok(())
    }

    fn query_cursor(&self) -> Option<CursorState> {
        if self.ptr.is_null() {
            return None;
        }
        let (mut vw, mut vh) = (0u32, 0u32);
        unsafe { id_macos_capture_size(self.ptr, &mut vw, &mut vh) };
        let mut x = 0u32;
        let mut y = 0u32;
        let mut vis = 0i32;
        let ok = unsafe { id_macos_query_cursor(self.ptr, vw, vh, &mut x, &mut y, &mut vis) };
        if ok != 0 {
            Some(CursorState {
                x,
                y,
                visible: vis != 0,
            })
        } else {
            None
        }
    }

    fn cursor_image_png(&self) -> Option<Vec<u8>> {
        if self.ptr.is_null() {
            return None;
        }
        let (mut vw, mut vh) = (0u32, 0u32);
        unsafe { id_macos_capture_size(self.ptr, &mut vw, &mut vh) };
        let mut ptr: *mut u8 = std::ptr::null_mut();
        let mut len: usize = 0;
        let ok = unsafe { id_macos_cursor_png(self.ptr, vw, vh, &mut ptr, &mut len) };
        if ok != 0 && !ptr.is_null() && len > 0 {
            let bytes = unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec();
            unsafe { id_macos_free_bytes(ptr) };
            Some(bytes)
        } else {
            None
        }
    }

    fn save_screenshot_png(&self, dest: &std::path::Path) -> Result<()> {
        if self.ptr.is_null() {
            return Err(anyhow!("macOS capture handle is closed"));
        }
        let mut ptr: *mut u8 = std::ptr::null_mut();
        let mut len: usize = 0;
        let ok = unsafe { id_macos_capture_screenshot_png(self.ptr, &mut ptr, &mut len) };
        if ok != 0 && !ptr.is_null() && len > 0 {
            let bytes = unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec();
            unsafe { id_macos_free_bytes(ptr) };
            std::fs::write(dest, &bytes)?;
            return Ok(());
        }
        // Fallback when lastPixelBuffer is empty (e.g. stream currently paused): capture target
        // display bounds silently via macOS built-in `screencapture`.
        let did = unsafe { id_macos_capture_display_id(self.ptr) };
        let target_did = if did != 0 {
            did
        } else {
            unsafe { id_macos_main_display_id() }
        };
        let (mut x, mut y, mut w, mut h) = (0i32, 0i32, 0u32, 0u32);
        let has_bounds =
            unsafe { id_macos_display_bounds(target_did, &mut x, &mut y, &mut w, &mut h) } != 0
                && w > 0
                && h > 0;
        let mut cmd = std::process::Command::new("/usr/sbin/screencapture");
        cmd.arg("-x").arg("-t").arg("png");
        if has_bounds {
            cmd.arg("-R").arg(format!("{x},{y},{w},{h}"));
        }
        cmd.arg(dest);
        let status = cmd.status()?;
        if !status.success() {
            return Err(anyhow!("screencapture 退出状态异常: {status}"));
        }
        Ok(())
    }

    fn cursor_image_png_if_changed(&self, last_hash: &mut u64) -> Option<Vec<u8>> {
        if self.ptr.is_null() {
            return None;
        }
        let (mut vw, mut vh) = (0u32, 0u32);
        unsafe { id_macos_capture_size(self.ptr, &mut vw, &mut vh) };
        let mut ptr: *mut u8 = std::ptr::null_mut();
        let mut len: usize = 0;
        let rc = unsafe {
            id_macos_cursor_png_if_changed(self.ptr, vw, vh, last_hash, &mut ptr, &mut len)
        };
        if rc == 1 && !ptr.is_null() && len > 0 {
            let bytes = unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec();
            unsafe { id_macos_free_bytes(ptr) };
            Some(bytes)
        } else {
            None
        }
    }

    fn stop(&mut self) {
        // Wake any blocked FrameReceiver immediately so stream_thread exits in parallel with SCStream stop.
        if !self.tx_box.is_null() {
            unsafe { (*self.tx_box).close() };
        }
        if !self.ptr.is_null() {
            unsafe { id_macos_capture_stop(self.ptr) };
            self.ptr = std::ptr::null_mut();
        }
        if !self.tx_box.is_null() {
            unsafe { drop(Box::from_raw(self.tx_box)) };
            self.tx_box = std::ptr::null_mut();
        }
    }
}

impl Drop for MacCaptureHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

impl DisplayBackend for MacOsBackend {
    fn supports_hidpi(&self) -> bool {
        true
    }

    fn supports_virtual_display(&self) -> bool {
        true
    }

    fn supports_window_routing(&self) -> bool {
        true
    }

    fn main_display_id(&self) -> u32 {
        unsafe { id_macos_main_display_id() }
    }

    fn display_bounds(&self, display_id: u32) -> Option<(i32, i32, u32, u32)> {
        let (mut x, mut y, mut w, mut h) = (0i32, 0i32, 0u32, 0u32);
        let ok = unsafe { id_macos_display_bounds(display_id, &mut x, &mut y, &mut w, &mut h) };
        if ok != 0 {
            Some((x, y, w, h))
        } else {
            None
        }
    }

    fn create_standalone_virtual_display(
        &self,
        name: &str,
        width: u32,
        height: u32,
        serial_num: u32,
    ) -> Result<Box<dyn StandaloneVirtualDisplayHandle>> {
        let c_name = CString::new(name)?;
        let ptr = unsafe {
            id_macos_virtual_display_create(c_name.as_ptr(), width, height, serial_num)
        };
        if ptr.is_null() {
            return Err(anyhow!(
                "创建 macOS 独立虚拟屏失败（请确认系统版本支持 CGVirtualDisplay）"
            ));
        }
        let display_id = unsafe { id_macos_virtual_display_id(ptr) };
        Ok(Box::new(MacStandaloneVirtualDisplay { ptr, display_id }))
    }

    fn list_desktop_windows(&self) -> Result<Vec<DesktopWindowInfo>> {
        let mut ptr: *mut u8 = std::ptr::null_mut();
        let mut len: usize = 0;
        let ok = unsafe { id_macos_list_windows_json(&mut ptr, &mut len) };
        if ok == 0 || ptr.is_null() || len == 0 {
            if !ptr.is_null() {
                unsafe { id_macos_free_bytes(ptr) };
            }
            return Ok(Vec::new());
        }
        let bytes = unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec();
        unsafe { id_macos_free_bytes(ptr) };
        let windows: Vec<DesktopWindowInfo> = serde_json::from_slice(&bytes)
            .map_err(|e| anyhow!("解析 macOS 窗口列表失败: {e}"))?;
        Ok(windows)
    }

    fn move_desktop_window(
        &self,
        window_id: u32,
        pid: i32,
        target_display_id: u32,
        layout: WindowMoveLayout,
    ) -> Result<()> {
        let mut err_buf = [0 as c_char; 512];
        let fill = if layout == WindowMoveLayout::FillScreen {
            1
        } else {
            0
        };
        let rc = unsafe {
            id_macos_move_window(
                window_id,
                pid,
                target_display_id,
                fill,
                err_buf.as_mut_ptr(),
                err_buf.len(),
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            let msg = cbuf_to_string(&err_buf);
            if msg.is_empty() {
                Err(anyhow!("移动窗口 {window_id} 失败（code={rc}）"))
            } else {
                Err(anyhow!("{msg}"))
            }
        }
    }

    fn capabilities(&self) -> crate::platform::PlatformCapabilities {
        crate::platform::PlatformCapabilities {
            hidpi: true,
            virtual_display: true,
            window_routing: true,
            screen_lock_detection: true,
            live_abr_quality: true,
            true_capture_pause: true,
            accessibility_permission_required: true,
            accessibility_granted: is_accessibility_trusted(),
            screen_recording_permission_required: true,
            screen_recording_granted: unsafe { id_macos_is_screen_capture_granted() } != 0,
        }
    }

    fn request_permission(&self, kind: &str) -> Result<String> {
        match kind {
            "screen_recording" => {
                let granted = unsafe { id_macos_request_permission(0) } != 0;
                if granted {
                    Ok("屏幕录制权限已授权，可直接连接使用。".to_string())
                } else {
                    Ok("已在主机上打开「系统设置 → 隐私与安全性 → 屏幕录制」。请勾选当前终端或 idis（升级版本后请先关闭再重新打开），然后重启 idis。".to_string())
                }
            }
            "accessibility" => {
                let granted = unsafe { id_macos_request_permission(1) } != 0;
                if granted {
                    Ok("辅助功能权限已授权，远程键鼠与触控已可用。".to_string())
                } else {
                    Ok("已在主机上打开「系统设置 → 隐私与安全性 → 辅助功能」。请勾选当前终端或 idis 后点击重新检测。".to_string())
                }
            }
            other => Err(anyhow!("未知权限类型: {other}")),
        }
    }

    fn recheck_permissions(&self) {
        let _ = unsafe { id_macos_probe_screen_capture_permission() };
    }

    fn lock_host_screen(&self) -> Result<()> {
        if unsafe { id_macos_lock_screen() } != 0 {
            return Ok(());
        }
        let status = std::process::Command::new("/usr/bin/pmset")
            .arg("displaysleepnow")
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(anyhow!("macOS 锁屏命令退出异常: {status}"))
        }
    }

    fn host_system_info(&self, override_host_name: &str) -> HostSystemInfo {
        let mut info = CHostInfo {
            user_name: [0; 128],
            host_name: [0; 256],
            os_version: [0; 256],
            physical_memory: 0,
            cpu_count: 1,
        };
        unsafe { id_macos_get_host_info(&mut info) };
        let mut host_name = cbuf_to_string(&info.host_name);
        if !override_host_name.is_empty() {
            host_name = override_host_name.to_string();
        }
        HostSystemInfo {
            user_name: cbuf_to_string(&info.user_name),
            host_name,
            os_version: cbuf_to_string(&info.os_version),
            physical_memory: info.physical_memory,
            cpu_count: info.cpu_count,
        }
    }

    fn publish_bonjour(
        &self,
        service_name: &str,
        telemetry_port: u16,
        data_port: u16,
    ) -> Result<Box<dyn BonjourHandle>> {
        let c_name = CString::new(service_name)?;
        let ptr = unsafe { id_macos_bonjour_start(c_name.as_ptr(), telemetry_port, data_port) };
        if ptr.is_null() {
            return Err(anyhow!("failed to start macOS NSNetService Bonjour publisher"));
        }
        Ok(Box::new(MacBonjourHandle { ptr }))
    }

    fn start_capture(
        &self,
        params: &CaptureParams,
    ) -> Result<(Box<dyn CaptureHandle>, FrameReceiver)> {
        let (tx, rx) = if params.all_intra {
            latest_frame_channel()
        } else {
            bounded_frame_channel(4)
        };
        let tx_box = Box::into_raw(Box::new(tx));
        let c_name = CString::new(format!("idis ({})", params.client_name))?;
        let use_virtual = if params.mode == CaptureMode::Extend { 1 } else { 0 };
        let ptr = unsafe {
            id_macos_capture_start(
                use_virtual,
                params.display_id,
                params.width,
                params.height,
                params.hidpi,
                params.max_pixel_edge,
                params.fps,
                params.bitrate_mbps,
                if params.show_cursor { 1 } else { 0 },
                if params.all_intra { 1 } else { 0 },
                params.display_serial,
                c_name.as_ptr(),
                frame_trampoline,
                tx_box as *mut c_void,
            )
        };
        if ptr.is_null() {
            unsafe { drop(Box::from_raw(tx_box)) };
            let screen_ok = unsafe { id_macos_is_screen_capture_granted() } != 0;
            if !screen_ok {
                return Err(anyhow!(
                    "macOS 拒绝了屏幕录制权限：请前往「系统设置 → 隐私与安全性 → 屏幕录制」勾选当前终端或 idis（升级版本后请先关闭再重新打开），然后重启 idis。（Screen Recording permission denied）"
                ));
            }
            return Err(anyhow!(
                "启动 macOS 屏幕采集失败（虚拟屏或 ScreenCaptureKit 尚未就绪，请稍后重试或重新连接）"
            ));
        }
        Ok((Box::new(MacCaptureHandle { ptr, tx_box }), rx))
    }
}
