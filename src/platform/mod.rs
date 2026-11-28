use crate::config::{CaptureMode, CaptureRect};
use crate::protocol::messages::InputEvent;
use anyhow::Result;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

#[cfg(any(target_os = "linux", target_os = "windows"))]
pub mod ffmpeg_capture;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(not(target_os = "macos"))]
pub mod mdns;
pub mod mock;
#[cfg(target_os = "windows")]
pub mod windows;

/// Maximum encoded long-edge pixel dimension supported by legacy iPad Air (A7 / iOS 12).
pub const IPAD_MAX_PIXEL_EDGE: u32 = 2048;
/// Maximum encoded long-edge pixel dimension for standalone Web viewers.
pub const WEB_MAX_PIXEL_EDGE: u32 = 3840;

/// An encoded H.264 Annex-B video frame ready to be packetized for legacy iDisplay.
#[derive(Debug, Clone)]
pub struct EncodedFrame {
    pub width: u32,
    pub height: u32,
    pub bytes_per_row: u32,
    pub annex_b: Vec<u8>,
    /// True when this frame is a self-contained IDR keyframe (with SPS+PPS).
    pub is_keyframe: bool,
}

/// Error returned by [`FrameReceiver::recv_timeout`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvFrameError {
    Timeout,
    Disconnected,
}

struct FrameSlotInner {
    queue: VecDeque<(u64, u64, Arc<EncodedFrame>)>,
    capacity: usize,
    closed: bool,
    woken: bool,
    overwritten: u64,
}

struct FrameSlot {
    state: Mutex<FrameSlotInner>,
    cvar: Condvar,
    senders: AtomicUsize,
}

/// Latest-frame overwrite sender: pushing a new frame always replaces any unread older frame
/// instead of tail-dropping the newest frame. This guarantees that idle sharpening refine IDRs
/// are never discarded behind an older blurry motion frame.
pub struct FrameSender {
    slot: Arc<FrameSlot>,
}

impl FrameSender {
    /// Store `frame` as the latest available frame, overwriting any unread older frame.
    /// Returns `false` if the receiver has been disconnected/closed.
    pub fn send_latest(&self, frame: EncodedFrame) -> bool {
        self.send_latest_shared(0, Arc::new(frame))
    }

    /// Zero-copy broadcast variant: store an `Arc<EncodedFrame>` paired with a monotonic sequence
    /// number so N subscribers share a single buffer without cloning H.264 bytes.
    pub fn send_latest_shared(&self, seq: u64, frame: Arc<EncodedFrame>) -> bool {
        self.send_latest_shared_tagged(seq, 0, frame)
    }

    /// Zero-copy broadcast variant with an explicit producer `tag` (e.g. `web_source_epoch`) so
    /// downstream WebSocket streams deterministically drop stale pre-switch / old-owner frames.
    pub fn send_latest_shared_tagged(&self, seq: u64, tag: u64, frame: Arc<EncodedFrame>) -> bool {
        let Ok(mut guard) = self.slot.state.lock() else {
            return false;
        };
        if guard.closed {
            return false;
        }
        if guard.capacity <= 1 {
            if !guard.queue.is_empty() {
                guard.overwritten = guard.overwritten.saturating_add(guard.queue.len() as u64);
                guard.queue.clear();
            }
            guard.queue.push_back((seq, tag, frame));
        } else {
            if guard.queue.len() >= guard.capacity {
                if frame.is_keyframe {
                    // Self-contained IDR supersedes queued stale frames cleanly when full.
                    let dropped = guard.queue.len() as u64;
                    guard.overwritten = guard.overwritten.saturating_add(dropped);
                    guard.queue.clear();
                } else {
                    guard.queue.pop_front();
                    guard.overwritten = guard.overwritten.saturating_add(1);
                }
            }
            guard.queue.push_back((seq, tag, frame));
        }
        self.slot.cvar.notify_one();
        true
    }

    /// Explicitly close the channel so waiting receivers wake immediately with `Disconnected`.
    pub fn close(&self) {
        if let Ok(mut guard) = self.slot.state.lock() {
            guard.closed = true;
            self.slot.cvar.notify_all();
        }
    }
}

impl Clone for FrameSender {
    fn clone(&self) -> Self {
        self.slot.senders.fetch_add(1, Ordering::AcqRel);
        Self {
            slot: self.slot.clone(),
        }
    }
}

impl Drop for FrameSender {
    fn drop(&mut self) {
        if self.slot.senders.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.close();
        }
    }
}

/// Cloneable wakeup handle paired with a [`FrameReceiver`] so external events (e.g. ACK arrival)
/// can wake a waiting streaming thread immediately with zero lost wakeups.
#[derive(Clone)]
pub struct FrameWaker {
    slot: Arc<FrameSlot>,
}

impl FrameWaker {
    pub fn wake(&self) {
        if let Ok(mut guard) = self.slot.state.lock() {
            guard.woken = true;
            self.slot.cvar.notify_all();
        }
    }
}

/// Receiver paired with [`FrameSender`]; always yields the newest available frame.
pub struct FrameReceiver {
    slot: Arc<FrameSlot>,
}

impl FrameReceiver {
    pub fn waker(&self) -> FrameWaker {
        FrameWaker {
            slot: self.slot.clone(),
        }
    }

    /// Drain and return how many unread frames were overwritten by newer frames since the last call.
    pub fn take_overwritten(&self) -> u64 {
        self.slot
            .state
            .lock()
            .map(|mut g| std::mem::take(&mut g.overwritten))
            .unwrap_or(0)
    }

    pub fn recv_timeout(&self, timeout: Duration) -> std::result::Result<EncodedFrame, RecvFrameError> {
        self.recv_timeout_shared(timeout)
            .map(|(_, frame, _)| Arc::unwrap_or_clone(frame))
    }

    /// Zero-copy receive returning `(seq, Arc<EncodedFrame>, overwritten_since_last_take)` atomically
    /// under the same lock, eliminating any TOCTOU drop-counting window for IPPP DPB gating.
    pub fn recv_timeout_shared(
        &self,
        timeout: Duration,
    ) -> std::result::Result<(u64, Arc<EncodedFrame>, u64), RecvFrameError> {
        self.recv_timeout_shared_tagged(timeout)
            .map(|(seq, _tag, frame, ov)| (seq, frame, ov))
    }

    /// Tagged zero-copy receive returning `(seq, tag, Arc<EncodedFrame>, overwritten_since_last_take)`.
    pub fn recv_timeout_shared_tagged(
        &self,
        timeout: Duration,
    ) -> std::result::Result<(u64, u64, Arc<EncodedFrame>, u64), RecvFrameError> {
        let Ok(guard) = self.slot.state.lock() else {
            return Err(RecvFrameError::Disconnected);
        };
        // Use `wait_timeout_while` so OS spurious Condvar wakeups (especially on Windows
        // `SleepConditionVariableSRW`) never return `RecvFrameError::Timeout` prematurely.
        let Ok((mut g, _)) = self.slot.cvar.wait_timeout_while(guard, timeout, |s| {
            s.queue.is_empty() && !s.closed && !s.woken
        }) else {
            return Err(RecvFrameError::Disconnected);
        };
        if let Some((seq, tag, frame)) = g.queue.pop_front() {
            let ov = std::mem::take(&mut g.overwritten);
            g.woken = false;
            return Ok((seq, tag, frame, ov));
        }
        g.woken = false;
        if g.closed {
            Err(RecvFrameError::Disconnected)
        } else {
            Err(RecvFrameError::Timeout)
        }
    }

    pub fn try_recv(&self) -> std::result::Result<EncodedFrame, RecvFrameError> {
        let Ok(mut guard) = self.slot.state.lock() else {
            return Err(RecvFrameError::Disconnected);
        };
        if let Some((_, _, frame)) = guard.queue.pop_front() {
            return Ok(Arc::unwrap_or_clone(frame));
        }
        if guard.closed {
            Err(RecvFrameError::Disconnected)
        } else {
            Err(RecvFrameError::Timeout)
        }
    }
}

impl Drop for FrameReceiver {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.slot.state.lock() {
            guard.closed = true;
            guard.queue.clear();
            self.slot.cvar.notify_all();
        }
    }
}

/// Create a bounded consecutive FIFO frame channel (`capacity >= 1`).
///
/// - `capacity == 1` behaves as a latest-frame overwrite slot (`--all-intra` / Web fan-out).
/// - `capacity > 1` (e.g. `6` for IPPP temporal streams) buffers brief TCP/Wi-Fi send micro-stalls
///   in strict decode order without overwriting P-frames or triggering 200-400ms IDR resync freezes.
pub fn bounded_frame_channel(capacity: usize) -> (FrameSender, FrameReceiver) {
    let cap = capacity.max(1);
    let slot = Arc::new(FrameSlot {
        state: Mutex::new(FrameSlotInner {
            queue: VecDeque::with_capacity(cap),
            capacity: cap,
            closed: false,
            woken: false,
            overwritten: 0,
        }),
        cvar: Condvar::new(),
        senders: AtomicUsize::new(1),
    });
    (
        FrameSender { slot: slot.clone() },
        FrameReceiver { slot },
    )
}

/// Create a latest-frame-overwrite channel pair (capacity = 1).
pub fn latest_frame_channel() -> (FrameSender, FrameReceiver) {
    bounded_frame_channel(1)
}

fn round_even(v: u64) -> u32 {
    (v.div_ceil(2) * 2) as u32
}

fn scale_even_rounded(num: u32, mul: u32, div: u32) -> u32 {
    let d = (div as u64).max(1);
    let rounded = ((num as u64) * (mul as u64) + d / 2) / d;
    round_even(rounded)
}

/// Clamp `(width, height)` proportionally so the long edge does not exceed `max_edge`,
/// keeping both dimensions even (rounded to nearest even to preserve aspect ratio) and at least `320x240`.
pub fn clamp_pixel_dimensions(width: u32, height: u32, max_edge: u32) -> (u32, u32) {
    let mut w = (width & !1).max(320);
    let mut h = (height & !1).max(240);
    let cap = (max_edge & !1).max(320);
    if w > cap {
        h = scale_even_rounded(h, cap, w).min(cap);
        w = cap;
    }
    if h > cap {
        w = scale_even_rounded(w, cap, h).min(cap);
        h = cap;
    }
    ((w & !1).max(320), (h & !1).max(240))
}

/// Compute a 1:1 integer-scaled logical resolution `(logical_w, logical_h)` such that
/// `logical_w * scale <= max_pixel_edge` and `logical_h * scale <= max_pixel_edge`,
/// ensuring zero fractional downscaling between virtual display rendering and H.264 encoding.
///
/// - When `override_logical` is `None` (auto mode): divides the device's physical panel resolution
///   `(phys_w, phys_h)` (clamped to `max_pixel_edge`) cleanly by `scale`:
///   - iPad `2048x1536` @ `2x` => `1024x768` (backing `2048x1536` == stream `2048x1536`, 1:1)
///   - iPad `2048x1536` @ `1x` => `2048x1536` (backing `2048x1536` == stream `2048x1536`, 1:1)
/// - When `override_logical` is `Some((ow, oh))`: preserves aspect ratio and snaps down only if
///   `max(ow, oh) * scale > max_pixel_edge`, guaranteeing exact integer pixel alignment.
pub fn compute_integer_scaled_logical(
    phys_w: u32,
    phys_h: u32,
    override_logical: Option<(u32, u32)>,
    hidpi: u32,
    max_pixel_edge: u32,
) -> (u32, u32) {
    let scale = if hidpi >= 2 { 2 } else { 1 };
    let cap = (max_pixel_edge & !1).max(640);
    let max_logical = (cap / scale) & !1;
    let (lw, lh) = match override_logical {
        None => {
            let (cw, ch) = clamp_pixel_dimensions(phys_w, phys_h, cap);
            (
                scale_even_rounded(cw, 1, scale).min(max_logical),
                scale_even_rounded(ch, 1, scale).min(max_logical),
            )
        }
        Some((ow, oh)) => {
            let mut w = (ow & !1).max(320);
            let mut h = (oh & !1).max(240);
            if w > max_logical {
                h = scale_even_rounded(h, max_logical, w).min(max_logical);
                w = max_logical;
            }
            if h > max_logical {
                w = scale_even_rounded(w, max_logical, h).min(max_logical);
                h = max_logical;
            }
            (w & !1, h & !1)
        }
    };
    (lw.max(320), lh.max(240))
}

/// Cursor position relative to the streamed display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CursorState {
    pub x: u32,
    pub y: u32,
    pub visible: bool,
}

/// System metadata returned in `AccessConfirmed.serverInfo`.
#[derive(Debug, Clone)]
pub struct HostSystemInfo {
    pub user_name: String,
    pub host_name: String,
    pub os_version: String,
    pub physical_memory: u64,
    pub cpu_count: u64,
}

/// Parameters for starting display capture and H.264 encoding.
#[derive(Debug, Clone)]
pub struct CaptureParams {
    pub mode: CaptureMode,
    pub display_id: u32,
    pub capture_rect: Option<CaptureRect>,
    pub width: u32,
    pub height: u32,
    pub hidpi: u32,
    pub max_pixel_edge: u32,
    pub fps: u32,
    pub bitrate_mbps: u32,
    pub encoder: String,
    pub ffmpeg_path: String,
    pub show_cursor: bool,
    pub client_name: String,
    /// Stable non-zero virtual display serial number so macOS WindowServer remembers
    /// display arrangement, scaling, and window positions across reconnects.
    pub display_serial: u32,
    /// When `true`, force every frame to be an IDR keyframe; when `false` (default), use IPPP
    /// temporal compression with on-demand keyframes (cuts bandwidth/power 60-80%).
    pub all_intra: bool,
}

/// How a window should be sized when routed to a target screen.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WindowMoveLayout {
    /// Keep the window's original dimensions (clamping only if larger than the target display).
    #[default]
    KeepSize,
    /// Resize the window to fill the target display's visible bounds.
    FillScreen,
}

/// Compute destination `(x, y, width, height)` when moving a window into a target monitor work area.
/// - `FillScreen`: fills the entire work area.
/// - `KeepSize`: preserves the window's dimensions (clamped to the target work area) and centers it.
pub fn compute_window_move_rect(
    cur_w: i32,
    cur_h: i32,
    work_x: i32,
    work_y: i32,
    work_w: i32,
    work_h: i32,
    layout: WindowMoveLayout,
) -> (i32, i32, i32, i32) {
    let tw = work_w.max(320);
    let th = work_h.max(240);
    match layout {
        WindowMoveLayout::FillScreen => (work_x, work_y, tw, th),
        WindowMoveLayout::KeepSize => {
            let nw = cur_w.max(120).min(tw);
            let nh = cur_h.max(80).min(th);
            let nx = work_x + (tw - nw) / 2;
            let ny = work_y + (th - nh) / 2;
            (nx, ny, nw, nh)
        }
    }
}

/// Snapshot of a visible desktop window (normal or floating overlay) reported by the OS.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DesktopWindowInfo {
    pub window_id: u32,
    pub pid: i32,
    pub app_name: String,
    pub bundle_id: String,
    pub title: String,
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
    pub layer: i32,
    pub is_floating: bool,
    pub display_id: u32,
}

/// Active headless/standalone virtual display handle (zero video capture or encoding overhead).
/// Dropping immediately destroys the virtual display so macOS moves parked windows back cleanly.
pub trait StandaloneVirtualDisplayHandle: Send {
    fn display_id(&self) -> u32;
    fn stop(&mut self);
}

/// Active screen capture & H.264 encoder handle. Dropping stops capture and removes any virtual display.
pub trait CaptureHandle: Send {
    fn resize(&mut self, width: u32, height: u32) -> Result<()>;

    /// Live OS display ID backing this capture when known (e.g. macOS `CGDirectDisplayID`).
    fn display_id(&self) -> Option<u32> {
        None
    }

    /// Current logical desktop bounds `(x, y, width, height)` of the captured display, if known
    /// (allows macOS to fall back to `SCDisplay.frame` when `CGDisplayBounds` is stale).
    fn display_bounds(&self) -> Option<(i32, i32, u32, u32)> {
        None
    }

    /// Request an immediate IDR keyframe from the encoder (used on drop recovery, new viewer join,
    /// or resume from pause in IPPP temporal compression mode).
    fn request_keyframe(&self) {}

    /// Suspend/resume screen capture & host display-sleep assertion while keeping any virtual
    /// display alive so desktop windows remain in place during lock-screen Pause or `StopStream`.
    fn set_paused(&mut self, _paused: bool) -> Result<()> {
        Ok(())
    }

    /// Notify capture/encoder pipeline of runtime low-power mode transitions.
    fn set_low_power(&mut self, _enabled: bool) -> Result<()> {
        Ok(())
    }

    /// Live-toggle whether the OS cursor is composited into captured video frames.
    fn set_show_cursor(&mut self, _show_cursor: bool) -> Result<()> {
        Ok(())
    }

    /// Live-reconfigure output resolution, FPS, H.264 bitrate (Mbps), HiDPI scale, and max streaming pixel edge without disconnecting.
    fn reconfigure(
        &mut self,
        width: u32,
        height: u32,
        _fps: u32,
        _bitrate_mbps: u32,
        _hidpi: u32,
        _max_pixel_edge: u32,
    ) -> Result<()> {
        self.resize(width, height)
    }

    /// Lightweight ABR fast-path: dynamically adjust streaming FPS, H.264 bitrate, and encoded
    /// pixel ceiling WITHOUT mutating the virtual display's logical desktop resolution or layout.
    fn update_stream_quality(
        &mut self,
        _fps: u32,
        _bitrate_mbps: u32,
        _max_pixel_edge: u32,
    ) -> Result<()> {
        Ok(())
    }

    fn inject_input(&self, event: &InputEvent) -> Result<()>;
    fn query_cursor(&self) -> Option<CursorState>;
    fn cursor_image_png(&self) -> Option<Vec<u8>> {
        None
    }
    /// Capture a lossless PNG screenshot of this display and write it to `dest`.
    fn save_screenshot_png(&self, _dest: &std::path::Path) -> Result<()> {
        anyhow::bail!("当前平台暂不支持截屏保存")
    }
    /// Hash-deduplicated cursor PNG fetch: returns `Some(png)` only when the cursor image or
    /// hotspot changed compared to `*last_hash` (updating `*last_hash` on change). Backends with
    /// expensive PNG encoding (e.g. macOS) override this to hash raw pixels BEFORE PNG compression.
    fn cursor_image_png_if_changed(&self, last_hash: &mut u64) -> Option<Vec<u8>> {
        let png = self.cursor_image_png()?;
        let mut h: u64 = 0xcbf29ce484222325;
        for &b in &png {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        if h == 0 {
            h = 1;
        }
        if *last_hash == h {
            return None;
        }
        *last_hash = h;
        Some(png)
    }
    fn stop(&mut self);
}

/// Active Bonjour/mDNS publisher handle. Dropping unpublishes services.
pub trait BonjourHandle: Send {
    fn stop(&mut self);
}

/// Runtime platform capability matrix advertised by the active [`DisplayBackend`].
/// Eliminates scattered `#[cfg(target_os = ...)]` checks across session, main, and Web UI layers.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct PlatformCapabilities {
    pub hidpi: bool,
    pub virtual_display: bool,
    pub window_routing: bool,
    pub screen_lock_detection: bool,
    pub live_abr_quality: bool,
    pub true_capture_pause: bool,
    pub accessibility_permission_required: bool,
    pub accessibility_granted: bool,
    pub screen_recording_permission_required: bool,
    pub screen_recording_granted: bool,
}

/// Platform abstraction implemented natively on macOS, Linux, and Windows, plus Mock for tests.
pub trait DisplayBackend: Send + Sync {
    /// Whether this backend natively renders Retina 2x HiDPI backing pixels (true on macOS).
    fn supports_hidpi(&self) -> bool {
        false
    }

    /// Whether this backend can create independent virtual displays on demand (true on macOS / Mock).
    fn supports_virtual_display(&self) -> bool {
        false
    }

    /// Whether this backend supports listing and moving desktop windows across displays.
    fn supports_window_routing(&self) -> bool {
        false
    }

    /// Structured capability snapshot for runtime decisions and Web Admin feature disclosure.
    fn capabilities(&self) -> PlatformCapabilities {
        PlatformCapabilities {
            hidpi: self.supports_hidpi(),
            virtual_display: self.supports_virtual_display(),
            window_routing: self.supports_window_routing(),
            screen_lock_detection: false,
            live_abr_quality: false,
            true_capture_pause: false,
            accessibility_permission_required: false,
            accessibility_granted: true,
            screen_recording_permission_required: false,
            screen_recording_granted: true,
        }
    }

    /// Prompt the OS permission dialog / open System Settings for `"screen_recording"` or `"accessibility"`.
    fn request_permission(&self, _kind: &str) -> Result<String> {
        Ok("当前平台无需额外系统权限授权".to_string())
    }

    /// Actively re-probe OS capture/input permissions on demand (used by Web Admin "重新检测" button).
    fn recheck_permissions(&self) {}

    /// Live OS screen-lock query (overridable by MockBackend for deterministic lock-policy tests).
    fn is_host_screen_locked(&self) -> bool {
        is_host_screen_locked()
    }

    /// Trigger the host OS screen lock immediately (invoked by the iPad `lock_host` edge gesture).
    fn lock_host_screen(&self) -> Result<()> {
        anyhow::bail!("当前平台暂不支持一键锁屏")
    }

    /// OS display ID for the host primary screen (`0` when unsupported).
    fn main_display_id(&self) -> u32 {
        0
    }

    /// Current logical desktop bounds `(x, y, width, height)` for an OS display ID.
    fn display_bounds(&self, _display_id: u32) -> Option<(i32, i32, u32, u32)> {
        None
    }

    /// Additional non-primary OS displays `(display_id, name, x, y, width, height)` available for window routing.
    fn list_additional_displays(&self) -> Vec<(u32, String, i32, i32, u32, u32)> {
        Vec::new()
    }

    /// Create a zero-encode standalone virtual display (without screen capture or H.264 encoding).
    fn create_standalone_virtual_display(
        &self,
        _name: &str,
        _width: u32,
        _height: u32,
        _serial_num: u32,
    ) -> Result<Box<dyn StandaloneVirtualDisplayHandle>> {
        anyhow::bail!("当前平台暂不支持创建独立虚拟屏（仅 macOS 支持）")
    }

    /// List visible desktop windows (including floating overlay widgets such as Notion recording bars).
    fn list_desktop_windows(&self) -> Result<Vec<DesktopWindowInfo>> {
        anyhow::bail!("当前平台暂不支持桌面窗口枚举（仅 macOS / Windows 支持）")
    }

    /// Move a desktop window onto the target OS display ID.
    fn move_desktop_window(
        &self,
        _window_id: u32,
        _pid: i32,
        _target_display_id: u32,
        _layout: WindowMoveLayout,
    ) -> Result<()> {
        anyhow::bail!("当前平台暂不支持跨屏窗口移动（仅 macOS / Windows 支持）")
    }

    fn host_system_info(&self, override_host_name: &str) -> HostSystemInfo;

    fn publish_bonjour(
        &self,
        service_name: &str,
        telemetry_port: u16,
        data_port: u16,
    ) -> Result<Box<dyn BonjourHandle>>;

    fn start_capture(
        &self,
        params: &CaptureParams,
    ) -> Result<(Box<dyn CaptureHandle>, FrameReceiver)>;
}

/// Returns `true` while the host OS console screen is locked (native on macOS & Windows).
pub fn is_host_screen_locked() -> bool {
    #[cfg(target_os = "macos")]
    {
        macos::is_screen_locked()
    }
    #[cfg(target_os = "windows")]
    {
        windows::is_screen_locked()
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        false
    }
}

/// Initialize early per-process platform settings before spawning threads or querying displays.
/// On Windows, enables Per-Monitor DPI Awareness v2 so display/cursor/window APIs use physical pixels.
pub fn init_process_runtime() {
    #[cfg(target_os = "windows")]
    windows::init_process_dpi_awareness();
}

pub fn enable_platform_diagnostics() {
    #[cfg(target_os = "macos")]
    macos::enable_native_diagnostics();
}

/// Perform a non-blocking main-thread platform event pump when active (no-op on Linux/Windows).
/// On macOS, drains pending CoreGraphics display-reconfiguration notifications without ever
/// adding idle wakeups (Invariant CON-3 / PWR-1 / PLT-2).
pub fn pump_main_runloop() {
    #[cfg(target_os = "macos")]
    macos::pump_main_runloop();
}

pub fn default_backend(force_mock: bool) -> Arc<dyn DisplayBackend> {
    if force_mock {
        return Arc::new(mock::MockBackend::new());
    }
    #[cfg(target_os = "macos")]
    {
        Arc::new(macos::MacOsBackend::new())
    }
    #[cfg(target_os = "linux")]
    {
        Arc::new(linux::LinuxBackend::new())
    }
    #[cfg(target_os = "windows")]
    {
        Arc::new(windows::WindowsBackend::new())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Arc::new(mock::MockBackend::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latest_frame_channel_overwrites_stale_with_newest() {
        let (tx, rx) = latest_frame_channel();
        let mk = |w: u32| EncodedFrame {
            width: w,
            height: 768,
            bytes_per_row: w * 4,
            annex_b: vec![0, 0, 0, 1, 0x65],
            is_keyframe: true,
        };
        assert!(tx.send_latest(mk(640)));
        assert!(tx.send_latest(mk(1024)));
        assert!(tx.send_latest(mk(2048)));
        let got = rx.recv_timeout(Duration::from_millis(50)).unwrap();
        assert_eq!(got.width, 2048, "must always deliver the newest frame (e.g. refine IDR)");
        assert_eq!(rx.try_recv().unwrap_err(), RecvFrameError::Timeout);
        drop(tx);
        assert_eq!(
            rx.recv_timeout(Duration::from_millis(50)).unwrap_err(),
            RecvFrameError::Disconnected
        );
    }

    #[test]
    fn bounded_frame_channel_preserves_ippp_fifo_and_resets_cleanly_on_full_idr() {
        let (tx, rx) = bounded_frame_channel(4);
        let mk = |seq: u32, idr: bool| EncodedFrame {
            width: 1000 + seq,
            height: 768,
            bytes_per_row: (1000 + seq) * 4,
            annex_b: vec![0, 0, 0, 1, if idr { 0x65 } else { 0x41 }],
            is_keyframe: idr,
        };
        // Push 4 consecutive IPPP frames: zero overwrites, strict FIFO order preserved!
        for i in 1..=4 {
            assert!(tx.send_latest(mk(i, i == 1)));
        }
        for i in 1..=4 {
            let (_seq, frame, ov) = rx.recv_timeout_shared(Duration::from_millis(50)).unwrap();
            assert_eq!(ov, 0, "within capacity must report zero overwrites");
            assert_eq!(frame.width, 1000 + i, "must preserve strict FIFO DPB order");
        }

        // Push 5 P-frames into cap=4: oldest (1) evicted, ov=1 reported on first take.
        for i in 1..=5 {
            assert!(tx.send_latest(mk(i, false)));
        }
        let (_seq, frame, ov) = rx.recv_timeout_shared(Duration::from_millis(50)).unwrap();
        assert_eq!(ov, 1);
        assert_eq!(frame.width, 1002);
        // Drain remaining 3 frames
        for expected in 3..=5 {
            let (_s, f, ov2) = rx.recv_timeout_shared(Duration::from_millis(50)).unwrap();
            assert_eq!(ov2, 0);
            assert_eq!(f.width, 1000 + expected);
        }

        // Fill queue with 4 P-frames then push a fresh IDR: IDR supersedes all 4 cleanly.
        for i in 1..=4 {
            assert!(tx.send_latest(mk(i, false)));
        }
        assert!(tx.send_latest(mk(99, true)));
        let (_s, idr_f, ov) = rx.recv_timeout_shared(Duration::from_millis(50)).unwrap();
        assert_eq!(ov, 4);
        assert!(idr_f.is_keyframe);
        assert_eq!(idr_f.width, 1099);
        assert_eq!(rx.try_recv().unwrap_err(), RecvFrameError::Timeout);
    }

    #[test]
    fn latest_frame_channel_ignores_spurious_cvar_wakeup_and_honors_waker() {
        let (tx, rx) = latest_frame_channel();
        let slot_for_spurious = rx.slot.clone();
        let tx_bg = tx.clone();
        let producer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            // Simulate a spurious Condvar wakeup (e.g. Windows SleepConditionVariableSRW)
            slot_for_spurious.cvar.notify_all();
            std::thread::sleep(Duration::from_millis(30));
            tx_bg.send_latest(EncodedFrame {
                width: 1024,
                height: 768,
                bytes_per_row: 1024 * 4,
                annex_b: vec![0, 0, 0, 1, 0x65],
                is_keyframe: true,
            });
        });
        let got = rx
            .recv_timeout(Duration::from_secs(1))
            .expect("spurious cvar wakeup must not cause premature Timeout");
        assert_eq!((got.width, got.height), (1024, 768));
        producer.join().unwrap();

        // Explicit FrameWaker::wake() must still interrupt recv_timeout immediately with Timeout.
        let waker = rx.waker();
        let wake_t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            waker.wake();
        });
        let t0 = std::time::Instant::now();
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(2)).unwrap_err(),
            RecvFrameError::Timeout
        );
        assert!(
            t0.elapsed() < Duration::from_millis(500),
            "FrameWaker::wake() must wake receiver promptly"
        );
        wake_t.join().unwrap();
        drop(tx);
    }

    #[test]
    fn integer_scaled_logical_snaps_to_exact_1to1() {
        // iPad Air 2048x1536 @ 2x -> 1024x768 (1024*2 == 2048, 768*2 == 1536)
        assert_eq!(
            compute_integer_scaled_logical(2048, 1536, None, 2, IPAD_MAX_PIXEL_EDGE),
            (1024, 768)
        );
        // iPad Air 2048x1536 @ 1x -> 2048x1536
        assert_eq!(
            compute_integer_scaled_logical(2048, 1536, None, 1, IPAD_MAX_PIXEL_EDGE),
            (2048, 1536)
        );
        // Portrait iPad 1536x2048 @ 2x -> 768x1024
        assert_eq!(
            compute_integer_scaled_logical(1536, 2048, None, 2, IPAD_MAX_PIXEL_EDGE),
            (768, 1024)
        );
        // Oversized custom 1920x1440 @ 2x (=3840x2880 > 2048) snaps cleanly to 1024x768 @ 2x
        assert_eq!(
            compute_integer_scaled_logical(2048, 1536, Some((1920, 1440)), 2, IPAD_MAX_PIXEL_EDGE),
            (1024, 768)
        );
        // Custom 1600x1200 @ 1x (<= 2048) stays exact 1600x1200
        assert_eq!(
            compute_integer_scaled_logical(2048, 1536, Some((1600, 1200)), 1, IPAD_MAX_PIXEL_EDGE),
            (1600, 1200)
        );
        // Standalone Web 1920x1080 @ 2x (=3840x2160 <= 3840) stays exact 1920x1080
        assert_eq!(
            compute_integer_scaled_logical(1920, 1080, Some((1920, 1080)), 2, WEB_MAX_PIXEL_EDGE),
            (1920, 1080)
        );
    }

    #[test]
    fn compute_window_move_rect_handles_keep_size_and_fill_screen() {
        // FillScreen covers the target monitor work area verbatim
        assert_eq!(
            compute_window_move_rect(800, 600, 1920, 0, 1280, 720, WindowMoveLayout::FillScreen),
            (1920, 0, 1280, 720)
        );
        // KeepSize centers smaller windows inside target work area
        assert_eq!(
            compute_window_move_rect(400, 120, 1920, 40, 1280, 680, WindowMoveLayout::KeepSize),
            (1920 + 440, 40 + 280, 400, 120)
        );
        // KeepSize clamps oversized windows to target work area
        assert_eq!(
            compute_window_move_rect(2560, 1440, -1280, 0, 1280, 720, WindowMoveLayout::KeepSize),
            (-1280, 0, 1280, 720)
        );
    }
}
