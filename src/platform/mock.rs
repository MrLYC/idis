use crate::platform::{
    latest_frame_channel, BonjourHandle, CaptureHandle, CaptureParams, CursorState,
    DesktopWindowInfo, DisplayBackend, EncodedFrame, FrameReceiver, FrameSender, HostSystemInfo,
    StandaloneVirtualDisplayHandle, WindowMoveLayout,
};
use crate::protocol::messages::InputEvent;
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// Minimal valid H.264 Annex-B SPS + PPS + IDR slice bytes for cross-platform protocol testing.
pub const SYNTHETIC_H264_ANNEX_B: &[u8] = &[
    // SPS NAL (type 7)
    0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0xC0, 0x1E, 0xD9, 0x00, 0xA0, 0x47, 0xFE, 0xC8,
    // PPS NAL (type 8)
    0x00, 0x00, 0x00, 0x01, 0x68, 0xCE, 0x38, 0x80,
    // IDR NAL (type 5)
    0x00, 0x00, 0x00, 0x01, 0x65, 0x88, 0x84, 0x00, 0x33, 0xFF,
];

/// Minimal valid H.264 Annex-B non-IDR P-frame slice (NAL type 1) for IPPP DPB testing.
pub const SYNTHETIC_H264_P_FRAME: &[u8] = &[
    0x00, 0x00, 0x00, 0x01, 0x41, 0x9A, 0x22, 0x11, 0x00, 0xAA, 0xBB,
];

pub type ReconfigureRecord = (u32, u32, u32, u32, u32, u32);
pub type DisplayBoundsMap = Arc<Mutex<HashMap<u32, (i32, i32, u32, u32)>>>;
pub type WindowMoveRecord = (u32, i32, u32, WindowMoveLayout);

/// Cross-platform mock backend for testing on Linux/CI without macOS frameworks.
pub struct MockBackend {
    pub recorded_inputs: Arc<Mutex<Vec<InputEvent>>>,
    pub recorded_resizes: Arc<Mutex<Vec<(u32, u32)>>>,
    pub recorded_reconfigures: Arc<Mutex<Vec<ReconfigureRecord>>>,
    pub recorded_show_cursor: Arc<Mutex<Vec<bool>>>,
    pub recorded_quality_updates: Arc<Mutex<Vec<(u32, u32, u32)>>>,
    pub recorded_capture_modes: Arc<Mutex<Vec<crate::config::CaptureMode>>>,
    pub recorded_pauses: Arc<Mutex<Vec<bool>>>,
    pub keyframe_requests: Arc<AtomicUsize>,
    pub query_cursor_calls: Arc<AtomicUsize>,
    pub cursor_visible: Arc<AtomicBool>,
    pub cursor_pos: Arc<Mutex<(u32, u32)>>,
    pub cursor_png: Arc<Mutex<Option<Vec<u8>>>>,
    pub screen_locked: Arc<AtomicBool>,
    pub live_abr_quality: Arc<AtomicBool>,
    pub fail_quality_updates: Arc<AtomicBool>,
    pub fail_next_start_capture: Arc<AtomicBool>,
    pub manual_frame_mode: Arc<AtomicBool>,
    pub frame_senders: Arc<Mutex<Vec<FrameSender>>>,
    pub next_mock_display_id: Arc<AtomicU32>,
    pub mock_display_bounds: DisplayBoundsMap,
    pub mock_windows: Arc<Mutex<Vec<DesktopWindowInfo>>>,
    pub recorded_window_moves: Arc<Mutex<Vec<WindowMoveRecord>>>,
    pub accessibility_granted: Arc<AtomicBool>,
}

impl Default for MockBackend {
    fn default() -> Self {
        let mut bounds = HashMap::new();
        bounds.insert(1, (0, 0, 1440, 900));
        Self {
            recorded_inputs: Arc::new(Mutex::new(Vec::new())),
            recorded_resizes: Arc::new(Mutex::new(Vec::new())),
            recorded_reconfigures: Arc::new(Mutex::new(Vec::new())),
            recorded_show_cursor: Arc::new(Mutex::new(Vec::new())),
            recorded_quality_updates: Arc::new(Mutex::new(Vec::new())),
            recorded_capture_modes: Arc::new(Mutex::new(Vec::new())),
            recorded_pauses: Arc::new(Mutex::new(Vec::new())),
            keyframe_requests: Arc::new(AtomicUsize::new(0)),
            query_cursor_calls: Arc::new(AtomicUsize::new(0)),
            cursor_visible: Arc::new(AtomicBool::new(true)),
            cursor_pos: Arc::new(Mutex::new((100, 120))),
            cursor_png: Arc::new(Mutex::new(None)),
            screen_locked: Arc::new(AtomicBool::new(false)),
            live_abr_quality: Arc::new(AtomicBool::new(false)),
            fail_quality_updates: Arc::new(AtomicBool::new(false)),
            fail_next_start_capture: Arc::new(AtomicBool::new(false)),
            manual_frame_mode: Arc::new(AtomicBool::new(false)),
            frame_senders: Arc::new(Mutex::new(Vec::new())),
            next_mock_display_id: Arc::new(AtomicU32::new(100)),
            mock_display_bounds: Arc::new(Mutex::new(bounds)),
            mock_windows: Arc::new(Mutex::new(Vec::new())),
            recorded_window_moves: Arc::new(Mutex::new(Vec::new())),
            accessibility_granted: Arc::new(AtomicBool::new(true)),
        }
    }
}

impl MockBackend {
    pub fn new() -> Self {
        Self::default()
    }

    /// Push a deterministic frame to the most recently started capture (used when `manual_frame_mode = true`).
    pub fn push_frame(&self, frame: EncodedFrame) -> bool {
        let senders = self.frame_senders.lock().unwrap();
        if let Some(tx) = senders.last() {
            tx.send_latest(frame)
        } else {
            false
        }
    }

    /// Push a deterministic frame to capture index `idx` (0-based).
    pub fn push_frame_to(&self, idx: usize, frame: EncodedFrame) -> bool {
        let senders = self.frame_senders.lock().unwrap();
        if let Some(tx) = senders.get(idx) {
            tx.send_latest(frame)
        } else {
            false
        }
    }
}

struct MockBonjour;
impl BonjourHandle for MockBonjour {
    fn stop(&mut self) {}
}

struct MockVirtualDisplay {
    display_id: u32,
    bounds_map: DisplayBoundsMap,
}

impl StandaloneVirtualDisplayHandle for MockVirtualDisplay {
    fn display_id(&self) -> u32 {
        self.display_id
    }

    fn stop(&mut self) {
        self.bounds_map.lock().unwrap().remove(&self.display_id);
    }
}

impl Drop for MockVirtualDisplay {
    fn drop(&mut self) {
        self.stop();
    }
}

struct MockCapture {
    display_id: u32,
    bounds_map: DisplayBoundsMap,
    is_virtual: bool,
    stop_flag: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
    size: Arc<Mutex<(u32, u32)>>,
    recorded_inputs: Arc<Mutex<Vec<InputEvent>>>,
    recorded_resizes: Arc<Mutex<Vec<(u32, u32)>>>,
    recorded_reconfigures: Arc<Mutex<Vec<ReconfigureRecord>>>,
    recorded_show_cursor: Arc<Mutex<Vec<bool>>>,
    recorded_quality_updates: Arc<Mutex<Vec<(u32, u32, u32)>>>,
    recorded_pauses: Arc<Mutex<Vec<bool>>>,
    keyframe_requests: Arc<AtomicUsize>,
    query_cursor_calls: Arc<AtomicUsize>,
    cursor_visible: Arc<AtomicBool>,
    cursor_pos: Arc<Mutex<(u32, u32)>>,
    cursor_png: Arc<Mutex<Option<Vec<u8>>>>,
    fail_quality_updates: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}

impl CaptureHandle for MockCapture {
    fn display_id(&self) -> Option<u32> {
        Some(self.display_id)
    }

    fn resize(&mut self, width: u32, height: u32) -> Result<()> {
        *self.size.lock().unwrap() = (width, height);
        self.recorded_resizes.lock().unwrap().push((width, height));
        Ok(())
    }

    fn set_paused(&mut self, paused: bool) -> Result<()> {
        self.paused.store(paused, Ordering::Release);
        self.recorded_pauses.lock().unwrap().push(paused);
        Ok(())
    }

    fn request_keyframe(&self) {
        self.keyframe_requests.fetch_add(1, Ordering::AcqRel);
    }

    fn set_show_cursor(&mut self, show_cursor: bool) -> Result<()> {
        self.recorded_show_cursor.lock().unwrap().push(show_cursor);
        Ok(())
    }

    fn update_stream_quality(
        &mut self,
        fps: u32,
        bitrate_mbps: u32,
        max_pixel_edge: u32,
    ) -> Result<()> {
        if self.fail_quality_updates.load(Ordering::Acquire) {
            return Err(anyhow!("injected update_stream_quality failure"));
        }
        self.recorded_quality_updates
            .lock()
            .unwrap()
            .push((fps, bitrate_mbps, max_pixel_edge));
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
        self.recorded_reconfigures
            .lock()
            .unwrap()
            .push((width, height, fps, bitrate_mbps, hidpi, max_pixel_edge));
        let (w, h) = if max_pixel_edge >= 320 {
            crate::platform::clamp_pixel_dimensions(width, height, max_pixel_edge)
        } else {
            (width, height)
        };
        self.resize(w, h)
    }

    fn inject_input(&self, event: &InputEvent) -> Result<()> {
        self.recorded_inputs.lock().unwrap().push(event.clone());
        Ok(())
    }

    fn query_cursor(&self) -> Option<CursorState> {
        self.query_cursor_calls.fetch_add(1, Ordering::AcqRel);
        let visible = self.cursor_visible.load(Ordering::Acquire);
        let (x, y) = *self.cursor_pos.lock().unwrap();
        Some(CursorState {
            x: if visible { x } else { 0 },
            y: if visible { y } else { 0 },
            visible,
        })
    }

    fn cursor_image_png(&self) -> Option<Vec<u8>> {
        self.cursor_png.lock().unwrap().clone()
    }

    fn stop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        if self.is_virtual {
            self.bounds_map.lock().unwrap().remove(&self.display_id);
        }
        if let Some(h) = self.join.take() {
            let _ = h.join();
        }
    }
}

impl Drop for MockCapture {
    fn drop(&mut self) {
        self.stop();
    }
}

impl DisplayBackend for MockBackend {
    fn supports_virtual_display(&self) -> bool {
        true
    }

    fn supports_window_routing(&self) -> bool {
        true
    }

    fn is_host_screen_locked(&self) -> bool {
        self.screen_locked.load(Ordering::Acquire)
    }

    fn main_display_id(&self) -> u32 {
        1
    }

    fn display_bounds(&self, display_id: u32) -> Option<(i32, i32, u32, u32)> {
        self.mock_display_bounds
            .lock()
            .unwrap()
            .get(&display_id)
            .copied()
    }

    fn create_standalone_virtual_display(
        &self,
        _name: &str,
        width: u32,
        height: u32,
        _serial_num: u32,
    ) -> Result<Box<dyn StandaloneVirtualDisplayHandle>> {
        let id = self.next_mock_display_id.fetch_add(1, Ordering::AcqRel);
        let x = ((id - 99) as i32) * 1600;
        self.mock_display_bounds
            .lock()
            .unwrap()
            .insert(id, (x, 0, width, height));
        Ok(Box::new(MockVirtualDisplay {
            display_id: id,
            bounds_map: self.mock_display_bounds.clone(),
        }))
    }

    fn list_desktop_windows(&self) -> Result<Vec<DesktopWindowInfo>> {
        Ok(self.mock_windows.lock().unwrap().clone())
    }

    fn move_desktop_window(
        &self,
        window_id: u32,
        pid: i32,
        target_display_id: u32,
        layout: WindowMoveLayout,
    ) -> Result<()> {
        if !self.accessibility_granted.load(Ordering::Acquire) {
            return Err(anyhow!("未获得辅助功能权限"));
        }
        let target_bounds = self
            .mock_display_bounds
            .lock()
            .unwrap()
            .get(&target_display_id)
            .copied()
            .ok_or_else(|| anyhow!("目标屏幕 {target_display_id} 不存在"))?;
        let mut wins = self.mock_windows.lock().unwrap();
        let Some(win) = wins
            .iter_mut()
            .find(|w| w.window_id == window_id && (pid <= 0 || w.pid == pid))
        else {
            return Err(anyhow!("窗口 {window_id} 不存在或已关闭"));
        };
        win.display_id = target_display_id;
        match layout {
            WindowMoveLayout::FillScreen => {
                win.x = target_bounds.0;
                win.y = target_bounds.1;
                win.width = target_bounds.2;
                win.height = target_bounds.3;
            }
            WindowMoveLayout::KeepSize => {
                win.width = win.width.min(target_bounds.2);
                win.height = win.height.min(target_bounds.3);
                win.x = target_bounds.0 + ((target_bounds.2.saturating_sub(win.width)) / 2) as i32;
                win.y = target_bounds.1 + ((target_bounds.3.saturating_sub(win.height)) / 2) as i32;
            }
        }
        self.recorded_window_moves
            .lock()
            .unwrap()
            .push((window_id, pid, target_display_id, layout));
        Ok(())
    }

    fn capabilities(&self) -> crate::platform::PlatformCapabilities {
        crate::platform::PlatformCapabilities {
            hidpi: false,
            virtual_display: true,
            window_routing: true,
            screen_lock_detection: true,
            live_abr_quality: self.live_abr_quality.load(Ordering::Acquire),
            true_capture_pause: true,
            accessibility_permission_required: false,
            accessibility_granted: self.accessibility_granted.load(Ordering::Acquire),
        }
    }

    fn host_system_info(&self, override_host_name: &str) -> HostSystemInfo {
        let host_name = if override_host_name.is_empty() {
            "MacM1-Mock".to_string()
        } else {
            override_host_name.to_string()
        };
        HostSystemInfo {
            user_name: std::env::var("USER").unwrap_or_else(|_| "user".to_string()),
            host_name,
            os_version: "Version 15.0 (Mock)".to_string(),
            physical_memory: 16 * 1024 * 1024 * 1024,
            cpu_count: 8,
        }
    }

    fn publish_bonjour(
        &self,
        _service_name: &str,
        _telemetry_port: u16,
        _data_port: u16,
    ) -> Result<Box<dyn BonjourHandle>> {
        Ok(Box::new(MockBonjour))
    }

    fn start_capture(
        &self,
        params: &CaptureParams,
    ) -> Result<(Box<dyn CaptureHandle>, FrameReceiver)> {
        if self.fail_next_start_capture.swap(false, Ordering::AcqRel) {
            anyhow::bail!("mock injected start_capture failure");
        }
        self.recorded_capture_modes.lock().unwrap().push(params.mode);
        let (tx, rx) = latest_frame_channel();
        self.frame_senders.lock().unwrap().push(tx.clone());
        let stop_flag = Arc::new(AtomicBool::new(false));
        let paused = Arc::new(AtomicBool::new(false));
        let size = Arc::new(Mutex::new((params.width, params.height)));

        let stop_bg = stop_flag.clone();
        let paused_bg = paused.clone();
        let manual_bg = self.manual_frame_mode.clone();
        let size_bg = size.clone();
        let interval = Duration::from_millis((1000 / params.fps.max(1)).max(10) as u64);

        let join = thread::spawn(move || {
            while !stop_bg.load(Ordering::SeqCst) {
                if paused_bg.load(Ordering::Acquire) || manual_bg.load(Ordering::Acquire) {
                    thread::sleep(Duration::from_millis(20));
                    continue;
                }
                let (w, h) = *size_bg.lock().unwrap();
                let frame = EncodedFrame {
                    width: w,
                    height: h,
                    bytes_per_row: w * 4,
                    annex_b: SYNTHETIC_H264_ANNEX_B.to_vec(),
                    is_keyframe: true,
                };
                if !tx.send_latest(frame) {
                    break;
                }
                thread::sleep(interval);
            }
        });

        let is_virtual = params.mode == crate::config::CaptureMode::Extend;
        let display_id = if is_virtual {
            let id = self.next_mock_display_id.fetch_add(1, Ordering::AcqRel);
            let x = ((id - 99) as i32) * 1600;
            self.mock_display_bounds
                .lock()
                .unwrap()
                .insert(id, (x, 0, params.width, params.height));
            id
        } else {
            1
        };

        Ok((
            Box::new(MockCapture {
                display_id,
                bounds_map: self.mock_display_bounds.clone(),
                is_virtual,
                stop_flag,
                paused,
                size,
                recorded_inputs: self.recorded_inputs.clone(),
                recorded_resizes: self.recorded_resizes.clone(),
                recorded_reconfigures: self.recorded_reconfigures.clone(),
                recorded_show_cursor: self.recorded_show_cursor.clone(),
                recorded_quality_updates: self.recorded_quality_updates.clone(),
                recorded_pauses: self.recorded_pauses.clone(),
                keyframe_requests: self.keyframe_requests.clone(),
                query_cursor_calls: self.query_cursor_calls.clone(),
                cursor_visible: self.cursor_visible.clone(),
                cursor_pos: self.cursor_pos.clone(),
                cursor_png: self.cursor_png.clone(),
                fail_quality_updates: self.fail_quality_updates.clone(),
                join: Some(join),
            }),
            rx,
        ))
    }
}
