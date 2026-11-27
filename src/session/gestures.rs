//! Edge-swipe gesture state machine and action router for iPad touch input.
//!
//! Recognizes 4 screen-edge horizontal short swipes relative to the active capture stream size:
//! - Left edge upper half -> swipe right (`left_top_swipe_right`)
//! - Left edge lower half -> swipe right (`left_bottom_swipe_right`)
//! - Right edge upper half -> swipe left (`right_top_swipe_left`)
//! - Right edge lower half -> swipe left (`right_bottom_swipe_left`)
//!
//! Design invariants:
//! - Touches outside configured active edge zones pass through with zero buffering / zero latency.
//! - Edge taps or vertical/slow drags inside an edge zone gracefully replay the buffered `MouseDown`
//!   so sidebar buttons, window close controls, and scrollbars near screen edges continue to work.
//! - Once a swipe triggers, remaining `MouseDragged` / `MouseUp` events until finger lift are swallowed
//!   so no stray click or drag ever leaks to the host desktop.

use crate::protocol::messages::InputEvent;
use crate::user_config::{EdgeGestureSlot, EdgeGesturesConfig, GestureAction};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Maximum duration for a short edge swipe before falling back to an ordinary drag.
pub const EDGE_SWIPE_MAX_DURATION: Duration = Duration::from_millis(650);

/// Local wall-clock date/time components used for screenshot directory (`idis-YYYY-MM-DD`) and filename.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalDateTimeParts {
    pub year: i32,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
    pub millis: u32,
}

fn utc_parts_from_unix_secs(secs: i64, millis: u32) -> LocalDateTimeParts {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400) as u32;
    // Howard Hinnant's civil-from-days algorithm.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let mut y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    if m <= 2 {
        y += 1;
    }
    LocalDateTimeParts {
        year: y as i32,
        month: m,
        day: d,
        hour: rem / 3600,
        minute: (rem % 3600) / 60,
        second: rem % 60,
        millis,
    }
}

/// Obtain current local system date/time with zero external crate dependencies.
pub fn local_date_time_now() -> LocalDateTimeParts {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let millis = dur.subsec_millis();

    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::Foundation::SYSTEMTIME;
        use windows_sys::Win32::System::SystemInformation::GetLocalTime;
        let mut st = SYSTEMTIME {
            wYear: 0,
            wMonth: 0,
            wDayOfWeek: 0,
            wDay: 0,
            wHour: 0,
            wMinute: 0,
            wSecond: 0,
            wMilliseconds: 0,
        };
        unsafe { GetLocalTime(&mut st) };
        if st.wYear >= 1970 && (1..=12).contains(&st.wMonth) && (1..=31).contains(&st.wDay) {
            return LocalDateTimeParts {
                year: st.wYear as i32,
                month: st.wMonth as u32,
                day: st.wDay as u32,
                hour: st.wHour as u32,
                minute: st.wMinute as u32,
                second: st.wSecond as u32,
                millis: st.wMilliseconds as u32,
            };
        }
    }

    #[cfg(unix)]
    {
        // Standard POSIX `struct tm` prefix (first 6 `c_int`s) padded to 120 bytes so OS-specific
        // trailing fields (`tm_gmtoff`, `tm_zone`) always fit safely inside the buffer.
        #[repr(C)]
        struct PosixTmBuf {
            tm_sec: std::ffi::c_int,
            tm_min: std::ffi::c_int,
            tm_hour: std::ffi::c_int,
            tm_mday: std::ffi::c_int,
            tm_mon: std::ffi::c_int,
            tm_year: std::ffi::c_int,
            _pad: [u64; 12],
        }
        extern "C" {
            fn localtime_r(timep: *const std::ffi::c_long, result: *mut PosixTmBuf) -> *mut PosixTmBuf;
        }
        let secs = dur.as_secs() as std::ffi::c_long;
        let mut out = PosixTmBuf {
            tm_sec: 0,
            tm_min: 0,
            tm_hour: 0,
            tm_mday: 0,
            tm_mon: 0,
            tm_year: 0,
            _pad: [0u64; 12],
        };
        let ptr = unsafe { localtime_r(&secs, &mut out) };
        if !ptr.is_null() {
            return LocalDateTimeParts {
                year: out.tm_year + 1900,
                month: (out.tm_mon + 1).clamp(1, 12) as u32,
                day: out.tm_mday.clamp(1, 31) as u32,
                hour: out.tm_hour.clamp(0, 23) as u32,
                minute: out.tm_min.clamp(0, 59) as u32,
                second: out.tm_sec.clamp(0, 59) as u32,
                millis,
            };
        }
    }

    utc_parts_from_unix_secs(dur.as_secs() as i64, millis)
}

/// Build the dated screenshot directory (`<base_dir>/idis-YYYY-MM-DD`) and PNG file path.
pub fn build_screenshot_target_path(
    base_dir: &Path,
    parts: LocalDateTimeParts,
    seq: u64,
) -> (PathBuf, PathBuf) {
    let dated_dir = base_dir.join(format!(
        "idis-{:04}-{:02}-{:02}",
        parts.year, parts.month, parts.day
    ));
    let filename = if seq == 0 {
        format!(
            "idis-{:04}{:02}{:02}-{:02}{:02}{:02}-{:03}.png",
            parts.year, parts.month, parts.day, parts.hour, parts.minute, parts.second, parts.millis
        )
    } else {
        format!(
            "idis-{:04}{:02}{:02}-{:02}{:02}{:02}-{:03}-{seq}.png",
            parts.year, parts.month, parts.day, parts.hour, parts.minute, parts.second, parts.millis
        )
    };
    let file_path = dated_dir.join(filename);
    (dated_dir, file_path)
}

/// Live diagnostic snapshot of the most recently recognized edge gesture.
#[derive(Debug, Clone, Serialize)]
pub struct LastGestureSnapshot {
    pub slot: EdgeGestureSlot,
    pub slot_label: String,
    pub action: String,
    pub peer: String,
    pub triggered_at_unix_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked_reason: Option<String>,
}

impl LastGestureSnapshot {
    pub fn now(
        slot: EdgeGestureSlot,
        action: &GestureAction,
        peer: &str,
        detail: Option<String>,
        blocked_reason: Option<String>,
    ) -> Self {
        let triggered_at_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        Self {
            slot,
            slot_label: slot.label_zh().to_string(),
            action: action.describe(),
            peer: peer.to_string(),
            triggered_at_unix_ms,
            detail,
            blocked_reason,
        }
    }
}

/// Output of feeding one decoded [`InputEvent`] into [`EdgeGestureTracker`].
#[derive(Debug, Clone, PartialEq)]
pub enum GestureDecision {
    /// Not part of an edge gesture — inject directly as ordinary input.
    Passthrough,
    /// Buffered or consumed as part of an edge gesture — do not inject.
    Swallow,
    /// Buffered edge touch turned out to be a normal tap/drag — replay buffered events in order.
    Replay(Vec<InputEvent>),
    /// An edge swipe completed — execute `action` and swallow remaining tail until finger lift.
    Trigger {
        slot: EdgeGestureSlot,
        action: GestureAction,
        start_x: f64,
        start_y: f64,
    },
}

#[derive(Debug, Clone)]
enum TrackerState {
    Idle,
    Pending {
        slot: EdgeGestureSlot,
        start_x: f64,
        start_y: f64,
        started_at: Instant,
        stream_w: f64,
    },
    Consumed,
}

/// Per-session state machine tracking a single in-progress edge touch.
#[derive(Debug, Clone)]
pub struct EdgeGestureTracker {
    state: TrackerState,
}

impl Default for EdgeGestureTracker {
    fn default() -> Self {
        Self {
            state: TrackerState::Idle,
        }
    }
}

impl EdgeGestureTracker {
    pub fn reset(&mut self) {
        self.state = TrackerState::Idle;
    }

    /// Classify a starting point `(x, y)` inside `(stream_w, stream_h)` into one of the 4 edge slots.
    pub fn classify_edge_slot(
        x: f64,
        y: f64,
        stream_w: f64,
        stream_h: f64,
        edge_zone_pct: u8,
    ) -> Option<EdgeGestureSlot> {
        if stream_w <= 1.0 || stream_h <= 1.0 || !x.is_finite() || !y.is_finite() {
            return None;
        }
        let edge_px = (stream_w * (edge_zone_pct.clamp(3, 25) as f64 / 100.0)).max(16.0);
        let is_top = y < stream_h * 0.5;
        if x <= edge_px {
            Some(if is_top {
                EdgeGestureSlot::LeftTopSwipeRight
            } else {
                EdgeGestureSlot::LeftBottomSwipeRight
            })
        } else if x >= stream_w - edge_px {
            Some(if is_top {
                EdgeGestureSlot::RightTopSwipeLeft
            } else {
                EdgeGestureSlot::RightBottomSwipeLeft
            })
        } else {
            None
        }
    }

    /// Process an incoming decoded touch/input event with explicit timestamp `now` (deterministic for tests).
    pub fn on_event(
        &mut self,
        event: &InputEvent,
        stream_size: (u32, u32),
        cfg: &EdgeGesturesConfig,
        now: Instant,
    ) -> GestureDecision {
        if !cfg.enabled {
            self.state = TrackerState::Idle;
            return GestureDecision::Passthrough;
        }

        let stream_w = stream_size.0 as f64;
        let stream_h = stream_size.1 as f64;

        match *event {
            InputEvent::MouseDown {
                x,
                y,
                right_click,
                tap_count,
            } => {
                // Always reset stale state if a prior MouseUp was dropped over the network.
                self.state = TrackerState::Idle;
                if right_click || tap_count >= 2 {
                    return GestureDecision::Passthrough;
                }
                let Some(slot) =
                    Self::classify_edge_slot(x, y, stream_w, stream_h, cfg.edge_zone_pct)
                else {
                    return GestureDecision::Passthrough;
                };
                if cfg.action_for(slot).is_none() {
                    return GestureDecision::Passthrough;
                }
                self.state = TrackerState::Pending {
                    slot,
                    start_x: x,
                    start_y: y,
                    started_at: now,
                    stream_w,
                };
                GestureDecision::Swallow
            }
            InputEvent::MouseDragged { x, y } => match self.state {
                TrackerState::Idle => GestureDecision::Passthrough,
                TrackerState::Consumed => GestureDecision::Swallow,
                TrackerState::Pending {
                    slot,
                    start_x,
                    start_y,
                    started_at,
                    stream_w: sw,
                } => {
                    let dx = x - start_x;
                    let dy = y - start_y;
                    let inward_dx = if slot.is_left_edge() { dx } else { -dx };
                    let min_swipe_px =
                        (sw * (cfg.min_swipe_pct.clamp(3, 30) as f64 / 100.0)).max(24.0);
                    let elapsed = now.saturating_duration_since(started_at);

                    if elapsed <= EDGE_SWIPE_MAX_DURATION
                        && inward_dx >= min_swipe_px
                        && dy.abs() <= inward_dx * 0.85
                    {
                        let action = cfg.action_for(slot).clone();
                        self.state = TrackerState::Consumed;
                        if action.is_none() {
                            return GestureDecision::Swallow;
                        }
                        return GestureDecision::Trigger {
                            slot,
                            action,
                            start_x,
                            start_y,
                        };
                    }

                    // Fall back to a normal drag if the user moves mostly vertically (scrollbar),
                    // moves outward toward the bezel, or holds beyond the short-swipe window.
                    if elapsed > EDGE_SWIPE_MAX_DURATION
                        || dy.abs() > min_swipe_px * 1.25
                        || inward_dx < -16.0
                    {
                        self.state = TrackerState::Idle;
                        return GestureDecision::Replay(vec![
                            InputEvent::MouseDown {
                                x: start_x,
                                y: start_y,
                                right_click: false,
                                tap_count: 1,
                            },
                            InputEvent::MouseDragged { x, y },
                        ]);
                    }

                    GestureDecision::Swallow
                }
            },
            InputEvent::MouseUp {
                x,
                y,
                double_click,
            } => match self.state {
                TrackerState::Idle => GestureDecision::Passthrough,
                TrackerState::Consumed => {
                    self.state = TrackerState::Idle;
                    GestureDecision::Swallow
                }
                TrackerState::Pending {
                    slot,
                    start_x,
                    start_y,
                    started_at,
                    stream_w: sw,
                } => {
                    self.state = TrackerState::Idle;
                    let dx = x - start_x;
                    let dy = y - start_y;
                    let inward_dx = if slot.is_left_edge() { dx } else { -dx };
                    let min_swipe_px =
                        (sw * (cfg.min_swipe_pct.clamp(3, 30) as f64 / 100.0)).max(24.0);
                    let elapsed = now.saturating_duration_since(started_at);

                    // Support ultra-fast flicks that jump directly from Began to Ended without
                    // an intermediate Moved packet.
                    if elapsed <= EDGE_SWIPE_MAX_DURATION
                        && inward_dx >= min_swipe_px
                        && dy.abs() <= inward_dx * 0.85
                    {
                        let action = cfg.action_for(slot).clone();
                        if action.is_none() {
                            return GestureDecision::Swallow;
                        }
                        return GestureDecision::Trigger {
                            slot,
                            action,
                            start_x,
                            start_y,
                        };
                    }

                    // Otherwise it was an ordinary tap near the edge -> replay down + up cleanly!
                    GestureDecision::Replay(vec![
                        InputEvent::MouseDown {
                            x: start_x,
                            y: start_y,
                            right_click: false,
                            tap_count: 1,
                        },
                        InputEvent::MouseUp {
                            x,
                            y,
                            double_click,
                        },
                    ])
                }
            },
            // Keyboard / scroll events are never buffered by the single-finger edge-swipe tracker.
            _ => GestureDecision::Passthrough,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled_cfg() -> EdgeGesturesConfig {
        EdgeGesturesConfig {
            enabled: true,
            edge_zone_pct: 8,
            min_swipe_pct: 6,
            screenshot_dir: String::new(),
            left_top_swipe_right: GestureAction::Hotkey {
                keys: "ctrl+left".into(),
            },
            left_bottom_swipe_right: GestureAction::Hotkey {
                keys: "cmd+tab".into(),
            },
            right_top_swipe_left: GestureAction::TogglePause,
            right_bottom_swipe_left: GestureAction::ToggleInput,
        }
    }

    #[test]
    fn recognizes_all_four_edge_swipes_and_swallows_tail() {
        let cfg = enabled_cfg();
        let size = (2048, 1536);
        let t0 = Instant::now();

        let cases = [
            (
                EdgeGestureSlot::LeftTopSwipeRight,
                (30.0, 200.0),
                (200.0, 215.0),
                cfg.left_top_swipe_right.clone(),
            ),
            (
                EdgeGestureSlot::LeftBottomSwipeRight,
                (30.0, 1200.0),
                (210.0, 1180.0),
                cfg.left_bottom_swipe_right.clone(),
            ),
            (
                EdgeGestureSlot::RightTopSwipeLeft,
                (2020.0, 300.0),
                (1840.0, 310.0),
                cfg.right_top_swipe_left.clone(),
            ),
            (
                EdgeGestureSlot::RightBottomSwipeLeft,
                (2015.0, 1300.0),
                (1820.0, 1285.0),
                cfg.right_bottom_swipe_left.clone(),
            ),
        ];

        for (expected_slot, (sx, sy), (ex, ey), expected_action) in cases {
            let mut tr = EdgeGestureTracker::default();
            let d1 = tr.on_event(
                &InputEvent::MouseDown {
                    x: sx,
                    y: sy,
                    right_click: false,
                    tap_count: 1,
                },
                size,
                &cfg,
                t0,
            );
            assert_eq!(d1, GestureDecision::Swallow);

            let d2 = tr.on_event(
                &InputEvent::MouseDragged { x: ex, y: ey },
                size,
                &cfg,
                t0 + Duration::from_millis(80),
            );
            assert_eq!(
                d2,
                GestureDecision::Trigger {
                    slot: expected_slot,
                    action: expected_action,
                    start_x: sx,
                    start_y: sy,
                }
            );

            // Subsequent drag and release must be swallowed without leaking clicks.
            assert_eq!(
                tr.on_event(
                    &InputEvent::MouseDragged {
                        x: ex + 5.0,
                        y: ey
                    },
                    size,
                    &cfg,
                    t0 + Duration::from_millis(120),
                ),
                GestureDecision::Swallow
            );
            assert_eq!(
                tr.on_event(
                    &InputEvent::MouseUp {
                        x: ex + 5.0,
                        y: ey,
                        double_click: false,
                    },
                    size,
                    &cfg,
                    t0 + Duration::from_millis(150),
                ),
                GestureDecision::Swallow
            );
        }
    }

    #[test]
    fn edge_tap_and_vertical_drag_replay_normal_mouse_events() {
        let cfg = enabled_cfg();
        let size = (2048, 1536);
        let t0 = Instant::now();
        let mut tr = EdgeGestureTracker::default();

        // 1) Tap near left-top edge (e.g. clicking macOS red close button) -> replays down + up.
        assert_eq!(
            tr.on_event(
                &InputEvent::MouseDown {
                    x: 24.0,
                    y: 40.0,
                    right_click: false,
                    tap_count: 1,
                },
                size,
                &cfg,
                t0,
            ),
            GestureDecision::Swallow
        );
        let up = tr.on_event(
            &InputEvent::MouseUp {
                x: 28.0,
                y: 42.0,
                double_click: false,
            },
            size,
            &cfg,
            t0 + Duration::from_millis(60),
        );
        assert_eq!(
            up,
            GestureDecision::Replay(vec![
                InputEvent::MouseDown {
                    x: 24.0,
                    y: 40.0,
                    right_click: false,
                    tap_count: 1,
                },
                InputEvent::MouseUp {
                    x: 28.0,
                    y: 42.0,
                    double_click: false,
                },
            ])
        );

        // 2) Vertical scrollbar drag near right edge -> replays down + drag cleanly.
        assert_eq!(
            tr.on_event(
                &InputEvent::MouseDown {
                    x: 2030.0,
                    y: 300.0,
                    right_click: false,
                    tap_count: 1,
                },
                size,
                &cfg,
                t0,
            ),
            GestureDecision::Swallow
        );
        let vdrag = tr.on_event(
            &InputEvent::MouseDragged {
                x: 2025.0,
                y: 520.0,
            },
            size,
            &cfg,
            t0 + Duration::from_millis(90),
        );
        assert_eq!(
            vdrag,
            GestureDecision::Replay(vec![
                InputEvent::MouseDown {
                    x: 2030.0,
                    y: 300.0,
                    right_click: false,
                    tap_count: 1,
                },
                InputEvent::MouseDragged {
                    x: 2025.0,
                    y: 520.0,
                },
            ])
        );
    }

    #[test]
    fn center_touch_and_unbound_edge_slot_passthrough_zero_delay() {
        let mut cfg = enabled_cfg();
        cfg.left_top_swipe_right = GestureAction::None;
        let size = (2048, 1536);
        let t0 = Instant::now();
        let mut tr = EdgeGestureTracker::default();

        // Center touch -> immediate Passthrough
        assert_eq!(
            tr.on_event(
                &InputEvent::MouseDown {
                    x: 1024.0,
                    y: 768.0,
                    right_click: false,
                    tap_count: 1,
                },
                size,
                &cfg,
                t0,
            ),
            GestureDecision::Passthrough
        );

        // Unbound left-top edge -> immediate Passthrough (no tap buffering)
        assert_eq!(
            tr.on_event(
                &InputEvent::MouseDown {
                    x: 20.0,
                    y: 200.0,
                    right_click: false,
                    tap_count: 1,
                },
                size,
                &cfg,
                t0,
            ),
            GestureDecision::Passthrough
        );
    }

    #[test]
    fn fast_flick_without_drag_packet_still_triggers_on_mouse_up() {
        let cfg = enabled_cfg();
        let size = (2048, 1536);
        let t0 = Instant::now();
        let mut tr = EdgeGestureTracker::default();

        assert_eq!(
            tr.on_event(
                &InputEvent::MouseDown {
                    x: 2020.0,
                    y: 200.0,
                    right_click: false,
                    tap_count: 1,
                },
                size,
                &cfg,
                t0,
            ),
            GestureDecision::Swallow
        );
        assert_eq!(
            tr.on_event(
                &InputEvent::MouseUp {
                    x: 1850.0,
                    y: 210.0,
                    double_click: false,
                },
                size,
                &cfg,
                t0 + Duration::from_millis(50),
            ),
            GestureDecision::Trigger {
                slot: EdgeGestureSlot::RightTopSwipeLeft,
                action: GestureAction::TogglePause,
                start_x: 2020.0,
                start_y: 200.0,
            }
        );
    }

    #[test]
    fn screenshot_target_path_uses_idis_date_folder_format() {
        let parts = LocalDateTimeParts {
            year: 2026,
            month: 11,
            day: 28,
            hour: 0,
            minute: 35,
            second: 9,
            millis: 42,
        };
        let (dir, file) = build_screenshot_target_path(Path::new("/tmp/shots"), parts, 0);
        assert_eq!(dir, PathBuf::from("/tmp/shots/idis-2026-11-28"));
        assert_eq!(
            file,
            PathBuf::from("/tmp/shots/idis-2026-11-28/idis-20261128-003509-042.png")
        );

        let (_dir2, file2) = build_screenshot_target_path(Path::new("/tmp/shots"), parts, 2);
        assert_eq!(
            file2,
            PathBuf::from("/tmp/shots/idis-2026-11-28/idis-20261128-003509-042-2.png")
        );

        // Verify local_date_time_now returns valid ranges.
        let now = local_date_time_now();
        assert!(now.year >= 2020);
        assert!((1..=12).contains(&now.month));
        assert!((1..=31).contains(&now.day));
    }
}
