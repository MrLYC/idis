use crate::config::AbrSensitivity;
use serde::Serialize;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Ladder of zero-flash network-adaptive quality tiers (0 = full user settings, 4 = weak-network survival).
///
/// All tiers keep `scale_pct = 100` (constant H.264 coded pixel dimensions) and adapt bitrate, QP,
/// and FPS in-place without rebuilding `VTCompressionSession` or mutating H.264 SPS dimensions,
/// preventing legacy iDisplay iOS from tearing down its decoder/OpenGL surface and flashing black.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct AbrTierSpec {
    pub tier: u8,
    pub label: &'static str,
    pub scale_pct: u8,
    pub bitrate_pct: u8,
    pub fps_pct: u8,
}

pub const ABR_LADDER: [AbrTierSpec; 5] = [
    AbrTierSpec {
        tier: 0,
        label: "原画",
        scale_pct: 100,
        bitrate_pct: 100,
        fps_pct: 100,
    },
    AbrTierSpec {
        tier: 1,
        label: "轻度降码率",
        scale_pct: 100,
        bitrate_pct: 65,
        fps_pct: 100,
    },
    AbrTierSpec {
        tier: 2,
        label: "中度降码率",
        scale_pct: 100,
        bitrate_pct: 40,
        fps_pct: 75,
    },
    AbrTierSpec {
        tier: 3,
        label: "低码率保流畅",
        scale_pct: 100,
        bitrate_pct: 25,
        fps_pct: 60,
    },
    AbrTierSpec {
        tier: 4,
        label: "极低码率保流畅",
        scale_pct: 100,
        bitrate_pct: 15,
        fps_pct: 50,
    },
];

pub fn tier_spec(tier: u8) -> AbrTierSpec {
    ABR_LADDER[(tier as usize).min(ABR_LADDER.len() - 1)]
}

/// Concrete streaming parameters derived from base user settings and an ABR tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct AbrTargets {
    pub tier: u8,
    pub scale_pct: u8,
    pub fps: u32,
    pub bitrate_mbps: u32,
    pub max_pixel_edge: u32,
}

impl AbrTargets {
    pub fn compute(
        tier: u8,
        base_fps: u32,
        base_bitrate_mbps: u32,
        base_max_pixel_edge: u32,
    ) -> Self {
        let spec = tier_spec(tier);
        let floor = base_fps.clamp(5, 10);
        let fps = ((base_fps.max(5) * spec.fps_pct as u32 + 50) / 100).clamp(floor, 120);
        let bitrate_mbps =
            ((base_bitrate_mbps.max(2) * spec.bitrate_pct as u32 + 50) / 100).clamp(2, 60);
        let base_edge = (base_max_pixel_edge.max(640)) & !1;
        let max_pixel_edge = if spec.scale_pct >= 100 {
            base_edge
        } else {
            let scaled = (base_edge * spec.scale_pct as u32 + 50) / 100;
            (scaled & !1).clamp(640, base_edge)
        };
        Self {
            tier: spec.tier,
            scale_pct: spec.scale_pct,
            fps,
            bitrate_mbps,
            max_pixel_edge,
        }
    }
}

/// Telemetry sample collected over a 1-second streaming window.
#[derive(Debug, Clone, Copy, Default)]
pub struct AbrWindowSample {
    pub sent_frames: u64,
    pub dropped_frames: u64,
    pub avg_send_ms: f64,
    pub max_send_ms: u64,
    pub avg_ack_rtt_ms: Option<f64>,
    pub in_flight_saturated: bool,
}

/// Live ABR state exposed to `SessionSnapshot` / Web Admin Console.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct AbrStatusSnapshot {
    pub enabled: bool,
    pub tier: u8,
    pub scale_pct: u8,
    pub target_fps: u32,
    pub target_bitrate_mbps: u32,
    pub rtt_ms: Option<u32>,
    pub unfocused_fps_halved: bool,
}

impl Default for AbrStatusSnapshot {
    fn default() -> Self {
        Self {
            enabled: true,
            tier: 0,
            scale_pct: 100,
            target_fps: 30,
            target_bitrate_mbps: 16,
            rtt_ms: None,
            unfocused_fps_halved: false,
        }
    }
}

/// Tunable thresholds derived from [`AbrSensitivity`].
#[derive(Debug, Clone, Copy)]
struct AbrPolicy {
    down_streak_required: u32,
    up_streak_required: u32,
    down_cooldown: Duration,
    up_cooldown: Duration,
    min_drop_total: u64,
    drop_ratio_threshold: f64,
    avg_send_ms_threshold: f64,
    max_send_ms_threshold: u64,
    rtt_with_pressure_ms: f64,
    healthy_max_rtt_ms: f64,
}

impl AbrPolicy {
    fn for_sensitivity(s: AbrSensitivity) -> Self {
        match s {
            AbrSensitivity::Conservative => Self {
                down_streak_required: 4,
                up_streak_required: 6,
                down_cooldown: Duration::from_secs(8),
                up_cooldown: Duration::from_secs(6),
                min_drop_total: 8,
                drop_ratio_threshold: 0.45,
                avg_send_ms_threshold: 55.0,
                max_send_ms_threshold: 220,
                rtt_with_pressure_ms: 240.0,
                healthy_max_rtt_ms: 110.0,
            },
            AbrSensitivity::Balanced => Self {
                down_streak_required: 3,
                up_streak_required: 10,
                down_cooldown: Duration::from_secs(6),
                up_cooldown: Duration::from_secs(8),
                min_drop_total: 6,
                drop_ratio_threshold: 0.35,
                avg_send_ms_threshold: 40.0,
                max_send_ms_threshold: 160,
                rtt_with_pressure_ms: 180.0,
                healthy_max_rtt_ms: 90.0,
            },
            AbrSensitivity::Aggressive => Self {
                down_streak_required: 2,
                up_streak_required: 12,
                down_cooldown: Duration::from_secs(4),
                up_cooldown: Duration::from_secs(10),
                min_drop_total: 6,
                drop_ratio_threshold: 0.25,
                avg_send_ms_threshold: 30.0,
                max_send_ms_threshold: 120,
                rtt_with_pressure_ms: 150.0,
                healthy_max_rtt_ms: 80.0,
            },
        }
    }
}

/// Hysteresis-guarded Adaptive Bitrate & FPS state machine (zero-flash constant pixel resolution).
///
/// - Uses configurable [`AbrSensitivity`] (`Conservative`, `Balanced`, `Aggressive`).
/// - Never treats pure Wi-Fi PSM high RTT (`drops == 0`, low socket write latency, non-saturated
///   in-flight window) as congestion, eliminating false downgrades during unfocused low-FPS viewing.
/// - Ignores completely idle/static desktop windows so stationary screens never trigger false shifts.
pub struct AbrController {
    tier: u8,
    sensitivity: AbrSensitivity,
    congested_streak: u32,
    healthy_streak: u32,
    last_change: Instant,
    /// Timestamp of the most recent step-up probe (`tier -> tier - 1`).
    last_up_at: Option<Instant>,
    /// Consecutive step-up probes that quickly regressed back down (exponential probe backoff
    /// prevents sawtooth thrashing on steady mid-tier bandwidth bottlenecks).
    failed_up_probes: u32,
}

impl AbrController {
    pub fn new(now: Instant) -> Self {
        Self::with_sensitivity(now, AbrSensitivity::Balanced)
    }

    pub fn with_sensitivity(now: Instant, sensitivity: AbrSensitivity) -> Self {
        let past = now
            .checked_sub(Duration::from_secs(60))
            .unwrap_or(now);
        Self {
            tier: 0,
            sensitivity,
            congested_streak: 0,
            healthy_streak: 0,
            last_change: past,
            last_up_at: None,
            failed_up_probes: 0,
        }
    }

    pub fn tier(&self) -> u8 {
        self.tier
    }

    pub fn sensitivity(&self) -> AbrSensitivity {
        self.sensitivity
    }

    pub fn set_sensitivity(&mut self, sensitivity: AbrSensitivity) {
        if self.sensitivity != sensitivity {
            self.sensitivity = sensitivity;
            self.congested_streak = 0;
            self.healthy_streak = 0;
            self.failed_up_probes = 0;
        }
    }

    /// Reset back to Tier 0 (full user quality), e.g. when user updates video settings or disables ABR.
    pub fn reset(&mut self, now: Instant) -> bool {
        let changed = self.tier != 0;
        self.tier = 0;
        self.congested_streak = 0;
        self.healthy_streak = 0;
        self.last_change = now;
        self.last_up_at = None;
        self.failed_up_probes = 0;
        changed
    }

    /// Evaluate a 1-second network/streaming window. Returns `Some(new_tier)` if the tier changed.
    pub fn evaluate(&mut self, sample: &AbrWindowSample, now: Instant) -> Option<u8> {
        let total = sample.sent_frames + sample.dropped_frames;
        // Static desktop with zero traffic: neither congested nor proven healthy enough to step up.
        if total == 0 {
            self.congested_streak = 0;
            return None;
        }

        let policy = AbrPolicy::for_sensitivity(self.sensitivity);
        let drop_ratio = sample.dropped_frames as f64 / total as f64;
        // Pure high RTT with zero drops and fast socket writes is typical of Wi-Fi 802.11 PSM wake
        // latency or healthy pipelining (`in_flight == limit` at steady 45-65ms decode+Wi-Fi RTT).
        // Require real frame drops or socket send pressure before counting RTT as congestion.
        let has_delivery_pressure = sample.dropped_frames > 0 || sample.avg_send_ms >= 15.0;
        let congested = sample.max_send_ms >= policy.max_send_ms_threshold
            || sample.avg_send_ms >= policy.avg_send_ms_threshold
            || (total >= policy.min_drop_total && drop_ratio >= policy.drop_ratio_threshold)
            || (has_delivery_pressure
                && sample
                    .avg_ack_rtt_ms
                    .is_some_and(|rtt| rtt >= policy.rtt_with_pressure_ms));

        if congested {
            self.healthy_streak = 0;
            self.congested_streak = self.congested_streak.saturating_add(1);
            let max_tier = (ABR_LADDER.len() - 1) as u8;
            if self.tier < max_tier
                && self.congested_streak >= policy.down_streak_required
                && now.saturating_duration_since(self.last_change) >= policy.down_cooldown
            {
                // If we just stepped UP within the last 20s and immediately congested again,
                // back off future step-up probes exponentially (1x -> 2x -> 4x) to eliminate sawtooth thrashing.
                if self
                    .last_up_at
                    .is_some_and(|up_ts| now.saturating_duration_since(up_ts) <= Duration::from_secs(20))
                {
                    self.failed_up_probes = (self.failed_up_probes + 1).min(2);
                } else {
                    self.failed_up_probes = 0;
                }
                self.last_up_at = None;
                self.tier += 1;
                self.congested_streak = 0;
                self.last_change = now;
                return Some(self.tier);
            }
            return None;
        }

        self.congested_streak = 0;
        // Clear failed-probe backoff ONLY once a step-up actually held stably for > 20s without stepping down.
        if self.last_up_at == Some(self.last_change)
            && self
                .last_up_at
                .is_some_and(|up_ts| now.saturating_duration_since(up_ts) > Duration::from_secs(20))
        {
            self.failed_up_probes = 0;
        }
        // Mostly-idle desktop (e.g. 1 Hz blinking cursor, 0 drops, unsaturated): neither congested
        // nor enough traffic to prove capacity, so hold recovery streak steady instead of decaying it.
        if sample.sent_frames < 2 && sample.dropped_frames == 0 && !sample.in_flight_saturated {
            return None;
        }
        let healthy = sample.sent_frames >= 2
            && !sample.in_flight_saturated
            && (sample.dropped_frames == 0 || (total >= 12 && drop_ratio < 0.10))
            && sample.avg_send_ms < 20.0
            && sample.max_send_ms < 60
            && sample
                .avg_ack_rtt_ms
                .is_none_or(|rtt| rtt < policy.healthy_max_rtt_ms);

        if healthy {
            self.healthy_streak = self.healthy_streak.saturating_add(1);
            let backoff_mult = 1u32 << self.failed_up_probes;
            let eff_up_streak = policy.up_streak_required.saturating_mul(backoff_mult);
            let eff_up_cooldown = policy.up_cooldown.saturating_mul(backoff_mult);
            if self.tier > 0
                && self.healthy_streak >= eff_up_streak
                && now.saturating_duration_since(self.last_change) >= eff_up_cooldown
            {
                self.tier -= 1;
                self.healthy_streak = 0;
                self.last_change = now;
                self.last_up_at = Some(now);
                return Some(self.tier);
            }
        } else {
            // Borderline window (not congested, not cleanly healthy): decay recovery streak slowly.
            self.healthy_streak = self.healthy_streak.saturating_sub(2);
        }
        None
    }
}

/// Adaptive in-flight video frame window controller (lightweight BDP + queuing-delay guard).
///
/// Separates inherent propagation/decode latency (`min_rtt_ms`) from queuing congestion
/// (`queue_ms = ewma_rtt_ms - min_rtt_ms`):
/// - When the link is clean (low queuing delay & fast socket writes) and baseline RTT requires
///   deeper pipelining to sustain target FPS (e.g. 60fps over Wi-Fi), smoothly expands `max_in_flight`
///   up to `8` (USB capped at `2`) so frames are not artificially starved or misread by ABR.
/// - When queuing delay or send blocking rises (Bufferbloat / Wi-Fi congestion), rapidly shrinks
///   `max_in_flight` down to `1..=2` to drain stale buffered frames and protect low latency.
pub struct InFlightController {
    is_usb: bool,
    limit: u32,
    /// Sliding window of recent active 1s RTT samples (BBR-style windowed `RTprop`) so a single
    /// transient low-RTT outlier expires cleanly within 25s instead of poisoning `min_rtt` for 10+ min.
    rtt_history: VecDeque<f64>,
    congested_streak: u32,
    expand_streak: u32,
    trim_streak: u32,
    last_change: Instant,
}

impl InFlightController {
    pub const USB_MAX_WINDOW: u32 = 2;
    pub const WIFI_MAX_WINDOW: u32 = 8;
    const MIN_RTT_WINDOW: usize = 25;
    const SHRINK_STREAK_REQUIRED: u32 = 2;
    const EXPAND_STREAK_REQUIRED: u32 = 3;
    const TRIM_STREAK_REQUIRED: u32 = 8;
    const SHRINK_COOLDOWN: Duration = Duration::from_secs(3);
    const EXPAND_COOLDOWN: Duration = Duration::from_secs(4);
    const TRIM_COOLDOWN: Duration = Duration::from_secs(6);

    pub const fn max_window_for_transport(is_usb: bool) -> u32 {
        if is_usb {
            Self::USB_MAX_WINDOW
        } else {
            Self::WIFI_MAX_WINDOW
        }
    }

    pub fn new(is_usb: bool, now: Instant) -> Self {
        let past = now
            .checked_sub(Duration::from_secs(60))
            .unwrap_or(now);
        Self {
            is_usb,
            limit: 2,
            rtt_history: VecDeque::with_capacity(Self::MIN_RTT_WINDOW),
            congested_streak: 0,
            expand_streak: 0,
            trim_streak: 0,
            last_change: past,
        }
    }

    fn windowed_min_rtt(&self) -> Option<f64> {
        self.rtt_history
            .iter()
            .copied()
            .reduce(f64::min)
    }

    pub fn limit(&self) -> u32 {
        self.limit
    }

    /// Keep internal state aligned while manual fixed mode is active.
    pub fn sync_manual(&mut self, manual_limit: u32, now: Instant) {
        let max_bound = if self.is_usb {
            Self::USB_MAX_WINDOW
        } else {
            Self::WIFI_MAX_WINDOW
        };
        // Match `SessionRegistry::reset_live_sessions_auto_in_flight()` so returning from manual
        // disabled (`0`) or oversized (`> max_bound`) mode to auto starts both `flow` and
        // `InFlightController` cleanly aligned at `2` (Iter-9 P2-C1).
        self.limit = if manual_limit == 0 || manual_limit > max_bound {
            2
        } else {
            manual_limit
        };
        self.congested_streak = 0;
        self.expand_streak = 0;
        self.trim_streak = 0;
        self.last_change = now;
    }

    /// Evaluate a 1-second window and return `Some(new_limit)` when `max_in_flight` should change.
    pub fn evaluate(
        &mut self,
        sample: &AbrWindowSample,
        target_fps: u32,
        now: Instant,
    ) -> Option<u32> {
        let total = sample.sent_frames + sample.dropped_frames;
        if total == 0 {
            self.congested_streak = 0;
            self.expand_streak = 0;
            return None;
        }
        let max_bound = if self.is_usb {
            Self::USB_MAX_WINDOW
        } else {
            Self::WIFI_MAX_WINDOW
        };

        let queue_ms = if let Some(rtt) = sample.avg_ack_rtt_ms {
            let base = self.windowed_min_rtt().unwrap_or(rtt);
            (rtt - base).max(0.0)
        } else {
            0.0
        };

        // Require genuine delivery pressure (real frame drops or blocking socket writes) before
        // treating high RTT as congestion. Hitting `in_flight == limit` with 0 drops and 0ms socket
        // writes is normal pipelining (not congestion) and must never collapse `max_in_flight` to 1
        // on a Wi-Fi 802.11 PSM wake spike.
        let drop_ratio = sample.dropped_frames as f64 / total as f64;
        let real_drop_pressure = sample.dropped_frames >= 3
            || (sample.dropped_frames > 0 && total >= 4 && drop_ratio >= 0.15);
        let has_delivery_pressure = real_drop_pressure || sample.avg_send_ms >= 15.0;
        // Guard against positive-feedback bufferbloat when already expanded above baseline (`limit > 2`):
        // if saturated queuing delay rises >=55ms above baseline, trim back toward floor=2 (never 1).
        let expanded_queue_bloat = self.limit > 2 && sample.in_flight_saturated && queue_ms >= 55.0;
        // Only collapse `max_in_flight` all the way to 1 when TCP socket writes themselves are
        // blocking or sustained drop pressure coincides with extreme RTT — normal Wi-Fi airtime
        // jitter at `avg_send_ms < 15ms` keeps >=2 frames in flight!
        let severe_congestion = (queue_ms >= 55.0 && sample.avg_send_ms >= 50.0)
            || sample.avg_send_ms >= 80.0
            || sample.max_send_ms >= 180
            || (real_drop_pressure && sample.avg_ack_rtt_ms.is_some_and(|r| r >= 200.0));
        let congested = severe_congestion
            || expanded_queue_bloat
            || (has_delivery_pressure && queue_ms >= 35.0)
            || sample.avg_send_ms >= 45.0
            || sample.max_send_ms >= 120
            || (has_delivery_pressure && sample.avg_ack_rtt_ms.is_some_and(|r| r >= 140.0));

        // Only feed non-congested RTT samples into `rtt_history` so sustained queuing bloat never
        // ratchets `windowed_min_rtt()` upward and triggers runaway expansion!
        if !congested {
            if let Some(rtt) = sample.avg_ack_rtt_ms {
                if self.rtt_history.len() >= Self::MIN_RTT_WINDOW {
                    self.rtt_history.pop_front();
                }
                self.rtt_history.push_back(rtt);
            }
        }

        if congested {
            self.expand_streak = 0;
            self.trim_streak = 0;
            self.congested_streak = self.congested_streak.saturating_add(1);
            let floor = if severe_congestion { 1 } else { 2.min(max_bound) };
            if self.limit > floor
                && self.congested_streak >= Self::SHRINK_STREAK_REQUIRED
                && now.saturating_duration_since(self.last_change) >= Self::SHRINK_COOLDOWN
            {
                self.limit -= 1;
                self.congested_streak = 0;
                self.last_change = now;
                return Some(self.limit);
            }
            return None;
        }

        self.congested_streak = 0;
        // Allow up to 20ms natural RTT spread on Wi-Fi (16.7ms 60Hz VSync quantization + airtime
        // variance) while keeping 12ms tight bound on USB.
        let clean_queue_cap = if self.is_usb { 12.0 } else { 20.0 };
        let clean_link = queue_ms < clean_queue_cap
            && sample.avg_send_ms < 18.0
            && sample.max_send_ms < 50
            && sample.sent_frames >= 3;

        if !clean_link {
            self.expand_streak = 0;
            self.trim_streak = self.trim_streak.saturating_sub(1);
            return None;
        }

        let base_rtt_ms = self
            .windowed_min_rtt()
            .unwrap_or(if self.is_usb { 10.0 } else { 20.0 });
        let fps = target_fps.clamp(10, 120) as f64;
        // Little's law pipeline depth from clean baseline RTT (+2 frame jitter headroom at >=45fps
        // on Wi-Fi so 60fps at 45-65ms RTT reaches 5-6 in-flight without starving on 67ms jitter).
        let min_healthy = 2.min(max_bound);
        let headroom = if !self.is_usb && fps >= 45.0 { 2 } else { 1 };
        let ideal = (((fps * (base_rtt_ms / 1000.0)).ceil() as u32) + headroom)
            .clamp(min_healthy, max_bound);

        if self.limit < ideal {
            self.trim_streak = 0;
            // Expand when pipeline is visibly needed (saturated / drops / actively streaming >=45fps)
            // or below healthy baseline floor (2), avoiding blind expansion on idle 60fps desktops.
            let high_fps_active = fps >= 45.0 && sample.sent_frames >= 35;
            let needs_depth = self.limit < 2
                || sample.in_flight_saturated
                || sample.dropped_frames > 0
                || high_fps_active;
            if needs_depth {
                self.expand_streak = self.expand_streak.saturating_add(1);
                if self.expand_streak >= Self::EXPAND_STREAK_REQUIRED
                    && now.saturating_duration_since(self.last_change) >= Self::EXPAND_COOLDOWN
                {
                    self.limit = (self.limit + 1).min(ideal);
                    self.expand_streak = 0;
                    self.last_change = now;
                    return Some(self.limit);
                }
            }
        } else if self.limit > ideal {
            self.expand_streak = 0;
            self.trim_streak = self.trim_streak.saturating_add(1);
            if self.trim_streak >= Self::TRIM_STREAK_REQUIRED
                && now.saturating_duration_since(self.last_change) >= Self::TRIM_COOLDOWN
            {
                self.limit = (self.limit - 1).max(ideal);
                self.trim_streak = 0;
                self.last_change = now;
                return Some(self.limit);
            }
        } else {
            self.expand_streak = 0;
            self.trim_streak = 0;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abr_degrades_on_sustained_congestion_and_recovers_with_hysteresis() {
        let t0 = Instant::now();
        let mut abr = AbrController::new(t0); // Balanced default
        let congested = AbrWindowSample {
            sent_frames: 10,
            dropped_frames: 6,
            avg_send_ms: 75.0,
            max_send_ms: 180,
            avg_ack_rtt_ms: Some(210.0),
            in_flight_saturated: true,
        };
        let healthy = AbrWindowSample {
            sent_frames: 20,
            dropped_frames: 0,
            avg_send_ms: 4.0,
            max_send_ms: 12,
            avg_ack_rtt_ms: Some(18.0),
            in_flight_saturated: false,
        };

        // Single transient spike must NOT degrade immediately
        assert_eq!(abr.evaluate(&congested, t0 + Duration::from_secs(1)), None);
        assert_eq!(abr.evaluate(&healthy, t0 + Duration::from_secs(2)), None);
        assert_eq!(abr.tier(), 0);

        // Balanced requires 3 consecutive congested windows to step down to Tier 1
        assert_eq!(abr.evaluate(&congested, t0 + Duration::from_secs(3)), None);
        assert_eq!(abr.evaluate(&congested, t0 + Duration::from_secs(4)), None);
        assert_eq!(
            abr.evaluate(&congested, t0 + Duration::from_secs(5)),
            Some(1)
        );

        // 6s cooldown prevents instant multi-tier collapse
        assert_eq!(abr.evaluate(&congested, t0 + Duration::from_secs(6)), None);
        assert_eq!(abr.evaluate(&congested, t0 + Duration::from_secs(7)), None);
        assert_eq!(abr.evaluate(&congested, t0 + Duration::from_secs(10)), None);
        assert_eq!(
            abr.evaluate(&congested, t0 + Duration::from_secs(11)),
            Some(2)
        );

        // Sustained congestion walks down through Tier 3 -> Tier 4 while keeping 100% pixel scale
        for s in 12..=35 {
            let _ = abr.evaluate(&congested, t0 + Duration::from_secs(s));
        }
        assert_eq!(abr.tier(), 4);
        assert_eq!(tier_spec(abr.tier()).scale_pct, 100);

        // Static desktop (0 frames) must NOT flap tier up or down
        let idle = AbrWindowSample::default();
        for s in 36..55 {
            assert_eq!(abr.evaluate(&idle, t0 + Duration::from_secs(s)), None);
        }
        assert_eq!(abr.tier(), 4);

        // 10 consecutive healthy active windows step up 4 -> 3 in Balanced mode
        let mut t = 55u64;
        for _ in 0..9 {
            assert_eq!(abr.evaluate(&healthy, t0 + Duration::from_secs(t)), None);
            t += 1;
        }
        assert_eq!(
            abr.evaluate(&healthy, t0 + Duration::from_secs(t)),
            Some(3)
        );
    }

    #[test]
    fn abr_targets_preserve_constant_resolution_and_minimums() {
        let t0 = AbrTargets::compute(0, 30, 16, 2048);
        assert_eq!((t0.fps, t0.bitrate_mbps, t0.max_pixel_edge), (30, 16, 2048));

        let t1 = AbrTargets::compute(1, 30, 16, 2048);
        assert_eq!((t1.fps, t1.bitrate_mbps, t1.max_pixel_edge), (30, 10, 2048));

        // Zero-flash Option A: ALL tiers preserve 100% pixel resolution (no VT rebuild / iPad flash)
        for tier in 0..=4 {
            let t = AbrTargets::compute(tier, 30, 16, 2048);
            assert_eq!(t.scale_pct, 100, "tier {tier} must keep 100% pixel resolution");
            assert_eq!(t.max_pixel_edge, 2048, "tier {tier} must keep constant max_pixel_edge");
            assert!(t.bitrate_mbps >= 2 && t.fps >= 10);
        }

        let t4 = AbrTargets::compute(4, 15, 4, 1024);
        assert_eq!(t4.max_pixel_edge, 1024);
        assert!(t4.bitrate_mbps >= 2 && t4.fps >= 10);
    }

    #[test]
    fn in_flight_controller_adapts_wifi_pipeline_and_shrinks_on_bufferbloat() {
        let t0 = Instant::now();
        let mut wifi = InFlightController::new(false, t0);
        assert_eq!(wifi.limit(), 2);

        // Clean 60fps Wi-Fi with 40ms baseline RTT: ideal = ceil(60*0.04) + 2 = 5 -> expands 2 -> 3 -> 4
        let clean_60 = AbrWindowSample {
            sent_frames: 40,
            dropped_frames: 2,
            avg_send_ms: 4.0,
            max_send_ms: 12,
            avg_ack_rtt_ms: Some(40.0),
            in_flight_saturated: true,
        };
        assert_eq!(wifi.evaluate(&clean_60, 60, t0 + Duration::from_secs(1)), None);
        assert_eq!(wifi.evaluate(&clean_60, 60, t0 + Duration::from_secs(2)), None);
        assert_eq!(wifi.evaluate(&clean_60, 60, t0 + Duration::from_secs(3)), Some(3));
        assert_eq!(wifi.evaluate(&clean_60, 60, t0 + Duration::from_secs(5)), None);
        assert_eq!(wifi.evaluate(&clean_60, 60, t0 + Duration::from_secs(6)), None);
        assert_eq!(wifi.evaluate(&clean_60, 60, t0 + Duration::from_secs(7)), Some(4));

        // Bufferbloat: RTT jumps from 40ms baseline to 100ms (+60ms queuing delay) -> shrinks down to 1
        let bloated = AbrWindowSample {
            sent_frames: 20,
            dropped_frames: 5,
            avg_send_ms: 65.0,
            max_send_ms: 150,
            avg_ack_rtt_ms: Some(100.0),
            in_flight_saturated: true,
        };
        assert_eq!(wifi.evaluate(&bloated, 60, t0 + Duration::from_secs(9)), None);
        assert_eq!(wifi.evaluate(&bloated, 60, t0 + Duration::from_secs(10)), Some(3));
        assert_eq!(wifi.evaluate(&bloated, 60, t0 + Duration::from_secs(12)), None);
        assert_eq!(wifi.evaluate(&bloated, 60, t0 + Duration::from_secs(13)), Some(2));
        assert_eq!(wifi.evaluate(&bloated, 60, t0 + Duration::from_secs(15)), None);
        assert_eq!(wifi.evaluate(&bloated, 60, t0 + Duration::from_secs(16)), Some(1));

        // USB stays capped at 2 even at 60fps
        let mut usb = InFlightController::new(true, t0);
        for s in 1..20 {
            assert_eq!(usb.evaluate(&clean_60, 60, t0 + Duration::from_secs(s)), None);
        }
        assert_eq!(usb.limit(), 2);
    }

    #[test]
    fn abr_ignores_wifi_psm_high_rtt_without_drops_and_respects_sensitivity() {
        let t0 = Instant::now();
        // Unfocused low-FPS Wi-Fi PSM wakeup latency: 0 drops, 0ms socket send, not saturated,
        // high RTT (220ms). Must NEVER trigger ABR downgrade under ANY sensitivity mode!
        let wifi_psm = AbrWindowSample {
            sent_frames: 11,
            dropped_frames: 0,
            avg_send_ms: 0.0,
            max_send_ms: 0,
            avg_ack_rtt_ms: Some(220.0),
            in_flight_saturated: false,
        };
        for sens in [
            AbrSensitivity::Conservative,
            AbrSensitivity::Balanced,
            AbrSensitivity::Aggressive,
        ] {
            let mut abr = AbrController::with_sensitivity(t0, sens);
            for s in 1..=20 {
                assert_eq!(
                    abr.evaluate(&wifi_psm, t0 + Duration::from_secs(s)),
                    None,
                    "zero-drop Wi-Fi PSM high RTT must never trigger downgrade for {sens:?}"
                );
            }
            assert_eq!(abr.tier(), 0);
        }

        // Moderate congestion (32% drops, 35ms avg send): Aggressive reacts in 2s, Conservative holds!
        let moderate = AbrWindowSample {
            sent_frames: 11,
            dropped_frames: 5,
            avg_send_ms: 35.0,
            max_send_ms: 130,
            avg_ack_rtt_ms: Some(155.0),
            in_flight_saturated: true,
        };
        let mut aggr = AbrController::with_sensitivity(t0, AbrSensitivity::Aggressive);
        let mut cons = AbrController::with_sensitivity(t0, AbrSensitivity::Conservative);
        assert_eq!(aggr.evaluate(&moderate, t0 + Duration::from_secs(1)), None);
        assert_eq!(aggr.evaluate(&moderate, t0 + Duration::from_secs(2)), Some(1));
        for s in 1..=10 {
            assert_eq!(
                cons.evaluate(&moderate, t0 + Duration::from_secs(s)),
                None,
                "Conservative ABR must ignore moderate transient jitter"
            );
        }
        assert_eq!(cons.tier(), 0);
    }

    #[test]
    fn in_flight_controller_recovers_from_transient_low_rtt_outlier() {
        let t0 = Instant::now();
        let mut wifi = InFlightController::new(false, t0);
        // Single bogus 7.4ms RTT sample followed by steady clean 65ms Wi-Fi RTT must expire
        // within the 25s sliding window and expand back up to 4 instead of pinning at 2 for 10min.
        let outlier = AbrWindowSample {
            sent_frames: 45,
            dropped_frames: 0,
            avg_send_ms: 1.0,
            max_send_ms: 4,
            avg_ack_rtt_ms: Some(7.4),
            in_flight_saturated: false,
        };
        let _ = wifi.evaluate(&outlier, 60, t0 + Duration::from_secs(1));

        let steady_65 = AbrWindowSample {
            sent_frames: 45,
            dropped_frames: 0,
            avg_send_ms: 1.5,
            max_send_ms: 8,
            avg_ack_rtt_ms: Some(65.0),
            in_flight_saturated: true,
        };
        for s in 2..=55 {
            let _ = wifi.evaluate(&steady_65, 60, t0 + Duration::from_secs(s));
        }
        assert!(
            wifi.limit() >= 5 && wifi.limit() <= InFlightController::WIFI_MAX_WINDOW,
            "transient 7.4ms RTT outlier must expire within 25s and expand 60fps@65ms RTT window >=5 (got {})",
            wifi.limit()
        );
    }

    #[test]
    fn in_flight_controller_ignores_saturated_wifi_psm_spike_and_expands_60fps_wifi_to_6() {
        let t0 = Instant::now();
        let mut wifi = InFlightController::new(false, t0);
        let mut abr = AbrController::with_sensitivity(t0, AbrSensitivity::Balanced);

        // Live-device scenario: 60fps over Wi-Fi with 48-60ms natural VSync+decode RTT jitter
        // (12ms spread) and fast socket writes must expand above 4 (to >=5, up to 8).
        for s in 1..=30u64 {
            let rtt = if s % 2 == 0 { 48.0 } else { 60.0 };
            let sample = AbrWindowSample {
                sent_frames: 58,
                dropped_frames: 0,
                avg_send_ms: 0.5,
                max_send_ms: 4,
                avg_ack_rtt_ms: Some(rtt),
                in_flight_saturated: true,
            };
            let _ = wifi.evaluate(&sample, 60, t0 + Duration::from_secs(s));
            assert_eq!(
                abr.evaluate(&sample, t0 + Duration::from_secs(s)),
                None,
                "healthy 60fps pipelining must never trigger ABR downgrade"
            );
        }
        assert!(
            wifi.limit() >= 5,
            "60fps Wi-Fi at 48-60ms RTT must expand beyond old cap 4 (got {})",
            wifi.limit()
        );

        // Wi-Fi PSM wakeup spike: avg_send=0.0ms, drops=0, rtt=235ms, EVEN with in_flight_saturated=true
        // must NEVER collapse max_in_flight to 1 or trigger ABR downgrade (expanded_queue_bloat may
        // gently trim toward floor=2, never below 2)!
        for s in 31..=45u64 {
            let psm = AbrWindowSample {
                sent_frames: 25,
                dropped_frames: 0,
                avg_send_ms: 0.0,
                max_send_ms: 1,
                avg_ack_rtt_ms: Some(235.0),
                in_flight_saturated: true,
            };
            let _ = wifi.evaluate(&psm, 30, t0 + Duration::from_secs(s));
            assert_eq!(abr.evaluate(&psm, t0 + Duration::from_secs(s)), None);
            assert!(
                wifi.limit() >= 2,
                "zero-drop zero-send-stall Wi-Fi PSM spike must never collapse max_in_flight below 2 (got {})",
                wifi.limit()
            );
        }
    }

    #[test]
    fn abr_targets_preserve_low_user_configured_fps_floor() {
        // P1-B4: user explicitly configuring 5..=9 fps must NOT be silently boosted to 10 fps.
        for base_fps in 5..=9 {
            let t0 = AbrTargets::compute(0, base_fps, 8, 1920);
            assert_eq!(t0.fps, base_fps, "Tier 0 must preserve user base_fps={base_fps}");
            let t4 = AbrTargets::compute(4, base_fps, 8, 1920);
            assert_eq!(
                t4.fps, base_fps,
                "Tier 4 must not exceed user base_fps={base_fps} or drop below 5"
            );
        }
        // Standard 30fps still respects the 10fps ABR safety floor at Tier 4 (50% -> 15fps)
        assert_eq!(AbrTargets::compute(4, 30, 16, 1920).fps, 15);
        assert_eq!(AbrTargets::compute(4, 15, 16, 1920).fps, 10);

        // Iter-9 P2-C1: sync_manual with oversized manual limit (12 on Wi-Fi / 4 on USB) resets to 2
        // matching SessionRegistry's auto baseline!
        let now = Instant::now();
        let mut wifi_ctrl = InFlightController::new(false, now);
        wifi_ctrl.sync_manual(12, now);
        assert_eq!(wifi_ctrl.limit(), 2);
        let mut usb_ctrl = InFlightController::new(true, now);
        usb_ctrl.sync_manual(4, now);
        assert_eq!(usb_ctrl.limit(), 2);
    }
}
