//! Shared O(1) fMP4 WebSocket muxer (Scheme 3) + WebRTC DataChannel shallow P2P relay hub (Scheme 1).
//!
//! Together these two layers eliminate both per-viewer CPU/memory duplication and O(N) host upload
//! bandwidth when many LAN browsers watch `/view` simultaneously:
//! 1. [`SharedWebMuxer`] muxes each captured H.264 Annex-B IDR frame **once** into a unified fMP4
//!    timeline (`tfdt`) and pre-frames the RFC 6455 binary WebSocket wire bytes into `Arc<Vec<u8>>`.
//!    All direct viewers reuse the exact same bytes in O(1) with zero copying.
//! 2. [`P2pRelayHub`] coordinates a shallow LAN WebRTC DataChannel relay tree (default: 1
//!    server-fed root viewer, fanout 3 for desktop / 2 for mobile fallback, max depth 3)
//!    using the existing authenticated WebSocket for JSON signaling. Because every node shares
//!    [`SharedWebMuxer`]'s single continuous fMP4 timeline, switching between WS Direct <-> P2P
//!    Parent <-> WS Fallback is seamless without resetting MediaSource.

use crate::fmp4::Fmp4Muxer;
use crate::platform::{EncodedFrame, FrameWaker};
use serde::Serialize;
use std::cmp::Reverse;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Number of viewers kept on direct server WebSocket video feed to act as the P2P tree root.
/// Setting this to `1` allows P2P relaying to kick in immediately starting from 2 viewers (saving 50% host upload).
pub const MAX_DIRECT_ROOTS: usize = 1;
/// Maximum number of downstream P2P children relayed by a desktop browser viewer.
pub const MAX_P2P_FANOUT: usize = 3;
/// Maximum number of downstream P2P children relayed by a foreground mobile/tablet fallback root.
pub const MOBILE_P2P_FANOUT: usize = 2;
/// Ring capacity for [`SharedWebMuxer`] so slower viewers lagging 1-11 frames at 60fps (~200ms)
/// still hit O(1) shared fMP4 packets without breaking DPB or triggering IDR storms.
const MUX_RING_CAPACITY: usize = 12;
/// Maximum tree depth (`0` = server-fed root, `1..=3` = P2P relays/leaves).
pub const MAX_P2P_DEPTH: u8 = 3;
/// Maximum accepted signaling JSON frame size from a WebSocket viewer (32 KiB).
pub const MAX_SIGNAL_PAYLOAD_BYTES: usize = 32 * 1024;

/// Build an unmasked server->client RFC 6455 WebSocket frame with a 1-byte message prefix in a
/// single allocation (avoids intermediate `prefix || payload` copy on the hot video mux path).
pub fn build_ws_frame_with_prefix(opcode: u8, prefix: u8, payload: &[u8]) -> Vec<u8> {
    let len = 1 + payload.len();
    let hdr_len = if len < 126 {
        2
    } else if len <= u16::MAX as usize {
        4
    } else {
        10
    };
    let mut out = Vec::with_capacity(hdr_len + len);
    out.push(0x80 | (opcode & 0x0F));
    if len < 126 {
        out.push(len as u8);
    } else if len <= u16::MAX as usize {
        out.push(126);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    out.push(prefix);
    out.extend_from_slice(payload);
    out
}

/// Pre-muxed, pre-framed fMP4 segment shared across all WebSocket viewers in O(1).
#[derive(Debug)]
pub struct MuxedWsPacket {
    /// Monotonic source frame sequence number from `SessionRegistry`.
    pub seq: u64,
    /// Timeline epoch (incremented when capture source switches or cache resets).
    pub epoch: u64,
    /// Monotonic init-segment generation (incremented on SPS/PPS/resolution change).
    pub init_gen: u64,
    pub source: &'static str,
    /// Producer `web_source_epoch` tag from `SessionRegistry` (prevents stale pre-lock / old-iPad
    /// IDR seeding across same-source epoch transitions; Iter-6 P1-B2).
    pub source_epoch: u64,
    pub codec: String,
    pub width: u32,
    pub height: u32,
    pub fps: u32,
    pub is_keyframe: bool,
    /// Pre-framed RFC 6455 binary frame (`opcode=0x2`) wrapping `0x01 || ftyp+moov`.
    pub init_ws_frame: Arc<Vec<u8>>,
    /// Pre-framed RFC 6455 binary frame (`opcode=0x2`) wrapping `(0x02 IDR | 0x03 P-frame) || moof+mdat`.
    pub media_ws_frame: Arc<Vec<u8>>,
}

struct SharedMuxInner {
    muxer: Fmp4Muxer,
    source: &'static str,
    source_epoch: u64,
    epoch: u64,
    init_gen: u64,
    last_init_ws_frame: Option<Arc<Vec<u8>>>,
    recent_packets: VecDeque<Arc<MuxedWsPacket>>,
    last_idr_packet: Option<Arc<MuxedWsPacket>>,
}

/// Global single-muxer cache shared by all browser viewers.
pub struct SharedWebMuxer {
    inner: Mutex<SharedMuxInner>,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl Default for SharedWebMuxer {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedWebMuxer {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(SharedMuxInner {
                muxer: Fmp4Muxer::new(30),
                source: "",
                source_epoch: 0,
                epoch: 1,
                init_gen: 0,
                last_init_ws_frame: None,
                recent_packets: VecDeque::with_capacity(MUX_RING_CAPACITY),
                last_idr_packet: None,
            }),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Mux `frame` once for `frame_seq`, or return the already-muxed & pre-framed `Arc<MuxedWsPacket>`
    /// from the bounded 12-frame ring buffer. Enforces monotonic `frame_seq` so a viewer lagging
    /// more than 12 frames behind never re-muxes a stale frame into the shared timeline.
    pub fn mux_or_get(
        &self,
        frame_seq: u64,
        source: &'static str,
        source_epoch: u64,
        fps: u32,
        frame: &EncodedFrame,
    ) -> Option<Arc<MuxedWsPacket>> {
        let mut g = self.inner.lock().unwrap();
        if let Some(hit) = g
            .recent_packets
            .iter()
            .rev()
            .find(|p| p.source == source && p.source_epoch == source_epoch && p.seq == frame_seq)
        {
            self.hits.fetch_add(1, Ordering::Relaxed);
            return Some(hit.clone());
        }
        // Strictly reject frames from an older source_epoch so late pre-switch/pre-lock frames
        // can NEVER roll back the shared muxer timeline or wipe newer epoch packets.
        if g.source_epoch > 0 && source_epoch < g.source_epoch {
            return None;
        }
        let same_timeline = g.source == source && g.source_epoch == source_epoch;
        if same_timeline {
            if let Some(newest) = g.recent_packets.back() {
                if frame_seq < newest.seq {
                    return None;
                }
            }
        }
        let eff_fps = fps.max(1);
        if !same_timeline {
            // Never reset the shared muxer or wipe recent packets/last_idr_packet on a stale
            // non-IDR P-frame during a source/epoch transition; wait for an IDR from the new epoch.
            if !frame.is_keyframe {
                return None;
            }
            g.muxer = Fmp4Muxer::new(eff_fps);
            g.source = source;
            g.source_epoch = source_epoch;
            g.epoch = g.epoch.saturating_add(1);
            g.last_init_ws_frame = None;
            g.recent_packets.clear();
            g.last_idr_packet = None;
        } else {
            g.muxer.set_fps(eff_fps);
        }

        let chunk = g.muxer.mux_frame(frame.width, frame.height, &frame.annex_b)?;
        if let Some(init) = chunk.init_segment {
            g.last_init_ws_frame = Some(Arc::new(build_ws_frame_with_prefix(0x2, 0x01, &init)));
            g.init_gen = g.init_gen.saturating_add(1);
        }
        let init_ws_frame = g.last_init_ws_frame.clone()?;

        let media_tag = if chunk.is_keyframe { 0x02 } else { 0x03 };
        let media_ws_frame = Arc::new(build_ws_frame_with_prefix(
            0x2,
            media_tag,
            &chunk.media_segment,
        ));

        let pkt = Arc::new(MuxedWsPacket {
            seq: frame_seq,
            epoch: g.epoch,
            init_gen: g.init_gen,
            source,
            source_epoch,
            codec: chunk.codec,
            width: frame.width,
            height: frame.height,
            fps: eff_fps,
            is_keyframe: chunk.is_keyframe,
            init_ws_frame,
            media_ws_frame,
        });
        if chunk.is_keyframe {
            g.last_idr_packet = Some(pkt.clone());
        }
        if g.recent_packets.len() >= MUX_RING_CAPACITY {
            g.recent_packets.pop_front();
        }
        g.recent_packets.push_back(pkt.clone());
        self.misses.fetch_add(1, Ordering::Relaxed);
        Some(pkt)
    }

    /// Seed the muxer cache with a static cached IDR ONLY when the cache is currently empty
    /// (e.g. first Web viewer joining an already-idle iPad session), without ever advancing
    /// `recent_packets` seq or overwriting a live stream timeline.
    pub fn seed_if_empty(
        &self,
        source: &'static str,
        source_epoch: u64,
        fps: u32,
        frame: &EncodedFrame,
    ) -> Option<Arc<MuxedWsPacket>> {
        if !frame.is_keyframe {
            return None;
        }
        let mut g = self.inner.lock().unwrap();
        // Never allow an older source_epoch seed to clobber a newer live timeline.
        if g.source_epoch > 0 && source_epoch < g.source_epoch {
            return None;
        }
        if let Some(ref idr) = g.last_idr_packet {
            if g.source == source && g.source_epoch == source_epoch {
                return Some(idr.clone());
            }
        }
        if !g.recent_packets.is_empty() && g.source == source && g.source_epoch == source_epoch {
            return g.last_idr_packet.clone();
        }
        let eff_fps = fps.max(1);
        g.muxer = Fmp4Muxer::new(eff_fps);
        g.source = source;
        g.source_epoch = source_epoch;
        g.epoch = g.epoch.saturating_add(1);
        g.last_init_ws_frame = None;
        g.recent_packets.clear();
        g.last_idr_packet = None;

        let chunk = g.muxer.mux_frame(frame.width, frame.height, &frame.annex_b)?;
        if !chunk.is_keyframe {
            return None;
        }
        if let Some(init) = chunk.init_segment {
            g.last_init_ws_frame = Some(Arc::new(build_ws_frame_with_prefix(0x2, 0x01, &init)));
            g.init_gen = g.init_gen.saturating_add(1);
        }
        let init_ws_frame = g.last_init_ws_frame.clone()?;
        let media_ws_frame = Arc::new(build_ws_frame_with_prefix(0x2, 0x02, &chunk.media_segment));
        let pkt = Arc::new(MuxedWsPacket {
            seq: 0,
            epoch: g.epoch,
            init_gen: g.init_gen,
            source,
            source_epoch,
            codec: chunk.codec,
            width: frame.width,
            height: frame.height,
            fps: eff_fps,
            is_keyframe: true,
            init_ws_frame,
            media_ws_frame,
        });
        g.last_idr_packet = Some(pkt.clone());
        g.recent_packets.push_back(pkt.clone());
        self.misses.fetch_add(1, Ordering::Relaxed);
        Some(pkt)
    }

    /// Return the most recent muxed IDR packet matching BOTH `source` and `source_epoch`
    /// (prevents stale pre-lock / old-iPad IDR flashes even when `source` string stays identical).
    pub fn latest_packet_for_source(
        &self,
        source: &str,
        source_epoch: u64,
    ) -> Option<Arc<MuxedWsPacket>> {
        let g = self.inner.lock().unwrap();
        g.last_idr_packet
            .as_ref()
            .filter(|p| p.source == source && p.source_epoch == source_epoch)
            .cloned()
    }

    /// Return the most recent muxed IDR packet (safe instant fallback when a P2P parent drops
    /// without injecting a broken P-frame into the browser MSE decoder).
    #[allow(dead_code)]
    pub fn latest_packet(&self) -> Option<Arc<MuxedWsPacket>> {
        self.inner.lock().unwrap().last_idr_packet.clone()
    }

    /// Reset muxer timeline and hit/miss counters when all Web viewers have disconnected.
    pub fn reset(&self) {
        let mut g = self.inner.lock().unwrap();
        g.muxer = Fmp4Muxer::new(30);
        g.source = "";
        g.source_epoch = 0;
        g.epoch = g.epoch.saturating_add(1);
        g.last_init_ws_frame = None;
        g.recent_packets.clear();
        g.last_idr_packet = None;
        self.hits.store(0, Ordering::Relaxed);
        self.misses.store(0, Ordering::Relaxed);
    }

    /// Return `(cache_hits, mux_operations)`.
    pub fn stats(&self) -> (u64, u64) {
        (
            self.hits.load(Ordering::Relaxed),
            self.misses.load(Ordering::Relaxed),
        )
    }

    /// Inspect internal `(source, source_epoch, mux_epoch, ring_len)` for deterministic fuzz/shadow tests.
    pub fn debug_state(&self) -> (&'static str, u64, u64, usize) {
        let g = self.inner.lock().unwrap();
        (g.source, g.source_epoch, g.epoch, g.recent_packets.len())
    }
}

/// Per-viewer P2P status shown in the Web Admin Console.
#[derive(Debug, Clone, Serialize)]
pub struct ViewerP2pSnapshot {
    /// `"root"`, `"relay"`, `"leaf"`, or `"direct"`.
    pub p2p_role: &'static str,
    pub p2p_parent_id: Option<u64>,
    pub p2p_children: usize,
    pub p2p_active: bool,
    pub p2p_depth: u8,
    pub p2p_supported: bool,
    pub p2p_can_relay: bool,
    pub p2p_relay_priority: u8,
    pub p2p_fallback_count: u32,
    pub p2p_fallback_reason: Option<String>,
}

/// Aggregate Web P2P + shared-muxer telemetry shown in the Web Admin Console.
#[derive(Debug, Clone, Serialize)]
pub struct WebP2pSummary {
    pub enabled: bool,
    pub total_viewers: usize,
    pub direct_viewers: usize,
    pub p2p_viewers: usize,
    pub relay_capable_viewers: usize,
    pub bandwidth_saved_pct: u8,
    pub mux_hits: u64,
    pub mux_misses: u64,
    pub inactive_reason: Option<String>,
}

struct P2pPeerNode {
    supported: bool,
    /// `0` = cannot relay (hidden/unsupported), `1` = mobile foreground fallback (fanout <=2),
    /// `2` = desktop foreground preferred relay (fanout <=3).
    relay_priority: u8,
    parent_id: Option<u64>,
    children: Vec<u64>,
    depth: u8,
    p2p_active: bool,
    ws_direct_paused: Arc<AtomicBool>,
    sig_tx: mpsc::SyncSender<String>,
    frame_waker: FrameWaker,
    /// Map of `parent_id -> (failed_at, consecutive_fail_count)` for exponential retry backoff.
    avoid_parents: HashMap<u64, (Instant, u32)>,
    /// Parent-side recent child fallback timestamps; if >= 2 children fall back within 30s,
    /// demote this parent for 30s so a blackholed root cannot keep trapping new viewers.
    recent_child_fallbacks: Vec<Instant>,
    parent_cooldown_until: Option<Instant>,
    fallback_count: u32,
    last_fallback_reason: Option<String>,
}

impl P2pPeerNode {
    fn can_relay(&self) -> bool {
        self.supported && self.relay_priority > 0
    }

    fn is_in_parent_cooldown(&self, now: Instant) -> bool {
        self.parent_cooldown_until.is_some_and(|until| now < until)
    }

    fn max_fanout(&self) -> usize {
        if self.relay_priority >= 2 {
            MAX_P2P_FANOUT
        } else if self.relay_priority == 1 {
            MOBILE_P2P_FANOUT
        } else {
            0
        }
    }
}

const AVOID_PARENT_BASE_SECS: u64 = 30;
const PERIODIC_REBALANCE_INTERVAL: Duration = Duration::from_secs(10);

fn avoid_ttl_for_failures(fail_count: u32) -> Duration {
    let shift = fail_count.saturating_sub(1).min(2); // 30s -> 60s -> 120s
    Duration::from_secs(AVOID_PARENT_BASE_SECS << shift)
}

/// Coordinates a shallow WebRTC DataChannel relay tree among authenticated LAN `/view` browsers.
pub struct P2pRelayHub {
    enabled: AtomicBool,
    nodes: Mutex<HashMap<u64, P2pPeerNode>>,
    join_order: Mutex<Vec<u64>>,
    last_periodic_rebalance: Mutex<Instant>,
}

impl Default for P2pRelayHub {
    fn default() -> Self {
        Self::new(true)
    }
}

impl P2pRelayHub {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled: AtomicBool::new(enabled),
            nodes: Mutex::new(HashMap::new()),
            join_order: Mutex::new(Vec::new()),
            last_periodic_rebalance: Mutex::new(Instant::now()),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    /// Periodic rebalance hook called from WebSocket heartbeats so expired `avoid_parents`
    /// backoff entries automatically retry P2P instead of deadlocking forever on direct WS.
    pub fn maybe_rebalance_periodic(&self) {
        if !self.is_enabled() {
            return;
        }
        {
            let mut last = self.last_periodic_rebalance.lock().unwrap();
            if last.elapsed() < PERIODIC_REBALANCE_INTERVAL {
                return;
            }
            *last = Instant::now();
        }
        let mut nodes = self.nodes.lock().unwrap();
        let order = self.join_order.lock().unwrap();
        if nodes.len() >= 2 {
            self.rebalance_locked(&mut nodes, &order);
        }
    }

    /// Toggle LAN P2P relaying at runtime. Disabling immediately restores WS video for all viewers.
    pub fn set_enabled(&self, enabled: bool) {
        let prev = self.enabled.swap(enabled, Ordering::AcqRel);
        if prev == enabled {
            return;
        }
        info!("Runtime setting updated: web p2p_relay_enabled={enabled}");
        let mut nodes = self.nodes.lock().unwrap();
        let order = self.join_order.lock().unwrap();
        if !enabled {
            for node in nodes.values_mut() {
                node.parent_id = None;
                node.children.clear();
                node.depth = 0;
                node.p2p_active = false;
                node.avoid_parents.clear();
                node.ws_direct_paused.store(false, Ordering::Release);
                Self::send_json(
                    node,
                    serde_json::json!({ "type": "p2p_reset", "enabled": false }),
                );
            }
        } else {
            for node in nodes.values_mut() {
                node.avoid_parents.clear();
            }
            self.rebalance_locked(&mut nodes, &order);
        }
    }

    /// Register a newly connected WebSocket viewer. Returns its `ws_direct_paused` flag (starts `false`).
    pub fn register(
        &self,
        viewer_id: u64,
        sig_tx: mpsc::SyncSender<String>,
        frame_waker: FrameWaker,
    ) -> Arc<AtomicBool> {
        let ws_direct_paused = Arc::new(AtomicBool::new(false));
        let node = P2pPeerNode {
            supported: false,
            relay_priority: 0,
            parent_id: None,
            children: Vec::new(),
            depth: 0,
            p2p_active: false,
            ws_direct_paused: ws_direct_paused.clone(),
            sig_tx,
            frame_waker,
            avoid_parents: HashMap::new(),
            recent_child_fallbacks: Vec::new(),
            parent_cooldown_until: None,
            fallback_count: 0,
            last_fallback_reason: None,
        };
        let mut nodes = self.nodes.lock().unwrap();
        let mut order = self.join_order.lock().unwrap();
        nodes.insert(viewer_id, node);
        if !order.contains(&viewer_id) {
            order.push(viewer_id);
        }
        ws_direct_paused
    }

    /// Unregister a disconnected viewer, immediately restoring WS video for any downstream children,
    /// and atomically invoking `on_empty` under the hub lock if zero viewers remain.
    pub fn unregister_and_maybe_reset<F: FnOnce()>(&self, viewer_id: u64, on_empty: F) -> usize {
        let mut nodes = self.nodes.lock().unwrap();
        let mut order = self.join_order.lock().unwrap();
        order.retain(|&id| id != viewer_id);
        let Some(removed) = nodes.remove(&viewer_id) else {
            return nodes.len();
        };

        // Detach from its parent.
        if let Some(pid) = removed.parent_id {
            if let Some(parent) = nodes.get_mut(&pid) {
                parent.children.retain(|&c| c != viewer_id);
                Self::send_json(
                    parent,
                    serde_json::json!({ "type": "p2p_remove_child", "child_id": viewer_id }),
                );
            }
        }

        // Release all children back to direct WS immediately so playback never stalls.
        for cid in removed.children {
            if let Some(child) = nodes.get_mut(&cid) {
                child.parent_id = None;
                child.depth = 0;
                child.p2p_active = false;
                child.ws_direct_paused.store(false, Ordering::Release);
                Self::send_json(child, serde_json::json!({ "type": "p2p_parent_lost" }));
            }
        }
        // Clear stale avoid entries referencing this dead viewer.
        for node in nodes.values_mut() {
            node.avoid_parents.remove(&viewer_id);
        }
        Self::recompute_depths_locked(&mut nodes);

        if nodes.is_empty() {
            on_empty();
        } else if self.is_enabled() {
            self.rebalance_locked(&mut nodes, &order);
        }
        nodes.len()
    }

    /// Unregister a disconnected viewer, immediately restoring WS video for any downstream children.
    #[cfg(test)]
    pub fn unregister(&self, viewer_id: u64) -> usize {
        self.unregister_and_maybe_reset(viewer_id, || {})
    }

    /// Handle client `p2p_hello` announcing WebRTC support and relay eligibility.
    #[allow(dead_code)]
    pub fn on_hello(&self, viewer_id: u64, supported: bool, can_relay: bool) {
        self.on_hello_with_priority(viewer_id, supported, if can_relay { 2 } else { 0 });
    }

    /// Handle client `p2p_hello` with explicit relay priority (`0`=none, `1`=mobile fallback, `2`=desktop).
    pub fn on_hello_with_priority(&self, viewer_id: u64, supported: bool, relay_priority: u8) {
        let mut nodes = self.nodes.lock().unwrap();
        let order = self.join_order.lock().unwrap();
        let (children_to_release, detached_parent) = {
            let Some(node) = nodes.get_mut(&viewer_id) else {
                return;
            };
            node.supported = supported;
            node.relay_priority = if supported { relay_priority.min(2) } else { 0 };
            let _ = Self::send_json(
                node,
                serde_json::json!({
                    "type": "p2p_welcome",
                    "viewer_id": viewer_id,
                    "enabled": self.is_enabled(),
                }),
            );
            info!(
                "[p2p] viewer #{viewer_id} hello (supported={}, relay_priority={})",
                node.supported, node.relay_priority
            );
            let allowed_fanout = node.max_fanout();
            let excess = if node.children.len() > allowed_fanout {
                node.children.split_off(allowed_fanout)
            } else {
                Vec::new()
            };
            for &cid in &excess {
                let _ = Self::send_json(
                    node,
                    serde_json::json!({ "type": "p2p_remove_child", "child_id": cid }),
                );
            }
            let detached_parent = if !node.supported {
                node.p2p_active = false;
                node.depth = 0;
                node.ws_direct_paused.store(false, Ordering::Release);
                node.frame_waker.wake();
                node.parent_id.take()
            } else {
                None
            };
            (excess, detached_parent)
        };
        if let Some(pid) = detached_parent {
            if let Some(parent) = nodes.get_mut(&pid) {
                parent.children.retain(|&c| c != viewer_id);
                let _ = Self::send_json(
                    parent,
                    serde_json::json!({ "type": "p2p_remove_child", "child_id": viewer_id }),
                );
            }
        }
        for cid in children_to_release {
            if let Some(child) = nodes.get_mut(&cid) {
                child.parent_id = None;
                child.depth = 0;
                child.p2p_active = false;
                child.ws_direct_paused.store(false, Ordering::Release);
                let _ = Self::send_json(child, serde_json::json!({ "type": "p2p_parent_lost" }));
            }
        }
        Self::recompute_depths_locked(&mut nodes);
        if self.is_enabled() {
            self.rebalance_locked(&mut nodes, &order);
        }
    }

    /// Handle client `p2p_caps` (e.g. tab hidden -> `can_relay = false` or tab visible -> `true`).
    #[allow(dead_code)]
    pub fn on_caps_update(&self, viewer_id: u64, can_relay: bool) {
        self.on_caps_update_with_priority(viewer_id, if can_relay { 2 } else { 0 });
    }

    /// Handle client `p2p_caps` with explicit relay priority (`0`=none, `1`=mobile fallback, `2`=desktop).
    pub fn on_caps_update_with_priority(&self, viewer_id: u64, relay_priority: u8) {
        let mut nodes = self.nodes.lock().unwrap();
        let order = self.join_order.lock().unwrap();
        let children_to_release: Vec<u64> = {
            let Some(node) = nodes.get_mut(&viewer_id) else {
                return;
            };
            let next_prio = if node.supported {
                relay_priority.min(2)
            } else {
                0
            };
            if node.relay_priority == next_prio {
                return;
            }
            node.relay_priority = next_prio;
            let allowed_fanout = node.max_fanout();
            if node.children.len() > allowed_fanout {
                let kids = node.children.split_off(allowed_fanout);
                for &cid in &kids {
                    Self::send_json(
                        node,
                        serde_json::json!({ "type": "p2p_remove_child", "child_id": cid }),
                    );
                }
                kids
            } else {
                Vec::new()
            }
        };

        for cid in children_to_release {
            if let Some(child) = nodes.get_mut(&cid) {
                child.parent_id = None;
                child.depth = 0;
                child.p2p_active = false;
                child.ws_direct_paused.store(false, Ordering::Release);
                Self::send_json(child, serde_json::json!({ "type": "p2p_parent_lost" }));
            }
        }
        Self::recompute_depths_locked(&mut nodes);
        if self.is_enabled() {
            self.rebalance_locked(&mut nodes, &order);
        }
    }

    /// Child confirms live P2P frames are flowing from `parent_id` -> pause server WS video push.
    pub fn on_p2p_active(&self, viewer_id: u64, parent_id: u64) {
        if !self.is_enabled() {
            return;
        }
        let mut nodes = self.nodes.lock().unwrap();
        let order = self.join_order.lock().unwrap();
        let parent_exists = nodes.contains_key(&parent_id);
        if !parent_exists {
            return;
        }
        let mut became_active = false;
        if let Some(node) = nodes.get_mut(&viewer_id) {
            if node.parent_id == Some(parent_id) {
                if !node.p2p_active {
                    became_active = true;
                }
                node.p2p_active = true;
                node.last_fallback_reason = None;
                node.ws_direct_paused.store(true, Ordering::Release);
                info!(
                    "[p2p] viewer #{viewer_id} switched to P2P stream from parent #{parent_id} (WS video offloaded)"
                );
            }
        }
        if became_active {
            self.rebalance_locked(&mut nodes, &order);
        }
    }

    /// Child reports P2P stall/failure -> immediately resume direct WS video and try another parent.
    pub fn on_p2p_fallback(&self, viewer_id: u64, reason: &str) {
        self.on_p2p_fallback_at(viewer_id, reason, Instant::now());
    }

    pub fn on_p2p_fallback_at(&self, viewer_id: u64, reason: &str, now: Instant) {
        let mut nodes = self.nodes.lock().unwrap();
        let order = self.join_order.lock().unwrap();
        let old_parent = {
            let Some(node) = nodes.get_mut(&viewer_id) else {
                return;
            };
            let prev = node.parent_id.take();
            if let Some(pid) = prev {
                let prev_count = node.avoid_parents.get(&pid).map(|(_, c)| *c).unwrap_or(0);
                node.avoid_parents
                    .insert(pid, (now, prev_count.saturating_add(1)));
            }
            node.fallback_count = node.fallback_count.saturating_add(1);
            node.last_fallback_reason = Some(reason.to_string());
            node.depth = 0;
            node.p2p_active = false;
            node.ws_direct_paused.store(false, Ordering::Release);
            node.frame_waker.wake();
            prev
        };
        if let Some(pid) = old_parent {
            if let Some(parent) = nodes.get_mut(&pid) {
                parent.children.retain(|&c| c != viewer_id);
                parent
                    .recent_child_fallbacks
                    .retain(|&ts| now.saturating_duration_since(ts) < Duration::from_secs(30));
                parent.recent_child_fallbacks.push(now);
                if parent.recent_child_fallbacks.len() >= 2 {
                    parent.parent_cooldown_until = Some(now + Duration::from_secs(30));
                }
                let _ = Self::send_json(
                    parent,
                    serde_json::json!({ "type": "p2p_remove_child", "child_id": viewer_id }),
                );
            }
            info!(
                "[p2p] viewer #{viewer_id} fell back to WS direct (prev parent #{pid}, reason={reason:?})"
            );
        }
        Self::recompute_depths_locked(&mut nodes);
        if self.is_enabled() {
            self.rebalance_locked_at(&mut nodes, &order, now);
        }
    }

    /// Forward WebRTC SDP/ICE signaling only across an active parent-child edge in the tree.
    pub fn route_signal(&self, from_id: u64, to_id: u64, signal: serde_json::Value) -> bool {
        if !self.is_enabled() || from_id == to_id {
            return false;
        }
        let nodes = self.nodes.lock().unwrap();
        let Some(from_node) = nodes.get(&from_id) else {
            return false;
        };
        let Some(to_node) = nodes.get(&to_id) else {
            return false;
        };
        let is_edge =
            from_node.parent_id == Some(to_id) || to_node.parent_id == Some(from_id);
        if !is_edge {
            return false;
        }
        Self::send_json(
            to_node,
            serde_json::json!({
                "type": "p2p_signal",
                "from": from_id,
                "signal": signal,
            }),
        );
        true
    }

    pub fn viewer_snapshot(&self, viewer_id: u64) -> ViewerP2pSnapshot {
        let nodes = self.nodes.lock().unwrap();
        if let Some(n) = nodes.get(&viewer_id) {
            let role = if n.parent_id.is_none() {
                if !n.children.is_empty() {
                    "root"
                } else {
                    "direct"
                }
            } else if !n.children.is_empty() {
                "relay"
            } else {
                "leaf"
            };
            ViewerP2pSnapshot {
                p2p_role: role,
                p2p_parent_id: n.parent_id,
                p2p_children: n.children.len(),
                p2p_active: n.p2p_active,
                p2p_depth: n.depth,
                p2p_supported: n.supported,
                p2p_can_relay: n.can_relay(),
                p2p_relay_priority: n.relay_priority,
                p2p_fallback_count: n.fallback_count,
                p2p_fallback_reason: n.last_fallback_reason.clone(),
            }
        } else {
            ViewerP2pSnapshot {
                p2p_role: "direct",
                p2p_parent_id: None,
                p2p_children: 0,
                p2p_active: false,
                p2p_depth: 0,
                p2p_supported: false,
                p2p_can_relay: false,
                p2p_relay_priority: 0,
                p2p_fallback_count: 0,
                p2p_fallback_reason: None,
            }
        }
    }

    pub fn summary(&self, mux_hits: u64, mux_misses: u64) -> WebP2pSummary {
        let nodes = self.nodes.lock().unwrap();
        let total = nodes.len();
        let p2p_viewers = nodes.values().filter(|n| n.p2p_active).count();
        let direct_viewers = total.saturating_sub(p2p_viewers);
        let relay_capable_viewers = nodes.values().filter(|n| n.can_relay()).count();
        let saved_pct = (p2p_viewers * 100).checked_div(total).unwrap_or(0) as u8;
        let enabled = self.is_enabled();
        let inactive_reason = if enabled && total >= 2 && p2p_viewers == 0 {
            if nodes.values().all(|n| !n.supported) {
                Some("浏览器不支持 WebRTC".to_string())
            } else if relay_capable_viewers == 0 {
                Some("无可用前台/中继节点".to_string())
            } else if nodes.values().any(|n| n.parent_id.is_some()) {
                Some("WebRTC 握手中".to_string())
            } else if let Some(reason) = nodes
                .values()
                .find_map(|n| n.last_fallback_reason.as_deref())
            {
                let label = match reason {
                    "connect_timeout" => "ICE/mDNS 连接超时（将自动重试）",
                    "stall_timeout" => "中继卡顿回退直连（将自动重试）",
                    other => other,
                };
                Some(label.to_string())
            } else {
                Some("等待周期重平衡".to_string())
            }
        } else {
            None
        };
        WebP2pSummary {
            enabled,
            total_viewers: total,
            direct_viewers,
            p2p_viewers,
            relay_capable_viewers,
            bandwidth_saved_pct: saved_pct,
            mux_hits,
            mux_misses,
            inactive_reason,
        }
    }

    fn send_json(node: &P2pPeerNode, val: serde_json::Value) -> bool {
        let ok = match node.sig_tx.try_send(val.to_string()) {
            Ok(()) => true,
            Err(e) => {
                warn!("[p2p] outbound signaling channel saturated/closed: {e}");
                false
            }
        };
        node.frame_waker.wake();
        ok
    }

    fn is_ancestor(nodes: &HashMap<u64, P2pPeerNode>, candidate_ancestor: u64, mut node_id: u64) -> bool {
        let mut hops = 0usize;
        while let Some(pid) = nodes.get(&node_id).and_then(|n| n.parent_id) {
            if pid == candidate_ancestor {
                return true;
            }
            node_id = pid;
            hops += 1;
            if hops > 32 {
                return true;
            }
        }
        false
    }

    fn recompute_depths_locked(nodes: &mut HashMap<u64, P2pPeerNode>) {
        let ids: Vec<u64> = nodes.keys().copied().collect();
        let mut computed: HashMap<u64, u8> = HashMap::with_capacity(ids.len());
        for &id in &ids {
            let mut depth = 0u8;
            let mut cur = id;
            let mut hops = 0usize;
            while let Some(pid) = nodes.get(&cur).and_then(|n| n.parent_id) {
                depth = depth.saturating_add(1);
                cur = pid;
                hops += 1;
                if hops > 32 {
                    break;
                }
            }
            computed.insert(id, depth);
        }
        for (id, d) in computed {
            if let Some(n) = nodes.get_mut(&id) {
                n.depth = d;
            }
        }
    }

    fn subtree_height(nodes: &HashMap<u64, P2pPeerNode>, node_id: u64, guard: u8) -> u8 {
        if guard > 16 {
            return 16;
        }
        let Some(node) = nodes.get(&node_id) else {
            return 0;
        };
        let mut max_child = 0u8;
        for &cid in &node.children {
            let h = 1u8.saturating_add(Self::subtree_height(nodes, cid, guard + 1));
            if h > max_child {
                max_child = h;
            }
        }
        max_child
    }

    pub fn rebalance_at(&self, now: Instant) {
        if !self.is_enabled() {
            return;
        }
        let mut nodes = self.nodes.lock().unwrap();
        let order = self.join_order.lock().unwrap();
        self.rebalance_locked_at(&mut nodes, &order, now);
    }

    /// Verify all structural forest invariants on the live P2P relay graph (used by fuzz/property tests).
    pub fn check_invariants(&self) -> Result<(), String> {
        let nodes = self.nodes.lock().unwrap();
        for (&id, node) in nodes.iter() {
            if node.children.len() > node.max_fanout() {
                return Err(format!(
                    "node #{id} fanout overflow: children={} > max_fanout={}",
                    node.children.len(),
                    node.max_fanout()
                ));
            }
            if node.depth > MAX_P2P_DEPTH {
                return Err(format!(
                    "node #{id} depth overflow: depth={} > MAX_P2P_DEPTH={MAX_P2P_DEPTH}",
                    node.depth
                ));
            }
            let paused = node.ws_direct_paused.load(Ordering::Acquire);
            if paused != node.p2p_active {
                return Err(format!(
                    "node #{id} ws_direct_paused ({paused}) != p2p_active ({})",
                    node.p2p_active
                ));
            }
            if node.parent_id.is_none() && paused {
                return Err(format!("node #{id} has no parent but ws_direct_paused=true"));
            }
            if let Some(pid) = node.parent_id {
                let Some(parent) = nodes.get(&pid) else {
                    return Err(format!("node #{id} points to missing parent #{pid}"));
                };
                if !parent.children.contains(&id) {
                    return Err(format!(
                        "asymmetric edge: node #{id}.parent_id=Some({pid}) but parent missing child"
                    ));
                }
                if Self::is_ancestor(&nodes, id, pid) {
                    return Err(format!("cycle detected involving node #{id} and parent #{pid}"));
                }
            }
            for &cid in &node.children {
                let Some(child) = nodes.get(&cid) else {
                    return Err(format!("node #{id} references missing child #{cid}"));
                };
                if child.parent_id != Some(id) {
                    return Err(format!(
                        "asymmetric edge: node #{id} lists child #{cid} with parent_id={:?}",
                        child.parent_id
                    ));
                }
            }
        }
        Ok(())
    }

    /// Assign P2P parents to eligible viewers beyond `MAX_DIRECT_ROOTS` while preserving low depth.
    fn rebalance_locked(&self, nodes: &mut HashMap<u64, P2pPeerNode>, order: &[u64]) {
        self.rebalance_locked_at(nodes, order, Instant::now());
    }

    fn rebalance_locked_at(
        &self,
        nodes: &mut HashMap<u64, P2pPeerNode>,
        order: &[u64],
        now: Instant,
    ) {
        for node in nodes.values_mut() {
            node.avoid_parents
                .retain(|_, (ts, count)| now.saturating_duration_since(*ts) < avoid_ttl_for_failures(*count));
        }
        Self::recompute_depths_locked(nodes);
        // Select direct roots: prefer higher relay priority (desktop=2 before mobile fallback=1),
        // breaking ties by oldest join order.
        let mut direct_roots: Vec<(usize, u64)> = order
            .iter()
            .enumerate()
            .filter_map(|(idx, &id)| {
                nodes
                    .get(&id)
                    .filter(|n| {
                        n.parent_id.is_none() && n.can_relay() && !n.is_in_parent_cooldown(now)
                    })
                    .map(|_| (idx, id))
            })
            .collect();
        direct_roots.sort_by_key(|&(idx, id)| (Reverse(nodes[&id].relay_priority), idx));
        direct_roots.truncate(MAX_DIRECT_ROOTS);
        let root_set: HashSet<u64> = direct_roots.into_iter().map(|(_, id)| id).collect();

        // Any other supported viewer currently without a parent should try to attach to a healthy parent.
        let unassigned: Vec<u64> = order
            .iter()
            .copied()
            .filter(|id| {
                !root_set.contains(id)
                    && nodes
                        .get(id)
                        .is_some_and(|n| n.supported && n.parent_id.is_none())
            })
            .collect();

        for cid in unassigned {
            let cid_height = Self::subtree_height(nodes, cid, 0);
            // Only pick a parent that is either a direct root (`parent_id == None`) or an already-active
            // P2P relay (`p2p_active == true`) with spare fanout and enough depth headroom for cid's subtree.
            let best_parent = order
                .iter()
                .copied()
                .filter(|&pid| {
                    if pid == cid {
                        return false;
                    }
                    let Some(p) = nodes.get(&pid) else {
                        return false;
                    };
                    let Some(c) = nodes.get(&cid) else {
                        return false;
                    };
                    if !p.can_relay()
                        || p.is_in_parent_cooldown(now)
                        || p.children.len() >= p.max_fanout()
                        || p.depth.saturating_add(1).saturating_add(cid_height) > MAX_P2P_DEPTH
                        || c.avoid_parents.contains_key(&pid)
                    {
                        return false;
                    }
                    let parent_is_live = p.parent_id.is_none() || p.p2p_active;
                    if !parent_is_live {
                        return false;
                    }
                    !Self::is_ancestor(nodes, cid, pid)
                })
                .min_by_key(|&pid| {
                    let p = &nodes[&pid];
                    // Prefer shallower depth, then desktop over mobile fallback, then fewest children.
                    (p.depth, Reverse(p.relay_priority), p.children.len(), pid)
                });

            if let Some(pid) = best_parent {
                let child_depth = nodes[&pid].depth.saturating_add(1);
                let parent_accepted = if let Some(parent) = nodes.get_mut(&pid) {
                    if Self::send_json(
                        parent,
                        serde_json::json!({ "type": "p2p_add_child", "child_id": cid }),
                    ) {
                        parent.children.push(cid);
                        true
                    } else {
                        // Saturated/dead signaling queue: demote parent instead of committing a broken edge.
                        parent.parent_cooldown_until = Some(now + Duration::from_secs(30));
                        false
                    }
                } else {
                    false
                };
                if !parent_accepted {
                    continue;
                }
                let child_accepted = if let Some(child) = nodes.get_mut(&cid) {
                    if Self::send_json(
                        child,
                        serde_json::json!({ "type": "p2p_assign_parent", "parent_id": pid }),
                    ) {
                        child.parent_id = Some(pid);
                        child.depth = child_depth;
                        child.p2p_active = false;
                        // Keep WS direct active until child confirms first P2P frame (`p2p_active`).
                        child.ws_direct_paused.store(false, Ordering::Release);
                        true
                    } else {
                        false
                    }
                } else {
                    false
                };
                if !child_accepted {
                    if let Some(parent) = nodes.get_mut(&pid) {
                        parent.children.retain(|&c| c != cid);
                        let _ = Self::send_json(
                            parent,
                            serde_json::json!({ "type": "p2p_remove_child", "child_id": cid }),
                        );
                    }
                    continue;
                }
                Self::recompute_depths_locked(nodes);
                debug!("[p2p] assigned viewer #{cid} -> parent #{pid} (depth={child_depth})");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::latest_frame_channel;
    use crate::platform::mock::SYNTHETIC_H264_ANNEX_B;

    fn make_test_frame(w: u32, h: u32) -> EncodedFrame {
        EncodedFrame {
            width: w,
            height: h,
            bytes_per_row: w * 4,
            annex_b: SYNTHETIC_H264_ANNEX_B.to_vec(),
            is_keyframe: true,
        }
    }

    #[test]
    fn shared_web_muxer_deduplicates_frames_and_resets_on_source_change() {
        let cache = SharedWebMuxer::new();
        let f1 = make_test_frame(1280, 720);

        let p1 = cache.mux_or_get(1, "standalone", 1, 30, &f1).unwrap();
        assert_eq!(cache.stats(), (0, 1));
        assert!(p1.init_ws_frame.len() > 10);
        assert!(p1.media_ws_frame.len() > 10);

        // Next 5 viewers reading the exact same frame sequence hit O(1) cache with identical Arc pointers
        for _ in 0..5 {
            let p_hit = cache.mux_or_get(1, "standalone", 1, 30, &f1).unwrap();
            assert!(Arc::ptr_eq(&p1, &p_hit));
        }
        assert_eq!(cache.stats(), (5, 1));

        // Next frame increments mux count once
        let p2 = cache.mux_or_get(2, "standalone", 1, 30, &f1).unwrap();
        assert_eq!(p2.epoch, p1.epoch);
        assert_eq!(p2.init_gen, p1.init_gen);
        assert_eq!(cache.stats(), (5, 2));

        // Switching capture source resets fMP4 timeline and bumps epoch + init_gen
        let p3 = cache.mux_or_get(3, "ipad", 2, 30, &f1).unwrap();
        assert!(p3.epoch > p2.epoch);
        assert!(p3.init_gen > p2.init_gen);

        // Iter-6 P1-B2: latest_packet_for_source MUST require matching source_epoch!
        assert!(cache.latest_packet_for_source("ipad", 2).is_some());
        assert!(
            cache.latest_packet_for_source("ipad", 3).is_none(),
            "stale pre-lock/old-iPad IDR must never be served for a newer source_epoch"
        );
    }

    #[test]
    fn p2p_relay_tree_offloads_viewers_handles_parent_loss_and_prevents_cycles() {
        let hub = P2pRelayHub::new(true);
        let mut rxs = HashMap::new();
        let mut paused_flags = HashMap::new();

        for id in 1..=6u64 {
            let (sig_tx, sig_rx) = mpsc::sync_channel(32);
            let (_ftx, frx) = latest_frame_channel();
            let flag = hub.register(id, sig_tx, frx.waker());
            rxs.insert(id, sig_rx);
            paused_flags.insert(id, flag);
        }

        // Viewer 1 is the direct server-fed root; starting from viewer 2, P2P relay attaches immediately!
        hub.on_hello(1, true, true);
        assert_eq!(hub.viewer_snapshot(1).p2p_parent_id, None);

        hub.on_hello(2, true, true);
        assert_eq!(
            hub.viewer_snapshot(2).p2p_parent_id,
            Some(1),
            "2nd viewer should immediately attach to root #1 for 2-viewer P2P offload"
        );
        assert_eq!(hub.viewer_snapshot(2).p2p_depth, 1);

        hub.on_hello(3, true, true);
        hub.on_hello(4, true, true);
        hub.on_hello(5, true, true);
        hub.on_hello(6, true, false); // mobile leaf-only

        // Viewers 2..4 attach directly to root #1 (fanout=3)
        for id in 2..=4 {
            let snap = hub.viewer_snapshot(id);
            assert_eq!(snap.p2p_parent_id, Some(1));
            assert_eq!(snap.p2p_depth, 1);
            // WS video must stay active until child confirms P2P frames arrived!
            assert!(!paused_flags[&id].load(Ordering::Acquire));
        }

        // Confirm P2P active for depth-1 relays (2..4) -> WS video offloaded on server!
        for id in 2..=4 {
            let pid = hub.viewer_snapshot(id).p2p_parent_id.unwrap();
            assert!(hub.route_signal(id, pid, serde_json::json!({ "sdp": "offer" })));
            hub.on_p2p_active(id, pid);
            assert!(paused_flags[&id].load(Ordering::Acquire));
        }
        // Trigger rebalance for remaining viewers (5, 6) now that depth-1 relays are live
        hub.on_caps_update(5, false);
        hub.on_caps_update(5, true);
        for id in 5..=6 {
            if let Some(pid) = hub.viewer_snapshot(id).p2p_parent_id {
                assert!(matches!(pid, 2..=4));
                hub.on_p2p_active(id, pid);
                assert!(paused_flags[&id].load(Ordering::Acquire));
            }
        }
        // Signaling between non-adjacent peers (e.g. 2 -> 3) must be rejected
        assert!(!hub.route_signal(2, 3, serde_json::json!({ "sdp": "spoof" })));

        let sum = hub.summary(100, 20);
        assert_eq!(sum.total_viewers, 6);
        assert!(sum.direct_viewers <= 2);
        assert!(sum.p2p_viewers >= 4);
        assert!(sum.bandwidth_saved_pct >= 66);

        // Root 1 disconnects -> its children immediately unpause WS direct and promote/reassign!
        let children_of_1: Vec<u64> = (2..=6)
            .filter(|id| hub.viewer_snapshot(*id).p2p_parent_id == Some(1))
            .collect();
        assert!(!children_of_1.is_empty());
        hub.unregister(1);
        for cid in &children_of_1 {
            assert!(!paused_flags[cid].load(Ordering::Acquire));
            // Should be promoted/reassigned without ever attaching to leaf-only viewer #6
            let new_pid = hub.viewer_snapshot(*cid).p2p_parent_id;
            assert_ne!(new_pid, Some(1));
            assert_ne!(new_pid, Some(6));
        }

        // Disabling P2P immediately restores all viewers to direct WS
        hub.set_enabled(false);
        for id in 2..=6 {
            assert!(!paused_flags[&id].load(Ordering::Acquire));
            assert_eq!(hub.viewer_snapshot(id).p2p_parent_id, None);
        }
    }

    #[test]
    fn shared_web_muxer_ring_handles_lagging_viewer_and_resets_stats() {
        let cache = SharedWebMuxer::new();
        let f = make_test_frame(1280, 720);
        let p1 = cache.mux_or_get(1, "ipad", 1, 60, &f).unwrap();
        let p2 = cache.mux_or_get(2, "ipad", 1, 60, &f).unwrap();
        let _p3 = cache.mux_or_get(3, "ipad", 1, 60, &f).unwrap();
        // Slower viewer requesting seq=1 while fast viewer already advanced to seq=3 still hits ring!
        let slow_hit1 = cache.mux_or_get(1, "ipad", 1, 60, &f).unwrap();
        let slow_hit2 = cache.mux_or_get(2, "ipad", 1, 60, &f).unwrap();
        assert!(Arc::ptr_eq(&p1, &slow_hit1));
        assert!(Arc::ptr_eq(&p2, &slow_hit2));
        assert_eq!(cache.stats(), (2, 3));

        cache.reset();
        assert_eq!(cache.stats(), (0, 0));
    }

    #[test]
    fn p2p_hub_mobile_fallback_relay_and_periodic_rebalance_after_fallback() {
        let hub = P2pRelayHub::new(true);
        let mut _sig_rxs = Vec::new();
        for id in 1..=3u64 {
            let (sig_tx, sig_rx) = mpsc::sync_channel(32);
            let (_ftx, frx) = latest_frame_channel();
            hub.register(id, sig_tx, frx.waker());
            _sig_rxs.push(sig_rx);
        }
        // All 3 viewers are foreground mobile (priority=1): viewer #1 becomes fallback root (fanout=2)
        hub.on_hello_with_priority(1, true, 1);
        hub.on_hello_with_priority(2, true, 1);
        hub.on_hello_with_priority(3, true, 1);
        assert_eq!(hub.viewer_snapshot(1).p2p_parent_id, None);
        assert_eq!(hub.viewer_snapshot(2).p2p_parent_id, Some(1));
        assert_eq!(hub.viewer_snapshot(3).p2p_parent_id, Some(1));

        // Viewer #2 fails once -> enters avoid_parents with reason recorded
        hub.on_p2p_fallback(2, "connect_timeout");
        assert_eq!(hub.viewer_snapshot(2).p2p_parent_id, None);
        assert_eq!(
            hub.viewer_snapshot(2).p2p_fallback_reason.as_deref(),
            Some("connect_timeout")
        );
        // Expire avoid entry & periodic timer in-place and verify periodic rebalance re-attaches #2
        {
            let mut nodes = hub.nodes.lock().unwrap();
            let expired = Instant::now() - Duration::from_secs(60);
            nodes.get_mut(&2).unwrap().avoid_parents.insert(1, (expired, 1));
        }
        *hub.last_periodic_rebalance.lock().unwrap() = Instant::now() - Duration::from_secs(30);
        hub.maybe_rebalance_periodic();
        assert_eq!(
            hub.viewer_snapshot(2).p2p_parent_id,
            Some(1),
            "periodic rebalance must recover viewer #2 after avoid backoff expires"
        );
    }
}
