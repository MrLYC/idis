//! Tier 0 4D Pareto-Frontier QoE Fuzz Suite (`\vec{Q} = (Q_lat, Q_vis, Q_pwr, Q_dpb)`):
//! Strictly logical-clock, zero `thread::sleep`, zero TCP sockets, deterministic seeded.
//!
//! Covers:
//! 1. Coupled closed-loop `AbrController` + `InFlightController` + Wi-Fi/TCP Link Plant
//! 2. Logical-clock `FlowControl` anti-deadlock & RTT expiry invariants
//! 3. Differential `AnnexBSplitter` + `Fmp4Muxer::mux_frame_at` chunking & `tfdt` monotonicity
//! 4. `SharedWebMuxer` cross-source & monotonic-epoch invariants
//! 5. `P2pRelayHub` 64-viewer topology churn (acyclicity, depth <= 3, fanout bounds, zero orphans)

mod common {
    pub mod fuzz;
}

use common::fuzz::{fuzz_seeds, FuzzRng};
use idis::abr::{AbrController, AbrTargets, AbrWindowSample, InFlightController};
use idis::config::AbrSensitivity;
use idis::fmp4::Fmp4Muxer;
use idis::platform::mock::SYNTHETIC_H264_ANNEX_B;
use idis::platform::{latest_frame_channel, EncodedFrame};
use idis::protocol::annexb::{is_self_contained_idr, AnnexBSplitter};
use idis::session::FlowControl;
use idis::web::fuzz_hooks::P2pRelayHub;
use idis::web::SharedWebMuxer;
use std::sync::mpsc::sync_channel;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy)]
enum LinkRegime {
    CleanLan,
    WifiPsmSparse,
    BlinkingCursorIdle,
    ModerateCongestion,
    SevereBufferbloat,
}

#[test]
fn fuzz_coupled_abr_and_inflight_pareto_frontier() {
    let t0 = Instant::now();

    // 1. Hard Pareto Oracle: Wi-Fi PSM high RTT (160..240ms) with 0 drops and fast socket writes
    //    MUST NOT cause EITHER `InFlightController` to collapse to 1 OR `AbrController` to downgrade!
    for sens in [
        AbrSensitivity::Conservative,
        AbrSensitivity::Balanced,
        AbrSensitivity::Aggressive,
    ] {
        let mut abr = AbrController::with_sensitivity(t0, sens);
        let mut ifc = InFlightController::new(false, t0);
        for sec in 1..=60u64 {
            let now = t0 + Duration::from_secs(sec);
            let psm_sample = AbrWindowSample {
                sent_frames: 6,
                dropped_frames: 0,
                avg_send_ms: 2.0,
                max_send_ms: 8,
                avg_ack_rtt_ms: Some(210.0),
                in_flight_saturated: false,
            };
            let _ = ifc.evaluate(&psm_sample, 30, now);
            let _ = abr.evaluate(&psm_sample, now);
            assert!(
                ifc.limit() >= 2,
                "Wi-Fi PSM false in_flight collapse (sens={sens:?}, sec={sec}, limit={})",
                ifc.limit()
            );
            assert_eq!(
                abr.tier(),
                0,
                "Wi-Fi PSM false ABR downgrade (sens={sens:?}, sec={sec}, tier={})",
                abr.tier()
            );
        }
    }

    // 2. Hard Pareto Oracle: Step congestion -> recovery under 1Hz blinking-cursor idle pauses
    //    must recover back to Tier 0 within <= 90s and keep `scale_pct == 100` at every tier.
    {
        let mut abr = AbrController::with_sensitivity(t0, AbrSensitivity::Balanced);
        for s in 1..=25u64 {
            let congested = AbrWindowSample {
                sent_frames: 10,
                dropped_frames: 15,
                avg_send_ms: 70.0,
                max_send_ms: 190,
                avg_ack_rtt_ms: Some(220.0),
                in_flight_saturated: true,
            };
            let _ = abr.evaluate(&congested, t0 + Duration::from_secs(s));
            let tgt = AbrTargets::compute(abr.tier(), 30, 16, 1920);
            assert_eq!(tgt.scale_pct, 100, "constant-resolution invariant violated");
        }
        assert!(abr.tier() >= 2, "must degrade under sustained congestion");

        // Interleave clean motion with blinking-cursor idle seconds (sent_frames=1, dropped=0)
        for s in 26..=115u64 {
            let sample = if s % 4 == 0 {
                AbrWindowSample {
                    sent_frames: 1,
                    dropped_frames: 0,
                    avg_send_ms: 1.0,
                    max_send_ms: 3,
                    avg_ack_rtt_ms: Some(20.0),
                    in_flight_saturated: false,
                }
            } else {
                AbrWindowSample {
                    sent_frames: 30,
                    dropped_frames: 0,
                    avg_send_ms: 2.0,
                    max_send_ms: 8,
                    avg_ack_rtt_ms: Some(18.0),
                    in_flight_saturated: false,
                }
            };
            let _ = abr.evaluate(&sample, t0 + Duration::from_secs(s));
        }
        assert_eq!(
            abr.tier(),
            0,
            "ABR must recover to Tier 0 within 90s even with blinking-cursor idle seconds"
        );
    }

    // 3. Seeded closed-loop Pareto dominance & anti-oscillation fuzzing
    for seed in fuzz_seeds(0xB201, 64) {
        let mut rng = FuzzRng::new(seed);
        let sens = *rng.pick(&[
            AbrSensitivity::Conservative,
            AbrSensitivity::Balanced,
            AbrSensitivity::Aggressive,
        ]);
        let mut abr = AbrController::with_sensitivity(t0, sens);
        let mut ifc = InFlightController::new(rng.next_bool(), t0);

        let regimes = [
            LinkRegime::CleanLan,
            LinkRegime::WifiPsmSparse,
            LinkRegime::BlinkingCursorIdle,
            LinkRegime::ModerateCongestion,
            LinkRegime::SevereBufferbloat,
        ];

        let mut sec = 0u64;
        for _phase in 0..6 {
            let regime = *rng.pick(&regimes);
            let dur = rng.range_u64(12, 24);
            let mut prev_dir: i8 = 0;
            let mut reversals_in_phase = 0u32;
            let mut prev_tier = abr.tier();

            for _ in 0..dur {
                sec += 1;
                let now = t0 + Duration::from_secs(sec);
                let tgt = AbrTargets::compute(abr.tier(), 30, 16, 1920);
                assert_eq!(tgt.scale_pct, 100);
                assert!(tgt.fps >= 10 && tgt.fps <= 30);
                assert!(tgt.bitrate_mbps >= 2 && tgt.bitrate_mbps <= 16);

                let sample = match regime {
                    LinkRegime::CleanLan => AbrWindowSample {
                        sent_frames: tgt.fps as u64,
                        dropped_frames: 0,
                        avg_send_ms: 1.0 + rng.next_f64() * 3.0,
                        max_send_ms: 4 + rng.range_u64(0, 8),
                        avg_ack_rtt_ms: Some(8.0 + rng.next_f64() * 12.0),
                        in_flight_saturated: false,
                    },
                    LinkRegime::WifiPsmSparse => AbrWindowSample {
                        sent_frames: rng.range_u64(2, 8),
                        dropped_frames: 0,
                        avg_send_ms: 1.0 + rng.next_f64() * 4.0,
                        max_send_ms: 5 + rng.range_u64(0, 10),
                        avg_ack_rtt_ms: Some(150.0 + rng.next_f64() * 90.0),
                        in_flight_saturated: false,
                    },
                    LinkRegime::BlinkingCursorIdle => AbrWindowSample {
                        sent_frames: rng.range_u64(0, 1),
                        dropped_frames: 0,
                        avg_send_ms: 1.0,
                        max_send_ms: 4,
                        avg_ack_rtt_ms: Some(25.0),
                        in_flight_saturated: false,
                    },
                    LinkRegime::ModerateCongestion => {
                        let cap_mbps = 5.0;
                        let overload = (tgt.bitrate_mbps as f64 / cap_mbps).max(0.5);
                        let drops = if overload > 1.15 {
                            ((overload - 1.0) * 10.0) as u64
                        } else {
                            0
                        };
                        AbrWindowSample {
                            sent_frames: (tgt.fps as u64).saturating_sub(drops).max(4),
                            dropped_frames: drops,
                            avg_send_ms: if overload > 1.15 { 40.0 * overload } else { 8.0 },
                            max_send_ms: if overload > 1.15 { 130 } else { 24 },
                            avg_ack_rtt_ms: Some(if overload > 1.15 { 155.0 } else { 35.0 }),
                            in_flight_saturated: overload > 1.15,
                        }
                    }
                    LinkRegime::SevereBufferbloat => {
                        let cap_mbps = 2.5;
                        let overload = (tgt.bitrate_mbps as f64 / cap_mbps).max(0.5);
                        let drops = if overload > 1.05 {
                            ((overload - 1.0) * 14.0) as u64
                        } else {
                            0
                        };
                        AbrWindowSample {
                            sent_frames: (tgt.fps as u64).saturating_sub(drops).max(3),
                            dropped_frames: drops,
                            avg_send_ms: if overload > 1.05 { 75.0 * overload } else { 10.0 },
                            max_send_ms: if overload > 1.05 { 210 } else { 30 },
                            avg_ack_rtt_ms: Some(if overload > 1.05 { 240.0 } else { 42.0 }),
                            in_flight_saturated: overload > 1.05,
                        }
                    }
                };

                let _ = ifc.evaluate(&sample, tgt.fps, now);
                let _ = abr.evaluate(&sample, now);
                let cur_tier = abr.tier();
                assert!(ifc.limit() >= 1 && ifc.limit() <= InFlightController::WIFI_MAX_WINDOW);

                let dir = (cur_tier as i8 - prev_tier as i8).signum();
                if dir != 0 {
                    if prev_dir != 0 && dir != prev_dir {
                        reversals_in_phase += 1;
                    }
                    prev_dir = dir;
                }
                prev_tier = cur_tier;
            }
            assert!(
                reversals_in_phase <= 2,
                "ABR thrashing detected (seed=0x{seed:x}, regime={regime:?}, reversals={reversals_in_phase})"
            );
        }
    }
}

#[test]
fn fuzz_flow_control_logical_clock_never_deadlocks_under_ack_loss() {
    for seed in fuzz_seeds(0xB202, 64) {
        let mut rng = FuzzRng::new(seed);
        let max_if = rng.range_u64(1, 4) as u32;
        let fc = FlowControl::new(max_if);
        let mut now_ms = 0u64;
        let mut sent_during_blackout = 0u32;

        // Establish initial ACK baseline
        assert!(fc.try_acquire_send_at(now_ms, true));
        now_ms += 16;
        fc.on_frame_received_at(now_ms);
        assert!(fc.try_acquire_send_at(now_ms, true));
        now_ms += 20;
        fc.on_picture_rendered_at(now_ms);

        // Random mix of sends, delayed ACKs, and 100% ACK blackouts
        for step in 0..200 {
            now_ms += rng.range_u64(8, 160);
            let blackout = (80..120).contains(&step);
            if fc.try_acquire_send_at(now_ms, true) && blackout {
                sent_during_blackout += 1;
            }
            if !blackout && rng.chance(7, 10) {
                now_ms += rng.range_u64(2, 40);
                if rng.next_bool() {
                    fc.on_picture_rendered_at(now_ms);
                } else {
                    fc.on_frame_received_at(now_ms);
                }
            }
            assert!(
                fc.in_flight() <= max_if,
                "in_flight {} exceeded max_in_flight {max_if} (seed=0x{seed:x})",
                fc.in_flight()
            );
        }
        assert!(
            sent_during_blackout >= 1,
            "FlowControl deadlocked under 100% ACK blackout (seed=0x{seed:x})"
        );
        // After >3s silence, stale RTT must expire to None
        assert_eq!(fc.ewma_rtt_ms_at(now_ms + 4000), None);
    }
}

fn extract_tfdt(media_seg: &[u8]) -> Option<u64> {
    fn walk<'a>(data: &'a [u8], want: &[u8; 4]) -> Option<&'a [u8]> {
        let mut off = 0;
        while off + 8 <= data.len() {
            let sz = u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
                as usize;
            if sz < 8 || off + sz > data.len() {
                break;
            }
            if &data[off + 4..off + 8] == want {
                return Some(&data[off + 8..off + sz]);
            }
            off += sz;
        }
        None
    }
    let moof = walk(media_seg, b"moof")?;
    let traf = walk(moof, b"traf")?;
    let tfdt = walk(traf, b"tfdt")?;
    if tfdt.len() >= 12 && tfdt[0] == 1 {
        Some(u64::from_be_bytes([
            tfdt[4], tfdt[5], tfdt[6], tfdt[7], tfdt[8], tfdt[9], tfdt[10], tfdt[11],
        ]))
    } else {
        None
    }
}

#[test]
fn fuzz_annexb_chunking_invariance_and_fmp4_tfdt_monotonicity() {
    let sps = [0x67u8, 0x42, 0x00, 0x1e, 0x9a, 0x74];
    let pps = [0x68u8, 0xce, 0x38, 0x80];
    let t0 = Instant::now();

    for seed in fuzz_seeds(0xB203, 64) {
        let mut rng = FuzzRng::new(seed);
        let mut stream = Vec::new();
        // Build a structured H.264 Annex-B byte stream with mixed 3B/4B start codes, AUD, SEI, IDR, multi-slice P
        for i in 0..16 {
            if i == 0 || rng.chance(1, 5) {
                let sc: &[u8] = if rng.next_bool() { &[0, 0, 0, 1] } else { &[0, 0, 1] };
                if rng.next_bool() {
                    stream.extend_from_slice(sc);
                    stream.extend_from_slice(&[0x09, 0x10]); // AUD
                }
                stream.extend_from_slice(sc);
                stream.extend_from_slice(&sps);
                stream.extend_from_slice(&[0, 0, 0, 1]);
                stream.extend_from_slice(&pps);
                stream.extend_from_slice(sc);
                stream.extend_from_slice(&[0x65, 0x88, i as u8, 0xAA]); // IDR slice 0
                if rng.next_bool() {
                    stream.extend_from_slice(&[0, 0, 0, 1, 0x65, 0x05, i as u8]); // IDR slice 1
                }
            } else {
                stream.extend_from_slice(&[0, 0, 1, 0x41, 0x9a, i as u8, 0xBB]); // P slice 0
                if rng.next_bool() {
                    stream.extend_from_slice(&[0, 0, 0, 1, 0x41, 0x05, i as u8]); // P slice 1
                }
            }
        }

        // Differential oracle: whole-buffer split MUST equal random-chunk streaming split
        let mut sp_whole = AnnexBSplitter::new();
        let mut aus_whole = sp_whole.push(&stream);
        aus_whole.extend(sp_whole.finish());

        let mut sp_chunked = AnnexBSplitter::new();
        let mut aus_chunked = Vec::new();
        let mut pos = 0;
        while pos < stream.len() {
            let take = (1 + rng.next_usize(11)).min(stream.len() - pos);
            aus_chunked.extend(sp_chunked.push(&stream[pos..pos + take]));
            pos += take;
        }
        aus_chunked.extend(sp_chunked.finish());
        assert_eq!(
            aus_whole, aus_chunked,
            "AnnexBSplitter chunking invariance violated (seed=0x{seed:x})"
        );

        // Feed split AUs into Fmp4Muxer with wild logical-clock jumps (0ms, 16ms, 500ms, 10s)
        let mut mux = Fmp4Muxer::new(30);
        let mut now = t0;
        let mut prev_tfdt: Option<u64> = None;
        for au in &aus_whole {
            let jump_ms = *rng.pick(&[0u64, 1, 16, 33, 500, 10_000]);
            now += Duration::from_millis(jump_ms);
            let idr_flag = is_self_contained_idr(au);
            let chunk = mux
                .mux_frame_at(1280, 720, au, now)
                .expect("every valid AU after initial IDR must mux cleanly");
            assert_eq!(
                chunk.is_keyframe, idr_flag,
                "is_self_contained_idr must agree with Fmp4Muxer::is_keyframe (seed=0x{seed:x})"
            );
            let tfdt = extract_tfdt(&chunk.media_segment).expect("media segment must contain tfdt");
            if let Some(prev) = prev_tfdt {
                assert!(
                    tfdt > prev,
                    "tfdt must strictly advance: {tfdt} <= {prev} (seed=0x{seed:x})"
                );
            }
            prev_tfdt = Some(tfdt);
        }
    }
}

#[test]
fn fuzz_shared_web_muxer_rejects_stale_epochs_and_allows_cross_source_seq_reset() {
    let idr_frame = EncodedFrame {
        width: 1280,
        height: 720,
        bytes_per_row: 1280 * 4,
        annex_b: SYNTHETIC_H264_ANNEX_B.to_vec(),
        is_keyframe: true,
    };
    let p_frame = EncodedFrame {
        width: 1280,
        height: 720,
        bytes_per_row: 1280 * 4,
        annex_b: vec![0, 0, 0, 1, 0x41, 0x9a, 0x01, 0x02],
        is_keyframe: false,
    };

    // 1. Direct regression for cross-source lower seq + stale epoch rollback
    let mux = SharedWebMuxer::new();
    let p1 = mux.mux_or_get(100, "ipad", 5, 30, &idr_frame).unwrap();
    assert_eq!(p1.source_epoch, 5);
    // Switch to standalone with LOWER seq=1 and higher epoch=6 -> MUST succeed!
    let p2 = mux.mux_or_get(1, "standalone", 6, 30, &idr_frame).unwrap();
    assert_eq!(p2.source, "standalone");
    assert_eq!(p2.source_epoch, 6);
    // Late stale epoch=5 IDR (even with higher seq=101!) MUST be rejected!
    assert!(mux.mux_or_get(101, "ipad", 5, 30, &idr_frame).is_none());
    assert!(mux.seed_if_empty("ipad", 5, 30, &idr_frame).is_none());
    assert_eq!(mux.debug_state().1, 6, "source_epoch must never roll back");

    // 2. Seeded randomized multi-source/epoch churn
    for seed in fuzz_seeds(0xB204, 64) {
        let mut rng = FuzzRng::new(seed);
        let cache = SharedWebMuxer::new();
        let mut max_seen_epoch = 0u64;
        let mut cur_epoch = 1u64;
        let mut seqs = [1u64, 1u64];

        for _ in 0..100 {
            if rng.chance(1, 8) {
                cur_epoch += 1;
            }
            let src_idx = rng.next_usize(2);
            let src = if src_idx == 0 { "ipad" } else { "standalone" };
            let use_stale = cur_epoch > 1 && rng.chance(1, 5);
            let ep = if use_stale { cur_epoch - 1 } else { cur_epoch };
            let frame = if rng.chance(1, 3) { &idr_frame } else { &p_frame };
            let seq = seqs[src_idx];
            seqs[src_idx] += 1;

            let res = if rng.chance(1, 6) {
                cache.seed_if_empty(src, ep, 30, frame)
            } else {
                cache.mux_or_get(seq, src, ep, 30, frame)
            };
            let (_, live_ep, _, _) = cache.debug_state();
            assert!(
                live_ep >= max_seen_epoch,
                "SharedWebMuxer source_epoch rolled back: {live_ep} < {max_seen_epoch} (seed=0x{seed:x})"
            );
            max_seen_epoch = live_ep;
            if let Some(pkt) = res {
                assert!(pkt.source_epoch <= live_ep);
            }
        }
    }
}

#[test]
fn fuzz_p2p_relay_hub_topology_invariants_under_churn() {
    let t0 = Instant::now();
    for seed in fuzz_seeds(0xB205, 64) {
        let mut rng = FuzzRng::new(seed);
        let hub = P2pRelayHub::new(true);
        let mut active_ids: Vec<u64> = Vec::new();
        let mut next_id = 1u64;
        let mut now = t0;
        let mut _receivers = Vec::new();

        for _step in 0..160 {
            now += Duration::from_secs(rng.range_u64(0, 20));
            match rng.next_usize(9) {
                0 | 1 if active_ids.len() < 16 => {
                    let id = next_id;
                    next_id += 1;
                    let (sig_tx, sig_rx) = sync_channel(rng.range_u64(1, 8) as usize);
                    let (_ftx, frx) = latest_frame_channel();
                    let _ = hub.register(id, sig_tx, frx.waker());
                    active_ids.push(id);
                    _receivers.push(sig_rx);
                    let supported = rng.chance(4, 5);
                    let prio = rng.range_u64(0, 2) as u8;
                    hub.on_hello_with_priority(id, supported, prio);
                }
                2 if !active_ids.is_empty() => {
                    let idx = rng.next_usize(active_ids.len());
                    let id = active_ids.remove(idx);
                    hub.unregister_and_maybe_reset(id, || {});
                }
                3 if !active_ids.is_empty() => {
                    let id = *rng.pick(&active_ids);
                    let prio = rng.range_u64(0, 2) as u8;
                    hub.on_caps_update_with_priority(id, prio);
                }
                4 if !active_ids.is_empty() => {
                    let id = *rng.pick(&active_ids);
                    let snap = hub.viewer_snapshot(id);
                    if let Some(pid) = snap.p2p_parent_id {
                        hub.on_p2p_active(id, pid);
                    }
                }
                5 if !active_ids.is_empty() => {
                    let id = *rng.pick(&active_ids);
                    hub.on_p2p_fallback_at(id, "stall_timeout", now);
                }
                6 if active_ids.len() >= 2 => {
                    let a = *rng.pick(&active_ids);
                    let b = *rng.pick(&active_ids);
                    let _ = hub.route_signal(a, b, serde_json::json!({"sdp": "v=0"}));
                }
                7 => {
                    hub.rebalance_at(now);
                }
                _ => {
                    let en = rng.chance(4, 5);
                    hub.set_enabled(en);
                    if en {
                        hub.rebalance_at(now);
                    }
                }
            }
            if let Err(err) = hub.check_invariants() {
                panic!(
                    "P2pRelayHub invariant violated: {err}\nReproduce: IDIS_FUZZ_SEED=0x{seed:x} cargo test --locked --test fuzz_pareto_qoe fuzz_p2p_relay_hub_topology_invariants_under_churn -- --exact --nocapture"
                );
            }
            let sum = hub.summary(0, 0);
            assert_eq!(sum.direct_viewers + sum.p2p_viewers, sum.total_viewers);
        }
    }
}
