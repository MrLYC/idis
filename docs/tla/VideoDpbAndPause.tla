------------------------ MODULE VideoDpbAndPause ------------------------
(*
  Formal TLA+ model of idis IPPP H.264 DPB reference-chain gating, shared-mode
  Web fan-out, P2P bounce recovery, macOS pause -> reconfigure -> resume
  dimension integrity, and pause-time deep-sleep assertion release.

  Code correspondence:
    - `src/platform/mod.rs` (`FrameSlot`: atomic `(seq, frame, overwritten)`)
    - `src/session/data_channel.rs` (`slot_awaiting_idr`, `ipad_awaiting_idr`)
    - `src/web/ws_stream.rs` (`viewer_awaiting_idr`, `viewer_needs_idr`, `lock_state_epoch`)
    - `src/web/viewer.html` (`mseAwaitingIdr`)
    - `macos/bridge.m` (`reconfigureWidth:`, `updateStreamFps:`, `id_macos_capture_set_paused`, `sleepAssertionID`)

  Guards Invariants: VID-1, VID-2, VID-3, VID-4, P2P-1, PWR-1, PWR-2.
*)

EXTENDS Naturals

Resolutions == {"low", "high"}
FrameKinds == {"none", "idr", "p"}

VARIABLES
    target_res,             \* Authoritative requested logical/pixel target resolution
    enc_res,                \* VideoToolbox encoder resolution
    atomic_size,            \* macOS _atomicSize mirror
    capture_paused,         \* SCStream hardware pause state
    sleep_assertion_held,   \* macOS IOPMAssertion(PreventUserIdleDisplaySleep) held
    active_stream_res,      \* Currently running SCStream resolution ("none" when paused)
    slot_frame,             \* Latest FrameSlot payload ("none" | "idr" | "p")
    slot_overwritten,       \* Atomic overwritten flag since last consumer pop
    slot_awaiting_idr,      \* Upstream FrameSlot DPB gate
    ipad_awaiting_idr,      \* iPad-local DPB gate
    ipad_paused,            \* iPad StopStream or on_lock_ipad=pause
    ipad_dpb_valid,         \* Whether iPad decoder holds valid reference chain
    web_follow_needs_idr,   \* Per-owner FollowIpad failover / mode-return IDR gate (P1-B1/B2)
    web_source,             \* Active Web stream source ("ipad" | "main")
    web_source_epoch,       \* Authoritative SessionRegistry web_source_epoch (0..1 bounded)
    web_cache_valid,        \* SessionRegistry last_*_web_frame populated (Iter-7 P1-B1)
    web_cache_epoch,        \* Epoch tag stored inside last_*_web_frame
    web_mux_source,         \* SharedWebMuxer committed source ("ipad" | "main")
    web_mux_epoch,          \* SharedWebMuxer committed source_epoch (P1-B2)
    web_awaiting_idr,       \* ws_stream writer DPB gate
    web_needs_idr,          \* Cross-thread atomic signal from ws reader (tab/P2P)
    web_tab_hidden,         \* Browser tab hidden
    web_p2p_active,         \* Browser currently receiving via P2P instead of WS
    web_dpb_valid,          \* Whether Web MSE decoder holds valid reference chain
    corrupt_decode_ipad,    \* Sticky safety violation detector (iPad P-frame on broken DPB)
    corrupt_decode_web,     \* Sticky safety violation detector (Web P-frame on broken DPB)
    stale_epoch_seed_leak   \* Sticky safety violation detector (pre-lock / dead-iPad IDR seed leak)

vars == <<
    target_res, enc_res, atomic_size, capture_paused, sleep_assertion_held, active_stream_res,
    slot_frame, slot_overwritten, slot_awaiting_idr,
    ipad_awaiting_idr, ipad_paused, ipad_dpb_valid,
    web_follow_needs_idr, web_source, web_source_epoch, web_cache_valid, web_cache_epoch,
    web_mux_source, web_mux_epoch,
    web_awaiting_idr, web_needs_idr, web_tab_hidden, web_p2p_active, web_dpb_valid,
    corrupt_decode_ipad, corrupt_decode_web, stale_epoch_seed_leak
>>

TypeOK ==
    /\ target_res \in Resolutions
    /\ enc_res \in Resolutions
    /\ atomic_size \in Resolutions
    /\ capture_paused \in BOOLEAN
    /\ sleep_assertion_held \in BOOLEAN
    /\ active_stream_res \in {"none"} \cup Resolutions
    /\ slot_frame \in FrameKinds
    /\ slot_overwritten \in BOOLEAN
    /\ slot_awaiting_idr \in BOOLEAN
    /\ ipad_awaiting_idr \in BOOLEAN
    /\ ipad_paused \in BOOLEAN
    /\ ipad_dpb_valid \in BOOLEAN
    /\ web_follow_needs_idr \in BOOLEAN
    /\ web_source \in {"ipad", "main"}
    /\ web_source_epoch \in {0, 1}
    /\ web_cache_valid \in BOOLEAN
    /\ web_cache_epoch \in {0, 1}
    /\ web_mux_source \in {"ipad", "main"}
    /\ web_mux_epoch \in {0, 1}
    /\ web_awaiting_idr \in BOOLEAN
    /\ web_needs_idr \in BOOLEAN
    /\ web_tab_hidden \in BOOLEAN
    /\ web_p2p_active \in BOOLEAN
    /\ web_dpb_valid \in BOOLEAN
    /\ corrupt_decode_ipad \in BOOLEAN
    /\ corrupt_decode_web \in BOOLEAN
    /\ stale_epoch_seed_leak \in BOOLEAN

Init ==
    /\ target_res = "low"
    /\ enc_res = "low"
    /\ atomic_size = "low"
    /\ capture_paused = FALSE
    /\ sleep_assertion_held = TRUE
    /\ active_stream_res = "low"
    /\ slot_frame = "none"
    /\ slot_overwritten = FALSE
    /\ slot_awaiting_idr = TRUE
    /\ ipad_awaiting_idr = TRUE
    /\ ipad_paused = FALSE
    /\ ipad_dpb_valid = FALSE
    /\ web_follow_needs_idr = TRUE
    /\ web_source = "ipad"
    /\ web_source_epoch = 0
    /\ web_cache_valid = FALSE
    /\ web_cache_epoch = 0
    /\ web_mux_source = "ipad"
    /\ web_mux_epoch = 0
    /\ web_awaiting_idr = TRUE
    /\ web_needs_idr = TRUE
    /\ web_tab_hidden = FALSE
    /\ web_p2p_active = FALSE
    /\ web_dpb_valid = FALSE
    /\ corrupt_decode_ipad = FALSE
    /\ corrupt_decode_web = FALSE
    /\ stale_epoch_seed_leak = FALSE

\* 1. Hardware encoder produces an IDR or P frame into bounded 1-slot FrameSlot (VID-2).
EncodeFrame(kind) ==
    /\ ~capture_paused
    /\ kind \in {"idr", "p"}
    /\ slot_overwritten' = (slot_overwritten \/ (slot_frame # "none"))
    /\ slot_frame' = kind
    /\ UNCHANGED <<target_res, enc_res, atomic_size, capture_paused, sleep_assertion_held,
                   active_stream_res, slot_awaiting_idr, ipad_awaiting_idr, ipad_paused,
                   ipad_dpb_valid, web_follow_needs_idr, web_source, web_source_epoch,
                   web_cache_valid, web_cache_epoch,
                   web_mux_source, web_mux_epoch, web_awaiting_idr, web_needs_idr, web_tab_hidden,
                   web_p2p_active, web_dpb_valid, corrupt_decode_ipad, corrupt_decode_web,
                   stale_epoch_seed_leak>>

\* 2. Stream thread consumes from FrameSlot, enforces upstream, FollowIpad-owner, SharedWebMuxer
\*    (source + source_epoch), and per-target IDR gates (VID-1, VID-3, P0-B1, P1-B2).
ConsumeSlot ==
    /\ slot_frame # "none"
    /\ LET
           ov == slot_overwritten
           f == slot_frame
           \* If slot overwrote an unread frame, reference chain broke for BOTH consumers.
           eff_slot_wait == slot_awaiting_idr \/ ov
           eff_ipad_wait == ipad_awaiting_idr \/ ov
           eff_ipad_dpb == IF ov THEN FALSE ELSE ipad_dpb_valid
           eff_web_dpb == IF ov THEN FALSE ELSE web_dpb_valid
           source_mismatch == (web_mux_source # web_source) \/ (web_mux_epoch # web_source_epoch)
           \* ws_stream + SharedWebMuxer + FollowIpad owner gate
           eff_web_wait == web_awaiting_idr \/ ov \/ web_needs_idr \/ web_tab_hidden
                           \/ web_p2p_active \/ web_follow_needs_idr \/ source_mismatch
       IN
       /\ slot_frame' = "none"
       /\ slot_overwritten' = FALSE
       /\ IF f = "idr" THEN
              \* Self-contained IDR resets slot gate, commits SharedWebMuxer source & epoch,
              \* tags `last_*_web_frame` with `web_source_epoch`, and feeds Web & iPad.
              /\ slot_awaiting_idr' = FALSE
              /\ web_follow_needs_idr' = (web_source # "ipad")
              /\ web_cache_valid' = TRUE
              /\ web_cache_epoch' = web_source_epoch
              /\ web_mux_source' = web_source
              /\ web_mux_epoch' = web_source_epoch
              /\ web_needs_idr' = FALSE
              /\ IF ~web_tab_hidden /\ ~web_p2p_active THEN
                     /\ web_awaiting_idr' = FALSE
                     /\ web_dpb_valid' = TRUE
                 ELSE
                     /\ web_awaiting_idr' = TRUE
                     /\ web_dpb_valid' = FALSE
              /\ IF ~ipad_paused THEN
                     /\ ipad_awaiting_idr' = FALSE
                     /\ ipad_dpb_valid' = TRUE
                 ELSE
                     /\ ipad_awaiting_idr' = TRUE
                     /\ ipad_dpb_valid' = FALSE
              /\ corrupt_decode_ipad' = corrupt_decode_ipad
              /\ corrupt_decode_web' = corrupt_decode_web
          ELSE
              \* f = "p": drop if upstream slot gate is set; never reset SharedWebMuxer on P-frame (P1-B3).
              IF eff_slot_wait THEN
                  /\ slot_awaiting_idr' = TRUE
                  /\ ipad_awaiting_idr' = TRUE
                  /\ ipad_dpb_valid' = FALSE
                  /\ web_follow_needs_idr' = (web_follow_needs_idr \/ (web_source # "ipad"))
                  /\ web_cache_valid' = web_cache_valid
                  /\ web_cache_epoch' = web_cache_epoch
                  /\ web_mux_source' = web_mux_source
                  /\ web_mux_epoch' = web_mux_epoch
                  /\ web_awaiting_idr' = TRUE
                  /\ web_needs_idr' = FALSE
                  /\ web_dpb_valid' = FALSE
                  /\ corrupt_decode_ipad' = corrupt_decode_ipad
                  /\ corrupt_decode_web' = corrupt_decode_web
              ELSE
                  /\ slot_awaiting_idr' = FALSE
                  /\ web_follow_needs_idr' = (web_follow_needs_idr \/ (web_source # "ipad"))
                  /\ web_cache_valid' = web_cache_valid
                  /\ web_cache_epoch' = web_cache_epoch
                  /\ web_mux_source' = web_mux_source
                  /\ web_mux_epoch' = web_mux_epoch
                  /\ web_needs_idr' = FALSE
                  \* Web fan-out happens regardless of `ipad_paused` (VID-3), gated on FollowIpad + Muxer source/epoch
                  /\ IF ~web_tab_hidden /\ ~web_p2p_active /\ ~eff_web_wait THEN
                         /\ web_awaiting_idr' = FALSE
                         /\ web_dpb_valid' = eff_web_dpb
                         /\ corrupt_decode_web' = (corrupt_decode_web \/ ~eff_web_dpb)
                     ELSE
                         /\ web_awaiting_idr' = TRUE
                         /\ web_dpb_valid' = FALSE
                         /\ corrupt_decode_web' = corrupt_decode_web
                  \* iPad delivery gated on `ipad_paused` and `eff_ipad_wait`
                  /\ IF ~ipad_paused /\ ~eff_ipad_wait THEN
                         /\ ipad_awaiting_idr' = FALSE
                         /\ ipad_dpb_valid' = eff_ipad_dpb
                         /\ corrupt_decode_ipad' = (corrupt_decode_ipad \/ ~eff_ipad_dpb)
                     ELSE
                         /\ ipad_awaiting_idr' = TRUE
                         /\ ipad_dpb_valid' = FALSE
                         /\ corrupt_decode_ipad' = corrupt_decode_ipad
    /\ UNCHANGED <<target_res, enc_res, atomic_size, capture_paused, sleep_assertion_held,
                   active_stream_res, ipad_paused, web_source, web_source_epoch,
                   web_tab_hidden, web_p2p_active, stale_epoch_seed_leak>>

\* 2b. Sustained iPad pending_queue overflow or age-cap drop: iPad resyncs on IDR while Web continues (VID-1).
IpadPendingOverflow ==
    /\ ~ipad_paused
    /\ ipad_awaiting_idr' = TRUE
    /\ ipad_dpb_valid' = FALSE
    /\ UNCHANGED <<target_res, enc_res, atomic_size, capture_paused, sleep_assertion_held,
                   active_stream_res, slot_frame, slot_overwritten, slot_awaiting_idr,
                   ipad_paused, web_follow_needs_idr, web_source, web_source_epoch,
                   web_cache_valid, web_cache_epoch,
                   web_mux_source, web_mux_epoch, web_awaiting_idr, web_needs_idr,
                   web_tab_hidden, web_p2p_active, web_dpb_valid, corrupt_decode_ipad,
                   corrupt_decode_web, stale_epoch_seed_leak>>

\* 2c. Live Web screen mode switch, 2-iPad FollowIpad owner failover, or lock-pause epoch bump (P0-B1/P1-B2).
\*     Note: intentionally leaves `web_cache_valid` & `web_cache_epoch` untouched to model a racing
\*     in-flight write-back or cross-mode cache residue (Iter-7 P1-B1)!
WebSourceSwitchOrFailover ==
    /\ web_source' = IF web_source = "ipad" THEN "main" ELSE "ipad"
    /\ web_source_epoch' = 1 - web_source_epoch
    /\ web_follow_needs_idr' = TRUE
    /\ web_dpb_valid' = FALSE
    /\ UNCHANGED <<target_res, enc_res, atomic_size, capture_paused, sleep_assertion_held,
                   active_stream_res, slot_frame, slot_overwritten, slot_awaiting_idr,
                   ipad_awaiting_idr, ipad_paused, ipad_dpb_valid, web_cache_valid, web_cache_epoch,
                   web_mux_source, web_mux_epoch,
                   web_awaiting_idr, web_needs_idr, web_tab_hidden, web_p2p_active,
                   corrupt_decode_ipad, corrupt_decode_web, stale_epoch_seed_leak>>

\* 2d. Same-source epoch bump (e.g. host lock-pause -> unlock, or 2-iPad FollowIpad failover keeping "ipad")
\*     while `last_*_web_frame` may still hold an old-epoch IDR from a concurrent write-back race.
WebSameSourceEpochBump ==
    /\ web_source_epoch' = 1 - web_source_epoch
    /\ web_follow_needs_idr' = TRUE
    /\ web_dpb_valid' = FALSE
    /\ UNCHANGED <<target_res, enc_res, atomic_size, capture_paused, sleep_assertion_held,
                   active_stream_res, slot_frame, slot_overwritten, slot_awaiting_idr,
                   ipad_awaiting_idr, ipad_paused, ipad_dpb_valid, web_source,
                   web_cache_valid, web_cache_epoch,
                   web_mux_source, web_mux_epoch, web_awaiting_idr, web_needs_idr,
                   web_tab_hidden, web_p2p_active, corrupt_decode_ipad, corrupt_decode_web,
                   stale_epoch_seed_leak>>

\* 2e. Newly joining / P2P-fallback Web viewer queries `SharedWebMuxer::latest_packet_for_source`
\*     and falls back to `SessionRegistry::cached_web_idr_frame()` (Iter-7 P1-B1 & P2-B3):
\*     BOTH paths MUST enforce `epoch = web_source_epoch`; seeding from an older-epoch cache
\*     trips `stale_epoch_seed_leak`.
WebViewerSeedFromMuxCache ==
    /\ LET
           mux_hit == (web_mux_source = web_source /\ web_mux_epoch = web_source_epoch)
           cache_hit == (~mux_hit /\ web_cache_valid /\ web_cache_epoch = web_source_epoch)
           seeded_epoch == IF mux_hit THEN web_mux_epoch
                           ELSE IF cache_hit THEN web_cache_epoch
                           ELSE web_source_epoch
       IN
       /\ stale_epoch_seed_leak' =
              (stale_epoch_seed_leak \/ ((mux_hit \/ cache_hit) /\ seeded_epoch # web_source_epoch))
       /\ IF cache_hit THEN
              /\ web_mux_source' = web_source
              /\ web_mux_epoch' = web_cache_epoch
          ELSE
              /\ web_mux_source' = web_mux_source
              /\ web_mux_epoch' = web_mux_epoch
    /\ UNCHANGED <<target_res, enc_res, atomic_size, capture_paused, sleep_assertion_held,
                   active_stream_res, slot_frame, slot_overwritten, slot_awaiting_idr,
                   ipad_awaiting_idr, ipad_paused, ipad_dpb_valid, web_follow_needs_idr,
                   web_source, web_source_epoch, web_cache_valid, web_cache_epoch,
                   web_awaiting_idr, web_needs_idr, web_tab_hidden, web_p2p_active,
                   web_dpb_valid, corrupt_decode_ipad, corrupt_decode_web>>

\* 3. iPad pause/resume (StopStream or on_lock_ipad=pause).
IpadPause ==
    /\ ~ipad_paused
    /\ ipad_paused' = TRUE
    /\ ipad_awaiting_idr' = TRUE
    /\ ipad_dpb_valid' = FALSE
    /\ UNCHANGED <<target_res, enc_res, atomic_size, capture_paused, sleep_assertion_held,
                   active_stream_res, slot_frame, slot_overwritten, slot_awaiting_idr,
                   web_follow_needs_idr, web_source, web_source_epoch,
                   web_cache_valid, web_cache_epoch,
                   web_mux_source, web_mux_epoch, web_awaiting_idr, web_needs_idr,
                   web_tab_hidden, web_p2p_active, web_dpb_valid, corrupt_decode_ipad,
                   corrupt_decode_web, stale_epoch_seed_leak>>

IpadResume ==
    /\ ipad_paused
    /\ ipad_paused' = FALSE
    /\ ipad_awaiting_idr' = TRUE
    /\ UNCHANGED <<target_res, enc_res, atomic_size, capture_paused, sleep_assertion_held,
                   active_stream_res, slot_frame, slot_overwritten, slot_awaiting_idr,
                   ipad_dpb_valid, web_follow_needs_idr, web_source, web_source_epoch,
                   web_cache_valid, web_cache_epoch,
                   web_mux_source, web_mux_epoch, web_awaiting_idr, web_needs_idr,
                   web_tab_hidden, web_p2p_active, web_dpb_valid, corrupt_decode_ipad,
                   corrupt_decode_web, stale_epoch_seed_leak>>

\* 4. Web browser tab background/foreground & P2P active/fallback bounce (VID-1, P2P-1).
WebTabHide ==
    /\ ~web_tab_hidden
    /\ web_tab_hidden' = TRUE
    /\ web_needs_idr' = TRUE
    /\ web_dpb_valid' = FALSE
    /\ UNCHANGED <<target_res, enc_res, atomic_size, capture_paused, sleep_assertion_held,
                   active_stream_res, slot_frame, slot_overwritten, slot_awaiting_idr,
                   ipad_awaiting_idr, ipad_paused, ipad_dpb_valid,
                   web_follow_needs_idr, web_source, web_source_epoch,
                   web_cache_valid, web_cache_epoch,
                   web_mux_source, web_mux_epoch, web_awaiting_idr, web_p2p_active,
                   corrupt_decode_ipad, corrupt_decode_web, stale_epoch_seed_leak>>

WebTabShow ==
    /\ web_tab_hidden
    /\ web_tab_hidden' = FALSE
    /\ web_needs_idr' = TRUE
    /\ UNCHANGED <<target_res, enc_res, atomic_size, capture_paused, sleep_assertion_held,
                   active_stream_res, slot_frame, slot_overwritten, slot_awaiting_idr,
                   ipad_awaiting_idr, ipad_paused, ipad_dpb_valid,
                   web_follow_needs_idr, web_source, web_source_epoch,
                   web_cache_valid, web_cache_epoch,
                   web_mux_source, web_mux_epoch, web_awaiting_idr, web_p2p_active,
                   web_dpb_valid, corrupt_decode_ipad, corrupt_decode_web, stale_epoch_seed_leak>>

WebP2pActivate ==
    /\ ~web_p2p_active
    /\ web_p2p_active' = TRUE
    /\ web_needs_idr' = TRUE
    /\ web_dpb_valid' = FALSE
    /\ UNCHANGED <<target_res, enc_res, atomic_size, capture_paused, sleep_assertion_held,
                   active_stream_res, slot_frame, slot_overwritten, slot_awaiting_idr,
                   ipad_awaiting_idr, ipad_paused, ipad_dpb_valid,
                   web_follow_needs_idr, web_source, web_source_epoch,
                   web_cache_valid, web_cache_epoch,
                   web_mux_source, web_mux_epoch, web_awaiting_idr, web_tab_hidden,
                   corrupt_decode_ipad, corrupt_decode_web, stale_epoch_seed_leak>>

WebP2pFallback ==
    /\ web_p2p_active
    /\ web_p2p_active' = FALSE
    /\ web_needs_idr' = TRUE
    /\ web_dpb_valid' = FALSE
    /\ UNCHANGED <<target_res, enc_res, atomic_size, capture_paused, sleep_assertion_held,
                   active_stream_res, slot_frame, slot_overwritten, slot_awaiting_idr,
                   ipad_awaiting_idr, ipad_paused, ipad_dpb_valid,
                   web_follow_needs_idr, web_source, web_source_epoch,
                   web_cache_valid, web_cache_epoch,
                   web_mux_source, web_mux_epoch, web_awaiting_idr, web_tab_hidden,
                   corrupt_decode_ipad, corrupt_decode_web, stale_epoch_seed_leak>>

\* 5. macOS hardware capture pause -> reconfigure -> resume (VID-4, PWR-1, PWR-2).
CapturePause ==
    /\ ~capture_paused
    /\ capture_paused' = TRUE
    \* Immediately release IOPMAssertion and stop SCStream so host can enter deep sleep (PWR-1/2).
    /\ sleep_assertion_held' = FALSE
    /\ active_stream_res' = "none"
    /\ slot_awaiting_idr' = TRUE
    /\ ipad_awaiting_idr' = TRUE
    /\ ipad_dpb_valid' = FALSE
    /\ web_awaiting_idr' = TRUE
    /\ web_dpb_valid' = FALSE
    /\ UNCHANGED <<target_res, enc_res, atomic_size, slot_frame, slot_overwritten,
                   ipad_paused, web_follow_needs_idr, web_source, web_source_epoch,
                   web_cache_valid, web_cache_epoch,
                   web_mux_source, web_mux_epoch, web_needs_idr, web_tab_hidden,
                   web_p2p_active, corrupt_decode_ipad, corrupt_decode_web,
                   stale_epoch_seed_leak>>

CaptureReconfigure(r) ==
    /\ r \in Resolutions
    /\ r # target_res
    /\ target_res' = r
    /\ enc_res' = r
    /\ atomic_size' = r
    /\ active_stream_res' = IF capture_paused THEN "none" ELSE r
    /\ slot_awaiting_idr' = TRUE
    /\ ipad_awaiting_idr' = TRUE
    /\ ipad_dpb_valid' = FALSE
    /\ web_awaiting_idr' = TRUE
    /\ web_dpb_valid' = FALSE
    /\ web_cache_valid' = FALSE
    /\ UNCHANGED <<capture_paused, sleep_assertion_held, slot_frame, slot_overwritten,
                   ipad_paused, web_follow_needs_idr, web_source, web_source_epoch,
                   web_cache_epoch,
                   web_mux_source, web_mux_epoch, web_needs_idr, web_tab_hidden,
                   web_p2p_active, corrupt_decode_ipad, corrupt_decode_web,
                   stale_epoch_seed_leak>>

CaptureResume ==
    /\ capture_paused
    /\ capture_paused' = FALSE
    /\ sleep_assertion_held' = TRUE
    \* Resume computes authoritative size from `target_res` (`computeCapturePixelWidth:`),
    \* rebuilds VT encoder if needed, refreshes `_atomicSize`, and starts SCStream at `target_res`.
    /\ enc_res' = target_res
    /\ atomic_size' = target_res
    /\ active_stream_res' = target_res
    /\ slot_awaiting_idr' = TRUE
    /\ ipad_awaiting_idr' = TRUE
    /\ web_awaiting_idr' = TRUE
    /\ UNCHANGED <<target_res, slot_frame, slot_overwritten,
                   ipad_paused, ipad_dpb_valid, web_follow_needs_idr, web_source, web_source_epoch,
                   web_cache_valid, web_cache_epoch,
                   web_mux_source, web_mux_epoch, web_needs_idr, web_tab_hidden,
                   web_p2p_active, web_dpb_valid, corrupt_decode_ipad, corrupt_decode_web,
                   stale_epoch_seed_leak>>

Next ==
    \/ EncodeFrame("idr")
    \/ EncodeFrame("p")
    \/ ConsumeSlot
    \/ IpadPendingOverflow
    \/ WebSourceSwitchOrFailover
    \/ WebSameSourceEpochBump
    \/ WebViewerSeedFromMuxCache
    \/ IpadPause
    \/ IpadResume
    \/ WebTabHide
    \/ WebTabShow
    \/ WebP2pActivate
    \/ WebP2pFallback
    \/ CapturePause
    \/ \E r \in Resolutions: CaptureReconfigure(r)
    \/ CaptureResume

Spec == Init /\ [][Next]_vars

\* ==================== SAFETY INVARIANTS ====================

\* VID-1: Neither iPad nor Web MSE EVER decodes a mid-GOP P-frame on a broken DPB.
IpadNeverDecodesCorruptPFrame == ~corrupt_decode_ipad
WebNeverDecodesCorruptPFrame == ~corrupt_decode_web
NoStaleEpochIdrLeak == ~stale_epoch_seed_leak

\* VID-4: Whenever capture is running, SCStream & VT encoder strictly match `target_res`
\* (prohibits pause -> reconfigure -> resume stale resolution regression).
ResumeMatchesReconfiguredResolution ==
    (~capture_paused) =>
        (active_stream_res = target_res /\ enc_res = target_res /\ atomic_size = target_res)

\* PWR-1 / PWR-2: Paused capture MUST release OS sleep-prevention assertion and stop SCStream.
PausedCaptureReleasesSleepAssertion ==
    capture_paused => (~sleep_assertion_held /\ active_stream_res = "none")

=============================================================================
