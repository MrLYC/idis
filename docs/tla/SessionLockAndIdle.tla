------------------------ MODULE SessionLockAndIdle ------------------------
(*
  Formal TLA+ model of idis host screen-lock policies, monotonic lock epochs,
  admission-time lazy lock refresh, zero-wakeup `wait_idle()` lifecycle, and
  deep-sleep / idle resource minimization invariants.

  Code correspondence:
    - `src/session/lock_policy.rs` (`wait_idle`, `refresh_host_lock_state_now`,
      `on_host_screen_lock_changed_with_grace`, `tick_host_lock_policy`)
    - `src/session/flow_control.rs` (`sync_capture_pause_states_inner`)
    - `src/session/handshake.rs` (iPad handshake admission)
    - `src/session/web_screen.rs` (`subscribe_web_stream`)
    - `src/web/routes.rs` (`/ws/stream`, `/api/admin/state`)
    - `macos/bridge.m` (`sleepAssertionID`, `id_macos_capture_set_paused`)
    - `src/main.rs` (idle/active event loop)

  Guards Invariants: CON-2, CON-3, PLT-1, PWR-1, PWR-2.
*)

EXTENDS Naturals

CONSTANTS
    MaxEpoch,       \* Upper bound on monotonic lock_epoch for finite TLC checking
    MaxSeq          \* Upper bound on activity_seq for finite TLC checking

Policies == {"pause", "disconnect", "keep"}

VARIABLES
    os_locked,              \* Ground-truth OS screen lock state
    cached_locked,          \* SessionRegistry.host_screen_locked
    enforced,               \* SessionRegistry.host_lock_enforced
    lock_epoch,             \* SessionRegistry.lock_state_epoch (monotonic)
    ipad_policy,            \* lock_action_ipad
    web_policy,             \* lock_action_web
    ipad_connected,         \* Authorized iPad session exists
    ipad_streaming,         \* iPad actively receiving unpaused frames
    web_connected,          \* At least one Web viewer subscribed
    web_streaming,          \* Web viewer actively receiving unpaused frames
    web_lock_disconnecting, \* SessionRegistry.web_lock_disconnecting
    activity_seq,           \* Leaf Condvar generation counter
    main_state,             \* "active" | "snapshotting" | "sleeping"
    main_observed_seq,      \* Snapshot captured before checking active connections
    sleep_assertion_held,   \* OS deep-sleep inhibitor (e.g. macOS IOPMAssertion) held
    capture_running         \* Hardware screen capture + H.264 encoder actively running

vars == <<
    os_locked, cached_locked, enforced, lock_epoch,
    ipad_policy, web_policy,
    ipad_connected, ipad_streaming,
    web_connected, web_streaming, web_lock_disconnecting,
    activity_seq, main_state, main_observed_seq,
    sleep_assertion_held, capture_running
>>

HasActive == ipad_connected \/ web_connected
HasStreaming == ipad_streaming \/ web_streaming

IpadDisconnectBlocking ==
    cached_locked /\ enforced /\ (ipad_policy = "disconnect")

WebDisconnectBlocking ==
    cached_locked /\ enforced /\ (web_policy = "disconnect")

TypeOK ==
    /\ os_locked \in BOOLEAN
    /\ cached_locked \in BOOLEAN
    /\ enforced \in BOOLEAN
    /\ lock_epoch \in 0..MaxEpoch
    /\ ipad_policy \in Policies
    /\ web_policy \in Policies
    /\ ipad_connected \in BOOLEAN
    /\ ipad_streaming \in BOOLEAN
    /\ web_connected \in BOOLEAN
    /\ web_streaming \in BOOLEAN
    /\ web_lock_disconnecting \in BOOLEAN
    /\ activity_seq \in 0..MaxSeq
    /\ main_state \in {"active", "snapshotting", "sleeping"}
    /\ main_observed_seq \in 0..MaxSeq
    /\ sleep_assertion_held \in BOOLEAN
    /\ capture_running \in BOOLEAN

Init ==
    /\ os_locked = FALSE
    /\ cached_locked = FALSE
    /\ enforced = FALSE
    /\ lock_epoch = 0
    /\ ipad_policy \in Policies
    /\ web_policy \in Policies
    /\ ipad_connected = FALSE
    /\ ipad_streaming = FALSE
    /\ web_connected = FALSE
    /\ web_streaming = FALSE
    /\ web_lock_disconnecting = FALSE
    /\ activity_seq = 0
    /\ main_state = "active"
    /\ main_observed_seq = 0
    /\ sleep_assertion_held = FALSE
    /\ capture_running = FALSE

\* Helper: keep OS deep-sleep assertion & capture strictly bound to active streaming (PWR-1, PWR-2).
SyncPowerState ==
    /\ sleep_assertion_held' = (ipad_streaming' \/ web_streaming')
    /\ capture_running' = (ipad_streaming' \/ web_streaming')

\* Helper: apply enforced lock state atomically for a given epoch.
ApplyEnforcedLock ==
    /\ enforced' = TRUE
    /\ IF ipad_policy = "disconnect" THEN
           /\ ipad_connected' = FALSE
           /\ ipad_streaming' = FALSE
       ELSE IF ipad_policy = "pause" THEN
           /\ ipad_connected' = ipad_connected
           /\ ipad_streaming' = FALSE
       ELSE
           /\ ipad_connected' = ipad_connected
           /\ ipad_streaming' = ipad_connected
    /\ IF web_policy = "disconnect" THEN
           /\ web_lock_disconnecting' = TRUE
           /\ web_connected' = FALSE
           /\ web_streaming' = FALSE
       ELSE IF web_policy = "pause" THEN
           /\ web_lock_disconnecting' = FALSE
           /\ web_connected' = web_connected
           /\ web_streaming' = FALSE
       ELSE
           /\ web_lock_disconnecting' = FALSE
           /\ web_connected' = web_connected
           /\ web_streaming' = web_connected
    /\ SyncPowerState

ApplyUnlock ==
    /\ cached_locked' = FALSE
    /\ enforced' = FALSE
    /\ web_lock_disconnecting' = FALSE
    /\ ipad_connected' = ipad_connected
    /\ ipad_streaming' = ipad_connected
    /\ web_connected' = web_connected
    /\ web_streaming' = web_connected
    /\ SyncPowerState

\* 1. Host OS locks or unlocks asynchronously at any time.
OsLock ==
    /\ ~os_locked
    /\ os_locked' = TRUE
    /\ UNCHANGED <<cached_locked, enforced, lock_epoch, ipad_policy, web_policy,
                   ipad_connected, ipad_streaming, web_connected, web_streaming,
                   web_lock_disconnecting, activity_seq, main_state, main_observed_seq,
                   sleep_assertion_held, capture_running>>

OsUnlock ==
    /\ os_locked
    /\ os_locked' = FALSE
    /\ UNCHANGED <<cached_locked, enforced, lock_epoch, ipad_policy, web_policy,
                   ipad_connected, ipad_streaming, web_connected, web_streaming,
                   web_lock_disconnecting, activity_seq, main_state, main_observed_seq,
                   sleep_assertion_held, capture_running>>

\* 2. Zero-wakeup `wait_idle()` two-phase generation snapshot (CON-3, PWR-1).
MainStartWaitIdle ==
    /\ main_state = "active"
    /\ ~HasActive
    /\ main_state' = "snapshotting"
    /\ main_observed_seq' = activity_seq
    /\ UNCHANGED <<os_locked, cached_locked, enforced, lock_epoch, ipad_policy, web_policy,
                   ipad_connected, ipad_streaming, web_connected, web_streaming,
                   web_lock_disconnecting, activity_seq,
                   sleep_assertion_held, capture_running>>

MainCommitSleepOrAbort ==
    /\ main_state = "snapshotting"
    /\ IF ~HasActive /\ activity_seq = main_observed_seq THEN
           main_state' = "sleeping"
       ELSE
           main_state' = "active"
    /\ UNCHANGED <<os_locked, cached_locked, enforced, lock_epoch, ipad_policy, web_policy,
                   ipad_connected, ipad_streaming, web_connected, web_streaming,
                   web_lock_disconnecting, activity_seq, main_observed_seq,
                   sleep_assertion_held, capture_running>>

\* 3. Active main loop polls OS lock state (skipped while sleeping -> 0 IPCs when idle).
MainPollLock ==
    /\ main_state = "active"
    /\ HasActive
    /\ lock_epoch < MaxEpoch
    /\ IF os_locked /\ ~cached_locked THEN
           \* Entering lock while active starts grace delay (or immediate if both Keep)
           /\ cached_locked' = TRUE
           /\ enforced' = FALSE
           /\ web_lock_disconnecting' = FALSE
           /\ lock_epoch' = lock_epoch + 1
           /\ UNCHANGED <<ipad_connected, ipad_streaming, web_connected, web_streaming,
                          sleep_assertion_held, capture_running>>
       ELSE IF ~os_locked /\ cached_locked THEN
           /\ lock_epoch' = lock_epoch + 1
           /\ ApplyUnlock
       ELSE
           UNCHANGED <<cached_locked, enforced, lock_epoch, ipad_connected, ipad_streaming,
                       web_connected, web_streaming, web_lock_disconnecting,
                       sleep_assertion_held, capture_running>>
    /\ UNCHANGED <<os_locked, ipad_policy, web_policy, activity_seq, main_state, main_observed_seq>>

\* Grace delay expires while active and still locked.
MainGraceElapsed ==
    /\ main_state = "active"
    /\ cached_locked
    /\ ~enforced
    /\ lock_epoch < MaxEpoch
    /\ lock_epoch' = lock_epoch + 1
    /\ ApplyEnforcedLock
    /\ UNCHANGED <<os_locked, cached_locked, ipad_policy, web_policy,
                   activity_seq, main_state, main_observed_seq>>

\* 4. Incoming iPad admission (`handshake.rs`: `refresh_host_lock_state_now(TRUE)`).
\*    When `os_locked` and NO active session exists, enforce immediately (0s grace, PLT-1).
\*    When `os_locked` and an existing active session/viewer IS protected by grace (`HasActive /\ ~enforced`),
\*    preserve grace for existing sessions (P1-A1) while still immediately rejecting incoming disconnect-policy clients!
IpadAdmit ==
    /\ ~ipad_connected
    /\ lock_epoch < MaxEpoch
    /\ activity_seq < MaxSeq
    /\ IF os_locked THEN
           IF HasActive /\ ~enforced THEN
               /\ cached_locked' = TRUE
               /\ enforced' = FALSE
               /\ lock_epoch' = IF cached_locked THEN lock_epoch ELSE lock_epoch + 1
               /\ web_lock_disconnecting' = web_lock_disconnecting
               /\ web_connected' = web_connected
               /\ web_streaming' = web_streaming
               /\ IF ipad_policy = "disconnect" THEN
                      /\ ipad_connected' = FALSE
                      /\ ipad_streaming' = FALSE
                      /\ UNCHANGED <<activity_seq, main_state>>
                  ELSE
                      /\ ipad_connected' = TRUE
                      /\ ipad_streaming' = TRUE
                      /\ activity_seq' = activity_seq + 1
                      /\ main_state' = IF main_state = "sleeping" THEN "active" ELSE main_state
           ELSE
               \* Idle wakeup or already enforced -> enforce immediately with 0 grace delay (PLT-1)
               /\ cached_locked' = TRUE
               /\ lock_epoch' = IF cached_locked /\ enforced THEN lock_epoch ELSE lock_epoch + 1
               /\ enforced' = TRUE
               /\ web_lock_disconnecting' = (web_policy = "disconnect")
               /\ web_connected' = IF web_policy = "disconnect" THEN FALSE ELSE web_connected
               /\ web_streaming' = IF web_policy = "keep" THEN web_connected ELSE FALSE
               /\ IF ipad_policy = "disconnect" THEN
                      \* Rejected before insertion
                      /\ ipad_connected' = FALSE
                      /\ ipad_streaming' = FALSE
                      /\ UNCHANGED <<activity_seq, main_state>>
                  ELSE
                      \* Admitted (paused if pause policy, streaming if keep) and wakes idle main loop
                      /\ ipad_connected' = TRUE
                      /\ ipad_streaming' = (ipad_policy = "keep")
                      /\ activity_seq' = activity_seq + 1
                      /\ main_state' = IF main_state = "sleeping" THEN "active" ELSE main_state
       ELSE
           \* Host is unlocked -> clear any stale lock state and admit streaming
           /\ cached_locked' = FALSE
           /\ enforced' = FALSE
           /\ web_lock_disconnecting' = FALSE
           /\ lock_epoch' = IF cached_locked THEN lock_epoch + 1 ELSE lock_epoch
           /\ ipad_connected' = TRUE
           /\ ipad_streaming' = TRUE
           /\ web_connected' = web_connected
           /\ web_streaming' = web_connected
           /\ activity_seq' = activity_seq + 1
           /\ main_state' = IF main_state = "sleeping" THEN "active" ELSE main_state
    /\ SyncPowerState
    /\ UNCHANGED <<os_locked, ipad_policy, web_policy, main_observed_seq>>

IpadDisconnect ==
    /\ ipad_connected
    /\ ipad_connected' = FALSE
    /\ ipad_streaming' = FALSE
    /\ sleep_assertion_held' = web_streaming
    /\ capture_running' = web_streaming
    /\ UNCHANGED <<os_locked, cached_locked, enforced, lock_epoch, ipad_policy, web_policy,
                   web_connected, web_streaming, web_lock_disconnecting,
                   activity_seq, main_state, main_observed_seq>>

\* 5. Incoming Web viewer admission (`routes.rs` / `web_screen.rs`: `refresh_host_lock_state_now(TRUE)`).
\*    Preserves active grace period for existing sessions while rejecting incoming `web_policy = "disconnect"`
\*    viewers immediately via `is_web_lock_disconnect_admit_blocked()` (P1-A1).
WebAdmit ==
    /\ ~web_connected
    /\ lock_epoch < MaxEpoch
    /\ activity_seq < MaxSeq
    /\ IF os_locked THEN
           IF HasActive /\ ~enforced THEN
               /\ cached_locked' = TRUE
               /\ enforced' = FALSE
               /\ lock_epoch' = IF cached_locked THEN lock_epoch ELSE lock_epoch + 1
               /\ ipad_connected' = ipad_connected
               /\ ipad_streaming' = ipad_streaming
               /\ web_lock_disconnecting' = web_lock_disconnecting
               /\ IF web_policy = "disconnect" THEN
                      /\ web_connected' = FALSE
                      /\ web_streaming' = FALSE
                      /\ UNCHANGED <<activity_seq, main_state>>
                  ELSE
                      /\ web_connected' = TRUE
                      /\ web_streaming' = TRUE
                      /\ activity_seq' = activity_seq + 1
                      /\ main_state' = IF main_state = "sleeping" THEN "active" ELSE main_state
           ELSE
               /\ cached_locked' = TRUE
               /\ lock_epoch' = IF cached_locked /\ enforced THEN lock_epoch ELSE lock_epoch + 1
               /\ enforced' = TRUE
               /\ ipad_connected' = IF ipad_policy = "disconnect" THEN FALSE ELSE ipad_connected
               /\ ipad_streaming' = IF ipad_policy = "keep" THEN ipad_connected ELSE FALSE
               /\ IF web_policy = "disconnect" THEN
                      /\ web_lock_disconnecting' = TRUE
                      /\ web_connected' = FALSE
                      /\ web_streaming' = FALSE
                      /\ UNCHANGED <<activity_seq, main_state>>
                  ELSE
                      /\ web_lock_disconnecting' = FALSE
                      /\ web_connected' = TRUE
                      /\ web_streaming' = (web_policy = "keep")
                      /\ activity_seq' = activity_seq + 1
                      /\ main_state' = IF main_state = "sleeping" THEN "active" ELSE main_state
       ELSE
           /\ cached_locked' = FALSE
           /\ enforced' = FALSE
           /\ web_lock_disconnecting' = FALSE
           /\ lock_epoch' = IF cached_locked THEN lock_epoch + 1 ELSE lock_epoch
           /\ ipad_connected' = ipad_connected
           /\ ipad_streaming' = ipad_connected
           /\ web_connected' = TRUE
           /\ web_streaming' = TRUE
           /\ activity_seq' = activity_seq + 1
           /\ main_state' = IF main_state = "sleeping" THEN "active" ELSE main_state
    /\ SyncPowerState
    /\ UNCHANGED <<os_locked, ipad_policy, web_policy, main_observed_seq>>

WebDisconnect ==
    /\ web_connected
    /\ web_connected' = FALSE
    /\ web_streaming' = FALSE
    /\ sleep_assertion_held' = ipad_streaming
    /\ capture_running' = ipad_streaming
    /\ UNCHANGED <<os_locked, cached_locked, enforced, lock_epoch, ipad_policy, web_policy,
                   ipad_connected, ipad_streaming, web_lock_disconnecting,
                   activity_seq, main_state, main_observed_seq>>

\* 6. On-demand admin/viewer unlock refresh (e.g. `/api/admin/state` or `/ws/stream` probe).
OnDemandRefreshUnlock ==
    /\ ~os_locked
    /\ cached_locked
    /\ lock_epoch < MaxEpoch
    /\ lock_epoch' = lock_epoch + 1
    /\ ApplyUnlock
    /\ UNCHANGED <<os_locked, ipad_policy, web_policy, activity_seq, main_state, main_observed_seq>>

Next ==
    \/ OsLock
    \/ OsUnlock
    \/ MainStartWaitIdle
    \/ MainCommitSleepOrAbort
    \/ MainPollLock
    \/ MainGraceElapsed
    \/ IpadAdmit
    \/ IpadDisconnect
    \/ WebAdmit
    \/ WebDisconnect
    \/ OnDemandRefreshUnlock

Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ WF_vars(OnDemandRefreshUnlock)
    /\ WF_vars(MainPollLock)
    /\ WF_vars(MainStartWaitIdle)
    /\ WF_vars(MainCommitSleepOrAbort)

\* ==================== SAFETY INVARIANTS ====================

\* PLT-1: When lock is enforced and policy != keep, target NEVER streams live frames.
NoStreamingWhenLockedAndEnforced ==
    /\ (cached_locked /\ enforced /\ ipad_policy # "keep") => ~ipad_streaming
    /\ (cached_locked /\ enforced /\ web_policy # "keep") => ~web_streaming

\* PLT-1: When disconnect policy is enforced, target has zero active connections.
NoConnectedWhenDisconnectEnforced ==
    /\ (cached_locked /\ enforced /\ ipad_policy = "disconnect") => ~ipad_connected
    /\ (cached_locked /\ enforced /\ web_policy = "disconnect") => ~web_connected

\* CON-3: Generation-snapshot wait_idle NEVER loses a wakeup while any session/viewer is active.
NoLostWakeupWhenActive ==
    HasActive => (main_state # "sleeping")

\* PLT-1: `web_lock_disconnecting` is strictly bound to enforced Web disconnect lock state.
WebLockoutConsistent ==
    web_lock_disconnecting => (cached_locked /\ enforced /\ web_policy = "disconnect")

\* Streaming implies connected.
StreamingImpliesConnected ==
    /\ ipad_streaming => ipad_connected
    /\ web_streaming => web_connected

\* PWR-1: NEVER inhibit OS deep sleep when idle or when all clients are paused/locked-out.
NoDeepSleepInhibitionWhenIdle ==
    (~HasStreaming) => (~sleep_assertion_held)

\* PWR-2: NEVER burn hardware capture/encoder resources when no client is actively streaming.
NoCaptureResourceBurnWhenIdle ==
    (~HasStreaming) => (~capture_running)

\* PWR-1 / CON-3: Zero-wakeup sleep state has zero clients, zero sleep assertion, zero capture.
ZeroPollingWakeupWhenSleeping ==
    (main_state = "sleeping") => (~HasActive /\ ~sleep_assertion_held /\ ~capture_running)

\* ==================== LIVENESS PROPERTIES ====================

\* PLT-1: Unlocking the host eventually clears any Web disconnect lockout (provided epoch bound
\* is not exhausted), guaranteeing zero permanent lockout.
UnlockEventuallyClearsLockout ==
    []((~os_locked /\ web_lock_disconnecting /\ lock_epoch < MaxEpoch)
        => <>(os_locked \/ ~web_lock_disconnecting))

\* PWR-1 / PWR-2: Once all clients disconnect and remain absent, the main loop is guaranteed
\* to enter zero-wakeup deep-sleep-ready standby (never stuck spinning in active polling).
IdleEventuallyEntersZeroWakeupSleep ==
    []((~HasActive /\ main_state # "sleeping")
        => <>(HasActive \/ main_state = "sleeping"))

=============================================================================
