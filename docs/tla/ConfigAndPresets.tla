------------------------ MODULE ConfigAndPresets ------------------------
(*
  Formal TLA+ model of idis unified YAML persistence (`~/.config/idis.yaml`),
  CLI override isolation (`persisted_baseline`), corrupt-YAML read-only protection,
  reversible low-power mode (`LowPowerSnapshot`), named config presets, and
  non-destructive partial `DevicePreferences::merge_from`.

  Code correspondence:
    - `src/user_config.rs` (`UserConfigFile`, `ConfigPreset`, `PollingConfigSection`)
    - `src/session/config_store.rs` (`persist_config_patch`, `apply_user_config`,
      `set_low_power`, `save_current_as_preset`, `apply_preset`, `delete_preset`)
    - `src/trust.rs` (`DevicePreferences::merge_from`, `TrustStore::update_device_prefs`)

  Guards Invariants: SEC-4, CFG-1, CFG-2, CFG-3, CFG-4.
*)

EXTENDS Naturals

FpsValues == {15, 30, 60}
PresetSlot == {"none", "30", "60"}

VARIABLES
    disk_corrupt,           \* config_read_only_corrupt
    disk_fps,               \* Value currently persisted on disk
    disk_allow_input,       \* Value currently persisted on disk
    disk_low_power,         \* Value currently persisted on disk
    baseline_fps,           \* SessionRegistry.persisted_baseline.ipad.fps
    baseline_allow_input,   \* SessionRegistry.persisted_baseline.allow_input
    baseline_low_power,     \* SessionRegistry.persisted_baseline.low_power
    runtime_fps,            \* Live VideoSettings.fps
    runtime_allow_input,    \* Live allow_input
    runtime_low_power,      \* Live low_power
    cli_override_fps,       \* TRUE while CLI `--fps 60` override is active & unedited via UI
    has_lp_snapshot,        \* LowPowerSnapshot.is_some()
    snap_fps,               \* LowPowerSnapshot.fps
    trusted_fps,            \* Set of trusted device fingerprints (must survive all preset/config ops)
    dev_pref_fps,           \* Per-device saved fps ("none" | "60")
    dev_pref_abr,           \* Per-device saved adaptive_quality ("on" | "off")
    custom_preset_fps,      \* Saved custom preset "p1" fps ("none" | "30" | "60")
    active_preset,          \* "none" | "p1" | "eco"
    corrupt_overwritten     \* Sticky violation detector: auto-write hit corrupt disk

vars == <<
    disk_corrupt, disk_fps, disk_allow_input, disk_low_power,
    baseline_fps, baseline_allow_input, baseline_low_power,
    runtime_fps, runtime_allow_input, runtime_low_power,
    cli_override_fps, has_lp_snapshot, snap_fps,
    trusted_fps, dev_pref_fps, dev_pref_abr,
    custom_preset_fps, active_preset, corrupt_overwritten
>>

TypeOK ==
    /\ disk_corrupt \in BOOLEAN
    /\ disk_fps \in FpsValues
    /\ disk_allow_input \in BOOLEAN
    /\ disk_low_power \in BOOLEAN
    /\ baseline_fps \in FpsValues
    /\ baseline_allow_input \in BOOLEAN
    /\ baseline_low_power \in BOOLEAN
    /\ runtime_fps \in FpsValues
    /\ runtime_allow_input \in BOOLEAN
    /\ runtime_low_power \in BOOLEAN
    /\ cli_override_fps \in BOOLEAN
    /\ has_lp_snapshot \in BOOLEAN
    /\ snap_fps \in FpsValues
    /\ trusted_fps \subseteq {"fp1", "fp2"}
    /\ dev_pref_fps \in {"none", "60"}
    /\ dev_pref_abr \in {"on", "off"}
    /\ custom_preset_fps \in PresetSlot
    /\ active_preset \in {"none", "p1", "eco"}
    /\ corrupt_overwritten \in BOOLEAN

\* Start with a valid disk baseline (fps=30), an optional corrupt-disk scenario,
\* a CLI `--fps 60` override on runtime, and an existing trusted iPad "fp1" with saved fps=60.
Init ==
    /\ disk_corrupt \in BOOLEAN
    /\ disk_fps = 30
    /\ disk_allow_input = FALSE
    /\ disk_low_power = FALSE
    /\ baseline_fps = 30
    /\ baseline_allow_input = FALSE
    /\ baseline_low_power = FALSE
    /\ runtime_fps = 60
    /\ runtime_allow_input = FALSE
    /\ runtime_low_power = FALSE
    /\ cli_override_fps = TRUE
    /\ has_lp_snapshot = FALSE
    /\ snap_fps = 30
    /\ trusted_fps = {"fp1"}
    /\ dev_pref_fps = "60"
    /\ dev_pref_abr = "on"
    /\ custom_preset_fps = "none"
    /\ active_preset = "none"
    /\ corrupt_overwritten = FALSE

\* 1. Unrelated runtime toggle (`allow_input`): patches ONLY `allow_input` on `persisted_baseline`
\*    (never leaks CLI `runtime_fps = 60` to disk) and skips write if `disk_corrupt` (CFG-1, CFG-2).
ToggleAllowInput ==
    /\ LET next_in == ~runtime_allow_input
           did_write == ~disk_corrupt
       IN
       /\ runtime_allow_input' = next_in
       /\ IF did_write THEN
              /\ baseline_allow_input' = next_in
              /\ disk_allow_input' = next_in
          ELSE
              /\ UNCHANGED <<baseline_allow_input, disk_allow_input>>
       /\ corrupt_overwritten' = (corrupt_overwritten \/ (disk_corrupt /\ did_write))
    /\ UNCHANGED <<disk_corrupt, disk_fps, disk_low_power, baseline_fps, baseline_low_power,
                   runtime_fps, runtime_low_power, cli_override_fps, has_lp_snapshot, snap_fps,
                   trusted_fps, dev_pref_fps, dev_pref_abr, custom_preset_fps, active_preset>>

\* 2. Reversible low-power toggle (CFG-4): snapshots runtime_fps, drops runtime to 15fps without
\*    clobbering baseline_fps/disk_fps; turning OFF restores exact snapshot!
EnableLowPower ==
    /\ ~runtime_low_power
    /\ LET did_write == ~disk_corrupt IN
       /\ runtime_low_power' = TRUE
       /\ has_lp_snapshot' = TRUE
       /\ snap_fps' = runtime_fps
       /\ runtime_fps' = 15
       /\ IF did_write THEN
              /\ baseline_low_power' = TRUE
              /\ disk_low_power' = TRUE
          ELSE
              /\ UNCHANGED <<baseline_low_power, disk_low_power>>
       /\ corrupt_overwritten' = (corrupt_overwritten \/ (disk_corrupt /\ did_write))
    /\ UNCHANGED <<disk_corrupt, disk_fps, disk_allow_input, baseline_fps, baseline_allow_input,
                   runtime_allow_input, cli_override_fps, trusted_fps, dev_pref_fps, dev_pref_abr,
                   custom_preset_fps, active_preset>>

DisableLowPower ==
    /\ runtime_low_power
    /\ LET did_write == ~disk_corrupt IN
       /\ runtime_low_power' = FALSE
       /\ runtime_fps' = IF has_lp_snapshot THEN snap_fps ELSE baseline_fps
       /\ has_lp_snapshot' = FALSE
       /\ IF did_write THEN
              /\ baseline_low_power' = FALSE
              /\ disk_low_power' = FALSE
          ELSE
              /\ UNCHANGED <<baseline_low_power, disk_low_power>>
       /\ corrupt_overwritten' = (corrupt_overwritten \/ (disk_corrupt /\ did_write))
    /\ UNCHANGED <<disk_corrupt, disk_fps, disk_allow_input, baseline_fps, baseline_allow_input,
                   runtime_allow_input, cli_override_fps, snap_fps, trusted_fps, dev_pref_fps,
                   dev_pref_abr, custom_preset_fps, active_preset>>

\* 3. Save current runtime as custom preset "p1" (blocked if disk_corrupt; never drops trusted_fps).
SavePresetP1 ==
    /\ ~disk_corrupt
    /\ custom_preset_fps' = IF runtime_fps = 60 THEN "60" ELSE "30"
    /\ active_preset' = "p1"
    /\ UNCHANGED <<disk_corrupt, disk_fps, disk_allow_input, disk_low_power,
                   baseline_fps, baseline_allow_input, baseline_low_power,
                   runtime_fps, runtime_allow_input, runtime_low_power,
                   cli_override_fps, has_lp_snapshot, snap_fps,
                   trusted_fps, dev_pref_fps, dev_pref_abr, corrupt_overwritten>>

\* 4. Apply built-in "eco" or custom "p1" preset (SEC-4: preserves trusted_fps; clears stale per-device
\*    prefs and CLI overrides because user explicitly applied a full config preset).
ApplyBuiltInEcoPreset ==
    /\ ~disk_corrupt
    /\ runtime_low_power' = TRUE
    /\ runtime_fps' = 15
    /\ baseline_low_power' = TRUE
    /\ baseline_fps' = 15
    /\ disk_low_power' = TRUE
    /\ disk_fps' = 15
    /\ cli_override_fps' = FALSE
    /\ has_lp_snapshot' = FALSE
    /\ dev_pref_fps' = "none"
    /\ active_preset' = "eco"
    /\ UNCHANGED <<disk_corrupt, disk_allow_input, baseline_allow_input, runtime_allow_input,
                   snap_fps, trusted_fps, dev_pref_abr, custom_preset_fps,
                   corrupt_overwritten>>

ApplyCustomPresetP1 ==
    /\ ~disk_corrupt
    /\ custom_preset_fps # "none"
    /\ LET f == IF custom_preset_fps = "60" THEN 60 ELSE 30 IN
       /\ runtime_low_power' = FALSE
       /\ runtime_fps' = f
       /\ baseline_low_power' = FALSE
       /\ baseline_fps' = f
       /\ disk_low_power' = FALSE
       /\ disk_fps' = f
       /\ cli_override_fps' = FALSE
       /\ has_lp_snapshot' = FALSE
       /\ dev_pref_fps' = "none"
       /\ active_preset' = "p1"
    /\ UNCHANGED <<disk_corrupt, disk_allow_input, baseline_allow_input, runtime_allow_input,
                   snap_fps, trusted_fps, dev_pref_abr, custom_preset_fps,
                   corrupt_overwritten>>

DeletePresetP1 ==
    /\ ~disk_corrupt
    /\ custom_preset_fps # "none"
    /\ custom_preset_fps' = "none"
    /\ active_preset' = IF active_preset = "p1" THEN "none" ELSE active_preset
    /\ UNCHANGED <<disk_corrupt, disk_fps, disk_allow_input, disk_low_power,
                   baseline_fps, baseline_allow_input, baseline_low_power,
                   runtime_fps, runtime_allow_input, runtime_low_power,
                   cli_override_fps, has_lp_snapshot, snap_fps,
                   trusted_fps, dev_pref_fps, dev_pref_abr, corrupt_overwritten>>

\* 5. Partial per-device preference update (`DevicePreferences::merge_from`, SEC-4):
\*    Toggling `adaptive_quality` merges ONLY `dev_pref_abr`, preserving `dev_pref_fps`!
PartialDevicePrefToggleAbr ==
    /\ dev_pref_abr' = IF dev_pref_abr = "on" THEN "off" ELSE "on"
    /\ UNCHANGED <<disk_corrupt, disk_fps, disk_allow_input, disk_low_power,
                   baseline_fps, baseline_allow_input, baseline_low_power,
                   runtime_fps, runtime_allow_input, runtime_low_power,
                   cli_override_fps, has_lp_snapshot, snap_fps,
                   trusted_fps, dev_pref_fps, custom_preset_fps, active_preset,
                   corrupt_overwritten>>

\* 6. Admin explicit repair of corrupt YAML (CFG-2, CFG-3).
RepairCorruptYaml ==
    /\ disk_corrupt
    /\ disk_corrupt' = FALSE
    /\ disk_fps' = 30
    /\ baseline_fps' = 30
    /\ runtime_fps' = 30
    /\ disk_allow_input' = FALSE
    /\ baseline_allow_input' = FALSE
    /\ runtime_allow_input' = FALSE
    /\ disk_low_power' = FALSE
    /\ baseline_low_power' = FALSE
    /\ runtime_low_power' = FALSE
    /\ cli_override_fps' = FALSE
    /\ has_lp_snapshot' = FALSE
    /\ UNCHANGED <<snap_fps, trusted_fps, dev_pref_fps, dev_pref_abr,
                   custom_preset_fps, active_preset, corrupt_overwritten>>

Next ==
    \/ ToggleAllowInput
    \/ EnableLowPower
    \/ DisableLowPower
    \/ SavePresetP1
    \/ ApplyBuiltInEcoPreset
    \/ ApplyCustomPresetP1
    \/ DeletePresetP1
    \/ PartialDevicePrefToggleAbr
    \/ RepairCorruptYaml

Spec == Init /\ [][Next]_vars

\* ==================== SAFETY INVARIANTS ====================

\* CFG-1: Temporary CLI `--fps 60` override NEVER leaks to disk during unrelated edits or low-power toggles.
CliOverrideNeverLeaksToDisk ==
    cli_override_fps => (disk_fps = 30 /\ baseline_fps = 30)

\* CFG-2: Automatic background saves NEVER overwrite a corrupt YAML file on disk.
CorruptDiskNeverAutoOverwritten ==
    /\ ~corrupt_overwritten
    /\ disk_corrupt => (disk_fps = 30 /\ ~disk_allow_input /\ ~disk_low_power)

\* CFG-3: When disk is clean, `disk` and `persisted_baseline` are strictly synchronized.
DiskAndBaselineConsistentWhenClean ==
    (~disk_corrupt) =>
        (disk_fps = baseline_fps /\ disk_allow_input = baseline_allow_input /\ disk_low_power = baseline_low_power)

\* SEC-4: Config/preset operations NEVER drop existing trusted device fingerprints.
PresetOpsNeverLoseTrustedDevices ==
    "fp1" \in trusted_fps

\* SEC-4: Partial `DevicePreferences::merge_from` NEVER clobbers unrelated saved per-device fields
\* (per-device fps is only cleared when user explicitly applies a full preset).
PartialPrefMergeNeverClobbersFps ==
    (cli_override_fps) => (dev_pref_fps = "60")

\* CFG-4: Low-power snapshot lifecycle is clean (no dangling snapshot once exited).
LowPowerSnapshotConsistent ==
    (~runtime_low_power) => (~has_lp_snapshot)

=============================================================================
