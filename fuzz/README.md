# `idis` Coverage-Guided Fuzz Targets (Tier 2 — `libFuzzer`)

This directory is an **isolated Cargo workspace** (`[workspace]` in `fuzz/Cargo.toml`) so stable Rust builds, `Cargo.lock`, and 3-OS CI (`cargo test/clippy --locked --all-targets`) remain completely unaffected.

## Targets

| Target | Entry Surface |
|---|---|
| `keyed_archive` | `unarchive`, `MessagePacket::decode`, `decode_input_event` |
| `framing_video` | `read_canal_block_limited`, `read_pt_frame_limited`, `parse_video_header` |
| `http_ws` | `parse_http_bytes`, `origin_matches_host`, `parse_ws_client_frame` |
| `annexb_fmp4` | `AnnexBSplitter`, `is_self_contained_idr`, `Fmp4Muxer::mux_frame_at` |
| `yaml_config` | `UserConfigFile::from_yaml_str` + roundtrip idempotency |

## Running Locally (Linux / macOS + Rust nightly)

```bash
rustup toolchain install nightly
cargo install cargo-fuzz --locked

# Run a single target for 2 minutes
cargo +nightly fuzz run --fuzz-dir fuzz keyed_archive -- -max_total_time=120 -max_len=65536

# Minimize any discovered crash input before adding it to Tier-0 regression tests
cargo +nightly fuzz tmin --fuzz-dir fuzz keyed_archive fuzz/artifacts/keyed_archive/crash-...
```

CI runs all 5 targets automatically every two weeks (`.github/workflows/fuzz.yml`, `cron: '0 3 1,15 * *'`) and supports manual `workflow_dispatch`.
