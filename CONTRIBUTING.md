# Contributing to `idis`

Thank you for your interest in contributing to `idis`!

## Development Prerequisites

- Rust stable toolchain (`rustup`)
- Node.js 18+ (for Web Admin / Viewer frontend tests)
- Optional: Java 17+ (to run TLA+ formal invariant checks locally)
- macOS: Xcode Command Line Tools (`xcode-select --install`) for compiling `macos/bridge.m`
- Linux / Windows: `ffmpeg` in `PATH` for live capture tests

## Running Checks Locally

Before opening a pull request, please ensure all checks pass cleanly:

```bash
# Unit + end-to-end integration tests (including the dual-mode client simulator)
cargo test --locked --all-targets

# Zero-warning lint check
cargo clippy --locked --all-targets -- -D warnings

# Web Admin / Viewer frontend + Objective-C static checks
node tests/web_frontend_test.mjs

# Optional: TLA+ formal model checking
./docs/tla/check.sh --download
```

## Dual-Mode End-to-End Client Simulator (`examples/client_sim.rs`)

You can test a live `idis` host without a physical tablet or extra browser using the built-in `client_sim` example (supports multi-resolution presets, live rotation, weak-network profiles, real `ffmpeg` H.264/fMP4 decode verification, and `ffplay` live preview):

```bash
# 1) Simulate 2 Web Extended Screen viewers with rotation, weak Wi-Fi profile, and real FFmpeg decode check
cargo run --example client_sim -- web \
  --admin-url http://127.0.0.1:8787 \
  --token "your-passcode" \
  --clients 2 --p2p-hello \
  --cycle-res 1280x720,720x1280,1920x1080 --rotate-every 5 \
  --net-profile wifi-weak --verify-decode --duration 20

# 2) Simulate a legacy iPad Air Wi-Fi client with orientation rotation, jitter/stalls, and live ffplay preview
cargo run --example client_sim -- ipad \
  --host 127.0.0.1 --port 56845 \
  --preset ipad-air --rotate-every 5 \
  --net-profile lossy-burst --verify-decode --preview --duration 30

# 3) Run the 4D Pareto Scenario Matrix scorecard (self-hosted loopback or against a live host)
cargo run --example client_sim -- matrix --self-host --target web --per-profile-secs 4
```

## 3-Tier Pareto Fuzz Testing Suite

- **Tier 0 (every PR, `<5s`, zero external dependencies, deterministic)**:
  - `cargo test --locked --test fuzz_parsers` — untrusted byte/protocol/HTTP/WS/YAML security & framing feasibility gate.
  - `cargo test --locked --test fuzz_pareto_qoe` — logical-clock 4D Pareto frontier tests (coupled ABR + InFlight + Wi-Fi PSM guard, `FlowControl`, `AnnexBSplitter` + `Fmp4Muxer`, `SharedWebMuxer`, `P2pRelayHub` topology churn).
  - `cargo test --locked --test fuzz_stateful_chaos` — TLA+ shadow-model action-sequence fuzzer with 3-phase `ddmin` shrinking + multi-thread lock-order chaos watchdog.
  - Override seed/budget locally: `IDIS_FUZZ_SEEDS=2000 cargo test --locked --test fuzz_pareto_qoe` or replay a single seed via `IDIS_FUZZ_SEED=0x...`.
- **Tier 1 (on-demand Pareto Matrix)**: `cargo run --example client_sim -- matrix --self-host` (or against a live host with `--verify-decode`).
- **Tier 2 (biweekly / on-demand Linux nightly `libFuzzer`)**: Isolated in [`fuzz/`](fuzz/README.md) with `.github/workflows/fuzz.yml` (`cron: '0 3 1,15 * *'`), completely invisible to root `Cargo.lock` and stable 3-OS CI.

## Guidelines

- Keep PRs focused and include regression tests for bug fixes or behavioral changes.
- Do not commit personal device identifiers, private IPs, tokens, or proprietary third-party code/assets.
- Update the relevant documentation under `docs/` and `README.md` / `README.en.md` when adding user-facing features or flags.
