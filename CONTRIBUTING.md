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
# Unit + end-to-end integration tests
cargo test --locked

# Zero-warning lint check
cargo clippy --locked --all-targets -- -D warnings

# Web Admin / Viewer frontend + Objective-C static checks
node tests/web_frontend_test.mjs

# Optional: TLA+ formal model checking
./docs/tla/check.sh --download
```

## Guidelines

- Keep PRs focused and include regression tests for bug fixes or behavioral changes.
- Do not commit personal device identifiers, private IPs, tokens, or proprietary third-party code/assets.
- Update the relevant documentation under `docs/` and `README.md` / `README.en.md` when adding user-facing features or flags.
