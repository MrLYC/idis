# idis

[简体中文](README.md) | [English](README.en.md)

Cross-platform **Web Extended Screen**, **macOS Virtual Display**, and **Automatic Window Routing** host for macOS, Linux, and Windows.  
Turn any browser on your local network (tablet, laptop, phone, secondary PC) into a low-latency extended display — **zero client installation required** — with optional compatibility for legacy USB/Wi-Fi display clients.

---

## Key Features

- **Zero-Install Web Extended Screen**
  - Hardware-accelerated H.264 capture with MSE fMP4 streaming for Chrome, Safari, Edge, and iOS 17+ (`ManagedMediaSource`). Scan a QR code or enter a passcode to go fullscreen immediately.
  - Flexible display sources: **Independent virtual extended display** (macOS), **Primary display**, or **Follow** mode, with custom resolution, Retina HiDPI, quality presets, and flicker-free constant-resolution ABR.
  - Built-in **LAN WebRTC P2P Relay**: when multiple browsers watch simultaneously, viewers automatically form a shallow LAN relay tree to offload host bandwidth, with seamless WebSocket fallback.
- **Strict Admin / Viewer Port Isolation & Idle Auto-Close**
  - The Web Admin Console defaults to loopback-only (`127.0.0.1:8787`, passwordless locally) and strictly rejects viewer/streaming endpoints.
  - Enabling Web viewing with a passcode dynamically opens an isolated random port on `0.0.0.0` strictly for viewer traffic; disabling viewing, entering low-power mode, or exceeding the idle timeout (`--port-idle-close-secs`, default `300s`) closes the external port immediately.
  - Optional legacy Wi-Fi compatibility ports also support dynamic runtime toggling and idle auto-close from the Admin Console.
- **Ephemeral Virtual Displays (macOS) & Automatic Window Routing (macOS / Windows)**
  - On macOS, spin up to 4 **zero-encode** temporary virtual displays directly from the Admin Console without attaching any external monitor or viewer (automatically destroyed on exit).
  - On both macOS and Windows, inspect regular windows and **floating overlays/topmost widgets**, move them across displays in one click, and define persistent `window_rules` (e.g. automatically tucking floating recording controls onto a virtual or secondary screen without moving main app windows).
- **Deep-Sleep Friendly & Low-Power Ready**
  - Event-driven **zero-wakeup standby** when idle (never blocks OS deep sleep); pauses capture and encoding automatically when tabs are backgrounded or the host locks.
  - Reversible **low-power mode**, configurable **lock-screen policies** (pause / disconnect / keep with grace delay), 4 built-in + custom YAML presets, and `launchd` / `systemd` Socket Activation templates.
- **Secure by Default & Lightweight Device Approval**
  - No external ports open by default, view-only by default (remote input opt-in), direct connections by default (no ambient proxy), and zero telemetry unless explicitly configured.
  - Optional LAN viewer approval lets you allow once, trust, or revoke devices directly from the Admin Console or terminal.
- **Optional Legacy Display Client Compatibility**
  - Optionally interoperates with legacy USB (`usbmuxd`) and LAN Wi-Fi display clients. See [Legacy Client Compatibility](docs/legacy-clients.md).

---

## Quickstart

### 1. Download or Build

- Download a prebuilt archive from [GitHub Releases](https://github.com/MrLYC/idis/releases) (`macos-arm64`, `macos-x86_64`, `linux-x86_64`, `linux-arm64`, `windows-x86_64`), or build from source:
  ```bash
  cargo build --release --locked
  ```

### 2. Start the Web Extended Screen

```bash
idis --web
```

1. Open **`http://127.0.0.1:8787/`** locally to access the Admin Console.
2. Generate or enter a viewing passcode in the **Ports & QR** panel.
3. `idis` automatically opens a dynamic `0.0.0.0:<random>` Viewer port and renders LAN quick-connect links & QR codes.
4. Scan the QR code (or open the URL) from any browser on your LAN and press `F` or double-click for fullscreen.

Or launch with a passcode and terminal QR code in one command:

```bash
idis --web --max-web-viewers 2 --web-view-token "your-passcode" --qr
```

### 3. Platform Prerequisites

- **macOS (12.3+)**: Grant **Screen Recording** permission (and **Accessibility** if using window routing or optional input injection) in *System Settings → Privacy & Security*.
- **Linux / Windows**: Ensure `ffmpeg` is in `PATH` (or pass `--ffmpeg-path`).

---

## Documentation

Full guides are available under `docs/` (currently written in Simplified Chinese):

- [Web Extended Screen Guide](docs/web-extended-screen.md)
- [macOS Virtual Displays & Window Routing](docs/virtual-displays.md)
- [Configuration & CLI Reference](docs/configuration.md)
- [Background Hosting & Zero-Wakeup Standby](docs/background-hosting.md)
- [Legacy Client Compatibility (Optional)](docs/legacy-clients.md)
- [Architecture & Formal Invariants (TLA+)](docs/architecture.md)
- [Security Policy](SECURITY.md) | [Contributing](CONTRIBUTING.md)

---

## Disclaimers & License

- **Undocumented macOS APIs**: Virtual display creation (`CGVirtualDisplay`) and exact AX window matching (`_AXUIElementGetWindow`) on macOS are resolved dynamically at runtime with graceful fallbacks. This tool is intended for standalone local/CLI use and is not designed for Mac App Store distribution.
- **Trademarks & Non-Affiliation**: `idis` is an independent open-source project and is not affiliated with, sponsored by, or endorsed by Apple Inc., SHAPE GmbH, or any other trademark holder. All third-party trademarks belong to their respective owners and are mentioned solely for interoperability context.
- **License**: Released under the [MIT License](LICENSE). Third-party crate notices included in compiled binaries are listed in [THIRD_PARTY_LICENSES.txt](THIRD_PARTY_LICENSES.txt).
