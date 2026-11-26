# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in `idis`, please **do not** open a public GitHub issue with exploit details.

Instead, report it privately via **GitHub Security Advisories** ("Security" → "Advisories" → "Report a vulnerability") on this repository. Please include:

- Affected version / OS platform
- Reproduction steps or proof of concept
- Potential impact and suggested remediation (if any)

We will acknowledge reports as quickly as possible and coordinate a fix before public disclosure.

## Security Model & Usage Boundaries

`idis` is designed with a **secure-by-default** posture for trusted local networks (LAN / VPN):

1. **Port Isolation by Default**
   - The Web Admin Console defaults to loopback-only (`127.0.0.1:8787`) and never serves viewer routes.
   - The Web Extended Screen opens a separate random port on `0.0.0.0` only while explicitly enabled with a passcode, and closes it automatically when disabled or after the configured idle timeout (`--port-idle-close-secs`, default `300s`).
   - Legacy Wi-Fi compatibility ports are disabled by default and can be toggled on demand (with the same idle auto-close protection).
2. **Plaintext LAN HTTP / Optional Reverse Proxy**
   - Built-in HTTP/WebSocket listeners do not terminate TLS and are intended for trusted home/office LANs or encrypted overlays (WireGuard, Tailscale). Do **not** expose raw `idis` ports directly to the public internet without a TLS reverse proxy.
3. **WebRTC LAN P2P Relay**
   - When multiple viewers share the same viewing passcode, LAN P2P relay assumes mutual trust among those viewers. Disable P2P relay in the Admin Console if viewers should not connect directly to each other.
4. **Device Approval & Input Injection**
   - Remote input injection (`--allow-input`) is disabled by default (view-only). Avoid enabling remote input over untrusted networks.
   - Optional legacy Wi-Fi compatibility uses unencrypted LAN TCP and device-trust approval; prefer USB or a trusted private network when using it.
5. **macOS Permissions**
   - Screen Recording and Accessibility permissions are required for capture, virtual display window routing, and optional input injection. Be mindful that granting Accessibility permission to a general-purpose terminal app extends that privilege to all commands run in that terminal.
