//! Dual-mode end-to-end client simulator for `idis` (`web` + `ipad` modes).
//!
//! Features:
//! - **Web Extended Screen (`web`)**: HTTP passcode login, optional approval, RFC 6455 WebSocket
//!   `/ws/stream`, ISO BMFF fMP4 (`ftyp`/`moov`/`moof`/`mdat`/`tfdt`/`trun`) integrity checks,
//!   multi-viewer concurrency, optional P2P signaling hello, tab visibility pause cycles, and
//!   live resolution/orientation switching via Admin API.
//! - **Legacy iPad (`ipad`)**: Authentic Canal telemetry + data channels (`v5`/`v4`), `Handshake`,
//!   `AccessConfirmed`, `FrameReceived`/`PictureRendered` ACKs, `Ping` RTT, live `OrientationChange`,
//!   live `ResolutionChange`, `StopStream`/`StartStream` pause cycles, and synthetic touch input.
//! - **Multi-Resolution & Rotation**: Built-in device presets (`ipad-air`, `ipad-pro-11`, `fhd`,
//!   `qhd`, `hd`, `phone`, `4k`), custom `WxH`, `--rotate-every`, and `--cycle-res`.
//! - **Weak-Network Emulation**: Presets (`lan`, `wifi-busy`, `wifi-weak`, `cellular`, `lossy-burst`)
//!   plus deterministic `--latency-ms`, `--jitter-ms`, `--bandwidth-kbps`, `--stall-prob`,
//!   `--stall-ms`, `--drop-ack-rate`, and `--reconnect-every`.
//! - **Real Media Verification & Preview**: Optional `--verify-decode` (pipes received H.264/fMP4
//!   into `ffmpeg -v error ... -f null -` to catch broken DPB chains or corrupt slices) and
//!   `--preview` (real-time playback via `ffplay`).

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use clap::{Args, Parser, Subcommand, ValueEnum};
use idis::protocol::annexb::is_self_contained_idr;
use idis::protocol::framing::{read_canal_block, write_canal_block};
use idis::protocol::keyed_archive::{archive, ArchivedValue};
use idis::protocol::messages::{MessagePacket, MessageType};
use idis::protocol::video::{parse_video_header, COMPRESSION_H264};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Parser, Debug)]
#[command(
    name = "client_sim",
    about = "Dual-mode Web & iPad client simulator for idis end-to-end testing (multi-resolution, rotation, weak-network & real H.264/fMP4 verification)"
)]
struct Cli {
    #[command(subcommand)]
    mode: SimMode,
}

#[derive(Subcommand, Debug)]
enum SimMode {
    /// Simulate 1..N Web Extended Screen browser viewers (/api/view/login + /ws/stream fMP4)
    Web(WebArgs),
    /// Simulate 1..N legacy iPad Wi-Fi clients (Canal telemetry + data + H.264 Annex-B)
    Ipad(IpadArgs),
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
enum DevicePreset {
    IpadAir,
    IpadMini,
    IpadPro11,
    IpadPro13,
    Hd,
    Fhd,
    Qhd,
    Phone,
    Uhd4k,
}

impl DevicePreset {
    fn dimensions(self) -> (u32, u32) {
        match self {
            DevicePreset::IpadAir | DevicePreset::IpadMini => (2048, 1536),
            DevicePreset::IpadPro11 => (2388, 1668),
            DevicePreset::IpadPro13 => (2732, 2048),
            DevicePreset::Hd => (1280, 720),
            DevicePreset::Fhd => (1920, 1080),
            DevicePreset::Qhd => (2560, 1440),
            DevicePreset::Phone => (1170, 2532),
            DevicePreset::Uhd4k => (3840, 2160),
        }
    }

    fn display_name(self) -> &'static str {
        match self {
            DevicePreset::IpadAir => "Sim iPad Air",
            DevicePreset::IpadMini => "Sim iPad mini",
            DevicePreset::IpadPro11 => "Sim iPad Pro 11",
            DevicePreset::IpadPro13 => "Sim iPad Pro 13",
            DevicePreset::Hd => "Sim 720p",
            DevicePreset::Fhd => "Sim 1080p",
            DevicePreset::Qhd => "Sim 1440p",
            DevicePreset::Phone => "Sim Phone",
            DevicePreset::Uhd4k => "Sim 4K",
        }
    }
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
enum NetProfile {
    /// Clean LAN (0ms delay, unlimited bandwidth, no stalls)
    Lan,
    /// Congested Wi-Fi (35ms +-25ms, 8 Mbps, 3% 250ms burst stalls)
    WifiBusy,
    /// Weak/far Wi-Fi (90ms +-60ms, 3 Mbps, 8% 500ms burst stalls)
    WifiWeak,
    /// Mobile hotspot / cellular (140ms +-80ms, 1.5 Mbps, 10% 700ms burst stalls)
    Cellular,
    /// Frequent roaming stalls (45ms +-40ms, 4 Mbps, 15% 900ms burst stalls)
    LossyBurst,
}

#[derive(Debug, Clone, Copy)]
struct EffectiveNetConfig {
    latency_ms: u64,
    jitter_ms: u64,
    bandwidth_kbps: u64,
    stall_prob: f64,
    stall_ms: u64,
    drop_ack_rate: f64,
}

impl NetProfile {
    fn defaults(self) -> EffectiveNetConfig {
        match self {
            NetProfile::Lan => EffectiveNetConfig {
                latency_ms: 0,
                jitter_ms: 0,
                bandwidth_kbps: 0,
                stall_prob: 0.0,
                stall_ms: 0,
                drop_ack_rate: 0.0,
            },
            NetProfile::WifiBusy => EffectiveNetConfig {
                latency_ms: 35,
                jitter_ms: 25,
                bandwidth_kbps: 8_000,
                stall_prob: 0.03,
                stall_ms: 250,
                drop_ack_rate: 0.0,
            },
            NetProfile::WifiWeak => EffectiveNetConfig {
                latency_ms: 90,
                jitter_ms: 60,
                bandwidth_kbps: 3_000,
                stall_prob: 0.08,
                stall_ms: 500,
                drop_ack_rate: 0.02,
            },
            NetProfile::Cellular => EffectiveNetConfig {
                latency_ms: 140,
                jitter_ms: 80,
                bandwidth_kbps: 1_500,
                stall_prob: 0.10,
                stall_ms: 700,
                drop_ack_rate: 0.03,
            },
            NetProfile::LossyBurst => EffectiveNetConfig {
                latency_ms: 45,
                jitter_ms: 40,
                bandwidth_kbps: 4_000,
                stall_prob: 0.15,
                stall_ms: 900,
                drop_ack_rate: 0.05,
            },
        }
    }
}

#[derive(Args, Debug, Clone)]
struct CommonArgs {
    /// Device resolution preset
    #[arg(long, value_enum, default_value_t = DevicePreset::IpadAir)]
    preset: DevicePreset,

    /// Explicit initial resolution `WxH` (overrides `--preset`, e.g. `1920x1080`)
    #[arg(long)]
    res: Option<String>,

    /// Comma-separated resolution sequence to cycle through (e.g. `1280x720,1920x1080,1080x1920`)
    #[arg(long)]
    cycle_res: Option<String>,

    /// Rotate orientation (swap W/H) or advance `--cycle-res` every N seconds (0 = disabled)
    #[arg(long, default_value_t = 0)]
    rotate_every: u64,

    /// Weak-network emulation preset
    #[arg(long, value_enum, default_value_t = NetProfile::Lan)]
    net_profile: NetProfile,

    /// Override artificial base latency (ms)
    #[arg(long)]
    latency_ms: Option<u64>,

    /// Override artificial jitter (+-ms)
    #[arg(long)]
    jitter_ms: Option<u64>,

    /// Override simulated receive bandwidth cap in kbps (0 = unlimited)
    #[arg(long)]
    bandwidth_kbps: Option<u64>,

    /// Override per-frame burst stall probability (0.0..=1.0)
    #[arg(long)]
    stall_prob: Option<f64>,

    /// Override burst stall duration (ms)
    #[arg(long)]
    stall_ms: Option<u64>,

    /// Override simulated dropped-ACK probability in iPad mode (0.0..=1.0)
    #[arg(long)]
    drop_ack_rate: Option<f64>,

    /// Disconnect and reconnect every N seconds (0 = disabled)
    #[arg(long, default_value_t = 0)]
    reconnect_every: u64,

    /// Deterministic PRNG seed for reproducible jitter/stall runs
    #[arg(long, default_value_t = 20261127)]
    seed: u64,

    /// Number of concurrent simulated clients
    #[arg(long, default_value_t = 1)]
    clients: usize,

    /// Test duration in seconds (0 = run until Ctrl-C)
    #[arg(long, default_value_t = 15)]
    duration: u64,

    /// Fail with non-zero exit code if fewer than N video frames/segments are received
    #[arg(long, default_value_t = 1)]
    min_frames: u64,

    /// Pipe received H.264 / fMP4 stream into `ffmpeg -v error ... -f null -` for real decode verification
    #[arg(long, default_value_t = false)]
    verify_decode: bool,

    /// Launch `ffplay` to preview client #0's live decoded video in a window
    #[arg(long, default_value_t = false)]
    preview: bool,

    /// Path to `ffmpeg` binary (used by `--verify-decode`)
    #[arg(long, default_value = "ffmpeg")]
    ffmpeg_path: String,

    /// Path to `ffplay` binary (used by `--preview`)
    #[arg(long, default_value = "ffplay")]
    ffplay_path: String,

    /// Print machine-readable JSON summary on exit
    #[arg(long, default_value_t = false)]
    json_summary: bool,

    /// Exit non-zero on any protocol/integrity warning (e.g. non-IDR after reset, tfdt regression, decode error)
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    strict: bool,
}

impl CommonArgs {
    fn resolve_net(&self) -> EffectiveNetConfig {
        let mut cfg = self.net_profile.defaults();
        if let Some(v) = self.latency_ms {
            cfg.latency_ms = v;
        }
        if let Some(v) = self.jitter_ms {
            cfg.jitter_ms = v;
        }
        if let Some(v) = self.bandwidth_kbps {
            cfg.bandwidth_kbps = v;
        }
        if let Some(v) = self.stall_prob {
            cfg.stall_prob = v.clamp(0.0, 1.0);
        }
        if let Some(v) = self.stall_ms {
            cfg.stall_ms = v;
        }
        if let Some(v) = self.drop_ack_rate {
            cfg.drop_ack_rate = v.clamp(0.0, 1.0);
        }
        cfg
    }

    fn resolve_initial_res(&self) -> Result<(u32, u32)> {
        if let Some(ref s) = self.res {
            parse_resolution(s)
        } else {
            let cycle = self.resolve_cycle_res()?;
            if let Some(&first) = cycle.first() {
                Ok(first)
            } else {
                Ok(self.preset.dimensions())
            }
        }
    }

    fn resolve_cycle_res(&self) -> Result<Vec<(u32, u32)>> {
        let Some(ref raw) = self.cycle_res else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        for part in raw.split(',') {
            let trimmed = part.trim();
            if !trimmed.is_empty() {
                out.push(parse_resolution(trimmed)?);
            }
        }
        Ok(out)
    }
}

#[derive(Args, Debug, Clone)]
struct WebArgs {
    /// Viewer base URL (e.g. `http://127.0.0.1:54321`). If omitted, auto-discovers from `--admin-url`.
    #[arg(long)]
    viewer_url: Option<String>,

    /// Admin Console base URL (e.g. `http://127.0.0.1:8787`) for auto-discovery & live resolution switching
    #[arg(long, default_value = "http://127.0.0.1:8787")]
    admin_url: String,

    /// Viewing passcode configured in `idis` (`--web-view-token`)
    #[arg(long, default_value = "")]
    token: String,

    /// Request LAN approval via `POST /api/view/request-approval` after login
    #[arg(long, default_value_t = false)]
    request_approval: bool,

    /// Send `p2p_hello` capability announcement on WebSocket connect to exercise P2P relay tree
    #[arg(long, default_value_t = false)]
    p2p_hello: bool,

    /// Simulate tab backgrounding cycle `VISIBLE_SECS:HIDDEN_SECS` (e.g. `6:4`)
    #[arg(long)]
    visibility_cycle: Option<String>,

    #[command(flatten)]
    common: CommonArgs,
}

#[derive(Args, Debug, Clone)]
struct IpadArgs {
    /// Target `idis` host IP or hostname
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// Target `idis` Wi-Fi telemetry port
    #[arg(long, default_value_t = 56845)]
    port: u16,

    /// Simulated client protocol version (`5` = 17B header with bytes_per_row, `4` = 13B header)
    #[arg(long, default_value_t = 5)]
    proto: u32,

    /// Base device UID prefix (each concurrent client appends `-<idx>`)
    #[arg(long, default_value = "sim-ipad-uid")]
    uid: String,

    /// Simulated device display name
    #[arg(long)]
    name: Option<String>,

    /// Simulated iOS version reported in handshake
    #[arg(long, default_value = "12.5.8")]
    ios_version: String,

    /// Send synthetic touch tap events every N seconds (0 = disabled)
    #[arg(long, default_value_t = 0)]
    send_touch_every: u64,

    /// Send `StopStream` / `StartStream` pause cycle `ACTIVE_SECS:PAUSE_SECS` (e.g. `6:3`)
    #[arg(long)]
    pause_cycle: Option<String>,

    /// Send periodic `Ping` requests every N seconds (0 = disabled)
    #[arg(long, default_value_t = 3)]
    ping_every: u64,

    #[command(flatten)]
    common: CommonArgs,
}

fn parse_resolution(spec: &str) -> Result<(u32, u32)> {
    let lower = spec.trim().to_ascii_lowercase();
    let (w_s, h_s) = lower
        .split_once('x')
        .ok_or_else(|| anyhow!("invalid resolution {spec:?}, expected WxH (e.g. 1920x1080)"))?;
    let w: u32 = w_s.trim().parse().with_context(|| format!("invalid width in {spec:?}"))?;
    let h: u32 = h_s.trim().parse().with_context(|| format!("invalid height in {spec:?}"))?;
    if w < 320 || h < 240 || w > 8192 || h > 8192 {
        bail!("resolution {w}x{h} out of supported range [320x240..8192x8192]");
    }
    Ok((w & !1, h & !1))
}

fn parse_cycle_pair(spec: &str) -> Result<(Duration, Duration)> {
    let (a, b) = spec
        .trim()
        .split_once(':')
        .ok_or_else(|| anyhow!("invalid cycle spec {spec:?}, expected ACTIVE_SECS:IDLE_SECS"))?;
    let s1: u64 = a.trim().parse().context("invalid first cycle duration")?;
    let s2: u64 = b.trim().parse().context("invalid second cycle duration")?;
    if s1 == 0 || s2 == 0 {
        bail!("cycle durations must both be >= 1s");
    }
    Ok((Duration::from_secs(s1), Duration::from_secs(s2)))
}

/// Deterministic fast xorshift64* PRNG for reproducible jitter/stall/drop simulation.
#[derive(Debug, Clone)]
struct SimRng {
    state: u64,
}

impl SimRng {
    fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 0x9E37_79B9_7F4A_7C15 } else { seed },
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn next_f64(&mut self) -> f64 {
        ((self.next_u64() >> 11) as f64) / ((1u64 << 53) as f64)
    }
}

/// Token-bucket + latency/jitter/stall weak-network shaper applied on the simulated client side.
struct WeakNetShaper {
    cfg: EffectiveNetConfig,
    rng: SimRng,
    next_bw_ready: Instant,
    stalls_injected: u64,
    dropped_acks: u64,
}

impl WeakNetShaper {
    fn new(cfg: EffectiveNetConfig, seed: u64) -> Self {
        Self {
            cfg,
            rng: SimRng::new(seed),
            next_bw_ready: Instant::now(),
            stalls_injected: 0,
            dropped_acks: 0,
        }
    }

    fn compute_delay(&mut self) -> Duration {
        let base = self.cfg.latency_ms as i64;
        let jit = if self.cfg.jitter_ms > 0 {
            let span = (self.cfg.jitter_ms * 2 + 1) as i64;
            (self.rng.next_u64() % span as u64) as i64 - self.cfg.jitter_ms as i64
        } else {
            0
        };
        let mut total_ms = (base + jit).max(0) as u64;
        if self.cfg.stall_prob > 0.0 && self.cfg.stall_ms > 0 && self.rng.next_f64() < self.cfg.stall_prob {
            self.stalls_injected += 1;
            total_ms = total_ms.saturating_add(self.cfg.stall_ms);
        }
        Duration::from_millis(total_ms)
    }

    /// Pace reception of `bytes` according to `bandwidth_kbps` + optional burst stall.
    fn pace_receive(&mut self, bytes: usize, stop: &AtomicBool) {
        if self.cfg.bandwidth_kbps > 0 && bytes > 0 {
            let bits = (bytes as u128) * 8;
            let micros = (bits * 1_000) / (self.cfg.bandwidth_kbps as u128).max(1);
            let now = Instant::now();
            let base = if self.next_bw_ready > now {
                self.next_bw_ready
            } else {
                now
            };
            let target = base + Duration::from_micros(micros as u64);
            self.next_bw_ready = target;
            if target > now {
                sleep_interruptible(target - now, stop);
            }
        }
        if self.cfg.stall_prob > 0.0
            && self.cfg.stall_ms > 0
            && self.rng.next_f64() < self.cfg.stall_prob
        {
            self.stalls_injected += 1;
            sleep_interruptible(Duration::from_millis(self.cfg.stall_ms), stop);
        }
    }

    fn should_drop_ack(&mut self) -> bool {
        if self.cfg.drop_ack_rate > 0.0 && self.rng.next_f64() < self.cfg.drop_ack_rate {
            self.dropped_acks += 1;
            true
        } else {
            false
        }
    }
}

fn sleep_interruptible(dur: Duration, stop: &AtomicBool) {
    let deadline = Instant::now() + dur;
    while !stop.load(Ordering::Acquire) {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let step = (deadline - now).min(Duration::from_millis(25));
        thread::sleep(step);
    }
}

/// Optional real decoder (`ffmpeg -f <fmt> -i pipe:0 -f null -`) or preview (`ffplay`) sink.
struct MediaPipeSink {
    child: Child,
    stdin: Option<ChildStdin>,
    stderr_lines: Arc<Mutex<Vec<String>>>,
    stderr_thread: Option<thread::JoinHandle<()>>,
    kind: &'static str,
}

impl MediaPipeSink {
    fn spawn_verifier(ffmpeg_path: &str, input_format: &str) -> Result<Self> {
        let mut cmd = Command::new(ffmpeg_path);
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x0800_0000);
        }
        cmd.args([
            "-hide_banner",
            "-loglevel",
            "error",
            "-nostdin",
            "-f",
            input_format,
            "-i",
            "pipe:0",
            "-f",
            "null",
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());

        let mut child = cmd
            .spawn()
            .with_context(|| format!("failed to spawn ffmpeg verifier ({ffmpeg_path:?})"))?;
        let stdin = child.stdin.take();
        let stderr = child.stderr.take();
        let stderr_lines = Arc::new(Mutex::new(Vec::new()));
        let lines_bg = stderr_lines.clone();
        let stderr_thread = stderr.map(|err| {
            thread::spawn(move || {
                let reader = BufReader::new(err);
                for line in reader.lines().map_while(Result::ok) {
                    let trimmed = line.trim().to_string();
                    if !trimmed.is_empty() {
                        if let Ok(mut guard) = lines_bg.lock() {
                            if guard.len() < 64 {
                                guard.push(trimmed);
                            }
                        }
                    }
                }
            })
        });

        Ok(Self {
            child,
            stdin,
            stderr_lines,
            stderr_thread,
            kind: "ffmpeg-verify",
        })
    }

    fn spawn_preview(ffplay_path: &str, input_format: &str, title: &str) -> Result<Self> {
        let mut cmd = Command::new(ffplay_path);
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x0800_0000);
        }
        cmd.args([
            "-hide_banner",
            "-loglevel",
            "error",
            "-fflags",
            "nobuffer",
            "-flags",
            "low_delay",
            "-framedrop",
            "-window_title",
            title,
            "-f",
            input_format,
            "-i",
            "pipe:0",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

        let mut child = cmd
            .spawn()
            .with_context(|| format!("failed to spawn ffplay preview ({ffplay_path:?})"))?;
        let stdin = child.stdin.take();
        Ok(Self {
            child,
            stdin,
            stderr_lines: Arc::new(Mutex::new(Vec::new())),
            stderr_thread: None,
            kind: "ffplay-preview",
        })
    }

    fn write_bytes(&mut self, data: &[u8]) {
        if let Some(ref mut sin) = self.stdin {
            if sin.write_all(data).is_err() {
                self.stdin = None;
            }
        }
    }

    fn finish(mut self) -> Vec<String> {
        drop(self.stdin.take());
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
                _ => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    break;
                }
            }
        }
        if let Some(t) = self.stderr_thread.take() {
            let _ = t.join();
        }
        let errs = self.stderr_lines.lock().map(|g| g.clone()).unwrap_or_default();
        if !errs.is_empty() {
            eprintln!("[{}] stderr reported {} error(s)", self.kind, errs.len());
        }
        errs
    }
}

#[derive(Debug, Default, Clone, Serialize)]
struct ClientSummary {
    client_index: usize,
    mode: String,
    elapsed_secs: f64,
    frames_received: u64,
    keyframes_received: u64,
    init_segments: u64,
    bytes_received: u64,
    avg_fps: f64,
    avg_mbps: f64,
    resolutions_seen: Vec<String>,
    rotations_sent: u64,
    reconnects: u64,
    pings_ok: u64,
    avg_ping_rtt_ms: f64,
    max_frame_gap_ms: u64,
    stalls_injected: u64,
    dropped_acks: u64,
    integrity_errors: Vec<String>,
    decode_errors: Vec<String>,
}

#[derive(Debug, Serialize)]
struct RunSummary {
    mode: String,
    net_profile: String,
    clients: Vec<ClientSummary>,
    total_frames: u64,
    total_bytes: u64,
    total_integrity_errors: usize,
    total_decode_errors: usize,
    passed: bool,
}

// ---------------------------------------------------------------------------
// ISO BMFF fMP4 inspection helpers (for Web Extended Screen verification)
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct Fmp4SegmentInfo {
    top_boxes: Vec<[u8; 4]>,
    tfdt: Option<u64>,
    is_sync_sample: Option<bool>,
}

fn iter_mp4_boxes(data: &[u8]) -> Vec<([u8; 4], &[u8])> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 8 <= data.len() {
        let size = u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]) as usize;
        let kind = [data[off + 4], data[off + 5], data[off + 6], data[off + 7]];
        if size < 8 || off + size > data.len() {
            break;
        }
        out.push((kind, &data[off + 8..off + size]));
        off += size;
    }
    out
}

fn inspect_fmp4_segment(data: &[u8]) -> Fmp4SegmentInfo {
    let mut info = Fmp4SegmentInfo::default();
    for (kind, body) in iter_mp4_boxes(data) {
        info.top_boxes.push(kind);
        if &kind == b"moof" {
            for (ckind, cbody) in iter_mp4_boxes(body) {
                if &ckind == b"traf" {
                    for (tkind, tbody) in iter_mp4_boxes(cbody) {
                        if &tkind == b"tfdt" && tbody.len() >= 8 {
                            let ver = tbody[0];
                            if ver == 1 && tbody.len() >= 12 {
                                info.tfdt = Some(u64::from_be_bytes([
                                    tbody[4], tbody[5], tbody[6], tbody[7], tbody[8], tbody[9],
                                    tbody[10], tbody[11],
                                ]));
                            } else if ver == 0 {
                                info.tfdt = Some(u32::from_be_bytes([
                                    tbody[4], tbody[5], tbody[6], tbody[7],
                                ]) as u64);
                            }
                        } else if &tkind == b"trun" && tbody.len() >= 12 {
                            let flags = ((tbody[1] as u32) << 16)
                                | ((tbody[2] as u32) << 8)
                                | (tbody[3] as u32);
                            // Standard idis trun flags = 0x000701:
                            // data_offset(4B) + sample_duration(4B) + sample_size(4B) + sample_flags(4B)
                            let mut pos = 8usize; // version+flags(4) + sample_count(4)
                            if (flags & 0x000001) != 0 {
                                pos += 4; // data_offset
                            }
                            if (flags & 0x000004) != 0 && pos + 4 <= tbody.len() {
                                let sf = u32::from_be_bytes([
                                    tbody[pos],
                                    tbody[pos + 1],
                                    tbody[pos + 2],
                                    tbody[pos + 3],
                                ]);
                                info.is_sync_sample = Some((sf & 0x0101_0000) == 0);
                            } else {
                                if (flags & 0x000100) != 0 {
                                    pos += 4; // sample_duration
                                }
                                if (flags & 0x000200) != 0 {
                                    pos += 4; // sample_size
                                }
                                if (flags & 0x000400) != 0 && pos + 4 <= tbody.len() {
                                    let sf = u32::from_be_bytes([
                                        tbody[pos],
                                        tbody[pos + 1],
                                        tbody[pos + 2],
                                        tbody[pos + 3],
                                    ]);
                                    info.is_sync_sample = Some((sf & 0x0101_0000) == 0);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    info
}

// ---------------------------------------------------------------------------
// Minimal std-only HTTP/1.1 & RFC 6455 WebSocket Client (zero new crates)
// ---------------------------------------------------------------------------

struct ParsedHttpUrl {
    host: String,
    port: u16,
    origin: String,
    host_header: String,
}

fn parse_http_url(raw: &str) -> Result<ParsedHttpUrl> {
    let trimmed = raw.trim().trim_end_matches('/');
    let rest = trimmed
        .strip_prefix("http://")
        .ok_or_else(|| anyhow!("only http:// URLs are supported, got {raw:?}"))?;
    let authority = rest.split('/').next().unwrap_or(rest);
    let (host, port) = if let Some(bracket) = authority.strip_prefix('[') {
        let (h, after) = bracket
            .split_once(']')
            .ok_or_else(|| anyhow!("invalid IPv6 URL {raw:?}"))?;
        let p = after
            .strip_prefix(':')
            .map(|s| s.parse::<u16>())
            .transpose()?
            .unwrap_or(80);
        (h.to_string(), p)
    } else if let Some((h, p_s)) = authority.rsplit_once(':') {
        (h.to_string(), p_s.parse::<u16>()?)
    } else {
        (authority.to_string(), 80)
    };
    let host_header = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    Ok(ParsedHttpUrl {
        host,
        port,
        origin: format!("http://{host_header}"),
        host_header,
    })
}

fn connect_tcp(host: &str, port: u16, timeout: Duration) -> Result<TcpStream> {
    let addr: SocketAddr = (host, port)
        .to_socket_addrs()?
        .find(|a| a.is_ipv4())
        .or_else(|| (host, port).to_socket_addrs().ok().and_then(|mut it| it.next()))
        .ok_or_else(|| anyhow!("failed to resolve {host}:{port}"))?;
    let stream = TcpStream::connect_timeout(&addr, timeout)
        .with_context(|| format!("failed to connect to {addr}"))?;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

struct HttpResp {
    status: u16,
    set_cookies: Vec<String>,
    body: Vec<u8>,
}

fn http_request(
    url: &ParsedHttpUrl,
    method: &str,
    path: &str,
    cookies: &BTreeMap<String, String>,
    json_body: Option<&serde_json::Value>,
    timeout: Duration,
) -> Result<HttpResp> {
    let mut stream = connect_tcp(&url.host, url.port, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    let body_bytes = json_body.map(|v| v.to_string().into_bytes()).unwrap_or_default();
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {}\r\nOrigin: {}\r\nConnection: close\r\n",
        url.host_header, url.origin
    );
    if !cookies.is_empty() {
        let cookie_hdr: Vec<String> = cookies.iter().map(|(k, v)| format!("{k}={v}")).collect();
        req.push_str(&format!("Cookie: {}\r\n", cookie_hdr.join("; ")));
    }
    if json_body.is_some() {
        req.push_str("Content-Type: application/json\r\n");
        req.push_str(&format!("Content-Length: {}\r\n", body_bytes.len()));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes())?;
    if !body_bytes.is_empty() {
        stream.write_all(&body_bytes)?;
    }
    stream.flush()?;

    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow!("malformed HTTP response from {}{path}", url.origin))?;
    let head = String::from_utf8_lossy(&raw[..split]);
    let mut lines = head.lines();
    let status_line = lines.next().unwrap_or("");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let mut set_cookies = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("set-cookie") {
                set_cookies.push(v.trim().to_string());
            }
        }
    }
    Ok(HttpResp {
        status,
        set_cookies,
        body: raw[split + 4..].to_vec(),
    })
}

fn absorb_cookies(jar: &mut BTreeMap<String, String>, set_cookies: &[String]) {
    for sc in set_cookies {
        if let Some(pair) = sc.split(';').next() {
            if let Some((k, v)) = pair.split_once('=') {
                jar.insert(k.trim().to_string(), v.trim().to_string());
            }
        }
    }
}

fn ws_connect(
    url: &ParsedHttpUrl,
    path: &str,
    cookies: &BTreeMap<String, String>,
    seed: u64,
) -> Result<TcpStream> {
    let mut stream = connect_tcp(&url.host, url.port, Duration::from_secs(5))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    let mut rng = SimRng::new(seed);
    let mut nonce = [0u8; 16];
    nonce[..8].copy_from_slice(&rng.next_u64().to_le_bytes());
    nonce[8..].copy_from_slice(&rng.next_u64().to_le_bytes());
    let key = base64::engine::general_purpose::STANDARD.encode(nonce);

    let mut req = format!(
        "GET {path} HTTP/1.1\r\nHost: {}\r\nOrigin: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n",
        url.host_header, url.origin
    );
    if !cookies.is_empty() {
        let cookie_hdr: Vec<String> = cookies.iter().map(|(k, v)| format!("{k}={v}")).collect();
        req.push_str(&format!("Cookie: {}\r\n", cookie_hdr.join("; ")));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes())?;
    stream.flush()?;

    // Read response headers byte-by-byte so we never over-read the first WebSocket frame.
    let mut head = Vec::with_capacity(512);
    let mut b = [0u8; 1];
    loop {
        stream.read_exact(&mut b)?;
        head.push(b[0]);
        if head.len() >= 4 && &head[head.len() - 4..] == b"\r\n\r\n" {
            break;
        }
        if head.len() > 16 * 1024 {
            bail!("WebSocket handshake header too large");
        }
    }
    let head_str = String::from_utf8_lossy(&head);
    let first_line = head_str.lines().next().unwrap_or("");
    if !first_line.contains(" 101 ") {
        bail!("WebSocket upgrade rejected: {first_line}");
    }
    Ok(stream)
}

fn ws_write_client_frame(stream: &mut TcpStream, opcode: u8, payload: &[u8], mask_key: [u8; 4]) -> Result<()> {
    let mut hdr = Vec::with_capacity(14);
    hdr.push(0x80 | (opcode & 0x0F));
    let len = payload.len();
    if len < 126 {
        hdr.push(0x80 | (len as u8));
    } else if len <= 65535 {
        hdr.push(0x80 | 126);
        hdr.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        hdr.push(0x80 | 127);
        hdr.extend_from_slice(&(len as u64).to_be_bytes());
    }
    hdr.extend_from_slice(&mask_key);
    let mut masked = Vec::with_capacity(len);
    for (i, &b) in payload.iter().enumerate() {
        masked.push(b ^ mask_key[i & 3]);
    }
    stream.write_all(&hdr)?;
    stream.write_all(&masked)?;
    stream.flush()?;
    Ok(())
}

enum WsFrame {
    Text(String),
    Binary(Vec<u8>),
    Ping(Vec<u8>),
    Pong,
    Close(Option<u16>),
}

fn ws_read_server_frame(stream: &mut TcpStream) -> std::io::Result<WsFrame> {
    let mut h2 = [0u8; 2];
    stream.read_exact(&mut h2)?;
    let opcode = h2[0] & 0x0F;
    let masked = (h2[1] & 0x80) != 0;
    let len_code = h2[1] & 0x7F;
    let len: usize = match len_code {
        0..=125 => len_code as usize,
        126 => {
            let mut b = [0u8; 2];
            stream.read_exact(&mut b)?;
            u16::from_be_bytes(b) as usize
        }
        _ => {
            let mut b = [0u8; 8];
            stream.read_exact(&mut b)?;
            u64::from_be_bytes(b) as usize
        }
    };
    let mask = if masked {
        let mut m = [0u8; 4];
        stream.read_exact(&mut m)?;
        Some(m)
    } else {
        None
    };
    if len > 32 * 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("WebSocket frame too large: {len}"),
        ));
    }
    let mut payload = vec![0u8; len];
    if len > 0 {
        stream.read_exact(&mut payload)?;
    }
    if let Some(m) = mask {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= m[i & 3];
        }
    }
    match opcode {
        0x1 => Ok(WsFrame::Text(String::from_utf8_lossy(&payload).to_string())),
        0x2 => Ok(WsFrame::Binary(payload)),
        0x8 => {
            let code = if payload.len() >= 2 {
                Some(u16::from_be_bytes([payload[0], payload[1]]))
            } else {
                None
            };
            Ok(WsFrame::Close(code))
        }
        0x9 => Ok(WsFrame::Ping(payload)),
        0xA => Ok(WsFrame::Pong),
        _ => Ok(WsFrame::Binary(payload)),
    }
}

// ---------------------------------------------------------------------------
// Legacy iPad Protocol Helpers
// ---------------------------------------------------------------------------

fn build_ipad_handshake(
    uid: &str,
    name: &str,
    ios_version: &str,
    w: u32,
    h: u32,
    proto: u32,
) -> Result<Vec<u8>> {
    let mut dict = BTreeMap::new();
    dict.insert("uniqueIdentifier".to_string(), ArchivedValue::String(uid.to_string()));
    dict.insert("name".to_string(), ArchivedValue::String(name.to_string()));
    dict.insert("model".to_string(), ArchivedValue::String("iPad Air".to_string()));
    dict.insert("systemName".to_string(), ArchivedValue::String("iPhone OS".to_string()));
    dict.insert(
        "systemVersion".to_string(),
        ArchivedValue::String(ios_version.to_string()),
    );
    dict.insert("clientVersion".to_string(), ArchivedValue::String("6.2.0".to_string()));
    dict.insert(
        "clientDataProtocolVersionKey".to_string(),
        ArchivedValue::String(proto.to_string()),
    );
    dict.insert(
        "clientOrientationKey".to_string(),
        ArchivedValue::Int(if w > h { 1 } else { 0 }),
    );
    dict.insert("screenWidth".to_string(), ArchivedValue::Int(w as i64));
    dict.insert("screenHeight".to_string(), ArchivedValue::Int(h as i64));
    dict.insert("supportsCursorPosition".to_string(), ArchivedValue::Bool(true));
    MessagePacket::new_send("Handshake", ArchivedValue::Dict(dict)).encode()
}

fn build_touch_event(phase: i64, x: f64, y: f64) -> Result<Vec<u8>> {
    let mut tf = BTreeMap::new();
    tf.insert("_phase".to_string(), ArchivedValue::Int(phase));
    tf.insert("_tapCount".to_string(), ArchivedValue::Int(1));
    tf.insert("_location.x".to_string(), ArchivedValue::Real(x));
    tf.insert("_location.y".to_string(), ArchivedValue::Real(y));
    let touch = ArchivedValue::Object {
        class_name: "MSMTouch".to_string(),
        classes: vec!["MSMTouch".to_string(), "NSObject".to_string()],
        fields: tf,
    };
    let mut ef = BTreeMap::new();
    ef.insert("_subtype".to_string(), ArchivedValue::Int(0));
    ef.insert("_allTouches".to_string(), ArchivedValue::Set(vec![touch]));
    let ev = ArchivedValue::Object {
        class_name: "MSMTouchEvent".to_string(),
        classes: vec![
            "MSMTouchEvent".to_string(),
            "MSMEvent".to_string(),
            "NSObject".to_string(),
        ],
        fields: ef,
    };
    archive(&ev)
}

fn build_resolution_change(w: u32, h: u32) -> Result<Vec<u8>> {
    let mut d = BTreeMap::new();
    d.insert("screenWidth".to_string(), ArchivedValue::Int(w as i64));
    d.insert("screenHeight".to_string(), ArchivedValue::Int(h as i64));
    MessagePacket::new_send("ResolutionChange", ArchivedValue::Dict(d)).encode()
}

// ---------------------------------------------------------------------------
// Mode 1: iPad Wi-Fi Simulator
// ---------------------------------------------------------------------------

fn run_ipad_client(
    idx: usize,
    args: &IpadArgs,
    stop: Arc<AtomicBool>,
) -> Result<ClientSummary> {
    let net_cfg = args.common.resolve_net();
    let (init_w, init_h) = args.common.resolve_initial_res()?;
    let cycle_res = args.common.resolve_cycle_res()?;
    let pause_cycle = args
        .pause_cycle
        .as_deref()
        .map(parse_cycle_pair)
        .transpose()?;

    let mut shaper = WeakNetShaper::new(net_cfg, args.common.seed.wrapping_add((idx as u64 + 1) * 7919));
    let mut verifier = if args.common.verify_decode {
        Some(MediaPipeSink::spawn_verifier(&args.common.ffmpeg_path, "h264")?)
    } else {
        None
    };
    let mut preview = if args.common.preview && idx == 0 {
        Some(MediaPipeSink::spawn_preview(
            &args.common.ffplay_path,
            "h264",
            "idis client_sim [iPad]",
        )?)
    } else {
        None
    };

    let uid = if args.common.clients > 1 {
        format!("{}-{}", args.uid, idx + 1)
    } else {
        args.uid.clone()
    };
    let base_name = args
        .name
        .as_deref()
        .unwrap_or_else(|| args.common.preset.display_name());
    let dev_name = if args.common.clients > 1 {
        format!("{base_name} #{}", idx + 1)
    } else {
        base_name.to_string()
    };

    let started = Instant::now();
    let deadline = if args.common.duration > 0 {
        Some(started + Duration::from_secs(args.common.duration))
    } else {
        None
    };

    let mut summary = ClientSummary {
        client_index: idx,
        mode: "ipad".to_string(),
        ..Default::default()
    };
    let mut resolutions: BTreeSet<String> = BTreeSet::new();
    let mut cur_w = init_w;
    let mut cur_h = init_h;
    let mut cur_orient: i64 = if cur_w > cur_h { 1 } else { 0 };
    let mut cycle_idx = 0usize;
    let mut ping_rtt_sum_ms = 0.0f64;
    let mut last_log = Instant::now();
    let mut win_frames = 0u64;
    let mut win_bytes = 0u64;

    while !stop.load(Ordering::Acquire) {
        if let Some(dl) = deadline {
            if Instant::now() >= dl {
                break;
            }
        }

        let mut tel = match connect_tcp(&args.host, args.port, Duration::from_secs(5)) {
            Ok(s) => s,
            Err(e) => {
                if summary.frames_received == 0 && summary.reconnects == 0 {
                    return Err(e);
                }
                summary.integrity_errors.push(format!("telemetry reconnect failed: {e}"));
                sleep_interruptible(Duration::from_millis(500), &stop);
                continue;
            }
        };
        tel.set_read_timeout(Some(Duration::from_secs(5)))?;
        tel.set_write_timeout(Some(Duration::from_secs(5)))?;

        let hs = build_ipad_handshake(&uid, &dev_name, &args.ios_version, cur_w, cur_h, args.proto)?;
        write_canal_block(&mut tel, &hs)?;

        // Read AccessConfirmed + VideoServiceAccessibleOnPort
        let mut data_port_opt: Option<u16> = None;
        let hs_deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < hs_deadline && data_port_opt.is_none() {
            let Some(block) = read_canal_block(&mut tel)? else {
                bail!("telemetry closed during handshake");
            };
            let pkt = MessagePacket::decode(&block)?;
            match pkt.name_method.as_str() {
                "AccessConfirmed" => {
                    let allowed = pkt
                        .param
                        .as_dict()
                        .and_then(|d| d.get("isAccess"))
                        .and_then(ArchivedValue::as_bool)
                        .unwrap_or(false);
                    if !allowed {
                        bail!("host declined iPad access (check approval / trust list / --no-confirm)");
                    }
                }
                "VideoServiceAccessibleOnPort" => {
                    data_port_opt = pkt.param.as_u64().map(|p| p as u16);
                }
                _ => {}
            }
        }
        let data_port = data_port_opt.ok_or_else(|| anyhow!("did not receive VideoServiceAccessibleOnPort"))?;
        let mut data = connect_tcp(&args.host, data_port, Duration::from_secs(5))?;
        data.set_read_timeout(Some(Duration::from_millis(250)))?;
        data.set_write_timeout(Some(Duration::from_secs(5)))?;
        tel.set_read_timeout(Some(Duration::from_millis(50)))?;

        eprintln!(
            "[ipad #{idx}] connected to {}:{} (data={data_port}, init={}x{}, proto=v{}, net={:?})",
            args.host, args.port, cur_w, cur_h, args.proto, args.common.net_profile
        );

        let conn_started = Instant::now();
        let mut last_rotate = Instant::now();
        let mut last_ping = Instant::now();
        let mut last_touch = Instant::now();
        let mut last_frame_at: Option<Instant> = None;
        let mut expect_idr = true;
        let mut paused = false;
        let mut pause_state_since = Instant::now();
        let mut last_dim: Option<(u32, u32)> = None;

        while !stop.load(Ordering::Acquire) {
            if let Some(dl) = deadline {
                if Instant::now() >= dl {
                    break;
                }
            }
            if args.common.reconnect_every > 0
                && conn_started.elapsed() >= Duration::from_secs(args.common.reconnect_every)
            {
                summary.reconnects += 1;
                eprintln!("[ipad #{idx}] simulating reconnect #{}", summary.reconnects);
                break;
            }

            // Pause / resume cycle
            if let Some((active_d, pause_d)) = pause_cycle {
                let target_d = if paused { pause_d } else { active_d };
                if pause_state_since.elapsed() >= target_d {
                    paused = !paused;
                    pause_state_since = Instant::now();
                    let method = if paused { "StopStream" } else { "StartStream" };
                    let pkt = MessagePacket::new_send(method, ArchivedValue::Null).encode()?;
                    let _ = write_canal_block(&mut tel, &pkt);
                    if !paused {
                        expect_idr = true;
                    }
                    eprintln!("[ipad #{idx}] sent {method}");
                }
            }

            // Rotation / multi-resolution cycle
            if args.common.rotate_every > 0
                && last_rotate.elapsed() >= Duration::from_secs(args.common.rotate_every)
            {
                last_rotate = Instant::now();
                summary.rotations_sent += 1;
                if !cycle_res.is_empty() {
                    cycle_idx = (cycle_idx + 1) % cycle_res.len();
                    let (nw, nh) = cycle_res[cycle_idx];
                    cur_w = nw;
                    cur_h = nh;
                    cur_orient = if cur_w > cur_h { 1 } else { 0 };
                    let pkt = build_resolution_change(cur_w, cur_h)?;
                    let _ = write_canal_block(&mut tel, &pkt);
                    eprintln!("[ipad #{idx}] sent ResolutionChange -> {cur_w}x{cur_h}");
                } else {
                    std::mem::swap(&mut cur_w, &mut cur_h);
                    cur_orient = if cur_orient == 1 { 0 } else { 1 };
                    let pkt = MessagePacket::new_send("OrientationChange", ArchivedValue::Int(cur_orient))
                        .encode()?;
                    let _ = write_canal_block(&mut tel, &pkt);
                    eprintln!(
                        "[ipad #{idx}] sent OrientationChange -> {} ({cur_w}x{cur_h})",
                        if cur_orient == 1 { "landscape" } else { "portrait" }
                    );
                }
            }

            // Periodic Ping RTT
            if args.ping_every > 0 && last_ping.elapsed() >= Duration::from_secs(args.ping_every) {
                last_ping = Instant::now();
                let ping_t0 = Instant::now();
                if let Ok(ping_bytes) = MessagePacket::new_request("Ping", ArchivedValue::Null, 5.0).encode() {
                    if write_canal_block(&mut tel, &ping_bytes).is_ok() {
                        // Drain telemetry responses briefly for Ping reply
                        let pong_dl = Instant::now() + Duration::from_millis(400);
                        while Instant::now() < pong_dl {
                            match read_canal_block(&mut tel) {
                                Ok(Some(b)) => {
                                    if let Ok(p) = MessagePacket::decode(&b) {
                                        if p.msg_type == MessageType::Response && p.name_method == "Ping" {
                                            summary.pings_ok += 1;
                                            ping_rtt_sum_ms += ping_t0.elapsed().as_secs_f64() * 1000.0;
                                            break;
                                        }
                                    }
                                }
                                Ok(None) => break,
                                Err(_) => break,
                            }
                        }
                    }
                }
            }

            // Periodic synthetic touch input
            if args.send_touch_every > 0
                && last_touch.elapsed() >= Duration::from_secs(args.send_touch_every)
            {
                last_touch = Instant::now();
                let x = (cur_w as f64) * 0.5;
                let y = (cur_h as f64) * 0.5;
                if let Ok(down) = build_touch_event(0, x, y) {
                    let _ = write_canal_block(&mut data, &down);
                }
                if let Ok(up) = build_touch_event(3, x, y) {
                    let _ = write_canal_block(&mut data, &up);
                }
            }

            // Read next video frame on data channel
            match read_canal_block(&mut data) {
                Ok(Some(frame)) => {
                    shaper.pace_receive(frame.len(), &stop);
                    let now = Instant::now();
                    if let Some(prev) = last_frame_at {
                        let gap_ms = now.duration_since(prev).as_millis() as u64;
                        if !paused {
                            summary.max_frame_gap_ms = summary.max_frame_gap_ms.max(gap_ms);
                        }
                    }
                    last_frame_at = Some(now);

                    let Some(hdr) = parse_video_header(&frame) else {
                        summary.integrity_errors.push(format!(
                            "unparseable video header (len={})",
                            frame.len()
                        ));
                        continue;
                    };
                    if hdr.compression != COMPRESSION_H264 {
                        summary.integrity_errors.push(format!(
                            "unexpected compression {} (expected H.264=11)",
                            hdr.compression
                        ));
                    }
                    let expected_hdr_len = if args.proto >= 5 { 17 } else { 13 };
                    if hdr.header_len != expected_hdr_len {
                        summary.integrity_errors.push(format!(
                            "header_len mismatch: got {}, expected {expected_hdr_len} for proto v{}",
                            hdr.header_len, args.proto
                        ));
                    }
                    let payload = &frame[hdr.payload_offset..];
                    let is_idr = is_self_contained_idr(payload);
                    if last_dim.is_some() && last_dim != Some((hdr.width, hdr.height)) {
                        // A resolution change should arrive on an IDR keyframe
                        if !is_idr {
                            summary.integrity_errors.push(format!(
                                "resolution switched {:?} -> {}x{} on non-IDR frame",
                                last_dim, hdr.width, hdr.height
                            ));
                        }
                    }
                    if expect_idr && !is_idr {
                        summary.integrity_errors.push(format!(
                            "expected IDR keyframe at stream start/resume, got non-IDR ({}B)",
                            payload.len()
                        ));
                    }
                    expect_idr = false;
                    last_dim = Some((hdr.width, hdr.height));
                    resolutions.insert(format!("{}x{}", hdr.width, hdr.height));

                    summary.frames_received += 1;
                    if is_idr {
                        summary.keyframes_received += 1;
                    }
                    summary.bytes_received += payload.len() as u64;
                    win_frames += 1;
                    win_bytes += payload.len() as u64;

                    if let Some(ref mut v) = verifier {
                        v.write_bytes(payload);
                    }
                    if let Some(ref mut p) = preview {
                        p.write_bytes(payload);
                    }

                    // Simulated weak-network ACK latency + optional ACK drop
                    if !shaper.should_drop_ack() {
                        let ack_delay = shaper.compute_delay();
                        if !ack_delay.is_zero() {
                            sleep_interruptible(ack_delay, &stop);
                        }
                        if let Ok(fr) =
                            MessagePacket::new_send("FrameReceived", ArchivedValue::Null).encode()
                        {
                            let _ = write_canal_block(&mut tel, &fr);
                        }
                        if let Ok(pr) =
                            MessagePacket::new_send("PictureRendered", ArchivedValue::Null).encode()
                        {
                            let _ = write_canal_block(&mut tel, &pr);
                        }
                    }
                }
                Ok(None) => {
                    eprintln!("[ipad #{idx}] data channel closed by host");
                    break;
                }
                Err(e) => {
                    let is_timeout = e
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|ioe| {
                            matches!(
                                ioe.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                            )
                        });
                    if !is_timeout {
                        eprintln!("[ipad #{idx}] data channel read ended: {e}");
                        break;
                    }
                }
            }

            if last_log.elapsed() >= Duration::from_secs(2) {
                let dt = last_log.elapsed().as_secs_f64().max(0.001);
                let fps = win_frames as f64 / dt;
                let mbps = (win_bytes as f64 * 8.0) / (dt * 1_000_000.0);
                eprintln!(
                    "[ipad #{idx}] live: {:.1} fps | {:.2} Mbps | total={} (idr={}) | dim={:?} | stalls={} | err={}",
                    fps,
                    mbps,
                    summary.frames_received,
                    summary.keyframes_received,
                    last_dim.unwrap_or((0, 0)),
                    shaper.stalls_injected,
                    summary.integrity_errors.len()
                );
                last_log = Instant::now();
                win_frames = 0;
                win_bytes = 0;
            }
        }
    }

    if let Some(v) = verifier {
        summary.decode_errors = v.finish();
    }
    if let Some(p) = preview {
        let _ = p.finish();
    }

    let elapsed = started.elapsed().as_secs_f64().max(0.001);
    summary.elapsed_secs = (elapsed * 100.0).round() / 100.0;
    summary.avg_fps = (summary.frames_received as f64 / elapsed * 10.0).round() / 10.0;
    summary.avg_mbps =
        ((summary.bytes_received as f64 * 8.0) / (elapsed * 1_000_000.0) * 100.0).round() / 100.0;
    summary.resolutions_seen = resolutions.into_iter().collect();
    summary.stalls_injected = shaper.stalls_injected;
    summary.dropped_acks = shaper.dropped_acks;
    if summary.pings_ok > 0 {
        summary.avg_ping_rtt_ms =
            (ping_rtt_sum_ms / summary.pings_ok as f64 * 10.0).round() / 10.0;
    }
    Ok(summary)
}

// ---------------------------------------------------------------------------
// Mode 2: Web Extended Screen Simulator
// ---------------------------------------------------------------------------

fn discover_viewer_url_from_admin(admin_url: &ParsedHttpUrl) -> Result<String> {
    let resp = http_request(
        admin_url,
        "GET",
        "/api/admin/state",
        &BTreeMap::new(),
        None,
        Duration::from_secs(5),
    )?;
    if resp.status != 200 {
        bail!(
            "Admin /api/admin/state returned HTTP {} (pass --viewer-url explicitly if admin is protected)",
            resp.status
        );
    }
    let val: serde_json::Value = serde_json::from_slice(&resp.body)?;
    if let Some(port) = val
        .pointer("/connection/web_viewer_port")
        .and_then(|v| v.as_u64())
    {
        return Ok(format!("http://{}:{port}", admin_url.host));
    }
    if let Some(first_url) = val
        .pointer("/connection/web_viewer_urls/0")
        .and_then(|v| v.as_str())
    {
        if let Some(stripped) = first_url.strip_suffix("/view") {
            return Ok(stripped.to_string());
        }
        return Ok(first_url.to_string());
    }
    bail!("Web Viewer port is not currently listening (enable Web viewing / set passcode in Admin Console first)")
}

fn push_web_resolution_via_admin(admin_url: &ParsedHttpUrl, w: u32, h: u32) -> Result<()> {
    let body = serde_json::json!({
        "web_width": w,
        "web_height": h,
    });
    let resp = http_request(
        admin_url,
        "POST",
        "/api/admin/settings",
        &BTreeMap::new(),
        Some(&body),
        Duration::from_secs(5),
    )?;
    if resp.status != 200 {
        bail!(
            "Admin POST /api/admin/settings ({w}x{h}) failed with HTTP {}",
            resp.status
        );
    }
    Ok(())
}

fn run_web_client(
    idx: usize,
    args: &WebArgs,
    viewer_url: &ParsedHttpUrl,
    admin_url: Option<&ParsedHttpUrl>,
    stop: Arc<AtomicBool>,
) -> Result<ClientSummary> {
    let net_cfg = args.common.resolve_net();
    let (mut cur_w, mut cur_h) = args.common.resolve_initial_res()?;
    let cycle_res = args.common.resolve_cycle_res()?;
    let vis_cycle = args
        .visibility_cycle
        .as_deref()
        .map(parse_cycle_pair)
        .transpose()?;

    let mut shaper = WeakNetShaper::new(net_cfg, args.common.seed.wrapping_add((idx as u64 + 1) * 9973));
    let mut verifier = if args.common.verify_decode {
        Some(MediaPipeSink::spawn_verifier(&args.common.ffmpeg_path, "mp4")?)
    } else {
        None
    };
    let mut preview = if args.common.preview && idx == 0 {
        Some(MediaPipeSink::spawn_preview(
            &args.common.ffplay_path,
            "mp4",
            "idis client_sim [Web]",
        )?)
    } else {
        None
    };

    let started = Instant::now();
    let deadline = if args.common.duration > 0 {
        Some(started + Duration::from_secs(args.common.duration))
    } else {
        None
    };

    let mut summary = ClientSummary {
        client_index: idx,
        mode: "web".to_string(),
        ..Default::default()
    };
    let mut resolutions: BTreeSet<String> = BTreeSet::new();
    let mut cycle_idx = 0usize;
    let mut last_log = Instant::now();
    let mut win_frames = 0u64;
    let mut win_bytes = 0u64;
    let mut mask_rng = SimRng::new(args.common.seed ^ 0xA5A5_5A5A ^ (idx as u64));

    // Only client #0 drives Admin resolution changes to avoid conflicting writes
    if idx == 0 && (args.common.res.is_some() || !cycle_res.is_empty()) {
        if let Some(adm) = admin_url {
            if let Err(e) = push_web_resolution_via_admin(adm, cur_w, cur_h) {
                eprintln!("[web #0] note: initial resolution update skipped ({e})");
            }
        }
    }

    while !stop.load(Ordering::Acquire) {
        if let Some(dl) = deadline {
            if Instant::now() >= dl {
                break;
            }
        }

        let mut cookies = BTreeMap::new();
        if !args.token.trim().is_empty() {
            let login_body = serde_json::json!({ "token": args.token.trim() });
            let resp = http_request(
                viewer_url,
                "POST",
                "/api/view/login",
                &cookies,
                Some(&login_body),
                Duration::from_secs(5),
            )?;
            if resp.status != 200 {
                bail!(
                    "Web viewer login failed: HTTP {} ({})",
                    resp.status,
                    String::from_utf8_lossy(&resp.body).trim()
                );
            }
            absorb_cookies(&mut cookies, &resp.set_cookies);
        }

        if args.request_approval {
            let resp = http_request(
                viewer_url,
                "POST",
                "/api/view/request-approval",
                &cookies,
                Some(&serde_json::json!({})),
                Duration::from_secs(30),
            )?;
            absorb_cookies(&mut cookies, &resp.set_cookies);
            if resp.status != 200 {
                bail!(
                    "Web viewer approval rejected: HTTP {} ({})",
                    resp.status,
                    String::from_utf8_lossy(&resp.body).trim()
                );
            }
        }

        let mut ws = ws_connect(
            viewer_url,
            "/ws/stream",
            &cookies,
            args.common.seed.wrapping_add(summary.reconnects * 31 + idx as u64),
        )?;
        ws.set_read_timeout(Some(Duration::from_millis(250)))?;
        ws.set_write_timeout(Some(Duration::from_secs(5)))?;

        if args.p2p_hello {
            let hello = serde_json::json!({
                "type": "p2p_hello",
                "webrtc": true,
                "mobile": false,
                "max_children": 2,
            })
            .to_string();
            let mk = (mask_rng.next_u64() as u32).to_le_bytes();
            let _ = ws_write_client_frame(&mut ws, 0x1, hello.as_bytes(), mk);
        }

        eprintln!(
            "[web #{idx}] WebSocket connected to {}/ws/stream (net={:?})",
            viewer_url.origin, args.common.net_profile
        );

        let conn_started = Instant::now();
        let mut last_rotate = Instant::now();
        let mut last_frame_at: Option<Instant> = None;
        let mut expect_init_binary = false;
        let mut expect_sync_media = true;
        let mut last_tfdt: Option<u64> = None;
        let mut last_dim: Option<(u32, u32)> = None;
        let mut visible = true;
        let mut vis_since = Instant::now();

        while !stop.load(Ordering::Acquire) {
            if let Some(dl) = deadline {
                if Instant::now() >= dl {
                    break;
                }
            }
            if args.common.reconnect_every > 0
                && conn_started.elapsed() >= Duration::from_secs(args.common.reconnect_every)
            {
                summary.reconnects += 1;
                eprintln!("[web #{idx}] simulating reconnect #{}", summary.reconnects);
                break;
            }

            // Tab visibility pause/resume simulation
            if let Some((vis_d, hid_d)) = vis_cycle {
                let target_d = if visible { vis_d } else { hid_d };
                if vis_since.elapsed() >= target_d {
                    visible = !visible;
                    vis_since = Instant::now();
                    let msg = serde_json::json!({
                        "type": "viewer_visibility",
                        "visible": visible,
                    })
                    .to_string();
                    let mk = (mask_rng.next_u64() as u32).to_le_bytes();
                    let _ = ws_write_client_frame(&mut ws, 0x1, msg.as_bytes(), mk);
                    if visible {
                        expect_sync_media = true;
                    }
                    eprintln!("[web #{idx}] sent viewer_visibility={visible}");
                }
            }

            // Live resolution/rotation via Admin API (client #0)
            if idx == 0
                && args.common.rotate_every > 0
                && last_rotate.elapsed() >= Duration::from_secs(args.common.rotate_every)
            {
                last_rotate = Instant::now();
                if let Some(adm) = admin_url {
                    if !cycle_res.is_empty() {
                        cycle_idx = (cycle_idx + 1) % cycle_res.len();
                        let (nw, nh) = cycle_res[cycle_idx];
                        cur_w = nw;
                        cur_h = nh;
                    } else {
                        std::mem::swap(&mut cur_w, &mut cur_h);
                    }
                    summary.rotations_sent += 1;
                    match push_web_resolution_via_admin(adm, cur_w, cur_h) {
                        Ok(()) => eprintln!("[web #0] switched Web resolution -> {cur_w}x{cur_h}"),
                        Err(e) => summary
                            .integrity_errors
                            .push(format!("admin resolution switch failed: {e}")),
                    }
                }
            }

            match ws_read_server_frame(&mut ws) {
                Ok(WsFrame::Text(txt)) => {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&txt) {
                        match v.get("type").and_then(|t| t.as_str()) {
                            Some("init") => {
                                let w = v.get("width").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
                                let h = v.get("height").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
                                if w > 0 && h > 0 {
                                    last_dim = Some((w, h));
                                    resolutions.insert(format!("{w}x{h}"));
                                }
                                expect_init_binary = true;
                                expect_sync_media = true;
                                if v.get("reset").and_then(|x| x.as_bool()).unwrap_or(false) {
                                    last_tfdt = None;
                                }
                            }
                            Some("p2p_role") => {
                                let role = v.get("role").and_then(|x| x.as_str()).unwrap_or("?");
                                eprintln!("[web #{idx}] P2P role assigned: {role}");
                            }
                            _ => {}
                        }
                    }
                }
                Ok(WsFrame::Binary(bin)) => {
                    shaper.pace_receive(bin.len(), &stop);
                    if bin.len() < 9 {
                        summary.integrity_errors.push(format!(
                            "truncated binary WebSocket segment ({}B)",
                            bin.len()
                        ));
                        continue;
                    }
                    // idis `/ws/stream` binary framing:
                    // - 0x01 || ftyp+moov (fMP4 init segment)
                    // - 0x02 || moof+mdat (fMP4 IDR keyframe media segment)
                    // - 0x03 || moof+mdat (fMP4 P-frame media segment)
                    let tag = bin[0];
                    let fmp4_bytes = &bin[1..];
                    let seg = inspect_fmp4_segment(fmp4_bytes);
                    let is_init = tag == 0x01
                        && seg.top_boxes.contains(b"ftyp")
                        && seg.top_boxes.contains(b"moov");
                    let is_media = (tag == 0x02 || tag == 0x03)
                        && seg.top_boxes.contains(b"moof")
                        && seg.top_boxes.contains(b"mdat");

                    if is_init {
                        summary.init_segments += 1;
                        expect_init_binary = false;
                        expect_sync_media = true;
                        last_tfdt = None;
                        if let Some(ref mut v) = verifier {
                            v.write_bytes(fmp4_bytes);
                        }
                        if let Some(ref mut p) = preview {
                            p.write_bytes(fmp4_bytes);
                        }
                    } else if is_media {
                        if expect_init_binary {
                            summary
                                .integrity_errors
                                .push("received media segment before expected fMP4 init segment".to_string());
                            expect_init_binary = false;
                        }
                        let now = Instant::now();
                        if let Some(prev) = last_frame_at {
                            let gap_ms = now.duration_since(prev).as_millis() as u64;
                            if visible {
                                summary.max_frame_gap_ms = summary.max_frame_gap_ms.max(gap_ms);
                            }
                        }
                        last_frame_at = Some(now);

                        let is_sync = seg.is_sync_sample.unwrap_or(tag == 0x02);
                        if (tag == 0x02) != is_sync {
                            summary.integrity_errors.push(format!(
                                "WS media tag 0x{tag:02x} disagreed with fMP4 trun sync={is_sync}"
                            ));
                        }
                        if expect_sync_media && !is_sync {
                            summary.integrity_errors.push(
                                "first fMP4 media segment after init/reset was not a sync IDR sample"
                                    .to_string(),
                            );
                        }
                        expect_sync_media = false;
                        if let Some(tfdt) = seg.tfdt {
                            if let Some(prev_t) = last_tfdt {
                                if tfdt < prev_t {
                                    summary.integrity_errors.push(format!(
                                        "fMP4 tfdt regressed: {tfdt} < {prev_t}"
                                    ));
                                }
                            }
                            last_tfdt = Some(tfdt);
                        }

                        summary.frames_received += 1;
                        if is_sync {
                            summary.keyframes_received += 1;
                        }
                        summary.bytes_received += fmp4_bytes.len() as u64;
                        win_frames += 1;
                        win_bytes += fmp4_bytes.len() as u64;

                        if let Some(ref mut v) = verifier {
                            v.write_bytes(fmp4_bytes);
                        }
                        if let Some(ref mut p) = preview {
                            p.write_bytes(fmp4_bytes);
                        }
                    } else {
                        summary.integrity_errors.push(format!(
                            "unrecognized binary WebSocket segment (tag=0x{tag:02x}, {}B, boxes={:?})",
                            bin.len(),
                            seg.top_boxes
                        ));
                    }
                }
                Ok(WsFrame::Ping(payload)) => {
                    let delay = shaper.compute_delay();
                    if !delay.is_zero() {
                        sleep_interruptible(delay, &stop);
                    }
                    let mk = (mask_rng.next_u64() as u32).to_le_bytes();
                    if ws_write_client_frame(&mut ws, 0xA, &payload, mk).is_ok() {
                        summary.pings_ok += 1;
                    }
                }
                Ok(WsFrame::Pong) => {}
                Ok(WsFrame::Close(code)) => {
                    eprintln!("[web #{idx}] WebSocket closed by host (code={code:?})");
                    break;
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(e) => {
                    eprintln!("[web #{idx}] WebSocket read error: {e}");
                    break;
                }
            }

            if last_log.elapsed() >= Duration::from_secs(2) {
                let dt = last_log.elapsed().as_secs_f64().max(0.001);
                let fps = win_frames as f64 / dt;
                let mbps = (win_bytes as f64 * 8.0) / (dt * 1_000_000.0);
                eprintln!(
                    "[web #{idx}] live: {:.1} fps | {:.2} Mbps | total={} (idr={}, init={}) | dim={:?} | stalls={} | err={}",
                    fps,
                    mbps,
                    summary.frames_received,
                    summary.keyframes_received,
                    summary.init_segments,
                    last_dim.unwrap_or((0, 0)),
                    shaper.stalls_injected,
                    summary.integrity_errors.len()
                );
                last_log = Instant::now();
                win_frames = 0;
                win_bytes = 0;
            }
        }
    }

    if let Some(v) = verifier {
        summary.decode_errors = v.finish();
    }
    if let Some(p) = preview {
        let _ = p.finish();
    }

    let elapsed = started.elapsed().as_secs_f64().max(0.001);
    summary.elapsed_secs = (elapsed * 100.0).round() / 100.0;
    summary.avg_fps = (summary.frames_received as f64 / elapsed * 10.0).round() / 10.0;
    summary.avg_mbps =
        ((summary.bytes_received as f64 * 8.0) / (elapsed * 1_000_000.0) * 100.0).round() / 100.0;
    summary.resolutions_seen = resolutions.into_iter().collect();
    summary.stalls_injected = shaper.stalls_injected;
    Ok(summary)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_c = stop.clone();
    let _ = ctrlc::set_handler(move || {
        stop_c.store(true, Ordering::Release);
    });

    let (mode_name, common, summaries) = match cli.mode {
        SimMode::Ipad(args) => {
            let count = args.common.clients.max(1);
            let mut handles = Vec::with_capacity(count);
            for i in 0..count {
                let a = args.clone();
                let s = stop.clone();
                handles.push(thread::spawn(move || run_ipad_client(i, &a, s)));
            }
            let mut results = Vec::with_capacity(count);
            for h in handles {
                let r = h
                    .join()
                    .map_err(|_| anyhow!("ipad simulator worker panicked"))??;
                results.push(r);
            }
            ("ipad".to_string(), args.common, results)
        }
        SimMode::Web(args) => {
            let admin_parsed = if !args.admin_url.trim().is_empty() {
                parse_http_url(&args.admin_url).ok()
            } else {
                None
            };
            let viewer_raw = match args.viewer_url.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                Some(u) => u.to_string(),
                None => {
                    let adm = admin_parsed
                        .as_ref()
                        .ok_or_else(|| anyhow!("pass --viewer-url or a valid --admin-url"))?;
                    discover_viewer_url_from_admin(adm)?
                }
            };
            let viewer_parsed = parse_http_url(&viewer_raw)?;
            let count = args.common.clients.max(1);
            let mut handles = Vec::with_capacity(count);
            for i in 0..count {
                let a = args.clone();
                let v = ParsedHttpUrl {
                    host: viewer_parsed.host.clone(),
                    port: viewer_parsed.port,
                    origin: viewer_parsed.origin.clone(),
                    host_header: viewer_parsed.host_header.clone(),
                };
                let adm = admin_parsed.as_ref().map(|x| ParsedHttpUrl {
                    host: x.host.clone(),
                    port: x.port,
                    origin: x.origin.clone(),
                    host_header: x.host_header.clone(),
                });
                let s = stop.clone();
                handles.push(thread::spawn(move || {
                    run_web_client(i, &a, &v, adm.as_ref(), s)
                }));
            }
            let mut results = Vec::with_capacity(count);
            for h in handles {
                let r = h
                    .join()
                    .map_err(|_| anyhow!("web simulator worker panicked"))??;
                results.push(r);
            }
            ("web".to_string(), args.common, results)
        }
    };

    let total_frames: u64 = summaries.iter().map(|s| s.frames_received).sum();
    let total_bytes: u64 = summaries.iter().map(|s| s.bytes_received).sum();
    let total_integrity_errors: usize = summaries.iter().map(|s| s.integrity_errors.len()).sum();
    let total_decode_errors: usize = summaries.iter().map(|s| s.decode_errors.len()).sum();
    let passed = total_frames >= common.min_frames
        && (!common.strict || (total_integrity_errors == 0 && total_decode_errors == 0));

    let report = RunSummary {
        mode: mode_name,
        net_profile: format!("{:?}", common.net_profile).to_lowercase(),
        clients: summaries,
        total_frames,
        total_bytes,
        total_integrity_errors,
        total_decode_errors,
        passed,
    };

    if common.json_summary {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("\n=== idis client_sim summary ({}) ===", report.mode);
        for c in &report.clients {
            println!(
                "  client #{}: {} frames ({} IDR, {} init) | {:.1} fps | {:.2} Mbps | res={:?} | rot={} | reconn={} | max_gap={}ms | stalls={} | err={} | decode_err={}",
                c.client_index,
                c.frames_received,
                c.keyframes_received,
                c.init_segments,
                c.avg_fps,
                c.avg_mbps,
                c.resolutions_seen,
                c.rotations_sent,
                c.reconnects,
                c.max_frame_gap_ms,
                c.stalls_injected,
                c.integrity_errors.len(),
                c.decode_errors.len()
            );
            for e in &c.integrity_errors {
                println!("    [integrity] {e}");
            }
            for e in &c.decode_errors {
                println!("    [decode] {e}");
            }
        }
        println!(
            "Result: {} (total_frames={}, integrity_errors={}, decode_errors={})",
            if report.passed { "PASS" } else { "FAIL" },
            report.total_frames,
            report.total_integrity_errors,
            report.total_decode_errors
        );
    }

    if !report.passed {
        std::process::exit(1);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use idis::config::AppConfig;
    use idis::fmp4::Fmp4Muxer;
    use idis::platform::mock::{MockBackend, SYNTHETIC_H264_ANNEX_B};
    use idis::session::SessionRegistry;
    use idis::transport::wifi::start_wifi_server;
    use idis::web::{start_web_server, LogBuffer};

    fn sim_test_config() -> AppConfig {
        let mut cfg = AppConfig::parse_from(["idis"]);
        cfg.telemetry_port = 0;
        cfg.data_port = 0;
        cfg.auto_accept = true;
        cfg.no_confirm = false;
        cfg.allow_input = true;
        cfg.mock = true;
        cfg.wifi = true;
        cfg.no_bonjour = true;
        cfg.no_usb = true;
        cfg.web = true;
        cfg.web_bind = "127.0.0.1:0".to_string();
        cfg.max_web_viewers = 4;
        cfg.web_view_token = Some("sim-pass-2026".to_string());
        cfg.config_file = Some("none".to_string());
        cfg.trusted_devices_file = Some("none".to_string());
        cfg
    }

    #[test]
    fn helpers_parse_resolutions_shape_weak_net_and_validate_fmp4() {
        assert_eq!(parse_resolution("1920x1080").unwrap(), (1920, 1080));
        assert_eq!(parse_resolution("1171x2533").unwrap(), (1170, 2532));
        assert!(parse_resolution("100x100").is_err());

        let mut shaper = WeakNetShaper::new(NetProfile::WifiWeak.defaults(), 42);
        let d = shaper.compute_delay();
        assert!(d <= Duration::from_millis(90 + 60 + 500));

        let mut muxer = Fmp4Muxer::new(30);
        let c1 = muxer.mux_frame(1280, 720, SYNTHETIC_H264_ANNEX_B).unwrap();
        let init_info = inspect_fmp4_segment(c1.init_segment.as_ref().unwrap());
        assert!(init_info.top_boxes.contains(b"ftyp"));
        assert!(init_info.top_boxes.contains(b"moov"));

        let m1 = inspect_fmp4_segment(&c1.media_segment);
        assert!(m1.top_boxes.contains(b"moof"));
        assert!(m1.top_boxes.contains(b"mdat"));
        assert_eq!(m1.is_sync_sample, Some(true));
        assert!(m1.tfdt.is_some());
    }

    #[test]
    fn ipad_simulator_handles_multi_res_rotation_and_weak_net_e2e() {
        let cfg = sim_test_config();
        let backend = Arc::new(MockBackend::new());
        let registry = Arc::new(SessionRegistry::new(cfg.clone(), backend.clone()));
        let stop = Arc::new(AtomicBool::new(false));
        let mut srv =
            start_wifi_server(cfg, backend.clone(), registry.clone(), stop.clone()).unwrap();

        let args = IpadArgs {
            host: "127.0.0.1".to_string(),
            port: srv.telemetry_addr.port(),
            proto: 5,
            uid: "sim-e2e-ipad".to_string(),
            name: Some("Sim iPad E2E".to_string()),
            ios_version: "12.5.8".to_string(),
            send_touch_every: 1,
            pause_cycle: None,
            ping_every: 1,
            common: CommonArgs {
                preset: DevicePreset::IpadAir,
                res: None,
                cycle_res: Some("1280x720,720x1280,1024x768".to_string()),
                rotate_every: 1,
                net_profile: NetProfile::WifiBusy,
                latency_ms: Some(15),
                jitter_ms: Some(10),
                bandwidth_kbps: Some(8_000),
                stall_prob: Some(0.05),
                stall_ms: Some(60),
                drop_ack_rate: Some(0.0),
                reconnect_every: 0,
                seed: 12345,
                clients: 1,
                duration: 3,
                min_frames: 5,
                verify_decode: false,
                preview: false,
                ffmpeg_path: "ffmpeg".to_string(),
                ffplay_path: "ffplay".to_string(),
                json_summary: false,
                strict: true,
            },
        };

        let summary = run_ipad_client(0, &args, stop.clone()).unwrap();
        stop.store(true, Ordering::SeqCst);
        srv.stop();

        assert!(
            summary.frames_received >= 5,
            "expected >=5 frames, got {}",
            summary.frames_received
        );
        assert!(summary.rotations_sent >= 1, "expected >=1 resolution rotation");
        assert!(
            summary.resolutions_seen.len() >= 2,
            "expected >=2 distinct resolutions, got {:?}",
            summary.resolutions_seen
        );
        assert!(summary.pings_ok >= 1, "expected >=1 successful Ping RTT");
        assert!(
            summary.integrity_errors.is_empty(),
            "unexpected integrity errors: {:?}",
            summary.integrity_errors
        );
    }

    #[test]
    fn web_simulator_handles_autodiscovery_rotation_p2p_and_weak_net_e2e() {
        let cfg = sim_test_config();
        let backend = Arc::new(MockBackend::new());
        let registry = Arc::new(SessionRegistry::new(cfg.clone(), backend.clone()));
        let stop = Arc::new(AtomicBool::new(false));
        let web_srv = start_web_server(
            "127.0.0.1:0",
            None,
            cfg.web_view_token.clone(),
            registry.clone(),
            LogBuffer::new(),
            stop.clone(),
        )
        .unwrap();

        let admin_base = format!("http://{}", web_srv.addr);
        let admin_parsed = parse_http_url(&admin_base).unwrap();
        let discovered_viewer = discover_viewer_url_from_admin(&admin_parsed).unwrap();
        let viewer_parsed = parse_http_url(&discovered_viewer).unwrap();

        let args = WebArgs {
            viewer_url: None,
            admin_url: admin_base,
            token: "sim-pass-2026".to_string(),
            request_approval: false,
            p2p_hello: true,
            visibility_cycle: None,
            common: CommonArgs {
                preset: DevicePreset::Hd,
                res: None,
                cycle_res: Some("1280x720,720x1280".to_string()),
                rotate_every: 1,
                net_profile: NetProfile::WifiWeak,
                latency_ms: Some(15),
                jitter_ms: Some(10),
                bandwidth_kbps: Some(8_000),
                stall_prob: Some(0.05),
                stall_ms: Some(50),
                drop_ack_rate: None,
                reconnect_every: 0,
                seed: 67890,
                clients: 2,
                duration: 3,
                min_frames: 5,
                verify_decode: false,
                preview: false,
                ffmpeg_path: "ffmpeg".to_string(),
                ffplay_path: "ffplay".to_string(),
                json_summary: false,
                strict: true,
            },
        };

        let a0 = args.clone();
        let a1 = args.clone();
        let v0 = ParsedHttpUrl {
            host: viewer_parsed.host.clone(),
            port: viewer_parsed.port,
            origin: viewer_parsed.origin.clone(),
            host_header: viewer_parsed.host_header.clone(),
        };
        let v1 = ParsedHttpUrl {
            host: viewer_parsed.host.clone(),
            port: viewer_parsed.port,
            origin: viewer_parsed.origin.clone(),
            host_header: viewer_parsed.host_header.clone(),
        };
        let adm0 = ParsedHttpUrl {
            host: admin_parsed.host.clone(),
            port: admin_parsed.port,
            origin: admin_parsed.origin.clone(),
            host_header: admin_parsed.host_header.clone(),
        };
        let s0 = stop.clone();
        let s1 = stop.clone();
        let t0 = thread::spawn(move || run_web_client(0, &a0, &v0, Some(&adm0), s0));
        let t1 = thread::spawn(move || run_web_client(1, &a1, &v1, None, s1));

        let r0 = t0.join().unwrap().unwrap();
        let r1 = t1.join().unwrap().unwrap();
        stop.store(true, Ordering::SeqCst);
        drop(web_srv);

        assert!(r0.frames_received >= 3 && r1.frames_received >= 3);
        assert!(r0.init_segments >= 1 && r1.init_segments >= 1);
        assert!(r0.rotations_sent >= 1);
        assert!(
            r0.resolutions_seen.len() >= 2,
            "expected >=2 Web resolutions after rotation, got {:?}",
            r0.resolutions_seen
        );
        assert!(
            r0.integrity_errors.is_empty() && r1.integrity_errors.is_empty(),
            "unexpected web integrity errors: {:?} / {:?}",
            r0.integrity_errors,
            r1.integrity_errors
        );
    }
}
