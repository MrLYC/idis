use crate::protocol::framing::{
    PEERTALK_USB_PORT, PT_FRAME_TYPE_DATA, PT_FRAME_TYPE_TELEMETRY,
};
use crate::session::SessionRegistry;
use crate::transport::{
    enable_tcp_keepalive, is_tcp_peer_closed, FrameWriter, SharedFrameWriter, WakePipe,
};
use anyhow::{anyhow, bail, Context, Result};
use plist::{Dictionary, Value};
use std::io::{self, Cursor, Read, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
#[cfg(unix)]
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

const USBMUX_VERSION_PLIST: u32 = 1;
const USBMUX_MESSAGE_PLIST: u32 = 8;

/// Cross-platform transport stream to Apple `usbmuxd`:
/// - macOS / Linux: Unix domain socket (`/var/run/usbmuxd`)
/// - Windows (or TCP bridge): TCP socket (`127.0.0.1:27015`)
pub enum UsbmuxStream {
    #[cfg(unix)]
    Unix(UnixStream),
    Tcp(TcpStream),
}

impl UsbmuxStream {
    pub fn connect(addr: &str) -> Result<Self> {
        #[cfg(unix)]
        {
            if addr.starts_with('/') || addr.starts_with('.') {
                let s = UnixStream::connect(addr)
                    .with_context(|| format!("failed to connect to usbmuxd Unix socket {addr}"))?;
                return Ok(Self::Unix(s));
            }
        }
        let mut last_err = None;
        let addrs: Vec<_> = addr
            .to_socket_addrs()
            .with_context(|| format!("failed to resolve usbmuxd TCP endpoint {addr}"))?
            .collect();
        if addrs.is_empty() {
            bail!("usbmuxd TCP endpoint {addr} resolved to no addresses");
        }
        for sa in addrs {
            match TcpStream::connect_timeout(&sa, Duration::from_secs(2)) {
                Ok(s) => {
                    let _ = s.set_nodelay(true);
                    enable_tcp_keepalive(&s);
                    return Ok(Self::Tcp(s));
                }
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err
            .map(anyhow::Error::from)
            .unwrap_or_else(|| anyhow!("failed to connect to usbmuxd TCP endpoint {addr}")))
            .with_context(|| format!("failed to connect to usbmuxd TCP endpoint {addr}"))
    }

    pub fn try_clone(&self) -> io::Result<Self> {
        match self {
            #[cfg(unix)]
            Self::Unix(s) => Ok(Self::Unix(s.try_clone()?)),
            Self::Tcp(s) => Ok(Self::Tcp(s.try_clone()?)),
        }
    }

    pub fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        match self {
            #[cfg(unix)]
            Self::Unix(s) => s.set_read_timeout(dur),
            Self::Tcp(s) => s.set_read_timeout(dur),
        }
    }

    pub fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        match self {
            #[cfg(unix)]
            Self::Unix(s) => s.set_write_timeout(dur),
            Self::Tcp(s) => s.set_write_timeout(dur),
        }
    }

    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        match self {
            #[cfg(unix)]
            Self::Unix(s) => s.shutdown(how),
            Self::Tcp(s) => s.shutdown(how),
        }
    }

    pub fn is_peer_closed(&self) -> bool {
        match self {
            #[cfg(unix)]
            Self::Unix(s) => crate::transport::is_unix_peer_closed(s),
            Self::Tcp(s) => is_tcp_peer_closed(s),
        }
    }

    #[cfg(unix)]
    pub fn as_raw_fd(&self) -> i32 {
        use std::os::unix::io::AsRawFd;
        match self {
            Self::Unix(s) => s.as_raw_fd(),
            Self::Tcp(s) => s.as_raw_fd(),
        }
    }
}

impl Write for &UsbmuxStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            #[cfg(unix)]
            UsbmuxStream::Unix(s) => (&*s).write(buf),
            UsbmuxStream::Tcp(s) => (&*s).write(buf),
        }
    }

    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        match self {
            #[cfg(unix)]
            UsbmuxStream::Unix(s) => (&*s).write_vectored(bufs),
            UsbmuxStream::Tcp(s) => (&*s).write_vectored(bufs),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            #[cfg(unix)]
            UsbmuxStream::Unix(s) => (&*s).flush(),
            UsbmuxStream::Tcp(s) => (&*s).flush(),
        }
    }
}

impl Read for UsbmuxStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            #[cfg(unix)]
            Self::Unix(s) => s.read(buf),
            Self::Tcp(s) => s.read(buf),
        }
    }
}

impl Write for UsbmuxStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            #[cfg(unix)]
            Self::Unix(s) => s.write(buf),
            Self::Tcp(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            #[cfg(unix)]
            Self::Unix(s) => s.flush(),
            Self::Tcp(s) => s.flush(),
        }
    }
}

/// Send a usbmuxd plist packet (`[size:u32_le][version=1:u32_le][msg=8:u32_le][tag:u32_le][xml_plist]`).
pub fn write_usbmux_plist<W: Write>(writer: &mut W, tag: u32, dict: &Dictionary) -> Result<()> {
    let mut xml = Vec::new();
    Value::Dictionary(dict.clone())
        .to_writer_xml(&mut xml)
        .context("failed to encode usbmuxd XML plist")?;
    let total_size = (16 + xml.len()) as u32;
    let mut hdr = [0u8; 16];
    hdr[0..4].copy_from_slice(&total_size.to_le_bytes());
    hdr[4..8].copy_from_slice(&USBMUX_VERSION_PLIST.to_le_bytes());
    hdr[8..12].copy_from_slice(&USBMUX_MESSAGE_PLIST.to_le_bytes());
    hdr[12..16].copy_from_slice(&tag.to_le_bytes());
    writer.write_all(&hdr)?;
    writer.write_all(&xml)?;
    writer.flush()?;
    Ok(())
}

fn sleep_interruptible(stop: &AtomicBool, wake: &WakePipe, total: Duration) {
    if stop.load(Ordering::SeqCst) {
        return;
    }
    let _ = wake.wait_timeout(total);
}

/// Read a usbmuxd plist packet safely even when the socket has a short read timeout.
/// Only returns `WouldBlock`/`TimedOut` when 0 bytes of the header have been consumed;
/// once >= 1 header byte arrives, finishes reading the entire packet within a 5s deadline
/// so a stalled peer can never hang shutdown or desync framing.
pub fn read_usbmux_plist<R: Read>(reader: &mut R) -> Result<Option<(u32, Dictionary)>> {
    let mut hdr = [0u8; 16];
    let first_n = loop {
        match reader.read(&mut hdr[0..1]) {
            Ok(0) => return Ok(None),
            Ok(n) => break n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    };
    let packet_deadline = Instant::now() + Duration::from_secs(5);
    let mut filled = first_n;
    while filled < 16 {
        match reader.read(&mut hdr[filled..]) {
            Ok(0) => bail!("unexpected EOF reading usbmuxd plist header"),
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e)
                if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) =>
            {
                if Instant::now() >= packet_deadline {
                    return Err(e.into());
                }
                thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => return Err(e.into()),
        }
    }
    let size = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
    let tag = u32::from_le_bytes([hdr[12], hdr[13], hdr[14], hdr[15]]);
    if !(16..=4 * 1024 * 1024).contains(&size) {
        bail!("invalid usbmuxd packet size: {size}");
    }
    let mut body = vec![0u8; size - 16];
    let mut body_filled = 0;
    while body_filled < body.len() {
        match reader.read(&mut body[body_filled..]) {
            Ok(0) => bail!("unexpected EOF reading usbmuxd plist body"),
            Ok(n) => body_filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e)
                if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) =>
            {
                if Instant::now() >= packet_deadline {
                    return Err(e.into());
                }
                thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => return Err(e.into()),
        }
    }
    let val = Value::from_reader(Cursor::new(&body)).context("failed to parse usbmuxd plist")?;
    let dict = val
        .into_dictionary()
        .ok_or_else(|| anyhow!("usbmuxd payload is not a dictionary"))?;
    Ok(Some((tag, dict)))
}

/// PeerTalk multiplexed writer sharing a single usbmuxd stream.
/// Decouples `shutdown(Shutdown::Both)` from the write serializer mutex so `close()` immediately
/// interrupts blocked writes on USB unplug/sleep instead of stalling for 5-10s.
pub struct PeerTalkWriter {
    write_lock: Arc<Mutex<()>>,
    stream: Arc<UsbmuxStream>,
    frame_type: u32,
    tag_counter: Arc<AtomicU32>,
}

impl PeerTalkWriter {
    pub fn new(
        write_lock: Arc<Mutex<()>>,
        stream: Arc<UsbmuxStream>,
        frame_type: u32,
        tag_counter: Arc<AtomicU32>,
    ) -> Self {
        Self {
            write_lock,
            stream,
            frame_type,
            tag_counter,
        }
    }
}

impl FrameWriter for PeerTalkWriter {
    fn send_frame(&self, payload: &[u8]) -> Result<()> {
        self.send_frame_parts(&[payload])
    }

    fn send_frame_parts(&self, parts: &[&[u8]]) -> Result<()> {
        let tag = self.tag_counter.fetch_add(1, Ordering::Relaxed);
        let _guard = self.write_lock.lock().unwrap();
        let mut s = &*self.stream;
        let res = crate::protocol::framing::write_pt_parts(&mut s, self.frame_type, tag, parts);
        if res.is_err() {
            // Immediately close multiplexed PeerTalk stream on partial write/timeout to avoid framing corruption.
            let _ = self.stream.shutdown(Shutdown::Both);
        }
        res
    }

    fn close(&self) {
        let _ = self.stream.shutdown(Shutdown::Both);
    }

    fn is_peer_closed(&self) -> bool {
        self.stream.is_peer_closed()
    }
}

fn connect_usbmux_device_port(addr: &str, device_id: i64, port: u16) -> Result<UsbmuxStream> {
    let mut stream = UsbmuxStream::connect(addr)?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));
    let mut req = Dictionary::new();
    req.insert(
        "MessageType".to_string(),
        Value::String("Connect".to_string()),
    );
    req.insert("DeviceID".to_string(), Value::Integer(device_id.into()));
    // usbmuxd expects PortNumber in network byte order (verified in -[PTUSBHub connectToDevice:port:]).
    let net_port = u16::swap_bytes(port) as i64;
    req.insert("PortNumber".to_string(), Value::Integer(net_port.into()));
    req.insert(
        "ClientVersionString".to_string(),
        Value::String("idis".to_string()),
    );
    req.insert(
        "ProgName".to_string(),
        Value::String("idis".to_string()),
    );
    req.insert("kLibUSBMuxVersion".to_string(), Value::Integer(3i64.into()));

    write_usbmux_plist(&mut stream, 1, &req)?;
    let (_, resp) = read_usbmux_plist(&mut stream)?
        .ok_or_else(|| anyhow!("EOF waiting for usbmuxd Connect response"))?;
    let number = resp
        .get("Number")
        .and_then(|v| v.as_signed_integer())
        .unwrap_or(-1);
    if number != 0 {
        bail!("usbmuxd Connect to device {device_id} port {port} refused (Number={number})");
    }
    let _ = stream.set_read_timeout(None);
    Ok(stream)
}

/// Serve a connected PeerTalk stream (already connected to device port 2345).
pub fn serve_peertalk_stream(
    stream: UsbmuxStream,
    session_key: String,
    registry: Arc<SessionRegistry>,
) -> Result<()> {
    serve_peertalk_stream_with_guard(stream, session_key, registry, None)
}

type ActiveDeviceMap = Arc<Mutex<std::collections::HashMap<i64, u64>>>;

fn serve_peertalk_stream_with_guard(
    stream: UsbmuxStream,
    session_key: String,
    registry: Arc<SessionRegistry>,
    still_active: Option<(&ActiveDeviceMap, i64, u64)>,
) -> Result<()> {
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let write_clone = stream.try_clone()?;
    let write_lock = Arc::new(Mutex::new(()));
    let shared_stream = Arc::new(write_clone);
    let tag_counter = Arc::new(AtomicU32::new(1));

    let tel_writer: SharedFrameWriter = Arc::new(PeerTalkWriter::new(
        write_lock.clone(),
        shared_stream.clone(),
        PT_FRAME_TYPE_TELEMETRY,
        tag_counter.clone(),
    ));
    let data_writer: SharedFrameWriter = Arc::new(PeerTalkWriter::new(
        write_lock,
        shared_stream,
        PT_FRAME_TYPE_DATA,
        tag_counter,
    ));

    let Some(session_id) = registry.register_usb_telemetry(
        session_key.clone(),
        tel_writer,
        data_writer,
        PEERTALK_USB_PORT,
    ) else {
        warn!("[{session_key}] USB connection rejected: max connection limit reached");
        return Ok(());
    };

    struct UsbSessionGuard {
        reg: Arc<SessionRegistry>,
        key: String,
        id: u64,
    }
    impl Drop for UsbSessionGuard {
        fn drop(&mut self) {
            self.reg.close_session_if_id(&self.key, self.id);
        }
    }
    let _usb_guard = UsbSessionGuard {
        reg: registry.clone(),
        key: session_key.clone(),
        id: session_id,
    };

    // Close the TOCTOU window where `Detached` or `ActiveDevicesGuard::drop` ran between
    // `connect_usbmux_device_port` and `register_usb_telemetry` above.
    if let Some((active_map, dev_id, expected_gen)) = still_active {
        if active_map.lock().unwrap().get(&dev_id) != Some(&expected_gen) {
            let _ = stream.shutdown(Shutdown::Both);
            return Ok(());
        }
    }

    let mut reader = stream;
    let mut unknown_pt_logs: u32 = 0;
    loop {
        let is_authed = registry.is_authorized_id(&session_key, session_id);
        let max_len = if is_authed {
            crate::protocol::framing::MAX_CONTROL_FRAME_SIZE
        } else {
            crate::protocol::framing::MAX_PREAUTH_FRAME_SIZE
        };
        match crate::protocol::framing::read_pt_frame_limited(&mut reader, max_len) {
            Ok(Some(frame)) => match frame.frame_type {
                PT_FRAME_TYPE_TELEMETRY => {
                    if let Err(e) = registry.handle_telemetry_bytes_for_session(
                        &session_key,
                        Some(session_id),
                        &frame.payload,
                    ) {
                        warn!("[{session_key}] USB telemetry packet error: {e:#}");
                    }
                }
                PT_FRAME_TYPE_DATA => {
                    if !is_authed {
                        debug!("[{session_key}] Ignoring pre-auth USB PT_FRAME_TYPE_DATA ({}B)", frame.payload.len());
                        continue;
                    }
                    if let Err(e) = registry.handle_data_bytes_for_session(
                        &session_key,
                        Some(session_id),
                        None,
                        &frame.payload,
                    ) {
                        debug!("[{session_key}] USB data input error: {e:#}");
                    }
                }
                other => {
                    if !is_authed {
                        debug!("[{session_key}] Ignoring pre-auth unknown PeerTalk frame type={other}");
                        continue;
                    }
                    // Some newer legacy-compatible iPad builds may send input bplists on an alternate
                    // PeerTalk frame_type; log clearly and attempt input decoding if payload contains bplist.
                    let scan_limit = frame.payload.len().min(38);
                    let looks_bplist = frame.payload[..scan_limit]
                        .windows(6)
                        .any(|w| w == b"bplist");
                    if unknown_pt_logs < 5 {
                        unknown_pt_logs += 1;
                        let head_hex: String = frame
                            .payload
                            .iter()
                            .take(16)
                            .map(|b| format!("{b:02x}"))
                            .collect();
                        warn!(
                            "[{session_key}] Received non-standard PeerTalk frame type={other} (len={}, looks_bplist={looks_bplist}, head={head_hex})",
                            frame.payload.len()
                        );
                        crate::debug_trace::record(
                            "usb",
                            "unknown_peertalk_frame",
                            serde_json::json!({
                                "key": session_key,
                                "frame_type": other,
                                "len": frame.payload.len(),
                                "looks_bplist": looks_bplist,
                                "head_hex": head_hex,
                            }),
                        );
                    }
                    if looks_bplist {
                        let _ = registry.handle_data_bytes_for_session(
                            &session_key,
                            Some(session_id),
                            None,
                            &frame.payload,
                        );
                    }
                }
            },
            Ok(None) => {
                info!("[{session_key}] USB PeerTalk connection closed (EOF)");
                break;
            }
            Err(e) => {
                debug!("[{session_key}] USB PeerTalk read ended: {e:#}");
                break;
            }
        }
    }

    Ok(())
}

/// Start background USB watcher talking to `usbmuxd` (`/var/run/usbmuxd` on macOS/Linux,
/// `127.0.0.1:27015` on Windows) and connecting to iOS devices on PeerTalk port 2345.
/// Handle to the background `usbmuxd` watcher thread; supports instant zero-wakeup shutdown.
pub struct UsbmuxWatcherHandle {
    stop: Arc<AtomicBool>,
    wake: Arc<WakePipe>,
    thread: Option<thread::JoinHandle<()>>,
}

impl UsbmuxWatcherHandle {
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.wake.wake();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for UsbmuxWatcherHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

pub fn start_usbmux_watcher(
    addr: String,
    registry: Arc<SessionRegistry>,
    stop: Arc<AtomicBool>,
) -> UsbmuxWatcherHandle {
    let local_stop = Arc::new(AtomicBool::new(false));
    let wake = Arc::new(WakePipe::new().expect("failed to create usbmux wake pipe"));
    let wake_t = wake.clone();
    let stop_t = stop;
    let local_stop_t = local_stop.clone();
    let thread = thread::spawn(move || {
        while !stop_t.load(Ordering::SeqCst)
            && !local_stop_t.load(Ordering::SeqCst)
            && !wake_t.is_woken()
        {
            #[cfg(unix)]
            if (addr.starts_with('/') || addr.starts_with('.')) && !Path::new(&addr).exists() {
                let wait = if registry.is_low_power() {
                    Duration::from_secs(10)
                } else {
                    Duration::from_secs(5)
                };
                debug!("usbmuxd socket {addr} not present; waiting {wait:?}...");
                sleep_interruptible(&stop_t, &wake_t, wait);
                continue;
            }
            match run_listen_loop(&addr, &registry, &stop_t, &local_stop_t, &wake_t) {
                Ok(()) => {
                    if !stop_t.load(Ordering::SeqCst)
                        && !local_stop_t.load(Ordering::SeqCst)
                        && !wake_t.is_woken()
                    {
                        debug!("usbmuxd listen stream closed (EOF); retrying in 2s");
                        sleep_interruptible(&stop_t, &wake_t, Duration::from_secs(2));
                    }
                }
                Err(e) => {
                    if !stop_t.load(Ordering::SeqCst)
                        && !local_stop_t.load(Ordering::SeqCst)
                        && !wake_t.is_woken()
                    {
                        debug!("usbmuxd listen loop exited: {e:#}; retrying in 2s");
                        sleep_interruptible(&stop_t, &wake_t, Duration::from_secs(2));
                    }
                }
            }
        }
    });
    UsbmuxWatcherHandle {
        stop: local_stop,
        wake,
        thread: Some(thread),
    }
}

fn run_listen_loop(
    addr: &str,
    registry: &Arc<SessionRegistry>,
    stop: &Arc<AtomicBool>,
    local_stop: &Arc<AtomicBool>,
    wake: &Arc<WakePipe>,
) -> Result<()> {
    let mut stream = UsbmuxStream::connect(addr)?;
    #[cfg(unix)]
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    #[cfg(not(unix))]
    stream.set_read_timeout(Some(Duration::from_millis(500)))?;
    let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));

    let mut req = Dictionary::new();
    req.insert("MessageType".to_string(), Value::String("Listen".to_string()));
    req.insert(
        "ClientVersionString".to_string(),
        Value::String("idis".to_string()),
    );
    req.insert(
        "ProgName".to_string(),
        Value::String("idis".to_string()),
    );
    req.insert("kLibUSBMuxVersion".to_string(), Value::Integer(3i64.into()));
    write_usbmux_plist(&mut stream, 1, &req)?;

    info!("USB watcher listening on {addr} (PeerTalk port {PEERTALK_USB_PORT})");

    // Track `DeviceID -> attach_gen` with a process-wide monotonic counter so neither rapid
    // unplug/replug nor a `run_listen_loop` restart across usbmuxd sleep/wake can reuse a
    // session key while an older poller/teardown thread is still winding down.
    static NEXT_USB_ATTACH_GEN: std::sync::atomic::AtomicU64 =
        std::sync::atomic::AtomicU64::new(1);
    let active_devices: Arc<Mutex<std::collections::HashMap<i64, u64>>> =
        Arc::new(Mutex::new(std::collections::HashMap::new()));
    // Ensure all per-device poller threads AND active USB sessions terminate if `run_listen_loop` exits/restarts
    // (e.g. usbmuxd daemon restart across Mac sleep/wake).
    struct ActiveDevicesGuard {
        active: Arc<Mutex<std::collections::HashMap<i64, u64>>>,
        registry: Arc<SessionRegistry>,
    }
    impl Drop for ActiveDevicesGuard {
        fn drop(&mut self) {
            let entries: Vec<(i64, u64)> = self
                .active
                .lock()
                .map(|mut g| g.drain().collect())
                .unwrap_or_default();
            for (id, gen) in entries {
                self.registry
                    .close_session(&format!("127.0.0.1:usb-{id}-{gen}"));
            }
        }
    }
    let _active_guard = ActiveDevicesGuard {
        active: active_devices.clone(),
        registry: registry.clone(),
    };

    while !stop.load(Ordering::SeqCst) && !local_stop.load(Ordering::SeqCst) && !wake.is_woken() {
        #[cfg(unix)]
        {
            match crate::transport::poll_fd_interruptible(stream.as_raw_fd(), wake)? {
                crate::transport::PollOutcome::Woken => return Ok(()),
                crate::transport::PollOutcome::Readable
                | crate::transport::PollOutcome::Timeout => {}
            }
        }
        match read_usbmux_plist(&mut stream) {
            Ok(Some((_tag, dict))) => {
                let msg_type = dict
                    .get("MessageType")
                    .and_then(|v| v.as_string())
                    .unwrap_or("");
                if msg_type == "Result" {
                    let num = dict.get("Number").and_then(|v| v.as_signed_integer()).unwrap_or(0);
                    if num != 0 {
                        bail!("usbmuxd Listen rejected with Result Number={num}");
                    }
                    continue;
                }
                if msg_type == "Attached" {
                    let Some(device_id) = dict.get("DeviceID").and_then(|v| v.as_signed_integer())
                    else {
                        continue;
                    };
                    let conn_type = dict
                        .get("Properties")
                        .and_then(|v| v.as_dictionary())
                        .and_then(|p| p.get("ConnectionType"))
                        .and_then(|v| v.as_string())
                        .unwrap_or("");
                    if conn_type != "USB" {
                        continue;
                    }
                    let my_gen = {
                        let mut guard = active_devices.lock().unwrap();
                        if guard.contains_key(&device_id) {
                            continue;
                        }
                        let g = NEXT_USB_ATTACH_GEN.fetch_add(1, Ordering::Relaxed);
                        guard.insert(device_id, g);
                        g
                    };

                    info!("USB iOS device attached (DeviceID={device_id}, gen={my_gen}); polling iDisplay app on port {PEERTALK_USB_PORT}");
                    let addr_c = addr.to_string();
                    let reg = registry.clone();
                    let stop_c = stop.clone();
                    let local_stop_c = local_stop.clone();
                    let wake_c = wake.clone();
                    let active_c = active_devices.clone();
                    thread::spawn(move || {
                        let key = format!("127.0.0.1:usb-{device_id}-{my_gen}");
                        while !stop_c.load(Ordering::SeqCst)
                            && !local_stop_c.load(Ordering::SeqCst)
                            && !wake_c.is_woken()
                            && active_c.lock().unwrap().get(&device_id) == Some(&my_gen)
                        {
                            // Do not hammer port 2345 every 4s while the host is locked with
                            // `on_lock_ipad=disconnect` (prevents flicker loops & lets `--idle-exit-secs` fire).
                            if reg.is_ipad_lock_disconnect_blocking() {
                                reg.refresh_host_lock_state_now(false);
                                if reg.is_ipad_lock_disconnect_blocking() {
                                    let wait = Duration::from_millis(
                                        reg.polling_config().usb_retry_ms.max(2000),
                                    );
                                    sleep_interruptible(&stop_c, &wake_c, wait);
                                    continue;
                                }
                            }
                            match connect_usbmux_device_port(&addr_c, device_id, PEERTALK_USB_PORT) {
                                Ok(pt_stream) => {
                                    // Re-check generation after blocking Connect in case Detached/replug fired mid-connect.
                                    if active_c.lock().unwrap().get(&device_id) != Some(&my_gen) {
                                        let _ = pt_stream.shutdown(Shutdown::Both);
                                        break;
                                    }
                                    info!("[{key}] Connected to iDisplay over USB PeerTalk!");
                                    let started = Instant::now();
                                    let _ = serve_peertalk_stream_with_guard(
                                        pt_stream,
                                        key.clone(),
                                        reg.clone(),
                                        Some((&active_c, device_id, my_gen)),
                                    );
                                    // If Detached fired while serving or just after, exit poller immediately
                                    // (`UsbSessionGuard` inside `serve_peertalk_stream_with_guard` already closed
                                    // the exact session ID without risking clobbering any newer session).
                                    if active_c.lock().unwrap().get(&device_id) != Some(&my_gen) {
                                        break;
                                    }
                                    // Back off slightly longer if rejected immediately (e.g. max_extended_screens
                                    // held by a different device) so we don't spam port 2345 every 1s.
                                    let wait = if started.elapsed() < Duration::from_secs(2) {
                                        Duration::from_secs(4)
                                    } else {
                                        Duration::from_secs(1)
                                    };
                                    sleep_interruptible(&stop_c, &wake_c, wait);
                                }
                                Err(_) => {
                                    // iDisplay app not open yet on iPad; retry using configured interval
                                    let retry_wait =
                                        Duration::from_millis(reg.polling_config().usb_retry_ms);
                                    sleep_interruptible(&stop_c, &wake_c, retry_wait);
                                }
                            }
                        }
                    });
                } else if msg_type == "Detached" {
                    if let Some(device_id) = dict.get("DeviceID").and_then(|v| v.as_signed_integer())
                    {
                        info!("USB iOS device detached (DeviceID={device_id})");
                        if let Some(old_gen) = active_devices.lock().unwrap().remove(&device_id) {
                            let reg_close = registry.clone();
                            let key = format!("127.0.0.1:usb-{device_id}-{old_gen}");
                            // Run teardown off the usbmuxd listen thread; generation-scoped key guarantees
                            // a slow teardown can NEVER kill a freshly replugged device session.
                            thread::spawn(move || {
                                reg_close.close_session(&key);
                            });
                        }
                    }
                }
            }
            Ok(None) => break,
            Err(e) => {
                if let Some(ioe) = e.downcast_ref::<io::Error>() {
                    if ioe.kind() == io::ErrorKind::WouldBlock
                        || ioe.kind() == io::ErrorKind::TimedOut
                    {
                        continue;
                    }
                }
                return Err(e);
            }
        }
    }
    Ok(())
}
