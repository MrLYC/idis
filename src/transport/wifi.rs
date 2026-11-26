use crate::config::AppConfig;
use crate::platform::{BonjourHandle, DisplayBackend};
use crate::protocol::framing::{
    read_canal_block_limited, read_canal_block_limited_deadline, write_canal_block,
    write_canal_parts, MAX_CONTROL_FRAME_SIZE, MAX_PREAUTH_FRAME_SIZE,
};
use crate::session::SessionRegistry;
use crate::transport::{
    accept_interruptible, enable_tcp_keepalive, is_tcp_peer_closed, FrameWriter, PollOutcome,
    SharedFrameWriter, WakePipe,
};
use anyhow::{Context, Result};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// `MSMCanalSocket` TCP writer (`[u32_le len][payload]`).
/// Uses a separate write serializer lock so `close()` can invoke `TcpStream::shutdown` lock-free
/// and immediately interrupt a thread blocked in `write_all` on a dead/sleeping iPad socket.
pub struct TcpCanalWriter {
    write_lock: Mutex<()>,
    stream: TcpStream,
}

impl TcpCanalWriter {
    pub fn new(stream: TcpStream) -> Self {
        Self {
            write_lock: Mutex::new(()),
            stream,
        }
    }
}

impl FrameWriter for TcpCanalWriter {
    fn send_frame(&self, payload: &[u8]) -> Result<()> {
        let _guard = self.write_lock.lock().unwrap();
        let mut s = &self.stream;
        let res = write_canal_block(&mut s, payload);
        if res.is_err() {
            // Immediately close on any partial-write/timeout error to prevent permanent frame desync.
            let _ = self.stream.shutdown(Shutdown::Both);
        }
        res
    }

    fn send_frame_parts(&self, parts: &[&[u8]]) -> Result<()> {
        let _guard = self.write_lock.lock().unwrap();
        let mut s = &self.stream;
        let res = write_canal_parts(&mut s, parts);
        if res.is_err() {
            let _ = self.stream.shutdown(Shutdown::Both);
        }
        res
    }

    fn close(&self) {
        let _ = self.stream.shutdown(Shutdown::Both);
    }

    fn is_peer_closed(&self) -> bool {
        is_tcp_peer_closed(&self.stream)
    }
}

pub struct WifiServerHandle {
    pub telemetry_addr: SocketAddr,
    pub data_addr: SocketAddr,
    stop: Arc<AtomicBool>,
    wake: Arc<WakePipe>,
    _bonjour: Option<Box<dyn BonjourHandle>>,
    threads: Vec<thread::JoinHandle<()>>,
}

impl WifiServerHandle {
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.wake.wake();
        #[cfg(not(unix))]
        {
            crate::transport::wake_blocking_listener_addr(self.telemetry_addr);
            crate::transport::wake_blocking_listener_addr(self.data_addr);
        }
        if let Some(mut b) = self._bonjour.take() {
            b.stop();
        }
        for h in self.threads.drain(..) {
            let _ = h.join();
        }
    }
}

impl Drop for WifiServerHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Runtime toggle & idle auto-close controller for the iPad Wi-Fi listener (telemetry + data + Bonjour).
pub struct WifiServerController {
    config: AppConfig,
    backend: Arc<dyn DisplayBackend>,
    registry: Arc<SessionRegistry>,
    global_stop: Arc<AtomicBool>,
    op_lock: Mutex<()>,
    state: Mutex<Option<(WifiServerHandle, Instant)>>,
}

impl WifiServerController {
    pub fn new(
        config: AppConfig,
        backend: Arc<dyn DisplayBackend>,
        registry: Arc<SessionRegistry>,
        global_stop: Arc<AtomicBool>,
    ) -> Self {
        Self {
            config,
            backend,
            registry,
            global_stop,
            op_lock: Mutex::new(()),
            state: Mutex::new(None),
        }
    }

    pub fn start(&self) -> Result<(SocketAddr, SocketAddr)> {
        self.start_with_prebound(None, None)
    }

    pub fn start_with_prebound(
        &self,
        prebound_tel: Option<TcpListener>,
        prebound_data: Option<TcpListener>,
    ) -> Result<(SocketAddr, SocketAddr)> {
        let _op = self.op_lock.lock().unwrap();
        if let Some((ref h, _)) = *self.state.lock().unwrap() {
            return Ok((h.telemetry_addr, h.data_addr));
        }
        let handle = start_wifi_server_with_listeners(
            self.config.clone(),
            self.backend.clone(),
            self.registry.clone(),
            self.global_stop.clone(),
            prebound_tel,
            prebound_data,
        )?;
        let addrs = (handle.telemetry_addr, handle.data_addr);
        *self.state.lock().unwrap() = Some((handle, Instant::now()));
        self.registry.record_wifi_activity();
        self.registry.notify_lifecycle_wakeup();
        crate::debug_trace::record(
            "lifecycle",
            "wifi_listener_opened",
            serde_json::json!({
                "telemetry_addr": addrs.0.to_string(),
                "data_addr": addrs.1.to_string(),
            }),
        );
        Ok(addrs)
    }

    pub fn stop(&self) -> bool {
        let _op = self.op_lock.lock().unwrap();
        self.stop_locked()
    }

    fn stop_locked(&self) -> bool {
        let old = self.state.lock().unwrap().take();
        if let Some((mut handle, _)) = old {
            let tel = handle.telemetry_addr;
            let data = handle.data_addr;
            self.registry.close_wifi_sessions();
            handle.stop();
            self.registry.notify_lifecycle_wakeup();
            info!("iPad Wi-Fi listener closed (telemetry={tel}, data={data})");
            crate::debug_trace::record(
                "lifecycle",
                "wifi_listener_closed",
                serde_json::json!({
                    "telemetry_addr": tel.to_string(),
                    "data_addr": data.to_string(),
                }),
            );
            true
        } else {
            false
        }
    }

    pub fn addrs(&self) -> Option<(SocketAddr, SocketAddr)> {
        self.state
            .lock()
            .unwrap()
            .as_ref()
            .map(|(h, _)| (h.telemetry_addr, h.data_addr))
    }

    pub fn is_running(&self) -> bool {
        self.addrs().is_some()
    }

    pub fn idle_duration(&self) -> Option<Duration> {
        let opened_at = self.state.lock().unwrap().as_ref().map(|(_, ts)| *ts)?;
        if self.registry.has_active_wifi_sessions() {
            self.registry.record_wifi_activity();
            return None;
        }
        let last = opened_at.max(self.registry.last_wifi_activity());
        Some(last.elapsed())
    }

    pub fn remaining_idle_close(&self, limit_secs: u64) -> Option<Duration> {
        if limit_secs == 0 {
            return None;
        }
        let idle = self.idle_duration()?;
        Some(Duration::from_secs(limit_secs).saturating_sub(idle))
    }

    pub fn tick_idle_close(&self, limit_secs: u64) -> bool {
        if limit_secs == 0 {
            return false;
        }
        let _op = self.op_lock.lock().unwrap();
        if let Some(idle) = self.idle_duration() {
            if idle >= Duration::from_secs(limit_secs) && !self.registry.has_active_wifi_sessions()
            {
                info!(
                    "iPad Wi-Fi port idle for {}s (limit={}s) — auto-closing.",
                    idle.as_secs(),
                    limit_secs
                );
                return self.stop_locked();
            }
        }
        false
    }
}

pub fn start_wifi_server(
    config: AppConfig,
    backend: Arc<dyn DisplayBackend>,
    registry: Arc<SessionRegistry>,
    global_stop: Arc<AtomicBool>,
) -> Result<WifiServerHandle> {
    start_wifi_server_with_listeners(config, backend, registry, global_stop, None, None)
}

pub fn start_wifi_server_with_listeners(
    config: AppConfig,
    backend: Arc<dyn DisplayBackend>,
    registry: Arc<SessionRegistry>,
    global_stop: Arc<AtomicBool>,
    prebound_tel: Option<TcpListener>,
    prebound_data: Option<TcpListener>,
) -> Result<WifiServerHandle> {
    let resolved = if prebound_tel.is_none() || prebound_data.is_none() {
        Some(
            crate::netinfo::resolve_control_bind(&config.bind_addr, config.telemetry_port)
                .with_context(|| {
                    format!("failed to resolve Wi-Fi bind address {:?}", config.bind_addr)
                })?,
        )
    } else {
        None
    };

    let tel_listener = match prebound_tel {
        Some(l) => l,
        None => {
            let (bind_ip, effective_tel_port) = resolved.unwrap();
            let tel_bind = SocketAddr::new(bind_ip, effective_tel_port);
            TcpListener::bind(tel_bind)
                .with_context(|| format!("failed to bind telemetry TCP listener on {tel_bind}"))?
        }
    };
    let data_listener = match prebound_data {
        Some(l) => l,
        None => {
            let bind_ip = resolved
                .map(|(ip, _)| ip)
                .unwrap_or_else(|| tel_listener.local_addr().map(|a| a.ip()).unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)));
            let data_bind = SocketAddr::new(bind_ip, config.data_port);
            TcpListener::bind(data_bind)
                .with_context(|| format!("failed to bind data TCP listener on {data_bind}"))?
        }
    };

    #[cfg(unix)]
    {
        tel_listener.set_nonblocking(true)?;
        data_listener.set_nonblocking(true)?;
    }
    #[cfg(not(unix))]
    {
        tel_listener.set_nonblocking(false)?;
        data_listener.set_nonblocking(false)?;
    }

    let telemetry_addr = tel_listener.local_addr()?;
    let data_addr = data_listener.local_addr()?;

    let sys = backend.host_system_info(&config.host_name);
    // Avoid leaking OS login username in unencrypted LAN Bonjour/mDNS broadcasts.
    let service_name = sys.host_name.clone();
    let bonjour = if config.no_bonjour {
        info!("Bonjour/mDNS broadcast disabled (--no-bonjour); connect manually via IP:port");
        None
    } else {
        match backend.publish_bonjour(&service_name, telemetry_addr.port(), data_addr.port()) {
            Ok(b) => Some(b),
            Err(e) => {
                warn!("Bonjour advertisement unavailable: {e:#}");
                None
            }
        }
    };

    info!(
        "Wi-Fi listening: telemetry={} data={} (Bonjour: _MSM_Video_Control_Service._tcp. / _MSM_Video_Service._tcp. as {:?})",
        telemetry_addr, data_addr, service_name
    );

    let local_stop = Arc::new(AtomicBool::new(false));
    let wake = Arc::new(WakePipe::new().context("failed to create Wi-Fi accept wake pipe")?);
    let mut threads = Vec::new();

    // Telemetry accept loop (zero-wakeup kernel wait via poll/blocking accept)
    {
        let stop_a = local_stop.clone();
        let stop_g = global_stop.clone();
        let wake_t = wake.clone();
        let reg = registry.clone();
        let data_port = data_addr.port();
        let preauth_workers = Arc::new(AtomicUsize::new(0));
        threads.push(thread::spawn(move || {
            while !stop_a.load(Ordering::SeqCst) && !stop_g.load(Ordering::SeqCst) {
                match accept_interruptible(&tel_listener, &wake_t) {
                    Ok(Some((stream, peer))) => {
                        let _ = stream.set_nonblocking(false);
                        let _ = stream.set_nodelay(true);
                        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                        enable_tcp_keepalive(&stream);
                        let canonical_ip = match peer.ip() {
                            std::net::IpAddr::V6(v6) => {
                                v6.to_ipv4_mapped().map(std::net::IpAddr::V4).unwrap_or(peer.ip())
                            }
                            other => other,
                        };
                        let key = canonical_ip.to_string();
                        if !reg.is_ip_allowed(&key) {
                            warn!("[{key}] Wi-Fi telemetry connection from {peer} rejected: IP not in --allow-ip");
                            let _ = stream.shutdown(Shutdown::Both);
                            continue;
                        }
                        // Cap concurrent pre-registration worker threads and move blocking ARP/NDP
                        // lookups OFF the accept loop so bursts never stall incoming TCP accepts.
                        if preauth_workers.fetch_add(1, Ordering::AcqRel) >= 16 {
                            preauth_workers.fetch_sub(1, Ordering::AcqRel);
                            warn!("[{key}] Wi-Fi telemetry connection from {peer} rejected: too many concurrent handshakes");
                            let _ = stream.shutdown(Shutdown::Both);
                            continue;
                        }
                        let reg_c = reg.clone();
                        let key_c = key.clone();
                        let workers_c = preauth_workers.clone();
                        thread::spawn(move || {
                            struct WorkerGuard(Arc<AtomicUsize>);
                            impl Drop for WorkerGuard {
                                fn drop(&mut self) {
                                    self.0.fetch_sub(1, Ordering::AcqRel);
                                }
                            }
                            let _preauth_guard = Some(WorkerGuard(workers_c));
                            info!("Wi-Fi telemetry connection accepted from {peer}");
                            let writer_stream = match stream.try_clone() {
                                Ok(s) => s,
                                Err(e) => {
                                    warn!("failed to clone telemetry stream: {e}");
                                    return;
                                }
                            };
                            let writer: SharedFrameWriter =
                                Arc::new(TcpCanalWriter::new(writer_stream));
                            let Some(session_id) = reg_c.register_telemetry(
                                key_c.clone(),
                                writer,
                                data_port,
                                false,
                            ) else {
                                warn!(
                                    "[{key_c}] Wi-Fi telemetry connection rejected (connection limit or active session protection)"
                                );
                                let _ = stream.shutdown(Shutdown::Both);
                                return;
                            };
                            let mut reader = stream;
                            // RAII guard ensures session cleanup even if a panic or early return occurs.
                            struct SessionGuard {
                                reg: Arc<SessionRegistry>,
                                key: String,
                                id: u64,
                            }
                            impl Drop for SessionGuard {
                                fn drop(&mut self) {
                                    self.reg.close_session_if_id(&self.key, self.id);
                                }
                            }
                            let _session_guard = SessionGuard {
                                reg: reg_c.clone(),
                                key: key_c.clone(),
                                id: session_id,
                            };
                            // Enforce a 15s TOTAL pre-auth deadline (allows pre-auth Ping probes while
                            // defeating slowloris keepalives) and 64 KiB frame cap until authorized.
                            let preauth_deadline = Instant::now() + Duration::from_secs(15);
                            let mut auth_timeout_cleared = false;
                            let mut preauth_guard = _preauth_guard;
                            loop {
                                let read_res = if !auth_timeout_cleared {
                                    read_canal_block_limited_deadline(
                                        &mut reader,
                                        MAX_PREAUTH_FRAME_SIZE,
                                        preauth_deadline,
                                    )
                                } else {
                                    read_canal_block_limited(&mut reader, MAX_CONTROL_FRAME_SIZE)
                                };
                                match read_res {
                                    Ok(Some(block)) => {
                                        if let Err(e) = reg_c.handle_telemetry_bytes_for_session(
                                            &key_c,
                                            Some(session_id),
                                            &block,
                                        ) {
                                            warn!("[{key_c}] telemetry packet error: {e:#}");
                                            if !auth_timeout_cleared {
                                                // Disconnect immediately on invalid pre-auth traffic.
                                                break;
                                            }
                                        }
                                        if !reg_c.has_session_id(&key_c, session_id) {
                                            break;
                                        }
                                        if !auth_timeout_cleared && reg_c.is_authorized_id(&key_c, session_id) {
                                            let _ = reader.set_read_timeout(None);
                                            auth_timeout_cleared = true;
                                            preauth_guard.take();
                                        }
                                    }
                                    Ok(None) => {
                                        info!("[{key_c}] telemetry EOF");
                                        break;
                                    }
                                    Err(e) => {
                                        if !auth_timeout_cleared {
                                            warn!("[{key_c}] pre-auth telemetry read ended: {e}");
                                        } else {
                                            debug!("[{key_c}] telemetry read ended: {e}");
                                        }
                                        break;
                                    }
                                }
                            }
                        });
                    }
                    Ok(None) => break,
                    Err(e) => {
                        warn!("telemetry accept error: {e}");
                        if wake_t.wait_timeout(Duration::from_millis(100)) == PollOutcome::Woken {
                            break;
                        }
                    }
                }
            }
        }));
    }

    // Data accept loop (kept open permanently, zero-wakeup kernel wait while idle)
    {
        let stop_a = local_stop.clone();
        let stop_g = global_stop.clone();
        let wake_d = wake.clone();
        let reg = registry.clone();
        let data_workers = Arc::new(AtomicUsize::new(0));
        threads.push(thread::spawn(move || {
            while !stop_a.load(Ordering::SeqCst) && !stop_g.load(Ordering::SeqCst) {
                match accept_interruptible(&data_listener, &wake_d) {
                    Ok(Some((stream, peer))) => {
                        let _ = stream.set_nonblocking(false);
                        let _ = stream.set_nodelay(true);
                        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                        enable_tcp_keepalive(&stream);
                        let canonical_ip = match peer.ip() {
                            std::net::IpAddr::V6(v6) => {
                                v6.to_ipv4_mapped().map(std::net::IpAddr::V4).unwrap_or(peer.ip())
                            }
                            other => other,
                        };
                        let key = canonical_ip.to_string();
                        if !reg.is_ip_allowed(&key) || !reg.is_authorized(&key) {
                            let reason = reg.unauthorized_data_reason(&key);
                            warn!(
                                "[{key}] Wi-Fi data connection from {peer} rejected: session not authorized ({reason})"
                            );
                            let _ = stream.shutdown(Shutdown::Both);
                            continue;
                        }
                        if data_workers.fetch_add(1, Ordering::AcqRel) >= 8 {
                            data_workers.fetch_sub(1, Ordering::AcqRel);
                            warn!("[{key}] Wi-Fi data connection from {peer} rejected: too many concurrent data channels");
                            let _ = stream.shutdown(Shutdown::Both);
                            continue;
                        }
                        info!("Wi-Fi data connection accepted from {peer}");
                        let writer_stream = match stream.try_clone() {
                            Ok(s) => s,
                            Err(e) => {
                                data_workers.fetch_sub(1, Ordering::AcqRel);
                                warn!("failed to clone data stream: {e}");
                                continue;
                            }
                        };
                        let writer: SharedFrameWriter = Arc::new(TcpCanalWriter::new(writer_stream));
                        let reg_c = reg.clone();
                        let key_c = key.clone();
                        let dw_count = data_workers.clone();
                        thread::spawn(move || {
                            struct DataWorkerGuard(Arc<AtomicUsize>);
                            impl Drop for DataWorkerGuard {
                                fn drop(&mut self) {
                                    self.0.fetch_sub(1, Ordering::AcqRel);
                                }
                            }
                            let _worker_guard = DataWorkerGuard(dw_count);
                            let (session_id, data_gen) = match reg_c.attach_data_channel_checked(
                                &key_c,
                                None,
                                writer,
                            ) {
                                Ok(ids) => ids,
                                Err(e) => {
                                    warn!("[{key_c}] failed to attach data channel: {e:#}");
                                    let _ = stream.shutdown(Shutdown::Both);
                                    return;
                                }
                            };
                            struct DataAttachmentGuard {
                                reg: Arc<SessionRegistry>,
                                key: String,
                                session_id: u64,
                                data_gen: u64,
                            }
                            impl Drop for DataAttachmentGuard {
                                fn drop(&mut self) {
                                    self.reg.close_data_attachment_if_match(
                                        &self.key,
                                        self.session_id,
                                        self.data_gen,
                                    );
                                }
                            }
                            let _attach_guard = DataAttachmentGuard {
                                reg: reg_c.clone(),
                                key: key_c.clone(),
                                session_id,
                                data_gen,
                            };
                            let mut reader = stream;
                            loop {
                                match read_canal_block_limited(&mut reader, MAX_CONTROL_FRAME_SIZE) {
                                    Ok(Some(block)) => {
                                        if let Err(e) = reg_c.handle_data_bytes_for_session(
                                            &key_c,
                                            Some(session_id),
                                            Some(data_gen),
                                            &block,
                                        ) {
                                            debug!("[{key_c}] data input decode error: {e:#}");
                                        }
                                    }
                                    Ok(None) => {
                                        info!("[{key_c}] data channel EOF");
                                        break;
                                    }
                                    Err(e) => {
                                        debug!("[{key_c}] data read ended: {e}");
                                        break;
                                    }
                                }
                            }
                        });
                    }
                    Ok(None) => break,
                    Err(e) => {
                        warn!("data accept error: {e}");
                        if wake_d.wait_timeout(Duration::from_millis(100)) == PollOutcome::Woken {
                            break;
                        }
                    }
                }
            }
        }));
    }

    Ok(WifiServerHandle {
        telemetry_addr,
        data_addr,
        stop: local_stop,
        wake,
        _bonjour: bonjour,
        threads,
    })
}
