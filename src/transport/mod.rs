pub mod socket_activation;
pub mod usbmux;
pub mod wifi;

use anyhow::Result;
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(unix)]
use std::sync::atomic::{AtomicBool, Ordering};

/// Thread-safe sender for writing length-framed payloads to a Telemetry or Data channel.
pub trait FrameWriter: Send + Sync {
    fn send_frame(&self, payload: &[u8]) -> Result<()>;
    /// Optional zero-copy scatter-gather write for framing `[video_hdr, annex_b]` without
    /// allocating an intermediate merged buffer. Default impl concatenates into `send_frame`.
    fn send_frame_parts(&self, parts: &[&[u8]]) -> Result<()> {
        let total: usize = parts.iter().map(|p| p.len()).sum();
        let mut merged = Vec::with_capacity(total);
        for p in parts {
            merged.extend_from_slice(p);
        }
        self.send_frame(&merged)
    }
    fn close(&self);
    /// Non-blocking best-effort check for whether the remote peer has closed/reset the socket
    /// (used to immediately cancel pending approval prompts when a client disconnects mid-handshake).
    fn is_peer_closed(&self) -> bool {
        false
    }
}

pub type SharedFrameWriter = Arc<dyn FrameWriter>;

/// Enable OS TCP keepalive (15s idle, 5s interval, 3 probes) on accepted streams so silently
/// dropped peers (Wi-Fi loss, sleep without FIN/RST) are detected even if `--ping-timeout-secs 0`.
pub fn enable_tcp_keepalive(stream: &TcpStream) {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use std::os::unix::io::AsRawFd;
        extern "C" {
            fn setsockopt(
                socket: i32,
                level: i32,
                name: i32,
                value: *const std::ffi::c_void,
                option_len: u32,
            ) -> i32;
        }
        let fd = stream.as_raw_fd();
        let enable: i32 = 1;
        let idle: i32 = 15;
        let interval: i32 = 5;
        let count: i32 = 3;

        #[cfg(target_os = "linux")]
        const SOL_SOCKET: i32 = 1;
        #[cfg(target_os = "linux")]
        const SO_KEEPALIVE: i32 = 9;
        #[cfg(target_os = "linux")]
        const IPPROTO_TCP: i32 = 6;
        #[cfg(target_os = "linux")]
        const TCP_KEEPIDLE: i32 = 4;
        #[cfg(target_os = "linux")]
        const TCP_KEEPINTVL: i32 = 5;
        #[cfg(target_os = "linux")]
        const TCP_KEEPCNT: i32 = 6;

        #[cfg(target_os = "macos")]
        const SOL_SOCKET: i32 = 0xffff;
        #[cfg(target_os = "macos")]
        const SO_KEEPALIVE: i32 = 0x0008;
        #[cfg(target_os = "macos")]
        const IPPROTO_TCP: i32 = 6;
        #[cfg(target_os = "macos")]
        const TCP_KEEPIDLE: i32 = 0x10; // TCP_KEEPALIVE on macOS
        #[cfg(target_os = "macos")]
        const TCP_KEEPINTVL: i32 = 0x101;
        #[cfg(target_os = "macos")]
        const TCP_KEEPCNT: i32 = 0x102;

        let sz = std::mem::size_of::<i32>() as u32;
        unsafe {
            let _ = setsockopt(
                fd,
                SOL_SOCKET,
                SO_KEEPALIVE,
                (&enable as *const i32).cast(),
                sz,
            );
            let _ = setsockopt(
                fd,
                IPPROTO_TCP,
                TCP_KEEPIDLE,
                (&idle as *const i32).cast(),
                sz,
            );
            let _ = setsockopt(
                fd,
                IPPROTO_TCP,
                TCP_KEEPINTVL,
                (&interval as *const i32).cast(),
                sz,
            );
            let _ = setsockopt(
                fd,
                IPPROTO_TCP,
                TCP_KEEPCNT,
                (&count as *const i32).cast(),
                sz,
            );
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = stream;
    }
}

#[cfg(unix)]
#[cfg(target_os = "macos")]
type UnixNfdsT = u32;
#[cfg(unix)]
#[cfg(not(target_os = "macos"))]
type UnixNfdsT = usize;

#[cfg(unix)]
#[repr(C)]
struct UnixPollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

#[cfg(unix)]
extern "C" {
    fn poll(fds: *mut UnixPollFd, nfds: UnixNfdsT, timeout: i32) -> i32;
}

#[cfg(unix)]
fn is_raw_fd_peer_closed(fd: i32) -> bool {
    extern "C" {
        fn recv(socket: i32, buf: *mut std::ffi::c_void, len: usize, flags: i32) -> isize;
    }
    const POLLERR: i16 = 0x0008;
    const POLLHUP: i16 = 0x0010;
    const POLLNVAL: i16 = 0x0020;
    #[cfg(target_os = "linux")]
    const POLLRDHUP: i16 = 0x2000;
    #[cfg(not(target_os = "linux"))]
    const POLLRDHUP: i16 = 0;

    // Non-destructive `poll(2)` check FIRST so peer FIN/RST is detected immediately even when
    // unread trailing bytes remain in the kernel receive queue (where `recv(MSG_PEEK)` returns 1).
    let mut pfd = UnixPollFd {
        fd,
        events: POLLRDHUP,
        revents: 0,
    };
    let prc = unsafe { poll(&mut pfd, 1, 0) };
    if prc > 0 && (pfd.revents & (POLLERR | POLLHUP | POLLNVAL | POLLRDHUP)) != 0 {
        return true;
    }

    // On macOS/XNU, `poll(2)` lacks `POLLRDHUP` and does not raise `POLLHUP` for TCP peer FIN
    // when unread trailing bytes remain in the receive queue. A zero-timeout `kqueue(EVFILT_READ)`
    // probe sets `EV_EOF` from `SBS_CANTRCVMORE` even with unread bytes queued.
    #[cfg(target_os = "macos")]
    if fd >= 0 {
        #[repr(C)]
        struct KEvent {
            ident: usize,
            filter: i16,
            flags: u16,
            fflags: u32,
            data: isize,
            udata: *mut std::ffi::c_void,
        }
        #[repr(C)]
        struct Timespec {
            tv_sec: isize,
            tv_nsec: isize,
        }
        extern "C" {
            fn kqueue() -> i32;
            fn kevent(
                kq: i32,
                changelist: *const KEvent,
                nchanges: i32,
                eventlist: *mut KEvent,
                nevents: i32,
                timeout: *const Timespec,
            ) -> i32;
            fn close(fd: i32) -> i32;
        }
        const EVFILT_READ: i16 = -1;
        const EV_ADD: u16 = 0x0001;
        const EV_ONESHOT: u16 = 0x0010;
        const EV_EOF: u16 = 0x8000;
        let kq = unsafe { kqueue() };
        if kq >= 0 {
            let change = KEvent {
                ident: fd as usize,
                filter: EVFILT_READ,
                flags: EV_ADD | EV_ONESHOT,
                fflags: 0,
                data: 0,
                udata: std::ptr::null_mut(),
            };
            let mut out = KEvent {
                ident: 0,
                filter: 0,
                flags: 0,
                fflags: 0,
                data: 0,
                udata: std::ptr::null_mut(),
            };
            let zero = Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            let n = unsafe { kevent(kq, &change, 1, &mut out, 1, &zero) };
            unsafe {
                let _ = close(kq);
            }
            if n > 0 && (out.flags & EV_EOF) != 0 {
                return true;
            }
        }
    }

    const MSG_PEEK: i32 = 0x2;
    #[cfg(target_os = "macos")]
    const MSG_DONTWAIT: i32 = 0x80;
    #[cfg(not(target_os = "macos"))]
    const MSG_DONTWAIT: i32 = 0x40;

    let mut byte = 0u8;
    let n = unsafe { recv(fd, (&mut byte as *mut u8).cast(), 1, MSG_PEEK | MSG_DONTWAIT) };
    if n == 0 {
        return true;
    }
    if n < 0 {
        let err = std::io::Error::last_os_error();
        return !matches!(
            err.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
        );
    }
    false
}

/// Non-invasive check whether a TCP peer has sent FIN/RST without modifying socket blocking mode.
pub fn is_tcp_peer_closed(stream: &TcpStream) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        is_raw_fd_peer_closed(stream.as_raw_fd())
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;

        #[repr(C)]
        struct WsaPollFd {
            fd: usize,
            events: i16,
            revents: i16,
        }
        #[link(name = "ws2_32")]
        extern "system" {
            fn WSAPoll(fd_array: *mut WsaPollFd, fds: u32, timeout: i32) -> i32;
            fn recv(s: usize, buf: *mut u8, len: i32, flags: i32) -> i32;
            fn WSAGetLastError() -> i32;
        }
        const POLLERR: i16 = 0x0001;
        const POLLHUP: i16 = 0x0002;
        const POLLNVAL: i16 = 0x0004;
        const POLLRDNORM: i16 = 0x0100;
        const MSG_PEEK: i32 = 0x2;
        const WSAEINTR: i32 = 10004;
        const WSAEWOULDBLOCK: i32 = 10035;

        let sock = stream.as_raw_socket() as usize;
        let mut pfd = WsaPollFd {
            fd: sock,
            events: POLLRDNORM,
            revents: 0,
        };
        let rc = unsafe { WSAPoll(&mut pfd, 1, 0) };
        if rc <= 0 {
            return false;
        }
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0 {
            return true;
        }
        if (pfd.revents & POLLRDNORM) != 0 {
            let mut byte = 0u8;
            let n = unsafe { recv(sock, &mut byte, 1, MSG_PEEK) };
            if n == 0 {
                return true;
            }
            if n < 0 {
                let err = unsafe { WSAGetLastError() };
                return !matches!(err, WSAEWOULDBLOCK | WSAEINTR);
            }
        }
        false
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = stream;
        false
    }
}

#[cfg(unix)]
pub fn is_unix_peer_closed(stream: &std::os::unix::net::UnixStream) -> bool {
    use std::os::unix::io::AsRawFd;
    is_raw_fd_peer_closed(stream.as_raw_fd())
}

/// Result of waiting for readability on a raw OS descriptor or an explicit wake signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollOutcome {
    Readable,
    Woken,
    Timeout,
}

/// Zero-wakeup cross-thread signal primitive used to interrupt blocking `accept()` and `usbmuxd`
/// reads without periodic `WouldBlock + thread::sleep` polling.
///
/// On Unix (macOS / Linux), backed by a `CLOEXEC` + `O_NONBLOCK` self-pipe polled via `poll(2)`
/// with infinite timeout (`0` CPU wakeups/sec while idle, allowing full CPU C-state / OS deep sleep).
pub struct WakePipe {
    #[cfg(unix)]
    read_fd: i32,
    #[cfg(unix)]
    write_fd: i32,
    #[cfg(unix)]
    woken: AtomicBool,
    #[cfg(not(unix))]
    woken: std::sync::atomic::AtomicBool,
}

impl WakePipe {
    pub fn new() -> io::Result<Self> {
        #[cfg(unix)]
        {
            extern "C" {
                fn pipe(fds: *mut i32) -> i32;
                fn fcntl(fd: i32, cmd: i32, ...) -> i32;
            }
            const F_GETFD: i32 = 1;
            const F_SETFD: i32 = 2;
            const FD_CLOEXEC: i32 = 1;
            const F_GETFL: i32 = 3;
            const F_SETFL: i32 = 4;
            #[cfg(target_os = "macos")]
            const O_NONBLOCK: i32 = 0x0004;
            #[cfg(not(target_os = "macos"))]
            const O_NONBLOCK: i32 = 0o4000;

            let mut fds = [-1i32; 2];
            if unsafe { pipe(fds.as_mut_ptr()) } != 0 {
                return Err(io::Error::last_os_error());
            }
            for &fd in &fds {
                unsafe {
                    let fd_flags = fcntl(fd, F_GETFD);
                    if fd_flags >= 0 {
                        let _ = fcntl(fd, F_SETFD, fd_flags | FD_CLOEXEC);
                    }
                    let fl_flags = fcntl(fd, F_GETFL);
                    if fl_flags >= 0 {
                        let _ = fcntl(fd, F_SETFL, fl_flags | O_NONBLOCK);
                    }
                }
            }
            Ok(Self {
                read_fd: fds[0],
                write_fd: fds[1],
                woken: AtomicBool::new(false),
            })
        }
        #[cfg(not(unix))]
        {
            Ok(Self {
                woken: std::sync::atomic::AtomicBool::new(false),
            })
        }
    }

    /// Permanently signal this wake pipe so any blocked `poll_fd_interruptible` / `wait_timeout`
    /// returns immediately with `PollOutcome::Woken`. Idempotent and thread-safe.
    pub fn wake(&self) {
        #[cfg(unix)]
        {
            if !self.woken.swap(true, Ordering::AcqRel) {
                extern "C" {
                    fn write(fd: i32, buf: *const std::ffi::c_void, count: usize) -> isize;
                }
                let byte = 1u8;
                let _ = unsafe { write(self.write_fd, (&byte as *const u8).cast(), 1) };
            }
        }
        #[cfg(not(unix))]
        {
            self.woken.store(true, std::sync::atomic::Ordering::Release);
        }
    }

    pub fn is_woken(&self) -> bool {
        #[cfg(unix)]
        {
            self.woken.load(Ordering::Acquire)
        }
        #[cfg(not(unix))]
        {
            self.woken.load(std::sync::atomic::Ordering::Acquire)
        }
    }

    /// Sleep up to `dur` with zero periodic wakeups, returning immediately if `wake()` is called.
    pub fn wait_timeout(&self, dur: std::time::Duration) -> PollOutcome {
        if self.is_woken() {
            return PollOutcome::Woken;
        }
        #[cfg(unix)]
        {
            const POLLIN: i16 = 0x0001;
            let deadline = std::time::Instant::now() + dur;
            loop {
                if self.is_woken() {
                    return PollOutcome::Woken;
                }
                let rem = deadline.saturating_duration_since(std::time::Instant::now());
                if rem.is_zero() {
                    return PollOutcome::Timeout;
                }
                let ms = rem.as_millis().min(i32::MAX as u128) as i32;
                let mut pfd = UnixPollFd {
                    fd: self.read_fd,
                    events: POLLIN,
                    revents: 0,
                };
                let rc = unsafe { poll(&mut pfd, 1, ms.max(1)) };
                if rc > 0 {
                    return PollOutcome::Woken;
                }
                if rc == 0 {
                    return PollOutcome::Timeout;
                }
                let err = io::Error::last_os_error();
                if err.kind() != io::ErrorKind::Interrupted {
                    return PollOutcome::Timeout;
                }
            }
        }
        #[cfg(not(unix))]
        {
            let deadline = std::time::Instant::now() + dur;
            while std::time::Instant::now() < deadline {
                if self.is_woken() {
                    return PollOutcome::Woken;
                }
                let rem = deadline.saturating_duration_since(std::time::Instant::now());
                std::thread::sleep(rem.min(std::time::Duration::from_millis(100)));
            }
            if self.is_woken() {
                PollOutcome::Woken
            } else {
                PollOutcome::Timeout
            }
        }
    }
}

#[cfg(unix)]
impl Drop for WakePipe {
    fn drop(&mut self) {
        extern "C" {
            fn close(fd: i32) -> i32;
        }
        unsafe {
            let _ = close(self.read_fd);
            let _ = close(self.write_fd);
        }
    }
}

/// Block indefinitely (zero periodic CPU wakeups) until either `fd` is readable/hung-up or
/// `wake_pipe.wake()` is invoked.
#[cfg(unix)]
pub fn poll_fd_interruptible(fd: i32, wake: &WakePipe) -> io::Result<PollOutcome> {
    const POLLIN: i16 = 0x0001;

    loop {
        if wake.is_woken() {
            return Ok(PollOutcome::Woken);
        }
        let mut pfds = [
            UnixPollFd {
                fd,
                events: POLLIN,
                revents: 0,
            },
            UnixPollFd {
                fd: wake.read_fd,
                events: POLLIN,
                revents: 0,
            },
        ];
        let rc = unsafe { poll(pfds.as_mut_ptr(), 2, -1) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if pfds[1].revents != 0 || wake.is_woken() {
            return Ok(PollOutcome::Woken);
        }
        if pfds[0].revents != 0 {
            return Ok(PollOutcome::Readable);
        }
    }
}

/// Accept a TCP connection with zero periodic CPU wakeups while idle, returning `Ok(None)`
/// immediately when `wake.wake()` is signaled.
pub fn accept_interruptible(
    listener: &TcpListener,
    wake: &WakePipe,
) -> io::Result<Option<(TcpStream, SocketAddr)>> {
    #[cfg(unix)]
    {
        loop {
            match poll_fd_interruptible(listener.as_raw_fd(), wake)? {
                PollOutcome::Woken => return Ok(None),
                PollOutcome::Readable | PollOutcome::Timeout => match listener.accept() {
                    Ok(pair) => return Ok(Some(pair)),
                    Err(e)
                        if e.kind() == io::ErrorKind::WouldBlock
                            || e.kind() == io::ErrorKind::Interrupted =>
                    {
                        if wake.is_woken() {
                            return Ok(None);
                        }
                        continue;
                    }
                    Err(e) => return Err(e),
                },
            }
        }
    }
    #[cfg(not(unix))]
    {
        if wake.is_woken() {
            return Ok(None);
        }
        match listener.accept() {
            Ok(pair) => {
                if wake.is_woken() {
                    let _ = pair.0.shutdown(std::net::Shutdown::Both);
                    return Ok(None);
                }
                Ok(Some(pair))
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                if wake.is_woken() {
                    Ok(None)
                } else {
                    Err(e)
                }
            }
            Err(e) => Err(e),
        }
    }
}

/// On non-Unix platforms (Windows), wake a blocking `TcpListener::accept()` on shutdown via a
/// short loopback self-connect so the listener thread never needs periodic polling.
#[cfg(not(unix))]
pub fn wake_blocking_listener_addr(addr: SocketAddr) {
    let target = match addr.ip() {
        std::net::IpAddr::V4(v4) if v4.is_unspecified() => {
            SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), addr.port())
        }
        std::net::IpAddr::V6(v6) if v6.is_unspecified() => {
            SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), addr.port())
        }
        _ => addr,
    };
    let _ = TcpStream::connect_timeout(&target, std::time::Duration::from_millis(200));
}

/// Install a POSIX async-signal-safe `SIGTERM` handler (used by macOS `launchd` and Linux
/// `systemd` to stop hosted services gracefully) backed by a dedicated self-pipe watcher thread
/// that remains permanently blocked in `read(2)` with zero CPU wakeups until `SIGTERM` arrives.
#[cfg(unix)]
pub fn install_sigterm_handler(on_term: Arc<dyn Fn() + Send + Sync + 'static>) {
    use std::sync::atomic::AtomicI32;

    static SIGTERM_PIPE_WR: AtomicI32 = AtomicI32::new(-1);

    extern "C" {
        fn pipe(fds: *mut i32) -> i32;
        fn fcntl(fd: i32, cmd: i32, ...) -> i32;
        fn read(fd: i32, buf: *mut std::ffi::c_void, count: usize) -> isize;
        fn write(fd: i32, buf: *const std::ffi::c_void, count: usize) -> isize;
        fn close(fd: i32) -> i32;
        fn signal(sig: i32, handler: usize) -> usize;
    }
    const F_GETFD: i32 = 1;
    const F_SETFD: i32 = 2;
    const FD_CLOEXEC: i32 = 1;
    const F_GETFL: i32 = 3;
    const F_SETFL: i32 = 4;
    #[cfg(target_os = "macos")]
    const O_NONBLOCK: i32 = 0x0004;
    #[cfg(not(target_os = "macos"))]
    const O_NONBLOCK: i32 = 0o4000;
    const SIGTERM: i32 = 15;

    extern "C" fn sigterm_trampoline(_sig: i32) {
        let fd = SIGTERM_PIPE_WR.load(Ordering::Relaxed);
        if fd >= 0 {
            #[cfg(target_os = "macos")]
            extern "C" {
                fn __error() -> *mut i32;
            }
            #[cfg(target_os = "linux")]
            extern "C" {
                fn __errno_location() -> *mut i32;
            }
            #[cfg(target_os = "macos")]
            let errno_ptr = unsafe { __error() };
            #[cfg(target_os = "linux")]
            let errno_ptr = unsafe { __errno_location() };
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            let saved_errno = unsafe { *errno_ptr };

            let b = 1u8;
            let _ = unsafe { write(fd, (&b as *const u8).cast(), 1) };

            #[cfg(any(target_os = "macos", target_os = "linux"))]
            unsafe {
                *errno_ptr = saved_errno;
            }
        }
    }

    let mut fds = [-1i32; 2];
    if unsafe { pipe(fds.as_mut_ptr()) } != 0 {
        return;
    }
    for &fd in &fds {
        unsafe {
            let fd_flags = fcntl(fd, F_GETFD);
            if fd_flags >= 0 {
                let _ = fcntl(fd, F_SETFD, fd_flags | FD_CLOEXEC);
            }
        }
    }
    // Only the write end is non-blocking so the signal handler can never block; the read end
    // blocks silently in kernel space with 0 CPU wakeups until SIGTERM fires.
    unsafe {
        let fl = fcntl(fds[1], F_GETFL);
        if fl >= 0 {
            let _ = fcntl(fds[1], F_SETFL, fl | O_NONBLOCK);
        }
    }
    if SIGTERM_PIPE_WR
        .compare_exchange(-1, fds[1], Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        unsafe {
            let _ = close(fds[0]);
            let _ = close(fds[1]);
        }
        return;
    }
    unsafe {
        let _ = signal(SIGTERM, sigterm_trampoline as *const () as usize);
    }
    let read_fd = fds[0];
    let _ = std::thread::Builder::new()
        .name("sigterm-watcher".to_string())
        .spawn(move || {
            let mut buf = [0u8; 1];
            loop {
                let n = unsafe { read(read_fd, buf.as_mut_ptr().cast(), 1) };
                if n > 0 {
                    // Restore SIG_DFL immediately so a 2nd SIGTERM terminates cleanly and a
                    // racing signal can never write into a closed/reused FD.
                    unsafe {
                        let _ = signal(SIGTERM, 0usize);
                    }
                    on_term();
                    break;
                }
                if n == 0 {
                    break;
                }
                if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                    break;
                }
            }
            // Leave the write-end pipe FD open (with SIGTERM_PIPE_WR = -1) until process exit so
            // any signal handler already mid-flight before SIG_DFL cannot hit a reused FD.
            SIGTERM_PIPE_WR.store(-1, Ordering::Release);
            unsafe {
                let _ = close(read_fd);
            }
        });
}

#[cfg(not(unix))]
pub fn install_sigterm_handler(_on_term: Arc<dyn Fn() + Send + Sync + 'static>) {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn tcp_keepalive_and_peer_closed_probe_work() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        enable_tcp_keepalive(&server);
        assert!(!is_tcp_peer_closed(&server));
        drop(client);
        // Wait briefly for loopback FIN delivery
        let mut closed = false;
        for _ in 0..20 {
            if is_tcp_peer_closed(&server) {
                closed = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        #[cfg(unix)]
        assert!(closed, "is_tcp_peer_closed should detect peer FIN");
        let _ = closed;
    }

    #[test]
    fn accept_interruptible_wakes_promptly_and_accepts_connections() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        #[cfg(unix)]
        listener.set_nonblocking(true).unwrap();
        let wake = Arc::new(WakePipe::new().unwrap());

        // 1. Accepts real connection immediately without polling delay
        let client_t = std::thread::spawn(move || TcpStream::connect(addr).unwrap());
        let accepted = accept_interruptible(&listener, &wake).unwrap();
        assert!(accepted.is_some());
        let _client = client_t.join().unwrap();

        // 2. Wakes up instantaneously from infinite kernel wait when wake() is called
        let wake_c = wake.clone();
        let t0 = std::time::Instant::now();
        let waker_t = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(25));
            wake_c.wake();
            #[cfg(not(unix))]
            wake_blocking_listener_addr(addr);
        });
        let res = accept_interruptible(&listener, &wake).unwrap();
        assert!(res.is_none(), "accept_interruptible should return None on wake");
        assert!(
            t0.elapsed() < std::time::Duration::from_millis(400),
            "wake should be prompt"
        );
        waker_t.join().unwrap();
    }

    #[test]
    fn wake_pipe_wait_timeout_and_poll_fd_interruptible_work() {
        let wake = Arc::new(WakePipe::new().unwrap());
        // 1. wait_timeout expires with PollOutcome::Timeout when not woken
        let t0 = std::time::Instant::now();
        assert_eq!(
            wake.wait_timeout(std::time::Duration::from_millis(30)),
            PollOutcome::Timeout
        );
        assert!(t0.elapsed() >= std::time::Duration::from_millis(20));

        // 2. wait_timeout returns PollOutcome::Woken promptly when woken from another thread
        let wake_c = wake.clone();
        let t1 = std::time::Instant::now();
        let h = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(20));
            wake_c.wake();
        });
        assert_eq!(
            wake.wait_timeout(std::time::Duration::from_secs(5)),
            PollOutcome::Woken
        );
        assert!(t1.elapsed() < std::time::Duration::from_millis(500));
        h.join().unwrap();

        // 3. Already-woken WakePipe returns immediately without blocking
        assert_eq!(
            wake.wait_timeout(std::time::Duration::from_secs(5)),
            PollOutcome::Woken
        );

        // 4. poll_fd_interruptible returns Readable on data and Woken on wake()
        #[cfg(unix)]
        {
            use std::io::Write;
            let (mut s1, s2) = std::os::unix::net::UnixStream::pair().unwrap();
            let wake2 = Arc::new(WakePipe::new().unwrap());
            let writer = std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(20));
                s1.write_all(b"x").unwrap();
                s1
            });
            let out = poll_fd_interruptible(s2.as_raw_fd(), &wake2).unwrap();
            assert_eq!(out, PollOutcome::Readable);
            let _s1 = writer.join().unwrap();

            let (s3, s4) = std::os::unix::net::UnixStream::pair().unwrap();
            let wake3 = Arc::new(WakePipe::new().unwrap());
            let wake3_c = wake3.clone();
            let w3 = std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(20));
                wake3_c.wake();
            });
            let out2 = poll_fd_interruptible(s4.as_raw_fd(), &wake3).unwrap();
            assert_eq!(out2, PollOutcome::Woken);
            w3.join().unwrap();
            drop(s3);
        }
    }
}
