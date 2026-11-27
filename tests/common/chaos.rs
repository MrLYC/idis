//! Cross-platform real OS chaos helpers for extreme-scenario fuzzing (`tests/fuzz_extreme_chaos.rs`).
//! Zero external crate dependencies: uses inline Unix FFI and `windows-sys` (already in `Cargo.toml`).

#![allow(dead_code)]

use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::Child;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Force the OS kernel to emit a real TCP `RST` (not graceful `FIN`) when closing `stream`
/// by setting `SO_LINGER { l_onoff: 1, l_linger: 0 }` and immediately dropping the socket.
pub fn force_tcp_rst(stream: TcpStream) {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        #[repr(C)]
        struct Linger {
            l_onoff: i32,
            l_linger: i32,
        }
        extern "C" {
            fn setsockopt(
                socket: i32,
                level: i32,
                option_name: i32,
                option_value: *const std::ffi::c_void,
                option_len: u32,
            ) -> i32;
        }
        #[cfg(target_os = "macos")]
        const SOL_SOCKET: i32 = 0xffff;
        #[cfg(not(target_os = "macos"))]
        const SOL_SOCKET: i32 = 1;
        #[cfg(target_os = "macos")]
        const SO_LINGER: i32 = 0x0080;
        #[cfg(not(target_os = "macos"))]
        const SO_LINGER: i32 = 13;

        let linger = Linger {
            l_onoff: 1,
            l_linger: 0,
        };
        unsafe {
            let _ = setsockopt(
                stream.as_raw_fd(),
                SOL_SOCKET,
                SO_LINGER,
                (&linger as *const Linger).cast(),
                std::mem::size_of::<Linger>() as u32,
            );
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::{setsockopt, LINGER, SOL_SOCKET, SO_LINGER};
        let linger = LINGER {
            l_onoff: 1,
            l_linger: 0,
        };
        unsafe {
            let _ = setsockopt(
                stream.as_raw_socket() as usize,
                SOL_SOCKET,
                SO_LINGER,
                (&linger as *const LINGER).cast(),
                std::mem::size_of::<LINGER>() as i32,
            );
        }
    }
    drop(stream);
}

/// Shrink `SO_RCVBUF` on `stream` so slow-reader / zero-window backpressure saturates loopback
/// kernel buffers within tens of milliseconds.
pub fn shrink_rcvbuf(stream: &TcpStream, bytes: i32) {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        extern "C" {
            fn setsockopt(
                socket: i32,
                level: i32,
                option_name: i32,
                option_value: *const std::ffi::c_void,
                option_len: u32,
            ) -> i32;
        }
        #[cfg(target_os = "macos")]
        const SOL_SOCKET: i32 = 0xffff;
        #[cfg(not(target_os = "macos"))]
        const SOL_SOCKET: i32 = 1;
        #[cfg(target_os = "macos")]
        const SO_RCVBUF: i32 = 0x1002;
        #[cfg(not(target_os = "macos"))]
        const SO_RCVBUF: i32 = 8;

        unsafe {
            let _ = setsockopt(
                stream.as_raw_fd(),
                SOL_SOCKET,
                SO_RCVBUF,
                (&bytes as *const i32).cast(),
                std::mem::size_of::<i32>() as u32,
            );
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::{setsockopt, SOL_SOCKET, SO_RCVBUF};
        unsafe {
            let _ = setsockopt(
                stream.as_raw_socket() as usize,
                SOL_SOCKET,
                SO_RCVBUF,
                (&bytes as *const i32).cast(),
                std::mem::size_of::<i32>() as i32,
            );
        }
    }
}

/// Shrink `SO_SNDBUF` on `stream` to accelerate write-side TCP zero-window saturation on loopback.
pub fn shrink_sndbuf(stream: &TcpStream, bytes: i32) {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        extern "C" {
            fn setsockopt(
                socket: i32,
                level: i32,
                option_name: i32,
                option_value: *const std::ffi::c_void,
                option_len: u32,
            ) -> i32;
        }
        #[cfg(target_os = "macos")]
        const SOL_SOCKET: i32 = 0xffff;
        #[cfg(not(target_os = "macos"))]
        const SOL_SOCKET: i32 = 1;
        #[cfg(target_os = "macos")]
        const SO_SNDBUF: i32 = 0x1001;
        #[cfg(not(target_os = "macos"))]
        const SO_SNDBUF: i32 = 7;

        unsafe {
            let _ = setsockopt(
                stream.as_raw_fd(),
                SOL_SOCKET,
                SO_SNDBUF,
                (&bytes as *const i32).cast(),
                std::mem::size_of::<i32>() as u32,
            );
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::{setsockopt, SOL_SOCKET, SO_SNDBUF};
        unsafe {
            let _ = setsockopt(
                stream.as_raw_socket() as usize,
                SOL_SOCKET,
                SO_SNDBUF,
                (&bytes as *const i32).cast(),
                std::mem::size_of::<i32>() as i32,
            );
        }
    }
}

/// Poll `pred` with a 5ms cadence until it returns `true` or `timeout` expires.
pub fn wait_until(timeout: Duration, mut pred: impl FnMut() -> bool, msg: &str) {
    let deadline = Instant::now() + timeout;
    loop {
        if pred() {
            return;
        }
        if Instant::now() >= deadline {
            panic!("wait_until timed out after {:?}: {msg}", timeout);
        }
        thread::sleep(Duration::from_millis(5));
    }
}

/// RAII deadlock watchdog: aborts the test process with a clear diagnostic if the guarded scope
/// hangs past `limit`, preventing stalled CI jobs on lock/join deadlocks.
pub struct DeadlockWatchdog {
    disarmed: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}

impl DeadlockWatchdog {
    pub fn arm(label: &'static str, limit: Duration) -> Self {
        let disarmed = Arc::new(AtomicBool::new(false));
        let d = disarmed.clone();
        let join = thread::spawn(move || {
            let deadline = Instant::now() + limit;
            while !d.load(Ordering::Acquire) {
                if Instant::now() >= deadline {
                    eprintln!("DEADLOCK WATCHDOG FIRED in {label} after {:?}", limit);
                    std::process::abort();
                }
                thread::sleep(Duration::from_millis(25));
            }
        });
        Self {
            disarmed,
            join: Some(join),
        }
    }
}

impl Drop for DeadlockWatchdog {
    fn drop(&mut self) {
        self.disarmed.store(true, Ordering::Release);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

/// RAII reaper ensuring spawned child processes and temporary shim files are always killed and
/// removed even if a test panics.
pub struct ChildReaperGuard {
    pub child: Option<Child>,
    pub cleanup_paths: Vec<PathBuf>,
}

impl ChildReaperGuard {
    pub fn new(child: Option<Child>, cleanup_paths: Vec<PathBuf>) -> Self {
        Self {
            child,
            cleanup_paths,
        }
    }
}

impl Drop for ChildReaperGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        for p in &self.cleanup_paths {
            let _ = std::fs::remove_file(p);
            let _ = std::fs::remove_dir_all(p);
        }
    }
}

/// Reserve `count` distinct ephemeral loopback ports simultaneously so the OS cannot recycle
/// port[0] into port[1], then drop the temporary listeners.
pub fn alloc_distinct_loopback_ports(count: usize) -> Vec<u16> {
    let listeners: Vec<TcpListener> = (0..count)
        .map(|_| TcpListener::bind("127.0.0.1:0").expect("bind ephemeral loopback port"))
        .collect();
    let ports = listeners
        .iter()
        .map(|l| l.local_addr().unwrap().port())
        .collect();
    drop(listeners);
    ports
}

/// Create a unique temporary directory for a subprocess/persistence chaos test.
pub fn temp_chaos_dir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(1);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("idis_chaos_{}_{}_{}", std::process::id(), tag, n));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp chaos dir");
    dir
}

/// Send real `SIGTERM` (signal 15) to `pid` on Unix without external crate dependencies.
#[cfg(unix)]
pub fn send_sigterm(pid: u32) -> std::io::Result<()> {
    extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    const SIGTERM: i32 = 15;
    let rc = unsafe { kill(pid as i32, SIGTERM) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}
