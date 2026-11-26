use anyhow::{bail, Result};
use std::io::{IoSlice, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

/// Hard wall-clock deadline across short-write retries in [`write_all_vectored`] so partial TCP
/// writes over a half-open Wi-Fi link cannot repeatedly reset `SO_SNDTIMEO` and stall for 10s+.
const MAX_VECTORED_WRITE_DEADLINE: Duration = Duration::from_secs(5);

/// Maximum single frame payload (32 MiB sanity cap for video frames).
pub const MAX_FRAME_SIZE: usize = 32 * 1024 * 1024;

/// Stricter cap (64 KiB) for unauthenticated incoming frames to prevent pre-auth OOM DoS.
pub const MAX_PREAUTH_FRAME_SIZE: usize = 64 * 1024;

/// Cap (256 KiB) for authenticated incoming Telemetry / input frames.
pub const MAX_CONTROL_FRAME_SIZE: usize = 256 * 1024;

/// PeerTalk PTProtocol header constants (verified from legacy PTProtocol.m).
pub const PT_PROTOCOL_VERSION: u32 = 1;
pub const PT_FRAME_TYPE_TELEMETRY: u32 = 100; // 0x64
pub const PT_FRAME_TYPE_DATA: u32 = 101; // 0x65
pub const PEERTALK_USB_PORT: u16 = 2345; // 0x0929

/// Write all slices to `writer` using `write_vectored` with a full short-write advancement loop
/// (eliminates per-frame heap allocation and payload copying on hot video send paths).
pub fn write_all_vectored<W: Write>(writer: &mut W, parts: &[&[u8]]) -> Result<()> {
    let start = Instant::now();
    let mut idx = 0usize;
    let mut off = 0usize;
    let mut writes = 0usize;
    while idx < parts.len() {
        while idx < parts.len() && off >= parts[idx].len() {
            idx += 1;
            off = 0;
        }
        if idx >= parts.len() {
            break;
        }
        if writes > 0 && start.elapsed() >= MAX_VECTORED_WRITE_DEADLINE {
            bail!(
                "write_vectored frame deadline exceeded ({}ms)",
                start.elapsed().as_millis()
            );
        }
        let mut ios: [IoSlice<'_>; 8] = [IoSlice::new(&[]); 8];
        let mut n_ios = 0usize;
        for (k, p) in parts[idx..].iter().enumerate().take(8) {
            let slice = if k == 0 { &p[off..] } else { p };
            if !slice.is_empty() {
                ios[n_ios] = IoSlice::new(slice);
                n_ios += 1;
            }
        }
        if n_ios == 0 {
            break;
        }
        let n = match writer.write_vectored(&ios[..n_ios]) {
            Ok(0) => bail!("write_vectored returned 0 bytes (connection closed)"),
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        };
        writes += 1;
        let mut rem = n;
        while rem > 0 && idx < parts.len() {
            let avail = parts[idx].len() - off;
            if rem < avail {
                off += rem;
                rem = 0;
            } else {
                rem -= avail;
                idx += 1;
                off = 0;
            }
        }
    }
    writer.flush()?;
    Ok(())
}

/// Zero-copy vectored variant of [`write_canal_block`] (stack-allocated slice table for <=7 parts).
pub fn write_canal_parts<W: Write>(writer: &mut W, parts: &[&[u8]]) -> Result<()> {
    let total: usize = parts.iter().map(|p| p.len()).sum();
    if total > MAX_FRAME_SIZE {
        bail!("MSMCanalSocket block too large: {total} bytes");
    }
    let len_bytes = (total as u32).to_le_bytes();
    if parts.len() <= 7 {
        let mut stack: [&[u8]; 8] = [&[]; 8];
        stack[0] = &len_bytes;
        for (i, p) in parts.iter().enumerate() {
            stack[i + 1] = p;
        }
        return write_all_vectored(writer, &stack[..1 + parts.len()]);
    }
    let mut all: Vec<&[u8]> = Vec::with_capacity(1 + parts.len());
    all.push(&len_bytes);
    all.extend_from_slice(parts);
    write_all_vectored(writer, &all)
}

/// Write an `MSMCanalSocket` length-prefixed block: `[u32_le len][payload]`.
/// Uses vectored I/O to avoid copying the payload buffer while still sending header + body together.
pub fn write_canal_block<W: Write>(writer: &mut W, payload: &[u8]) -> Result<()> {
    write_canal_parts(writer, &[payload])
}

/// Read an `MSMCanalSocket` length-prefixed block: `[u32_le len][payload]`.
/// Returns `Ok(None)` on clean EOF at frame boundary.
pub fn read_canal_block<R: Read>(reader: &mut R) -> Result<Option<Vec<u8>>> {
    read_canal_block_limited(reader, MAX_FRAME_SIZE)
}

/// Read an `MSMCanalSocket` length-prefixed block with an explicit maximum payload size.
/// Returns `Ok(None)` on clean EOF at frame boundary.
/// Reads large payloads incrementally so a malicious 4-byte length header followed by EOF
/// cannot trigger an immediate multi-megabyte allocation spike.
pub fn read_canal_block_limited<R: Read>(
    reader: &mut R,
    max_size: usize,
) -> Result<Option<Vec<u8>>> {
    let cap = max_size.min(MAX_FRAME_SIZE);
    let mut len_buf = [0u8; 4];
    loop {
        match reader.read(&mut len_buf[..1]) {
            Ok(0) => return Ok(None),
            Ok(_) => break,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    reader.read_exact(&mut len_buf[1..])?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len == 0 {
        return Ok(Some(Vec::new()));
    }
    if len > cap {
        bail!("MSMCanalSocket incoming frame too large: {} bytes (limit={})", len, cap);
    }
    let mut payload = Vec::with_capacity(len.min(65536));
    let mut remaining = len;
    let mut chunk = [0u8; 16384];
    while remaining > 0 {
        let to_read = remaining.min(chunk.len());
        match reader.read(&mut chunk[..to_read]) {
            Ok(0) => bail!("unexpected EOF reading MSMCanalSocket frame"),
            Ok(n) => {
                payload.extend_from_slice(&chunk[..n]);
                remaining -= n;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(Some(payload))
}

/// Read an `MSMCanalSocket` block enforcing a hard wall-clock `deadline` across every individual
/// `read()` syscall so Slowloris byte-by-byte trickling cannot reset `SO_RCVTIMEO`.
pub fn read_canal_block_limited_deadline(
    stream: &mut TcpStream,
    max_size: usize,
    deadline: Instant,
) -> Result<Option<Vec<u8>>> {
    fn read_exact_deadline(
        stream: &mut TcpStream,
        buf: &mut [u8],
        deadline: Instant,
        eof_ok_at_zero: bool,
    ) -> Result<bool> {
        let mut filled = 0usize;
        while filled < buf.len() {
            let rem = deadline.saturating_duration_since(Instant::now());
            if rem.is_zero() {
                bail!("pre-auth handshake deadline exceeded");
            }
            stream.set_read_timeout(Some(rem))?;
            match stream.read(&mut buf[filled..]) {
                Ok(0) => {
                    if filled == 0 && eof_ok_at_zero {
                        return Ok(false);
                    }
                    bail!("unexpected EOF reading MSMCanalSocket frame");
                }
                Ok(n) => filled += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(true)
    }

    let cap = max_size.min(MAX_FRAME_SIZE);
    let mut len_buf = [0u8; 4];
    if !read_exact_deadline(stream, &mut len_buf, deadline, true)? {
        return Ok(None);
    }
    let len = u32::from_le_bytes(len_buf) as usize;
    if len == 0 {
        return Ok(Some(Vec::new()));
    }
    if len > cap {
        bail!("MSMCanalSocket incoming frame too large: {} bytes (limit={})", len, cap);
    }
    let mut payload = Vec::with_capacity(len.min(65536));
    let mut remaining = len;
    let mut chunk = [0u8; 16384];
    while remaining > 0 {
        let to_read = remaining.min(chunk.len());
        read_exact_deadline(stream, &mut chunk[..to_read], deadline, false)?;
        payload.extend_from_slice(&chunk[..to_read]);
        remaining -= to_read;
    }
    Ok(Some(payload))
}

/// PeerTalk `PTProtocol` frame (16-byte big-endian header + payload).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PtFrame {
    pub version: u32,
    pub frame_type: u32,
    pub tag: u32,
    pub payload: Vec<u8>,
}

/// Zero-copy vectored variant of [`write_pt_frame`] (stack-allocated slice table for <=7 parts).
pub fn write_pt_parts<W: Write>(
    writer: &mut W,
    frame_type: u32,
    tag: u32,
    parts: &[&[u8]],
) -> Result<()> {
    let total: usize = parts.iter().map(|p| p.len()).sum();
    if total > MAX_FRAME_SIZE {
        bail!("PTProtocol payload too large: {total} bytes");
    }
    let mut hdr = [0u8; 16];
    hdr[0..4].copy_from_slice(&PT_PROTOCOL_VERSION.to_be_bytes());
    hdr[4..8].copy_from_slice(&frame_type.to_be_bytes());
    hdr[8..12].copy_from_slice(&tag.to_be_bytes());
    hdr[12..16].copy_from_slice(&(total as u32).to_be_bytes());
    if parts.len() <= 7 {
        let mut stack: [&[u8]; 8] = [&[]; 8];
        stack[0] = &hdr;
        for (i, p) in parts.iter().enumerate() {
            stack[i + 1] = p;
        }
        return write_all_vectored(writer, &stack[..1 + parts.len()]);
    }
    let mut all: Vec<&[u8]> = Vec::with_capacity(1 + parts.len());
    all.push(&hdr);
    all.extend_from_slice(parts);
    write_all_vectored(writer, &all)
}

/// Write a PeerTalk `PTProtocol` frame: `[version: u32_be][type: u32_be][tag: u32_be][size: u32_be][payload]`.
pub fn write_pt_frame<W: Write>(
    writer: &mut W,
    frame_type: u32,
    tag: u32,
    payload: &[u8],
) -> Result<()> {
    write_pt_parts(writer, frame_type, tag, &[payload])
}

/// Read a PeerTalk `PTProtocol` frame up to `MAX_FRAME_SIZE`. Returns `Ok(None)` on clean EOF.
pub fn read_pt_frame<R: Read>(reader: &mut R) -> Result<Option<PtFrame>> {
    read_pt_frame_limited(reader, MAX_FRAME_SIZE)
}

/// Read a PeerTalk `PTProtocol` frame enforcing an explicit maximum payload size `max_size`
/// (prevents pre-auth or control-plane 32 MiB allocations on USB PeerTalk streams).
pub fn read_pt_frame_limited<R: Read>(reader: &mut R, max_size: usize) -> Result<Option<PtFrame>> {
    let mut hdr = [0u8; 16];
    loop {
        match reader.read(&mut hdr[..1]) {
            Ok(0) => return Ok(None),
            Ok(_) => break,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    reader.read_exact(&mut hdr[1..])?;
    let version = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
    let frame_type = u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
    let tag = u32::from_be_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]);
    let size = u32::from_be_bytes([hdr[12], hdr[13], hdr[14], hdr[15]]) as usize;
    if version != PT_PROTOCOL_VERSION {
        bail!("unexpected PTProtocol version: {version}");
    }
    let limit = max_size.min(MAX_FRAME_SIZE);
    if size > limit {
        bail!("PTProtocol incoming frame too large: {size} bytes (limit {limit})");
    }
    let mut payload = vec![0u8; size];
    if size > 0 {
        reader.read_exact(&mut payload)?;
    }
    Ok(Some(PtFrame {
        version,
        frame_type,
        tag,
        payload,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn canal_block_roundtrip() {
        let mut buf = Vec::new();
        write_canal_block(&mut buf, b"hello").unwrap();
        write_canal_block(&mut buf, b"world!").unwrap();
        assert_eq!(&buf[0..4], &5u32.to_le_bytes());

        let mut cur = Cursor::new(buf);
        assert_eq!(read_canal_block(&mut cur).unwrap(), Some(b"hello".to_vec()));
        assert_eq!(read_canal_block(&mut cur).unwrap(), Some(b"world!".to_vec()));
        assert_eq!(read_canal_block(&mut cur).unwrap(), None);
    }

    #[test]
    fn pt_frame_roundtrip() {
        let mut buf = Vec::new();
        write_pt_frame(&mut buf, PT_FRAME_TYPE_TELEMETRY, 7, b"abc").unwrap();
        assert_eq!(&buf[0..4], &1u32.to_be_bytes());
        assert_eq!(&buf[4..8], &100u32.to_be_bytes());
        assert_eq!(&buf[8..12], &7u32.to_be_bytes());
        assert_eq!(&buf[12..16], &3u32.to_be_bytes());

        let mut cur = Cursor::new(buf);
        let f = read_pt_frame(&mut cur).unwrap().unwrap();
        assert_eq!(f.version, 1);
        assert_eq!(f.frame_type, PT_FRAME_TYPE_TELEMETRY);
        assert_eq!(f.tag, 7);
        assert_eq!(f.payload, b"abc");
        assert_eq!(read_pt_frame(&mut cur).unwrap(), None);
    }

    #[test]
    fn mid_header_truncated_eof_returns_err_not_clean_eof() {
        // BUG-A7 regression: 0 bytes = clean EOF (Ok(None)); 1..3B Canal or 1..15B PT = Err
        let mut canal_trunc = Cursor::new(vec![0x05, 0x00]);
        assert!(read_canal_block(&mut canal_trunc).is_err());

        let mut canal_oversized = Cursor::new(u32::to_le_bytes(2048).to_vec());
        assert!(read_canal_block_limited(&mut canal_oversized, 1024).is_err());

        let mut pt_trunc = Cursor::new(vec![0, 0, 0, 1, 0, 0]);
        assert!(read_pt_frame(&mut pt_trunc).is_err());

        let mut pt_bad_ver = Cursor::new([0, 0, 0, 99, 0, 0, 0, 100, 0, 0, 0, 1, 0, 0, 0, 0]);
        assert!(read_pt_frame(&mut pt_bad_ver).is_err());
    }

    #[test]
    fn canal_and_pt_readers_retry_eintr_on_first_byte_and_mid_header() {
        struct EintrReader {
            data: Vec<u8>,
            pos: usize,
            eintr_next: bool,
        }
        impl Read for EintrReader {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.eintr_next {
                    self.eintr_next = false;
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "simulated EINTR",
                    ));
                }
                if self.pos >= self.data.len() {
                    return Ok(0);
                }
                self.eintr_next = true;
                buf[0] = self.data[self.pos];
                self.pos += 1;
                Ok(1)
            }
        }

        let mut cbuf = Vec::new();
        write_canal_block(&mut cbuf, b"eintr-ok").unwrap();
        let mut cr = EintrReader { data: cbuf, pos: 0, eintr_next: true };
        assert_eq!(read_canal_block(&mut cr).unwrap(), Some(b"eintr-ok".to_vec()));
        assert_eq!(read_canal_block(&mut cr).unwrap(), None);

        let mut pbuf = Vec::new();
        write_pt_frame(&mut pbuf, PT_FRAME_TYPE_DATA, 9, b"pt-eintr").unwrap();
        let mut pr = EintrReader { data: pbuf, pos: 0, eintr_next: true };
        let f = read_pt_frame(&mut pr).unwrap().unwrap();
        assert_eq!(f.payload, b"pt-eintr");
        assert_eq!(read_pt_frame(&mut pr).unwrap(), None);

        // P2-A4: read_pt_frame_limited rejects oversized PeerTalk frames before allocating
        let mut big = Vec::new();
        write_pt_frame(&mut big, PT_FRAME_TYPE_TELEMETRY, 1, &vec![0xAA; 1024]).unwrap();
        let mut cur = Cursor::new(big);
        assert!(
            read_pt_frame_limited(&mut cur, 256).is_err(),
            "read_pt_frame_limited must reject frame exceeding max_size"
        );
    }
}
