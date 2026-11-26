use super::{HTTP_REQUEST_DEADLINE, MAX_HTTP_REQUEST_BYTES, MAX_WS_CONTROL_PAYLOAD};
use anyhow::Result;
use base64::Engine as _;
use serde::Serialize;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, TcpStream};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub(super) struct HttpRequest {
    pub(super) method: String,
    pub(super) path: String,
    pub(super) query: Option<String>,
    pub(super) headers: HashMap<String, String>,
    pub(super) body: Vec<u8>,
}

/// Read a single `\n`-terminated line with both a strict byte upper bound and a hard wall-clock
/// `deadline` re-applied before every underlying `read()` syscall (defeats Slowloris byte-by-byte trickle DoS).
fn read_line_limited(
    reader: &mut BufReader<TcpStream>,
    max_bytes: usize,
    deadline: Instant,
) -> Result<Option<String>> {
    let mut buf = Vec::new();
    loop {
        if reader.buffer().is_empty() {
            let rem = deadline.saturating_duration_since(Instant::now());
            if rem.is_zero() {
                anyhow::bail!("HTTP request deadline exceeded");
            }
            reader.get_ref().set_read_timeout(Some(rem))?;
        }
        let available = match reader.fill_buf() {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        };
        if available.is_empty() {
            if buf.is_empty() {
                return Ok(None);
            }
            break;
        }
        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            let take = pos + 1;
            if buf.len() + take > max_bytes {
                anyhow::bail!("HTTP header line exceeds limit");
            }
            buf.extend_from_slice(&available[..take]);
            reader.consume(take);
            break;
        } else {
            let take = available.len();
            if buf.len() + take > max_bytes {
                anyhow::bail!("HTTP header line exceeds limit");
            }
            buf.extend_from_slice(available);
            reader.consume(take);
        }
    }
    String::from_utf8(buf)
        .map(Some)
        .map_err(|_| anyhow::anyhow!("non-UTF-8 HTTP header"))
}

pub(super) fn read_http_request(stream: &TcpStream) -> Result<Option<HttpRequest>> {
    // Enforce a hard total request deadline (defeats Slowloris byte-by-byte trickle DoS).
    let deadline = Instant::now() + HTTP_REQUEST_DEADLINE;
    let update_timeout = |s: &TcpStream| -> Result<()> {
        let rem = deadline.saturating_duration_since(Instant::now());
        if rem.is_zero() {
            anyhow::bail!("HTTP request deadline exceeded");
        }
        s.set_read_timeout(Some(rem))?;
        Ok(())
    };
    update_timeout(stream)?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut remaining = MAX_HTTP_REQUEST_BYTES;
    let Some(request_line) = read_line_limited(&mut reader, remaining, deadline)? else {
        return Ok(None);
    };
    remaining = remaining.saturating_sub(request_line.len());
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        anyhow::bail!("malformed HTTP request line");
    }
    let method = parts[0].to_uppercase();
    let raw_target = parts[1];
    let (path, query) = match raw_target.split_once('?') {
        Some((p, q)) => (p.to_string(), Some(q.to_string())),
        None => (raw_target.to_string(), None),
    };

    let mut headers = HashMap::new();
    let mut saw_header_end = false;
    loop {
        if remaining == 0 {
            anyhow::bail!("HTTP headers too large");
        }
        let Some(line) = read_line_limited(&mut reader, remaining, deadline)? else {
            break;
        };
        remaining = remaining.saturating_sub(line.len());
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            saw_header_end = true;
            break;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            // Reject duplicate security-sensitive headers (RFC 9112 §3.2 / §6.3)
            if matches!(
                key.as_str(),
                "host"
                    | "content-length"
                    | "origin"
                    | "sec-fetch-site"
                    | "sec-fetch-mode"
                    | "sec-fetch-dest"
                    | "content-type"
            ) && headers.contains_key(&key)
            {
                anyhow::bail!("duplicate security-sensitive HTTP header: {key}");
            }
            if key == "cookie" {
                headers
                    .entry(key)
                    .and_modify(|existing: &mut String| {
                        existing.push_str("; ");
                        existing.push_str(v.trim());
                    })
                    .or_insert_with(|| v.trim().to_string());
            } else {
                headers.insert(key, v.trim().to_string());
            }
        }
    }
    if !saw_header_end {
        anyhow::bail!("incomplete HTTP headers (premature EOF)");
    }

    let content_len = match headers.get("content-length") {
        None => 0usize,
        Some(v) => v
            .trim()
            .parse::<usize>()
            .map_err(|_| anyhow::anyhow!("malformed Content-Length header"))?,
    };
    if content_len > MAX_HTTP_REQUEST_BYTES {
        anyhow::bail!("HTTP body too large ({content_len} bytes)");
    }
    let mut body = vec![0u8; content_len];
    let mut filled = 0usize;
    while filled < content_len {
        update_timeout(stream)?;
        match reader.read(&mut body[filled..]) {
            Ok(0) => anyhow::bail!("premature EOF reading HTTP body"),
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }

    Ok(Some(HttpRequest {
        method,
        path,
        query,
        headers,
        body,
    }))
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_nibble(bytes[i + 1]), hex_nibble(bytes[i + 2])) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        } else if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn percent_encode_query_val(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

pub(super) fn parse_query_param(query: Option<&str>, key: &str) -> Option<String> {
    let q = query?;
    for pair in q.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if percent_decode(k) == key {
            return Some(percent_decode(v));
        }
    }
    None
}

pub(super) fn parse_cookies(headers: &HashMap<String, String>) -> HashMap<String, String> {
    let mut out = HashMap::new();
    if let Some(cookie_hdr) = headers.get("cookie") {
        for part in cookie_hdr.split(';') {
            if let Some((k, v)) = part.trim().split_once('=') {
                out.insert(k.trim().to_string(), v.trim().to_string());
            }
        }
    }
    out
}

pub(super) fn is_loopback_peer(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    }
}

/// Strictly validate `Host` & proxy headers for loopback passwordless mode to defeat DNS Rebinding
/// and accidental reverse-proxy exposure.
pub(super) fn is_safe_loopback_host(headers: &HashMap<String, String>, listen_port: u16) -> bool {
    if headers.contains_key("x-forwarded-for")
        || headers.contains_key("x-forwarded-host")
        || headers.contains_key("forwarded")
        || headers.contains_key("x-real-ip")
        || headers.contains_key("via")
        || headers.contains_key("cf-connecting-ip")
    {
        return false;
    }
    let Some(raw_host) = headers.get("host").map(|s| s.trim()) else {
        return false;
    };
    let (host_part, port_opt) = if let Some(rest) = raw_host.strip_prefix('[') {
        let Some((h, after)) = rest.split_once(']') else {
            return false;
        };
        let port = after.strip_prefix(':').and_then(|p| p.parse::<u16>().ok());
        if !after.is_empty() && port.is_none() {
            return false;
        }
        (h, port)
    } else if let Some((h, p)) = raw_host.rsplit_once(':') {
        let Ok(port) = p.parse::<u16>() else {
            return false;
        };
        (h, Some(port))
    } else {
        (raw_host, None)
    };

    let trimmed_host = host_part.trim_end_matches('.');
    let valid_host = trimmed_host.eq_ignore_ascii_case("localhost")
        || trimmed_host
            .parse::<IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false);
    let valid_port = match port_opt {
        Some(p) => p == listen_port,
        None => listen_port == 80,
    };
    valid_host && valid_port
}

fn normalize_host_port(raw: &str, default_port: u16) -> Option<(String, u16)> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    let (h, p) = if let Some(rest) = s.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        let port = if after.is_empty() {
            default_port
        } else {
            after.strip_prefix(':')?.parse::<u16>().ok()?
        };
        (host, port)
    } else if let Some((host, port_str)) = s.rsplit_once(':') {
        let port = port_str.parse::<u16>().ok()?;
        (host, port)
    } else {
        (s, default_port)
    };
    Some((h.to_ascii_lowercase(), p))
}

/// Basic CSRF / CSWSH guard: if an `Origin` header is present, its host[:port] must match `Host`
/// (normalizing default ports `:80` for `http` and `:443` for `https`).
pub(super) fn origin_matches_host(headers: &HashMap<String, String>) -> bool {
    if let Some(sfs) = headers.get("sec-fetch-site") {
        let v = sfs.trim().to_ascii_lowercase();
        if v != "same-origin" && v != "none" {
            return false;
        }
    }
    let Some(origin) = headers.get("origin") else {
        return true;
    };
    let Some(host) = headers.get("host") else {
        return false;
    };
    let origin_trim = origin.trim();
    let lower = origin_trim.to_ascii_lowercase();
    let (default_port, rest) = if lower.starts_with("https://") {
        (443u16, &origin_trim[8..])
    } else if lower.starts_with("http://") {
        (80u16, &origin_trim[7..])
    } else {
        return false;
    };
    let origin_host = rest.split('/').next().unwrap_or("");
    match (
        normalize_host_port(origin_host, default_port),
        normalize_host_port(host, default_port),
    ) {
        (Some(o), Some(h)) => o == h,
        _ => origin_host.eq_ignore_ascii_case(host.trim()),
    }
}

pub(super) fn is_json_content_type(headers: &HashMap<String, String>) -> bool {
    headers
        .get("content-type")
        .map(|ct| {
            ct.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case("application/json")
        })
        .unwrap_or(false)
}

pub(super) fn send_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    extra_headers: &[String],
    body: &[u8],
) -> Result<()> {
    send_response_with_csp(
        stream,
        status,
        content_type,
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; media-src 'self' blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'",
        extra_headers,
        body,
    )
}

pub(super) fn send_viewer_html_response(
    stream: &mut TcpStream,
    extra_headers: &[String],
    body: &[u8],
) -> Result<()> {
    send_response_with_csp(
        stream,
        "200 OK",
        "text/html; charset=utf-8",
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; media-src 'self' blob:; connect-src 'self' ws: wss:; frame-ancestors 'none'; base-uri 'none'",
        extra_headers,
        body,
    )
}

fn send_response_with_csp(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    csp: &str,
    extra_headers: &[String],
    body: &[u8],
) -> Result<()> {
    let mut hdr = format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         Cache-Control: no-store\r\n\
         X-Content-Type-Options: nosniff\r\n\
         X-Frame-Options: DENY\r\n\
         Referrer-Policy: no-referrer\r\n\
         Content-Security-Policy: {csp}\r\n",
        body.len()
    );
    for h in extra_headers {
        hdr.push_str(h);
        hdr.push_str("\r\n");
    }
    hdr.push_str("\r\n");
    stream.write_all(hdr.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;
    Ok(())
}

pub(super) fn send_json<T: Serialize>(
    stream: &mut TcpStream,
    status: &str,
    extra_headers: &[String],
    value: &T,
) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    send_response(
        stream,
        status,
        "application/json; charset=utf-8",
        extra_headers,
        &bytes,
    )
}


/// Write a single unmasked server->client RFC 6455 WebSocket frame.
pub(super) fn write_ws_frame<W: Write>(writer: &mut W, opcode: u8, payload: &[u8]) -> std::io::Result<()> {
    let mut hdr = Vec::with_capacity(10);
    hdr.push(0x80 | (opcode & 0x0F));
    let len = payload.len();
    if len < 126 {
        hdr.push(len as u8);
    } else if len <= u16::MAX as usize {
        hdr.push(126);
        hdr.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        hdr.push(127);
        hdr.extend_from_slice(&(len as u64).to_be_bytes());
    }
    writer.write_all(&hdr)?;
    writer.write_all(payload)?;
    writer.flush()
}

/// Read a single client->server RFC 6455 frame.
/// Only returns `WouldBlock`/`TimedOut` when 0 bytes of the header have been consumed so a
/// mid-frame timeout never leaves residual bytes and desynchronizes the WebSocket stream.
pub(super) fn read_ws_control_frame<R: Read>(reader: &mut R) -> std::io::Result<Option<(u8, Vec<u8>)>> {
    let mut hdr = [0u8; 2];
    match reader.read(&mut hdr[0..1]) {
        Ok(0) => return Ok(None),
        Ok(_) => {}
        Err(e) => return Err(e),
    }
    if let Err(e) = reader.read_exact(&mut hdr[1..2]) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            format!("incomplete websocket frame header: {e}"),
        ));
    }
    let opcode = hdr[0] & 0x0F;
    let masked = (hdr[1] & 0x80) != 0;
    let mut len = (hdr[1] & 0x7F) as u64;
    if len == 126 {
        let mut ext = [0u8; 2];
        reader.read_exact(&mut ext).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::UnexpectedEof, format!("ws ext16: {e}"))
        })?;
        len = u16::from_be_bytes(ext) as u64;
    } else if len == 127 {
        let mut ext = [0u8; 8];
        reader.read_exact(&mut ext).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::UnexpectedEof, format!("ws ext64: {e}"))
        })?;
        len = u64::from_be_bytes(ext);
    }
    // RFC 6455 §5.5: all control frames (opcode >= 0x8) MUST have a payload <= 125 bytes.
    let max_len = if opcode >= 0x8 {
        MAX_WS_CONTROL_PAYLOAD
    } else {
        MAX_HTTP_REQUEST_BYTES as u64
    };
    if len > max_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "websocket client frame too large",
        ));
    }
    let mut mask_key = [0u8; 4];
    if masked {
        reader.read_exact(&mut mask_key).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::UnexpectedEof, format!("ws mask: {e}"))
        })?;
    }
    let mut payload = vec![0u8; len as usize];
    if len > 0 {
        reader.read_exact(&mut payload).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("ws payload: {e}"),
            )
        })?;
    }
    if masked {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask_key[i % 4];
        }
    }
    Ok(Some((opcode, payload)))
}

/// Compute RFC 6455 `Sec-WebSocket-Accept = base64(SHA-1(key + GUID))`.
pub(super) fn compute_ws_accept(key: &str) -> String {
    let mut input = Vec::with_capacity(key.len() + 36);
    input.extend_from_slice(key.trim().as_bytes());
    input.extend_from_slice(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    let digest = sha1_digest(&input);
    base64::engine::general_purpose::STANDARD.encode(digest)
}

/// Minimal pure-Rust RFC 3174 SHA-1 implementation (used exclusively for RFC 6455 WebSocket handshake).
fn sha1_digest(data: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x6745_2301;
    let mut h1: u32 = 0xEFCD_AB89;
    let mut h2: u32 = 0x98BA_DCFE;
    let mut h3: u32 = 0x1032_5476;
    let mut h4: u32 = 0xC3D2_E1F0;

    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    let (blocks, _) = msg.as_chunks::<64>();
    for chunk in blocks {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

/// Cryptographically secure random lowercase hex string of `num_bytes * 2` characters.
pub fn generate_random_hex(num_bytes: usize) -> String {
    let mut buf = vec![0u8; num_bytes];
    if getrandom::getrandom(&mut buf).is_err() {
        // Extremely unlikely fallback using monotonic time + process ID
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
            ^ (std::process::id() as u128);
        for (i, b) in buf.iter_mut().enumerate() {
            *b = ((seed >> ((i % 16) * 8)) & 0xFF) as u8;
        }
    }
    let mut s = String::with_capacity(num_bytes * 2);
    for b in buf {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Constant-time string equality check for auth tokens.
pub(super) fn ct_eq(a: &str, b: &str) -> bool {
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    let mut diff = ab.len() ^ bb.len();
    let max_len = ab.len().max(bb.len());
    for i in 0..max_len {
        let x = ab.get(i).copied().unwrap_or(0);
        let y = bb.get(i).copied().unwrap_or(0);
        diff |= (x ^ y) as usize;
    }
    diff == 0
}
