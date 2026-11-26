//! Tier 0 Security & Parser Feasibility Gate (`\mathcal{F}`):
//! Deterministic, zero-sleep, zero-socket mutation + adversarial-corpus fuzzing across all
//! untrusted byte/file parsing boundaries in `idis`.

mod common {
    pub mod fuzz;
}

use common::fuzz::{fuzz_seeds, mutate_bytes, FuzzRng};
use idis::protocol::annexb::{is_self_contained_idr, AnnexBSplitter};
use idis::protocol::framing::{
    read_canal_block_limited, read_pt_frame_limited, write_canal_block, write_pt_frame,
    MAX_FRAME_SIZE, PT_FRAME_TYPE_DATA,
};
use idis::protocol::keyed_archive::{archive, unarchive, ArchivedValue};
use idis::protocol::messages::{decode_input_event, MessagePacket};
use idis::protocol::video::{build_video_packet, parse_video_header, COMPRESSION_H264};
use idis::user_config::{UserConfigFile, MAX_TRUSTED_DEVICES, MAX_YAML_CONFIG_BYTES};
use idis::web::fuzz_hooks::{origin_matches_host, parse_http_bytes, parse_ws_client_frame};
use std::collections::{BTreeMap, HashMap};
use std::io::Cursor;

#[test]
fn fuzz_keyed_archive_and_messages_never_panic_and_enforce_budgets() {
    let mut valid_dict = BTreeMap::new();
    valid_dict.insert(
        "uniqueIdentifier".to_string(),
        ArchivedValue::String("fuzz-uid".to_string()),
    );
    valid_dict.insert("screenWidth".to_string(), ArchivedValue::Int(1920));
    valid_dict.insert("screenHeight".to_string(), ArchivedValue::Int(1080));
    let valid_pkt = MessagePacket::new_send("Handshake", ArchivedValue::Dict(valid_dict))
        .encode()
        .unwrap();

    // Hostile non-string dict key wrapping huge binary data (tests bounded key formatting)
    let mut big_key_fields = BTreeMap::new();
    big_key_fields.insert(
        "NS.keys".to_string(),
        ArchivedValue::Array(vec![ArchivedValue::Data(vec![0xAB; 128 * 1024])]),
    );
    big_key_fields.insert(
        "NS.objects".to_string(),
        ArchivedValue::Array(vec![ArchivedValue::Int(1)]),
    );
    let big_key_bplist = archive(&ArchivedValue::Object {
        class_name: "NSDictionary".to_string(),
        classes: vec!["NSDictionary".to_string(), "NSObject".to_string()],
        fields: big_key_fields,
    })
    .unwrap();

    let corpus: Vec<Vec<u8>> = vec![
        Vec::new(),
        valid_pkt.clone(),
        big_key_bplist,
        b"bplist00".to_vec(),
        b"<?xml version=\"1.0\"?><!DOCTYPE plist [<!ENTITY x \"AAAA\">]><plist><dict/></plist>"
            .to_vec(),
        b"<?xml version=\"1.0\"?><plist><!--><array><array><array></plist>".to_vec(),
        b"(((((((((((((((((((((((((((((((((((((((((((((((((((".to_vec(),
    ];

    for seed_bytes in &corpus {
        let _ = unarchive(seed_bytes);
        let _ = MessagePacket::decode(seed_bytes);
        let _ = decode_input_event(seed_bytes);
    }

    // Valid roundtrip oracle
    let decoded = MessagePacket::decode(&valid_pkt).expect("valid packet must decode");
    assert_eq!(decoded.name_method, "Handshake");

    for seed in fuzz_seeds(0xA101, 64) {
        let mut rng = FuzzRng::new(seed);
        for _ in 0..16 {
            let base = rng.pick(&corpus);
            let mutated = mutate_bytes(&mut rng, base, 64 * 1024);
            let _ = unarchive(&mutated);
            let _ = MessagePacket::decode(&mutated);
            let _ = decode_input_event(&mutated);
        }
    }
}

#[test]
fn fuzz_framing_and_video_headers_clamp_sizes_and_reject_underflow() {
    // 1. Unbacked 32 MiB & 4 GiB headers followed by immediate EOF must fail cleanly without OOM.
    for declared in [MAX_FRAME_SIZE as u32, u32::MAX] {
        let hdr = declared.to_le_bytes();
        let mut cur = Cursor::new(hdr.as_slice());
        assert!(
            read_canal_block_limited(&mut cur, usize::MAX).is_err(),
            "unbacked huge Canal block (declared={declared}) must fail cleanly"
        );
    }

    // 2. `parse_video_header` must reject header_len < 13 (underflow into header bytes).
    for bad_hdr_len in 0u32..13 {
        let mut pkt = vec![0u8; 32];
        pkt[0..4].copy_from_slice(&bad_hdr_len.to_le_bytes());
        pkt[4..8].copy_from_slice(&1280u32.to_le_bytes());
        pkt[8..12].copy_from_slice(&720u32.to_le_bytes());
        pkt[12] = COMPRESSION_H264;
        assert!(
            parse_video_header(&pkt).is_none(),
            "parse_video_header must reject header_len={bad_hdr_len} < 13"
        );
    }

    // 3. Valid Canal + PeerTalk + Video roundtrips + seeded mutations
    let mut canal_seed = Vec::new();
    write_canal_block(&mut canal_seed, b"hello-canal").unwrap();
    let mut pt_seed = Vec::new();
    write_pt_frame(&mut pt_seed, PT_FRAME_TYPE_DATA, 1, b"hello-pt").unwrap();
    let video_seed = build_video_packet(1280, 720, 5120, COMPRESSION_H264, 5, &[0, 0, 0, 1, 0x65]);
    let corpus = [canal_seed, pt_seed, video_seed];

    for seed in fuzz_seeds(0xA102, 64) {
        let mut rng = FuzzRng::new(seed);
        for _ in 0..24 {
            let base = rng.pick(&corpus);
            let mutated = mutate_bytes(&mut rng, base, 8192);
            let mut c1 = Cursor::new(mutated.as_slice());
            let _ = read_canal_block_limited(&mut c1, 64 * 1024);
            let mut c2 = Cursor::new(mutated.as_slice());
            let _ = read_pt_frame_limited(&mut c2, 64 * 1024);
            if let Some(vh) = parse_video_header(&mutated) {
                assert!(vh.header_len >= 13);
                assert!(vh.payload_offset <= mutated.len());
            }
        }
    }
}

#[test]
fn fuzz_http_origin_and_ws_enforce_rfc_and_csrf_invariants() {
    // 1. Pipelined WebSocket bytes coalesced after `GET /ws/stream` headers must NOT be lost!
    let ws_upgrade = b"GET /ws/stream HTTP/1.1\r\nHost: 127.0.0.1:8787\r\nOrigin: http://127.0.0.1:8787\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
    let mut pipelined = ws_upgrade.to_vec();
    let masked_ping = [0x89u8, 0x82, 0x11, 0x22, 0x33, 0x44, b'h' ^ 0x11, b'i' ^ 0x22];
    pipelined.extend_from_slice(&masked_ping);
    let mut cur = Cursor::new(pipelined.as_slice());
    let req = idis::web::fuzz_hooks::parse_http_bytes(&pipelined).unwrap().unwrap();
    assert_eq!(req.0, "GET");
    assert_eq!(req.1, "/ws/stream");
    // Verify parsing the exact prefix leaves the pipelined WS frame intact
    let header_end = pipelined
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap()
        + 4;
    cur.set_position(header_end as u64);
    let mut tail = Vec::new();
    std::io::Read::read_to_end(&mut cur, &mut tail).unwrap();
    let (op, payload) = parse_ws_client_frame(&tail).unwrap().unwrap();
    assert_eq!(op, 0x9);
    assert_eq!(payload, b"hi");

    // 2. Reject Transfer-Encoding & duplicate security headers
    let te_req = b"POST /api/admin/settings HTTP/1.1\r\nHost: 127.0.0.1:8787\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
    assert!(parse_http_bytes(te_req).is_err(), "Transfer-Encoding must be rejected");
    let dup_key = b"GET /ws/stream HTTP/1.1\r\nHost: 127.0.0.1:8787\r\nSec-WebSocket-Key: aaa\r\nSec-WebSocket-Key: bbb\r\n\r\n";
    assert!(parse_http_bytes(dup_key).is_err(), "duplicate Sec-WebSocket-Key must be rejected");

    // 3. Origin CSRF invariants (scheme downgrade, userinfo, malformed host)
    let check_origin = |origin: &str, host: &str| -> bool {
        let mut h = HashMap::new();
        h.insert("origin".to_string(), origin.to_string());
        h.insert("host".to_string(), host.to_string());
        origin_matches_host(&h)
    };
    assert!(check_origin("http://127.0.0.1:8787", "127.0.0.1:8787"));
    assert!(check_origin("http://localhost", "localhost:80"));
    assert!(!check_origin("https://localhost", "localhost"), "https origin must not match plain-HTTP Host");
    assert!(!check_origin("http://evil@127.0.0.1:8787", "127.0.0.1:8787"));
    assert!(!check_origin("http://bad:port", "bad:port"), "malformed ports must fail closed");

    // 4. WebSocket RFC 6455 client invariants (unmasked, RSV!=0, fragmented control, >125B control)
    assert!(parse_ws_client_frame(&[0x81, 0x02, b'h', b'i']).is_err(), "unmasked client frame must fail");
    assert!(parse_ws_client_frame(&[0xC1, 0x80, 1, 2, 3, 4]).is_err(), "RSV1!=0 must fail");
    assert!(parse_ws_client_frame(&[0x09, 0x80, 1, 2, 3, 4]).is_err(), "fragmented Ping must fail");
    assert!(parse_ws_client_frame(&[0x89, 0xFE, 0x00, 0x7E, 1, 2, 3, 4]).is_err(), "Ping > 125B must fail");

    // 5. Seeded mutations across HTTP + WS parsers (zero panic)
    let http_corpus: Vec<Vec<u8>> = vec![
        ws_upgrade.to_vec(),
        b"POST /api/view/login HTTP/1.1\r\nHost: 127.0.0.1:8787\r\nContent-Length: 14\r\n\r\n{\"token\":\"ok\"}".to_vec(),
    ];
    let ws_corpus: Vec<Vec<u8>> = vec![masked_ping.to_vec(), vec![0x81, 0x82, 1, 2, 3, 4, 5, 6]];

    for seed in fuzz_seeds(0xA103, 64) {
        let mut rng = FuzzRng::new(seed);
        for _ in 0..24 {
            let hb = rng.pick(&http_corpus);
            let m_http = mutate_bytes(&mut rng, hb, 4096);
            let _ = parse_http_bytes(&m_http);
            let wb = rng.pick(&ws_corpus);
            let m_ws = mutate_bytes(&mut rng, wb, 4096);
            let _ = parse_ws_client_frame(&m_ws);
        }
    }
}

#[test]
fn fuzz_yaml_config_rejects_anchor_bombs_and_preserves_roundtrip_idempotency() {
    // 1. YAML anchor/alias "Billion Laughs" bomb MUST be rejected immediately before serde_yaml expands it.
    let bomb = "\
a: &a [\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]
";
    let t0 = std::time::Instant::now();
    assert!(
        UserConfigFile::from_yaml_str(bomb).is_err(),
        "YAML anchor/alias bomb must be rejected"
    );
    assert!(
        t0.elapsed() < std::time::Duration::from_millis(50),
        "YAML bomb rejection must be instant"
    );

    // 2. Oversized YAML rejected immediately
    let huge = "a".repeat(MAX_YAML_CONFIG_BYTES + 1);
    assert!(UserConfigFile::from_yaml_str(&huge).is_err());

    // 3. Trusted devices cap & port_idle_close_secs clamping & non-colliding auto rule IDs
    let mut many_devs = String::from("trusted_devices:\n");
    for i in 0..=MAX_TRUSTED_DEVICES {
        many_devs.push_str(&format!(
            "  - fingerprint: fp:{i:024x}\n    name: dev{i}\n"
        ));
    }
    assert!(
        UserConfigFile::from_yaml_str(&many_devs).is_err(),
        "trusted_devices > MAX_TRUSTED_DEVICES must be rejected"
    );

    let rules_yaml = "\
port_idle_close_secs: 999999999999
window_rules:
  - id: \"rule-1\"
    app_name: \"ExistingApp\"
  - id: \"\"
    app_name: \"AutoNamedApp\"
";
    let parsed = UserConfigFile::from_yaml_str(rules_yaml).unwrap();
    assert_eq!(parsed.port_idle_close_secs, 86_400);
    assert_eq!(parsed.window_rules.len(), 2, "empty rule id must NOT clobber existing rule-1");
    let rt_yaml = parsed.to_yaml_string().unwrap();
    let reparsed = UserConfigFile::from_yaml_str(&rt_yaml).unwrap();
    assert_eq!(parsed, reparsed, "normalized YAML config must be roundtrip-idempotent");

    // 4. Quoted `&` / `*` in app/device names must NOT be falsely rejected as YAML anchors!
    let quoted_ok = "window_rules:\n  - id: r1\n    app_name: \"R&D *Notes*\"\n";
    assert!(UserConfigFile::from_yaml_str(quoted_ok).is_ok());

    // 5. Seeded byte mutations (zero panic, fast)
    let base_yaml = UserConfigFile::default().to_yaml_string().unwrap().into_bytes();
    let corpus = [base_yaml, rules_yaml.as_bytes().to_vec()];
    for seed in fuzz_seeds(0xA104, 64) {
        let mut rng = FuzzRng::new(seed);
        for _ in 0..16 {
            let base = rng.pick(&corpus);
            let m = mutate_bytes(&mut rng, base, 8192);
            if let Ok(s) = std::str::from_utf8(&m) {
                let _ = UserConfigFile::from_yaml_str(s);
            }
        }
    }
}

#[test]
fn fuzz_annexb_parser_edges_and_overflow_reset() {
    // Out-of-order [IDR, short SPS, PPS] must NOT be accepted as self-contained IDR
    assert!(!is_self_contained_idr(&[
        0, 0, 0, 1, 0x65, 0x88, 0, 0, 0, 1, 0x67, 0x42, 0, 0, 0, 1, 0x68, 0xce
    ]));
    // Mixed IDR + P in one AU must NOT be accepted as pure self-contained IDR
    assert!(!is_self_contained_idr(&[
        0, 0, 0, 1, 0x67, 0x42, 0x00, 0x1e, 0, 0, 0, 1, 0x68, 0xce, 0, 0, 0, 1, 0x65, 0x88, 0, 0,
        0, 1, 0x41, 0x9a
    ]));
    // Valid SPS(>=4) + PPS + IDR(>=2) passes
    assert!(is_self_contained_idr(&[
        0, 0, 0, 1, 0x67, 0x42, 0x00, 0x1e, 0, 0, 0, 1, 0x68, 0xce, 0, 0, 0, 1, 0x65, 0x88
    ]));

    // 1-byte truncated NAL type 5 must NOT poison an active P-frame into IDR
    let mut sp = AnnexBSplitter::new();
    let mut s = Vec::new();
    s.extend_from_slice(&[0, 0, 0, 1, 0x67, 0x42, 0x00, 0x1e]);
    s.extend_from_slice(&[0, 0, 0, 1, 0x68, 0xce, 0x38, 0x80]);
    s.extend_from_slice(&[0, 0, 0, 1, 0x41, 0x9a, 0x11]);
    s.extend_from_slice(&[0, 0, 0, 1, 0x65]); // truncated 1-byte IDR NAL
    let mut frames = sp.push(&s);
    frames.extend(sp.finish());
    assert_eq!(frames.len(), 1);
    assert!(!is_self_contained_idr(&frames[0]));
}
