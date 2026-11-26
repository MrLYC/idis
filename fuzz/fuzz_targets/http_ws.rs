#![no_main]

use idis::web::fuzz_hooks::{origin_matches_host, parse_http_bytes, parse_ws_client_frame};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 128 * 1024 {
        return;
    }
    if let Ok(Some((_, _, headers, _))) = parse_http_bytes(data) {
        let _ = origin_matches_host(&headers);
    }
    let _ = parse_ws_client_frame(data);
});
