#![no_main]

use idis::fmp4::Fmp4Muxer;
use idis::protocol::annexb::{is_self_contained_idr, AnnexBSplitter};
use libfuzzer_sys::fuzz_target;
use std::time::{Duration, Instant};

fuzz_target!(|data: &[u8]| {
    if data.len() > 256 * 1024 {
        return;
    }
    let mut sp_whole = AnnexBSplitter::new();
    let mut aus = sp_whole.push(data);
    aus.extend(sp_whole.finish());

    let mut mux = Fmp4Muxer::new(30);
    let mut now = Instant::now();
    for au in aus.iter().take(64) {
        let _ = is_self_contained_idr(au);
        now += Duration::from_millis(33);
        let _ = mux.mux_frame_at(1280, 720, au, now);
    }
});
