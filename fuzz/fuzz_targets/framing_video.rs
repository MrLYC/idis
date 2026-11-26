#![no_main]

use idis::protocol::framing::{read_canal_block_limited, read_pt_frame_limited};
use idis::protocol::video::parse_video_header;
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let mut c1 = Cursor::new(data);
    let _ = read_canal_block_limited(&mut c1, 256 * 1024);

    let mut c2 = Cursor::new(data);
    let _ = read_pt_frame_limited(&mut c2, 256 * 1024);

    if let Some(vh) = parse_video_header(data) {
        assert!(vh.header_len >= 13);
        assert!(vh.payload_offset <= data.len());
    }
});
