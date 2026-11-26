#![no_main]

use idis::protocol::keyed_archive::unarchive;
use idis::protocol::messages::{decode_input_event, MessagePacket};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 256 * 1024 {
        return;
    }
    let _ = unarchive(data);
    let _ = MessagePacket::decode(data);
    let _ = decode_input_event(data);
});
