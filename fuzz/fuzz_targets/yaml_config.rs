#![no_main]

use idis::user_config::UserConfigFile;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 256 * 1024 {
        return;
    }
    if let Ok(raw) = std::str::from_utf8(data) {
        if let Ok(cfg) = UserConfigFile::from_yaml_str(raw) {
            if let Ok(serialized) = cfg.to_yaml_string() {
                let reparsed = UserConfigFile::from_yaml_str(&serialized)
                    .expect("valid normalized config must always re-parse cleanly");
                assert_eq!(cfg, reparsed);
            }
        }
    }
});
