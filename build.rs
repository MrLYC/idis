fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os == "macos" {
        #[cfg(target_os = "macos")]
        {
            println!("cargo:rerun-if-changed=macos/bridge.m");
            cc::Build::new()
                .file("macos/bridge.m")
                .flag("-fobjc-arc")
                .flag("-fmodules")
                .flag("-Wno-deprecated-declarations")
                .compile("idis_macos_bridge");

            for fw in [
                "Foundation",
                "AppKit",
                "CoreGraphics",
                "CoreMedia",
                "CoreVideo",
                "VideoToolbox",
                "ScreenCaptureKit",
                "IOSurface",
                "IOKit",
                "ApplicationServices",
            ] {
                println!("cargo:rustc-link-lib=framework={fw}");
            }
        }
    }
}
