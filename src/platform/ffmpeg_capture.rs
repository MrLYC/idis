use crate::platform::{clamp_pixel_dimensions, EncodedFrame, FrameSender, IPAD_MAX_PIXEL_EDGE};
use crate::protocol::annexb::AnnexBSplitter;
use anyhow::{anyhow, Context, Result};
use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use tracing::{debug, info, warn};

/// Specification for launching an FFmpeg screen-capture + H.264 Annex-B encoding pipeline.
#[derive(Debug, Clone)]
pub struct FfmpegPipelineSpec {
    pub ffmpeg_path: String,
    pub input_args: Vec<String>,
    pub out_width: u32,
    pub out_height: u32,
    pub max_pixel_edge: u32,
    pub fps: u32,
    pub bitrate_mbps: u32,
    pub encoder: String,
    pub all_intra: bool,
}

pub struct FfmpegProcess {
    child: Child,
    stop: Arc<AtomicBool>,
    reader_thread: Option<thread::JoinHandle<()>>,
}

impl FfmpegPipelineSpec {
    /// Construct the deterministic FFmpeg CLI argument vector (pure helper for cross-platform unit tests).
    pub fn build_args(&self) -> (Vec<String>, u32, u32) {
        let mut args: Vec<String> = vec![
            "-hide_banner".to_string(),
            "-loglevel".to_string(),
            "error".to_string(),
            "-nostdin".to_string(),
        ];
        args.extend(self.input_args.iter().cloned());

        let max_edge = if self.max_pixel_edge >= 320 {
            self.max_pixel_edge
        } else {
            IPAD_MAX_PIXEL_EDGE
        };
        let (w, h) = clamp_pixel_dimensions(self.out_width, self.out_height, max_edge);
        let bitrate = format!("{}M", self.bitrate_mbps.max(2));
        let bufsize = format!("{}M", (self.bitrate_mbps.max(2) * 2));

        let vf = if self.encoder == "h264_vaapi" {
            format!("scale={w}:{h}:flags=lanczos:out_color_matrix=bt709,format=nv12,hwupload")
        } else {
            format!("scale={w}:{h}:flags=lanczos:out_color_matrix=bt709,format=yuv420p")
        };
        args.extend([
            "-vf".to_string(),
            vf,
            "-colorspace".to_string(),
            "bt709".to_string(),
            "-color_primaries".to_string(),
            "bt709".to_string(),
            "-color_trc".to_string(),
            "bt709".to_string(),
            "-c:v".to_string(),
            self.encoder.clone(),
        ]);

        let gop = if self.all_intra {
            1u32
        } else {
            self.fps.max(1).saturating_mul(2).clamp(15, 120)
        };
        let gop_str = gop.to_string();
        if self.encoder == "libx264" {
            let crf = if self.bitrate_mbps >= 30 {
                "14"
            } else if self.bitrate_mbps >= 20 {
                "17"
            } else if self.bitrate_mbps >= 12 {
                "19"
            } else {
                "23"
            };
            let x264_params = format!(
                "repeat-headers=1:annexb=1:keyint={gop}:min-keyint={gop}:scenecut=0"
            );
            args.extend([
                "-preset".to_string(),
                "superfast".to_string(),
                "-tune".to_string(),
                "zerolatency".to_string(),
                "-profile:v".to_string(),
                "main".to_string(),
                "-g".to_string(),
                gop_str.clone(),
                "-keyint_min".to_string(),
                gop_str,
                "-bf".to_string(),
                "0".to_string(),
                "-crf".to_string(),
                crf.to_string(),
                "-x264-params".to_string(),
                x264_params,
            ]);
        } else {
            args.extend([
                "-profile:v".to_string(),
                "main".to_string(),
                "-g".to_string(),
                gop_str,
                "-bf".to_string(),
                "0".to_string(),
                "-b:v".to_string(),
                bitrate.clone(),
                "-bsf:v".to_string(),
                "dump_extra".to_string(),
            ]);
        }

        args.extend([
            "-maxrate".to_string(),
            bitrate,
            "-bufsize".to_string(),
            bufsize,
            "-r".to_string(),
            self.fps.max(1).to_string(),
            "-f".to_string(),
            "h264".to_string(),
            "pipe:1".to_string(),
        ]);
        (args, w, h)
    }
}

impl FfmpegProcess {
    pub fn spawn(spec: &FfmpegPipelineSpec, tx: FrameSender) -> Result<Self> {
        let (args, w, h) = spec.build_args();
        let mut cmd = Command::new(&spec.ffmpeg_path);
        crate::proxy::strip_proxy_env_on_command(&mut cmd);
        cmd.args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        info!(
            "Spawning FFmpeg capture ({} -> {}x{} @ {}fps, encoder={})",
            spec.ffmpeg_path, w, h, spec.fps, spec.encoder
        );
        let mut child = cmd.spawn().with_context(|| {
            format!(
                "failed to launch {:?} — please install FFmpeg (Linux: `sudo apt install ffmpeg`, Windows: `winget install Gyan.FFmpeg`)",
                spec.ffmpeg_path
            )
        })?;

        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("failed to capture ffmpeg stdout"))?;
        let stderr = child.stderr.take();

        if let Some(mut err_pipe) = stderr {
            thread::spawn(move || {
                let mut msg = String::new();
                if err_pipe.read_to_string(&mut msg).is_ok() && !msg.trim().is_empty() {
                    warn!("ffmpeg stderr: {}", msg.trim());
                }
            });
        }

        let stop = Arc::new(AtomicBool::new(false));
        let stop_bg = stop.clone();
        let reader_thread = thread::spawn(move || {
            let mut splitter = AnnexBSplitter::new();
            let mut buf = [0u8; 65536];
            while !stop_bg.load(Ordering::SeqCst) {
                match stdout.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        for au in splitter.push(&buf[..n]) {
                            let is_kf = crate::protocol::annexb::is_self_contained_idr(&au);
                            if !tx.send_latest(EncodedFrame {
                                width: w,
                                height: h,
                                bytes_per_row: w * 4,
                                annex_b: au,
                                is_keyframe: is_kf,
                            }) {
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        debug!("ffmpeg stdout read ended: {e}");
                        break;
                    }
                }
            }
            // Only flush buffered tail AU on natural EOF; intentional `stop()` kills FFmpeg mid-write,
            // so flushing `splitter.finish()` would emit a truncated NAL (e.g. half an IDR slice) into `tx`.
            if !stop_bg.load(Ordering::SeqCst) {
                for au in splitter.finish() {
                    let is_kf = crate::protocol::annexb::is_self_contained_idr(&au);
                    let _ = tx.send_latest(EncodedFrame {
                        width: w,
                        height: h,
                        bytes_per_row: w * 4,
                        annex_b: au,
                        is_keyframe: is_kf,
                    });
                }
                warn!("FFmpeg capture process exited unexpectedly — closing frame stream");
                tx.close();
            }
        });

        Ok(Self {
            child,
            stop,
            reader_thread: Some(reader_thread),
        })
    }

    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(t) = self.reader_thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for FfmpegProcess {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffmpeg_args_builder_handles_all_intra_ippp_vaapi_and_nvenc() {
        let base = FfmpegPipelineSpec {
            ffmpeg_path: "ffmpeg".to_string(),
            input_args: vec!["-draw_mouse".to_string(), "0".to_string()],
            out_width: 1920,
            out_height: 1080,
            max_pixel_edge: 0,
            fps: 30,
            bitrate_mbps: 20,
            encoder: "libx264".to_string(),
            all_intra: true,
        };
        let (args_ai, w, h) = base.build_args();
        assert_eq!((w, h), (1920, 1080));
        assert!(args_ai.iter().any(|a| a.contains("keyint=1:min-keyint=1")));
        assert!(args_ai.windows(2).any(|w| w == ["-draw_mouse", "0"]));

        let mut ippp = base.clone();
        ippp.all_intra = false;
        let (args_ippp, _, _) = ippp.build_args();
        assert!(args_ippp.iter().any(|a| a.contains("keyint=60:min-keyint=60")));

        let mut vaapi = ippp.clone();
        vaapi.encoder = "h264_vaapi".to_string();
        let (args_v, _, _) = vaapi.build_args();
        assert!(args_v.iter().any(|a| a.contains("hwupload")));
        assert!(args_v.windows(2).any(|w| w == ["-bsf:v", "dump_extra"]));
    }
}
