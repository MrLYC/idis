//! Pure-Rust H.264 Annex-B -> Fragmented MP4 (ISO BMFF) muxer for browser MSE playback.
//!
//! All platforms in `idis` output intra-only H.264 Baseline Annex-B frames
//! (each containing SPS + PPS + IDR). Converting them to fMP4 (`ftyp+moov` init segment
//! followed by `moof+mdat` per frame) enables low-latency hardware-accelerated playback
//! via `<video>` + `MediaSource` / `ManagedMediaSource` over plain HTTP on LAN without
//! requiring HTTPS/WebCodecs or any external CDN.

use std::time::Instant;

/// Timescale for fMP4 media timeline (90 kHz standard for H.264).
const TIMESCALE: u32 = 90_000;

/// Stateful Fragmented MP4 muxer turning H.264 Annex-B frames into MSE-ready segments.
pub struct Fmp4Muxer {
    fps: u32,
    width: u32,
    height: u32,
    sps: Vec<u8>,
    pps: Vec<u8>,
    seq_number: u32,
    decode_time: u64,
    last_frame_at: Option<Instant>,
    codec_string: String,
    initialized: bool,
}

/// Output produced by [`Fmp4Muxer::mux_frame`].
pub struct MuxedChunk {
    /// Emitted on the first frame or whenever SPS/PPS/resolution changes.
    pub init_segment: Option<Vec<u8>>,
    /// ISO BMFF codec string for MSE (e.g. `avc1.42c01f`).
    pub codec: String,
    /// Single-frame `moof + mdat` media segment ready for `SourceBuffer.appendBuffer`.
    pub media_segment: Vec<u8>,
    /// True when this media segment is an IDR sync sample (`sample_flags = 0x02000000`).
    pub is_keyframe: bool,
}

impl Fmp4Muxer {
    pub fn new(fps: u32) -> Self {
        Self {
            fps: fps.max(1),
            width: 0,
            height: 0,
            sps: Vec::new(),
            pps: Vec::new(),
            seq_number: 1,
            decode_time: 0,
            last_frame_at: None,
            codec_string: "avc1.42c01f".to_string(),
            initialized: false,
        }
    }

    pub fn set_fps(&mut self, fps: u32) {
        self.fps = fps.max(1);
    }

    /// Convert an H.264 Annex-B frame into an optional fMP4 init segment + media segment.
    /// Returns `None` if the frame has no VCL slice NALs or SPS/PPS have not been seen yet.
    pub fn mux_frame(&mut self, width: u32, height: u32, annex_b: &[u8]) -> Option<MuxedChunk> {
        let nals = split_annexb_nals(annex_b);
        if nals.is_empty() {
            return None;
        }

        let mut new_sps: Option<&[u8]> = None;
        let mut new_pps: Option<&[u8]> = None;
        let mut vcl_nals: Vec<&[u8]> = Vec::new();
        let mut is_idr = false;

        for nal in nals {
            if nal.is_empty() {
                continue;
            }
            match nal[0] & 0x1F {
                7 => new_sps = Some(nal),
                8 => new_pps = Some(nal),
                9 => {} // AUD: skip in AVCC mdat
                5 => {
                    is_idr = true;
                    vcl_nals.push(nal);
                }
                1 => {
                    // Non-IDR P-frame slice (IPPP temporal compression).
                    vcl_nals.push(nal);
                }
                _ => {}
            }
        }

        if vcl_nals.is_empty() {
            return None;
        }
        // Require the very first emitted frame of a stream/timeline to be an IDR with valid SPS/PPS.
        if !self.initialized && !is_idr {
            return None;
        }

        let cand_sps = new_sps.unwrap_or(self.sps.as_slice());
        let cand_pps = new_pps.unwrap_or(self.pps.as_slice());
        if cand_sps.len() < 4 || cand_pps.is_empty() || width == 0 || height == 0 {
            return None;
        }
        let config_changed = cand_sps != self.sps.as_slice()
            || cand_pps != self.pps.as_slice()
            || width != self.width
            || height != self.height;
        // Invariant VID-1: never emit a new init segment / stream re-config paired with a non-IDR P-frame.
        if config_changed && !is_idr {
            return None;
        }
        if config_changed {
            self.sps = cand_sps.to_vec();
            self.pps = cand_pps.to_vec();
            self.width = width;
            self.height = height;
        }

        let init_segment = if !self.initialized || config_changed {
            self.codec_string = format!(
                "avc1.{:02x}{:02x}{:02x}",
                self.sps[1], self.sps[2], self.sps[3]
            );
            self.initialized = true;
            Some(build_init_segment(
                self.width,
                self.height,
                &self.sps,
                &self.pps,
            ))
        } else {
            None
        };

        let default_duration = (TIMESCALE / self.fps.max(1)).max(1);
        let now = Instant::now();
        // Bound duration tightly around the nominal frame interval (max ~2x nominal, <= 100ms)
        // and clamp as u64 before casting to u32 so static->motion idle pauses never bloat Frame N's
        // future duration (preventing 300ms latency locks or unnecessary MSE seeks).
        let min_ticks = (default_duration / 2).max(1) as u64;
        let max_ticks = (default_duration.saturating_mul(2)).min(TIMESCALE / 10).max(default_duration) as u64;
        let frame_duration = match self.last_frame_at {
            Some(prev) => {
                let delta_ticks = ((now.saturating_duration_since(prev).as_micros() as u64)
                    .saturating_mul(TIMESCALE as u64))
                    / 1_000_000;
                delta_ticks.clamp(min_ticks, max_ticks) as u32
            }
            None => default_duration,
        };
        self.last_frame_at = Some(now);
        let media_segment = build_media_segment_from_nals(
            self.seq_number,
            self.decode_time,
            frame_duration,
            is_idr,
            &vcl_nals,
        );
        self.seq_number = self.seq_number.wrapping_add(1).max(1);
        self.decode_time = self.decode_time.saturating_add(frame_duration as u64);

        Some(MuxedChunk {
            init_segment,
            codec: self.codec_string.clone(),
            media_segment,
            is_keyframe: is_idr,
        })
    }
}

/// Split an Annex-B byte stream into individual NAL units (without start codes).
pub fn split_annexb_nals(data: &[u8]) -> Vec<&[u8]> {
    let mut starts: Vec<(usize, usize)> = Vec::new();
    let mut i = 0;
    while i + 3 <= data.len() {
        if data[i] == 0 && data[i + 1] == 0 {
            if i + 4 <= data.len() && data[i + 2] == 0 && data[i + 3] == 1 {
                starts.push((i, i + 4));
                i += 4;
                continue;
            } else if data[i + 2] == 1 {
                starts.push((i, i + 3));
                i += 3;
                continue;
            }
        }
        i += 1;
    }

    let mut out = Vec::with_capacity(starts.len());
    for idx in 0..starts.len() {
        let payload_start = starts[idx].1;
        let payload_end = if idx + 1 < starts.len() {
            starts[idx + 1].0
        } else {
            data.len()
        };
        if payload_end > payload_start {
            out.push(&data[payload_start..payload_end]);
        }
    }
    out
}

fn mp4_box(fourcc: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let size = (8 + body.len()) as u32;
    let mut buf = Vec::with_capacity(size as usize);
    buf.extend_from_slice(&size.to_be_bytes());
    buf.extend_from_slice(fourcc);
    buf.extend_from_slice(body);
    buf
}

fn mp4_full_box(fourcc: &[u8; 4], version: u8, flags: u32, body: &[u8]) -> Vec<u8> {
    let mut full = Vec::with_capacity(4 + body.len());
    full.push(version);
    full.push(((flags >> 16) & 0xFF) as u8);
    full.push(((flags >> 8) & 0xFF) as u8);
    full.push((flags & 0xFF) as u8);
    full.extend_from_slice(body);
    mp4_box(fourcc, &full)
}

fn build_init_segment(width: u32, height: u32, sps: &[u8], pps: &[u8]) -> Vec<u8> {
    // ftyp
    let mut ftyp_body = Vec::new();
    ftyp_body.extend_from_slice(b"isom");
    ftyp_body.extend_from_slice(&0x0000_0200u32.to_be_bytes());
    ftyp_body.extend_from_slice(b"isom");
    ftyp_body.extend_from_slice(b"iso5");
    ftyp_body.extend_from_slice(b"avc1");
    let ftyp = mp4_box(b"ftyp", &ftyp_body);

    // mvhd (version 0)
    let mut mvhd_body = Vec::new();
    mvhd_body.extend_from_slice(&0u32.to_be_bytes()); // creation_time
    mvhd_body.extend_from_slice(&0u32.to_be_bytes()); // modification_time
    mvhd_body.extend_from_slice(&TIMESCALE.to_be_bytes()); // timescale
    mvhd_body.extend_from_slice(&0u32.to_be_bytes()); // duration (fragmented)
    mvhd_body.extend_from_slice(&0x0001_0000u32.to_be_bytes()); // rate 1.0
    mvhd_body.extend_from_slice(&0x0100u16.to_be_bytes()); // volume 1.0
    mvhd_body.extend_from_slice(&[0u8; 10]); // reserved
    // Identity matrix (9 x u32)
    let matrix: [u32; 9] = [0x0001_0000, 0, 0, 0, 0x0001_0000, 0, 0, 0, 0x4000_0000];
    for m in matrix {
        mvhd_body.extend_from_slice(&m.to_be_bytes());
    }
    mvhd_body.extend_from_slice(&[0u8; 24]); // pre_defined
    mvhd_body.extend_from_slice(&2u32.to_be_bytes()); // next_track_ID
    let mvhd = mp4_full_box(b"mvhd", 0, 0, &mvhd_body);

    // tkhd (version 0, flags = 3: track enabled & in movie)
    let mut tkhd_body = Vec::new();
    tkhd_body.extend_from_slice(&0u32.to_be_bytes()); // creation_time
    tkhd_body.extend_from_slice(&0u32.to_be_bytes()); // modification_time
    tkhd_body.extend_from_slice(&1u32.to_be_bytes()); // track_ID = 1
    tkhd_body.extend_from_slice(&0u32.to_be_bytes()); // reserved
    tkhd_body.extend_from_slice(&0u32.to_be_bytes()); // duration
    tkhd_body.extend_from_slice(&[0u8; 8]); // reserved
    tkhd_body.extend_from_slice(&0u16.to_be_bytes()); // layer
    tkhd_body.extend_from_slice(&0u16.to_be_bytes()); // alternate_group
    tkhd_body.extend_from_slice(&0u16.to_be_bytes()); // volume (video = 0)
    tkhd_body.extend_from_slice(&0u16.to_be_bytes()); // reserved
    for m in matrix {
        tkhd_body.extend_from_slice(&m.to_be_bytes());
    }
    tkhd_body.extend_from_slice(&(width << 16).to_be_bytes()); // fixed-point 16.16 width
    tkhd_body.extend_from_slice(&(height << 16).to_be_bytes()); // fixed-point 16.16 height
    let tkhd = mp4_full_box(b"tkhd", 0, 3, &tkhd_body);

    // mdhd (version 0)
    let mut mdhd_body = Vec::new();
    mdhd_body.extend_from_slice(&0u32.to_be_bytes()); // creation_time
    mdhd_body.extend_from_slice(&0u32.to_be_bytes()); // modification_time
    mdhd_body.extend_from_slice(&TIMESCALE.to_be_bytes());
    mdhd_body.extend_from_slice(&0u32.to_be_bytes()); // duration
    mdhd_body.extend_from_slice(&0x55C4u16.to_be_bytes()); // language = 'und'
    mdhd_body.extend_from_slice(&0u16.to_be_bytes());
    let mdhd = mp4_full_box(b"mdhd", 0, 0, &mdhd_body);

    // hdlr
    let mut hdlr_body = Vec::new();
    hdlr_body.extend_from_slice(&0u32.to_be_bytes()); // pre_defined
    hdlr_body.extend_from_slice(b"vide");
    hdlr_body.extend_from_slice(&[0u8; 12]); // reserved
    hdlr_body.extend_from_slice(b"VideoHandler\0");
    let hdlr = mp4_full_box(b"hdlr", 0, 0, &hdlr_body);

    // vmhd
    let vmhd = mp4_full_box(b"vmhd", 0, 1, &[0u8; 8]);

    // dinf -> dref -> url
    let url = mp4_full_box(b"url ", 0, 1, &[]);
    let mut dref_body = Vec::new();
    dref_body.extend_from_slice(&1u32.to_be_bytes());
    dref_body.extend_from_slice(&url);
    let dref = mp4_full_box(b"dref", 0, 0, &dref_body);
    let dinf = mp4_box(b"dinf", &dref);

    // avcC (ISO/IEC 14496-15 AVCDecoderConfigurationRecord)
    let mut avcc_body = vec![
        1,      // configurationVersion
        sps[1], // AVCProfileIndication
        sps[2], // profile_compatibility
        sps[3], // AVCLevelIndication
        0xFF,   // 6 bits reserved (111111) + 2 bits lengthSizeMinusOne (3 => 4 bytes)
        0xE1,   // 3 bits reserved (111) + 5 bits numOfSequenceParameterSets (1)
    ];
    avcc_body.extend_from_slice(&(sps.len() as u16).to_be_bytes());
    avcc_body.extend_from_slice(sps);
    avcc_body.push(1); // numOfPictureParameterSets
    avcc_body.extend_from_slice(&(pps.len() as u16).to_be_bytes());
    avcc_body.extend_from_slice(pps);
    // ISO/IEC 14496-15 Section 5.3.3.1.2: High/extended profiles require 4 trailing chroma/bit-depth bytes.
    if matches!(
        sps[1],
        100 | 110 | 122 | 244 | 44 | 83 | 86 | 118 | 128 | 138 | 139 | 134
    ) {
        avcc_body.push(0xFC | 0x01); // reserved(6) + chroma_format_idc = 1 (4:2:0)
        avcc_body.push(0xF8);        // reserved(5) + bit_depth_luma_minus8 = 0 (8-bit)
        avcc_body.push(0xF8);        // reserved(5) + bit_depth_chroma_minus8 = 0 (8-bit)
        avcc_body.push(0x00);        // numOfSequenceParameterSetExt = 0
    }
    let avcc = mp4_box(b"avcC", &avcc_body);

    // avc1 sample entry
    let mut avc1_body = Vec::new();
    avc1_body.extend_from_slice(&[0u8; 6]); // reserved
    avc1_body.extend_from_slice(&1u16.to_be_bytes()); // data_reference_index
    avc1_body.extend_from_slice(&[0u8; 16]); // pre_defined + reserved
    avc1_body.extend_from_slice(&(width as u16).to_be_bytes());
    avc1_body.extend_from_slice(&(height as u16).to_be_bytes());
    avc1_body.extend_from_slice(&0x0048_0000u32.to_be_bytes()); // horizresolution 72 dpi
    avc1_body.extend_from_slice(&0x0048_0000u32.to_be_bytes()); // vertresolution 72 dpi
    avc1_body.extend_from_slice(&0u32.to_be_bytes()); // reserved
    avc1_body.extend_from_slice(&1u16.to_be_bytes()); // frame_count
    avc1_body.extend_from_slice(&[0u8; 32]); // compressorname
    avc1_body.extend_from_slice(&0x0018u16.to_be_bytes()); // depth 24
    avc1_body.extend_from_slice(&(-1i16).to_be_bytes()); // pre_defined = -1
    avc1_body.extend_from_slice(&avcc);
    let avc1 = mp4_box(b"avc1", &avc1_body);

    // stsd
    let mut stsd_body = Vec::new();
    stsd_body.extend_from_slice(&1u32.to_be_bytes());
    stsd_body.extend_from_slice(&avc1);
    let stsd = mp4_full_box(b"stsd", 0, 0, &stsd_body);

    // Empty required sample table boxes for fragmented MP4
    let stts = mp4_full_box(b"stts", 0, 0, &0u32.to_be_bytes());
    let stsc = mp4_full_box(b"stsc", 0, 0, &0u32.to_be_bytes());
    let stsz = mp4_full_box(b"stsz", 0, 0, &[0u8; 8]);
    let stco = mp4_full_box(b"stco", 0, 0, &0u32.to_be_bytes());

    let mut stbl_body = Vec::new();
    stbl_body.extend_from_slice(&stsd);
    stbl_body.extend_from_slice(&stts);
    stbl_body.extend_from_slice(&stsc);
    stbl_body.extend_from_slice(&stsz);
    stbl_body.extend_from_slice(&stco);
    let stbl = mp4_box(b"stbl", &stbl_body);

    let mut minf_body = Vec::new();
    minf_body.extend_from_slice(&vmhd);
    minf_body.extend_from_slice(&dinf);
    minf_body.extend_from_slice(&stbl);
    let minf = mp4_box(b"minf", &minf_body);

    let mut mdia_body = Vec::new();
    mdia_body.extend_from_slice(&mdhd);
    mdia_body.extend_from_slice(&hdlr);
    mdia_body.extend_from_slice(&minf);
    let mdia = mp4_box(b"mdia", &mdia_body);

    let mut trak_body = Vec::new();
    trak_body.extend_from_slice(&tkhd);
    trak_body.extend_from_slice(&mdia);
    let trak = mp4_box(b"trak", &trak_body);

    // mvex -> trex
    let mut trex_body = Vec::new();
    trex_body.extend_from_slice(&1u32.to_be_bytes()); // track_ID = 1
    trex_body.extend_from_slice(&1u32.to_be_bytes()); // default_sample_description_index
    trex_body.extend_from_slice(&0u32.to_be_bytes()); // default_sample_duration
    trex_body.extend_from_slice(&0u32.to_be_bytes()); // default_sample_size
    trex_body.extend_from_slice(&0u32.to_be_bytes()); // default_sample_flags
    let trex = mp4_full_box(b"trex", 0, 0, &trex_body);
    let mvex = mp4_box(b"mvex", &trex);

    let mut moov_body = Vec::new();
    moov_body.extend_from_slice(&mvhd);
    moov_body.extend_from_slice(&trak);
    moov_body.extend_from_slice(&mvex);
    let moov = mp4_box(b"moov", &moov_body);

    let mut out = Vec::with_capacity(ftyp.len() + moov.len());
    out.extend_from_slice(&ftyp);
    out.extend_from_slice(&moov);
    out
}

fn build_media_segment_from_nals(
    seq_number: u32,
    decode_time: u64,
    duration: u32,
    is_sync: bool,
    vcl_nals: &[&[u8]],
) -> Vec<u8> {
    let sample_len: usize = vcl_nals.iter().map(|n| 4 + n.len()).sum();
    let mfhd = mp4_full_box(b"mfhd", 0, 0, &seq_number.to_be_bytes());
    let tfhd = mp4_full_box(b"tfhd", 0, 0x02_0000, &1u32.to_be_bytes());
    let tfdt = mp4_full_box(b"tfdt", 1, 0, &decode_time.to_be_bytes());

    let sample_flags: u32 = if is_sync { 0x0200_0000 } else { 0x0101_0000 };
    let trun_box_len = 8 + 4 + 20;
    let traf_box_len = 8 + tfhd.len() + tfdt.len() + trun_box_len;
    let moof_box_len = 8 + mfhd.len() + traf_box_len;
    let data_offset = (moof_box_len + 8) as i32;

    let mut trun_body = Vec::with_capacity(20);
    trun_body.extend_from_slice(&1u32.to_be_bytes());
    trun_body.extend_from_slice(&data_offset.to_be_bytes());
    trun_body.extend_from_slice(&duration.to_be_bytes());
    trun_body.extend_from_slice(&(sample_len as u32).to_be_bytes());
    trun_body.extend_from_slice(&sample_flags.to_be_bytes());
    let trun = mp4_full_box(b"trun", 0, 0x00_0701, &trun_body);

    let mut traf_body = Vec::with_capacity(tfhd.len() + tfdt.len() + trun.len());
    traf_body.extend_from_slice(&tfhd);
    traf_body.extend_from_slice(&tfdt);
    traf_body.extend_from_slice(&trun);
    let traf = mp4_box(b"traf", &traf_body);

    let mut moof_body = Vec::with_capacity(mfhd.len() + traf.len());
    moof_body.extend_from_slice(&mfhd);
    moof_body.extend_from_slice(&traf);
    let moof = mp4_box(b"moof", &moof_body);

    // Single allocation for `moof + mdat header + AVCC NALs` (eliminates 2 full-frame copies).
    let mdat_len = (8 + sample_len) as u32;
    let mut out = Vec::with_capacity(moof.len() + 8 + sample_len);
    out.extend_from_slice(&moof);
    out.extend_from_slice(&mdat_len.to_be_bytes());
    out.extend_from_slice(b"mdat");
    for nal in vcl_nals {
        out.extend_from_slice(&(nal.len() as u32).to_be_bytes());
        out.extend_from_slice(nal);
    }
    out
}

#[allow(dead_code)]
fn build_media_segment(
    seq_number: u32,
    decode_time: u64,
    duration: u32,
    is_sync: bool,
    sample_data: &[u8],
) -> Vec<u8> {
    let mfhd = mp4_full_box(b"mfhd", 0, 0, &seq_number.to_be_bytes());

    // tfhd: flags = 0x020000 (default-base-is-moof)
    let tfhd = mp4_full_box(b"tfhd", 0, 0x02_0000, &1u32.to_be_bytes());

    // tfdt: version 1 (64-bit baseMediaDecodeTime)
    let tfdt = mp4_full_box(b"tfdt", 1, 0, &decode_time.to_be_bytes());

    // trun: flags = 0x000701 (data-offset-present | sample-duration | sample-size | sample-flags)
    // Sample flags: sync sample (IDR) = 0x02000000, non-sync = 0x01010000
    let sample_flags: u32 = if is_sync { 0x0200_0000 } else { 0x0101_0000 };
    // Compute moof size ahead of time to set exact data_offset = moof_size + 8 (mdat header).
    // trun body = 4 (count) + 4 (data_offset) + 4 (duration) + 4 (size) + 4 (flags) = 20 bytes -> trun box = 32 bytes
    let trun_box_len = 8 + 4 + 20;
    let traf_box_len = 8 + tfhd.len() + tfdt.len() + trun_box_len;
    let moof_box_len = 8 + mfhd.len() + traf_box_len;
    let data_offset = (moof_box_len + 8) as i32;

    let mut trun_body = Vec::with_capacity(20);
    trun_body.extend_from_slice(&1u32.to_be_bytes()); // sample_count = 1
    trun_body.extend_from_slice(&data_offset.to_be_bytes());
    trun_body.extend_from_slice(&duration.to_be_bytes());
    trun_body.extend_from_slice(&(sample_data.len() as u32).to_be_bytes());
    trun_body.extend_from_slice(&sample_flags.to_be_bytes());
    let trun = mp4_full_box(b"trun", 0, 0x00_0701, &trun_body);

    let mut traf_body = Vec::with_capacity(tfhd.len() + tfdt.len() + trun.len());
    traf_body.extend_from_slice(&tfhd);
    traf_body.extend_from_slice(&tfdt);
    traf_body.extend_from_slice(&trun);
    let traf = mp4_box(b"traf", &traf_body);

    let mut moof_body = Vec::with_capacity(mfhd.len() + traf.len());
    moof_body.extend_from_slice(&mfhd);
    moof_body.extend_from_slice(&traf);
    let moof = mp4_box(b"moof", &moof_body);
    debug_assert_eq!(moof.len(), moof_box_len);

    let mdat = mp4_box(b"mdat", sample_data);

    let mut out = Vec::with_capacity(moof.len() + mdat.len());
    out.extend_from_slice(&moof);
    out.extend_from_slice(&mdat);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::mock::SYNTHETIC_H264_ANNEX_B;

    #[test]
    fn muxes_synthetic_annexb_into_valid_fmp4_boxes() {
        let mut muxer = Fmp4Muxer::new(30);
        // Non-IDR P-frame BEFORE any init IDR must be skipped cleanly
        let p_frame = [0, 0, 0, 1, 0x41, 0x9a, 0x01, 0x02];
        assert!(muxer.mux_frame(1024, 768, &p_frame).is_none());

        let c1 = muxer
            .mux_frame(1024, 768, SYNTHETIC_H264_ANNEX_B)
            .expect("first frame should produce init + media segments");
        assert!(c1.is_keyframe);
        let init = c1.init_segment.expect("first frame must emit init segment");
        assert_eq!(&init[4..8], b"ftyp");
        assert!(init.windows(4).any(|w| w == b"moov"));
        assert!(init.windows(4).any(|w| w == b"avcC"));
        assert!(c1.codec.starts_with("avc1."));

        assert_eq!(&c1.media_segment[4..8], b"moof");
        assert!(c1.media_segment.windows(4).any(|w| w == b"mdat"));

        // Second identical-config frame should not re-emit init segment
        let c2 = muxer
            .mux_frame(1024, 768, SYNTHETIC_H264_ANNEX_B)
            .expect("second frame should produce media segment");
        assert!(c2.init_segment.is_none());
        assert!(c2.is_keyframe);

        // Resolution change must re-emit init segment
        let c3 = muxer
            .mux_frame(1280, 720, SYNTHETIC_H264_ANNEX_B)
            .expect("resolution change should re-emit init segment");
        assert!(c3.init_segment.is_some());
        assert!(c3.is_keyframe);

        // Non-IDR P-frame AFTER init IDR must mux cleanly as a non-keyframe media segment (IPPP)
        let c_p = muxer
            .mux_frame(1280, 720, &p_frame)
            .expect("P-frame after init IDR should mux in IPPP mode");
        assert!(c_p.init_segment.is_none());
        assert!(!c_p.is_keyframe);
        assert_eq!(&c_p.media_segment[4..8], b"moof");

        // High-profile (0x64 = 100) SPS must include ISO 14496-15 4-byte chroma/bit-depth extension
        let high_frame = [
            0, 0, 0, 1, 0x67, 0x64, 0x00, 0x28, 0xAC, 0xD9,
            0, 0, 0, 1, 0x68, 0xEE, 0x3C, 0x80,
            0, 0, 0, 1, 0x65, 0x88, 0x84, 0x00,
        ];
        let c_hi = muxer
            .mux_frame(1920, 1080, &high_frame)
            .expect("High-profile IDR must mux cleanly");
        assert_eq!(c_hi.codec, "avc1.640028");
        let hi_init = c_hi.init_segment.unwrap();
        assert!(hi_init.windows(4).any(|w| w == [0xFD, 0xF8, 0xF8, 0x00]));

        // BUG-B2 regression: non-IDR P-frame with changed dimensions or SPS must NEVER emit
        // a new init_segment or corrupt muxer state; subsequent same-config P-frame still works.
        assert!(
            muxer.mux_frame(640, 480, &p_frame).is_none(),
            "P-frame with changed dimensions must be rejected"
        );
        let p_with_new_sps = [
            0, 0, 0, 1, 0x67, 0x42, 0xC0, 0x1E, 0xD9, 0x00, 0xA0, 0x47,
            0, 0, 0, 1, 0x41, 0x9A, 0x22, 0x11,
        ];
        assert!(
            muxer.mux_frame(1920, 1080, &p_with_new_sps).is_none(),
            "P-frame carrying a changed SPS must be rejected without mutating muxer SPS"
        );
        let c_p_after = muxer
            .mux_frame(1920, 1080, &p_frame)
            .expect("muxer state must remain uncorrupted after rejected P-frame");
        assert!(c_p_after.init_segment.is_none());
        assert!(!c_p_after.is_keyframe);

        // Multi-NAL AUD + SEI + 3-byte/4-byte start codes + multi-slice IDR
        let complex_idr = [
            0, 0, 1, 0x09, 0x10, // AUD (3-byte start code)
            0, 0, 0, 1, 0x06, 0x05, 0x01, 0xAA, // SEI
            0, 0, 1, 0x67, 0x42, 0xC0, 0x1E, 0xD9, 0x00, 0xA0, 0x47, 0xFE, 0xC8, // SPS
            0, 0, 1, 0x68, 0xCE, 0x38, 0x80, // PPS
            0, 0, 0, 1, 0x65, 0x88, 0x84, 0x00, // IDR slice 1
            0, 0, 1, 0x65, 0x44, 0x22, 0x11, // IDR slice 2
        ];
        let c_complex = muxer
            .mux_frame(1280, 720, &complex_idr)
            .expect("AUD+SEI+multi-slice IDR with mixed 3B/4B start codes must mux cleanly");
        assert!(c_complex.init_segment.is_some());
        assert!(c_complex.is_keyframe);
    }
}
