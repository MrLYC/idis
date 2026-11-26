/// Streaming H.264 Annex-B Access Unit splitter.
///
/// Splits a continuous raw H.264 Annex-B byte stream (e.g., from `ffmpeg -f h264 pipe:1`)
/// into complete per-frame Access Units with cached SPS + PPS prepended before every IDR frame
/// for streaming H.264 consumers.
pub struct AnnexBSplitter {
    buf: Vec<u8>,
    last_sps: Option<Vec<u8>>,
    last_pps: Option<Vec<u8>>,
    current_au: Vec<u8>,
    has_vcl: bool,
    au_is_idr: bool,
}

impl AnnexBSplitter {
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(256 * 1024),
            last_sps: None,
            last_pps: None,
            current_au: Vec::with_capacity(128 * 1024),
            has_vcl: false,
            au_is_idr: false,
        }
    }

    /// Push newly read bytes and return any completed Access Units (frames).
    pub fn push(&mut self, data: &[u8]) -> Vec<Vec<u8>> {
        self.buf.extend_from_slice(data);
        let mut frames = Vec::new();
        let mut search_from = 0;

        while let Some((sc_pos, sc_len)) = find_start_code(&self.buf, search_from) {
            let nal_start = sc_pos + sc_len;
            let Some((next_sc_pos, _)) = find_start_code(&self.buf, nal_start) else {
                // Keep from `sc_pos` onward for the next read, enforcing the 8 MiB safety cap even
                // after an initial start code (prevents unbounded OOM/O(N^2) growth on wedged streams).
                if sc_pos > 0 {
                    self.buf.drain(0..sc_pos);
                }
                if self.buf.len() > 8 * 1024 * 1024 {
                    self.buf.clear();
                }
                return frames;
            };

            let nal = self.buf[nal_start..next_sc_pos].to_vec();
            if let Some(frame) = self.ingest_nal(&nal) {
                frames.push(frame);
            }
            search_from = next_sc_pos;
        }

        if search_from > 0 {
            self.buf.drain(0..search_from);
        } else if self.buf.len() > 8 * 1024 * 1024 {
            // Prevent unbounded growth if garbage arrives without start codes
            self.buf.clear();
        }
        frames
    }

    /// Flush any remaining buffered NAL at EOF.
    pub fn finish(&mut self) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        if let Some((sc_pos, sc_len)) = find_start_code(&self.buf, 0) {
            let nal = self.buf[sc_pos + sc_len..].to_vec();
            if let Some(frame) = self.ingest_nal(&nal) {
                frames.push(frame);
            }
        }
        self.buf.clear();
        if self.has_vcl {
            frames.push(self.take_au());
        }
        frames
    }

    fn ingest_nal(&mut self, nal: &[u8]) -> Option<Vec<u8>> {
        if nal.is_empty() {
            return None;
        }
        let nal_type = nal[0] & 0x1F;
        let mut completed = None;

        match nal_type {
            7 => {
                // SPS: starts a new Access Unit if we already accumulated a VCL slice
                if self.has_vcl {
                    completed = Some(self.take_au());
                }
                self.last_sps = Some(nal.to_vec());
            }
            8 => {
                if self.has_vcl {
                    completed = Some(self.take_au());
                }
                self.last_pps = Some(nal.to_vec());
            }
            9 => {
                // Access Unit Delimiter
                if self.has_vcl {
                    completed = Some(self.take_au());
                }
            }
            5 => {
                // IDR slice: only start a new Access Unit when `first_mb_in_slice == 0`
                // (Exp-Golomb 0 -> MSB of nal[1] is 1). Multi-slice IDR frames stay merged!
                let starts_new_picture = nal.len() >= 2 && (nal[1] & 0x80) != 0;
                if self.has_vcl && starts_new_picture {
                    completed = Some(self.take_au());
                }
                self.current_au.extend_from_slice(&[0, 0, 0, 1]);
                self.current_au.extend_from_slice(nal);
                self.has_vcl = true;
                self.au_is_idr = true;
            }
            1 => {
                // Non-IDR VCL slice: merge continuation slices into the same Access Unit.
                let starts_new_picture = nal.len() >= 2 && (nal[1] & 0x80) != 0;
                if self.has_vcl && starts_new_picture {
                    completed = Some(self.take_au());
                }
                self.current_au.extend_from_slice(&[0, 0, 0, 1]);
                self.current_au.extend_from_slice(nal);
                self.has_vcl = true;
            }
            _ => {
                // SEI or other supplemental NALs can be ignored or attached; skip for minimal size
            }
        }
        completed
    }

    fn take_au(&mut self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.current_au.len() + 64);
        if self.au_is_idr {
            if let Some(ref sps) = self.last_sps {
                out.extend_from_slice(&[0, 0, 0, 1]);
                out.extend_from_slice(sps);
            }
            if let Some(ref pps) = self.last_pps {
                out.extend_from_slice(&[0, 0, 0, 1]);
                out.extend_from_slice(pps);
            }
        }
        out.extend_from_slice(&self.current_au);
        self.current_au.clear();
        self.has_vcl = false;
        self.au_is_idr = false;
        out
    }
}

impl Default for AnnexBSplitter {
    fn default() -> Self {
        Self::new()
    }
}

/// Check that an Annex-B Access Unit contains SPS (7), PPS (8), and at least one IDR slice (5).
/// Because intermediate frames may be dropped under backpressure, only self-contained IDR frames
/// should be transmitted to legacy iDisplay / browser MSE decoders.
pub fn is_self_contained_idr(annex_b: &[u8]) -> bool {
    let mut has_sps = false;
    let mut has_pps = false;
    let mut has_idr = false;
    let mut pos = 0;
    while let Some((sc_pos, sc_len)) = find_start_code(annex_b, pos) {
        let nal_start = sc_pos + sc_len;
        if nal_start < annex_b.len() {
            match annex_b[nal_start] & 0x1F {
                7 => has_sps = true,
                8 => has_pps = true,
                5 => has_idr = true,
                _ => {}
            }
            if has_sps && has_pps && has_idr {
                return true;
            }
        }
        pos = nal_start;
    }
    false
}

fn find_start_code(data: &[u8], from: usize) -> Option<(usize, usize)> {
    let mut i = from;
    while i + 3 <= data.len() {
        if data[i] == 0 && data[i + 1] == 0 {
            if data[i + 2] == 1 {
                return Some((i, 3));
            }
            if i + 4 <= data.len() && data[i + 2] == 0 && data[i + 3] == 1 {
                return Some((i, 4));
            }
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_intra_only_annexb_frames_with_sps_pps() {
        let mut stream = Vec::new();
        // Frame 1: SPS + PPS + IDR
        stream.extend_from_slice(&[0, 0, 0, 1, 0x67, 0x42, 0x00, 0x1e]);
        stream.extend_from_slice(&[0, 0, 0, 1, 0x68, 0xce, 0x38, 0x80]);
        stream.extend_from_slice(&[0, 0, 0, 1, 0x65, 0x88, 0x84, 0x01]);
        // Frame 2: IDR without repeating SPS/PPS -> splitter must auto-prepend cached SPS+PPS!
        stream.extend_from_slice(&[0, 0, 0, 1, 0x65, 0x88, 0x84, 0x02]);

        let mut sp = AnnexBSplitter::new();
        let mut frames = Vec::new();
        // Feed in tiny 5-byte chunks to verify streaming boundary handling
        for chunk in stream.chunks(5) {
            frames.extend(sp.push(chunk));
        }
        frames.extend(sp.finish());

        assert_eq!(frames.len(), 2);
        assert!(frames[0].starts_with(&[0, 0, 0, 1, 0x67]));
        assert!(frames[1].starts_with(&[0, 0, 0, 1, 0x67]));
        assert!(frames[1].ends_with(&[0x65, 0x88, 0x84, 0x02]));
    }

    #[test]
    fn keeps_multi_slice_idr_in_single_access_unit() {
        let mut stream = Vec::new();
        stream.extend_from_slice(&[0, 0, 0, 1, 0x67, 0x42, 0x00, 0x1e]);
        stream.extend_from_slice(&[0, 0, 0, 1, 0x68, 0xce, 0x38, 0x80]);
        // Slice 0 of frame 1: first_mb_in_slice = 0 (MSB of 0x88 is 1)
        stream.extend_from_slice(&[0, 0, 0, 1, 0x65, 0x88, 0x01]);
        // Slice 1 of frame 1: first_mb_in_slice > 0 (MSB of 0x05 is 0) -> MUST stay in frame 1!
        stream.extend_from_slice(&[0, 0, 0, 1, 0x65, 0x05, 0x02]);
        // Slice 0 of frame 2: first_mb_in_slice = 0 (MSB of 0x88 is 1) -> starts frame 2!
        stream.extend_from_slice(&[0, 0, 0, 1, 0x65, 0x88, 0x03]);

        let mut sp = AnnexBSplitter::new();
        let mut frames = sp.push(&stream);
        frames.extend(sp.finish());

        assert_eq!(frames.len(), 2);
        assert!(frames[0].ends_with(&[0, 0, 0, 1, 0x65, 0x05, 0x02]));
        assert!(frames[1].ends_with(&[0, 0, 0, 1, 0x65, 0x88, 0x03]));
    }

    #[test]
    fn ippp_splitter_handles_3byte_start_codes_aud_sei_multislice_p_and_garbage_cap() {
        let mut stream = Vec::new();
        // AU0: AUD + SPS + PPS + IDR (mixed 3B/4B start codes)
        stream.extend_from_slice(&[0, 0, 1, 0x09, 0x10]);
        stream.extend_from_slice(&[0, 0, 1, 0x67, 0x42, 0x00, 0x1e]);
        stream.extend_from_slice(&[0, 0, 0, 1, 0x68, 0xce, 0x38, 0x80]);
        stream.extend_from_slice(&[0, 0, 1, 0x65, 0x88, 0x01]);
        // AU1: SEI + 2-slice P-frame (slice 0 has MSB=1, slice 1 has MSB=0 -> stays in AU1)
        stream.extend_from_slice(&[0, 0, 1, 0x06, 0x05, 0xaa]);
        stream.extend_from_slice(&[0, 0, 1, 0x41, 0x9a, 0x11]);
        stream.extend_from_slice(&[0, 0, 0, 1, 0x41, 0x05, 0x22]);
        // AU2: Single-slice P-frame
        stream.extend_from_slice(&[0, 0, 1, 0x41, 0x9a, 0x33]);
        // AU3: Second IDR without repeating SPS/PPS -> auto-prepends cached SPS+PPS
        stream.extend_from_slice(&[0, 0, 1, 0x65, 0x88, 0x44]);

        let mut sp = AnnexBSplitter::new();
        let mut frames = Vec::new();
        for chunk in stream.chunks(3) {
            frames.extend(sp.push(chunk));
        }
        frames.extend(sp.finish());
        assert_eq!(frames.len(), 4);
        assert!(is_self_contained_idr(&frames[0]), "AU0 must be self-contained IDR");
        assert!(!is_self_contained_idr(&frames[1]), "AU1 P-frame must NOT be IDR");
        assert!(frames[1].windows(3).any(|w| w == [0x41, 0x05, 0x22]), "AU1 must retain slice 1");
        assert!(!is_self_contained_idr(&frames[2]), "AU2 P-frame must NOT be IDR");
        assert!(is_self_contained_idr(&frames[3]), "AU3 must auto-prepend SPS+PPS");

        // Negative matrix for is_self_contained_idr
        assert!(!is_self_contained_idr(&[]));
        assert!(!is_self_contained_idr(&[0, 0, 0, 1, 0x65, 0x88])); // bare IDR (no SPS/PPS)
        assert!(!is_self_contained_idr(&[0, 0, 0, 1, 0x67, 0x42, 0, 0, 0, 1, 0x68, 0xce, 0, 0, 0, 1, 0x41, 0x9a]));

        // BUG-A2-6 regression: >8 MiB after an initial start code MUST clear buffer instead of growing unboundedly
        let mut cap_sp = AnnexBSplitter::new();
        let mut big = vec![0xAA; 8 * 1024 * 1024 + 64];
        big[0] = 0;
        big[1] = 0;
        big[2] = 1;
        let out = cap_sp.push(&big);
        assert!(out.is_empty());
        assert!(cap_sp.buf.is_empty(), "buffer must clear when exceeding 8 MiB after single start code");
    }
}
