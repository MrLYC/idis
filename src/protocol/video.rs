/// Video codec compression type wire constants.
pub const COMPRESSION_VP8: u8 = 10;
pub const COMPRESSION_H264: u8 = 11;

/// Build a legacy display client video data packet header + Annex-B payload.
///
/// Header layout (little-endian):
/// - `u32 header_len`: 17 if `data_protocol_version >= 5`, else 13
/// - `u32 width`
/// - `u32 height`
/// - `u8  compression` (`11` = H.264 Annex-B, `10` = VP8)
/// - `u32 bytes_per_row` (present only when `data_protocol_version >= 5`)
/// - `<compressed_payload>`
///
/// Stack-allocate the 13- or 17-byte legacy iDisplay video packet header without copying the payload.
/// Returns `(header_bytes, active_len)` for zero-copy vectored socket transmission.
pub fn build_video_header(
    width: u32,
    height: u32,
    bytes_per_row: u32,
    compression: u8,
    data_protocol_version: u32,
) -> ([u8; 17], usize) {
    let include_bpr = data_protocol_version >= 5;
    let header_len: u32 = if include_bpr { 17 } else { 13 };
    let mut hdr = [0u8; 17];
    hdr[0..4].copy_from_slice(&header_len.to_le_bytes());
    hdr[4..8].copy_from_slice(&width.to_le_bytes());
    hdr[8..12].copy_from_slice(&height.to_le_bytes());
    hdr[12] = compression;
    if include_bpr {
        hdr[13..17].copy_from_slice(&bytes_per_row.to_le_bytes());
        (hdr, 17)
    } else {
        (hdr, 13)
    }
}

pub fn build_video_packet(
    width: u32,
    height: u32,
    bytes_per_row: u32,
    compression: u8,
    data_protocol_version: u32,
    compressed_payload: &[u8],
) -> Vec<u8> {
    let include_bpr = data_protocol_version >= 5;
    let header_len: u32 = if include_bpr { 17 } else { 13 };
    let mut out = Vec::with_capacity(header_len as usize + compressed_payload.len());
    out.extend_from_slice(&header_len.to_le_bytes());
    out.extend_from_slice(&width.to_le_bytes());
    out.extend_from_slice(&height.to_le_bytes());
    out.push(compression);
    if include_bpr {
        out.extend_from_slice(&bytes_per_row.to_le_bytes());
    }
    out.extend_from_slice(compressed_payload);
    out
}

/// Parsed video packet header (useful for tests and diagnostics).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedVideoHeader {
    pub header_len: u32,
    pub width: u32,
    pub height: u32,
    pub compression: u8,
    pub bytes_per_row: Option<u32>,
    pub payload_offset: usize,
}

pub fn parse_video_header(packet: &[u8]) -> Option<ParsedVideoHeader> {
    if packet.len() < 13 {
        return None;
    }
    let header_len = u32::from_le_bytes([packet[0], packet[1], packet[2], packet[3]]);
    let width = u32::from_le_bytes([packet[4], packet[5], packet[6], packet[7]]);
    let height = u32::from_le_bytes([packet[8], packet[9], packet[10], packet[11]]);
    let compression = packet[12];
    let bytes_per_row = if header_len >= 17 && packet.len() >= 17 {
        Some(u32::from_le_bytes([
            packet[13], packet[14], packet[15], packet[16],
        ]))
    } else {
        None
    };
    let payload_offset = header_len as usize;
    if packet.len() < payload_offset {
        return None;
    }
    Some(ParsedVideoHeader {
        header_len,
        width,
        height,
        compression,
        bytes_per_row,
        payload_offset,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn video_packet_v5_and_v4() {
        let annexb = [0, 0, 0, 1, 0x67, 0x42, 0x00, 0x1e];
        let pkt5 = build_video_packet(1024, 768, 4096, COMPRESSION_H264, 5, &annexb);
        let h5 = parse_video_header(&pkt5).unwrap();
        assert_eq!(h5.header_len, 17);
        assert_eq!(h5.width, 1024);
        assert_eq!(h5.height, 768);
        assert_eq!(h5.compression, COMPRESSION_H264);
        assert_eq!(h5.bytes_per_row, Some(4096));
        assert_eq!(&pkt5[h5.payload_offset..], &annexb);

        let pkt4 = build_video_packet(1024, 768, 4096, COMPRESSION_H264, 4, &annexb);
        let h4 = parse_video_header(&pkt4).unwrap();
        assert_eq!(h4.header_len, 13);
        assert_eq!(h4.bytes_per_row, None);
        assert_eq!(&pkt4[h4.payload_offset..], &annexb);
    }
}
