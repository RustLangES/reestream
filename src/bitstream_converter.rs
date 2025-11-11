use byteorder::{BigEndian, ReadBytesExt};
use std::error::Error;
use std::io::{Cursor, Read};

/// Network abstraction layer type for H264 packet we might find.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NalType {
    Unspecified = 0,
    Slice = 1,
    Dpa = 2,
    Dpb = 3,
    Dpc = 4,
    IdrSlice = 5,
    Sei = 6,
    Sps = 7,
    Pps = 8,
    Aud = 9,
    EndSequence = 10,
    EndStream = 11,
    FillerData = 12,
    SpsExt = 13,
    Prefix = 14,
    SubSps = 15,
    Dps = 16,
    Reserved17 = 17,
    Reserved18 = 18,
    AuxiliarySlice = 19,
    ExtenSlice = 20,
    DepthExtenSlice = 21,
    Reserved22 = 22,
    Reserved23 = 23,
    Unspecified24 = 24,
    Unspecified25 = 25,
    Unspecified26 = 26,
    Unspecified27 = 27,
    Unspecified28 = 28,
    Unspecified29 = 29,
    Unspecified30 = 30,
    Unspecified31 = 31,
}

#[allow(clippy::fallible_impl_from)]
impl From<u8> for NalType {
    /// Reads NAL from header byte.
    fn from(value: u8) -> Self {
        use NalType::*;
        match value {
            0 => Unspecified,
            1 => Slice,
            2 => Dpa,
            3 => Dpb,
            4 => Dpc,
            5 => IdrSlice,
            6 => Sei,
            7 => Sps,
            8 => Pps,
            9 => Aud,
            10 => EndSequence,
            11 => EndStream,
            12 => FillerData,
            13 => SpsExt,
            14 => Prefix,
            15 => SubSps,
            16 => Dps,
            17 => Reserved17,
            18 => Reserved18,
            19 => AuxiliarySlice,
            20 => ExtenSlice,
            21 => DepthExtenSlice,
            22 => Reserved22,
            23 => Reserved23,
            24 => Unspecified24,
            25 => Unspecified25,
            26 => Unspecified26,
            27 => Unspecified27,
            28 => Unspecified28,
            29 => Unspecified29,
            30 => Unspecified30,
            31 => Unspecified31,
            _ => panic!("Invalid NAL type: {}", value),
        }
    }
}

impl NalType {
    pub const fn name(&self) -> &'static str {
        use NalType::*;
        match self {
            Unspecified => "Unspecified",
            Slice => "Slice",
            Dpa => "DPA",
            Dpb => "DPB",
            Dpc => "DPC",
            IdrSlice => "IDR Slice",
            Sei => "SEI",
            Sps => "SPS",
            Pps => "PPS",
            Aud => "AUD",
            EndSequence => "End Sequence",
            EndStream => "End Stream",
            FillerData => "Filler Data",
            SpsExt => "SPS Extension",
            Prefix => "Prefix",
            SubSps => "Subset SPS",
            Dps => "DPS",
            Reserved17 => "Reserved 17",
            Reserved18 => "Reserved 18",
            AuxiliarySlice => "Auxiliary Slice",
            ExtenSlice => "Extension Slice",
            DepthExtenSlice => "Depth Extension Slice",
            Reserved22 => "Reserved 22",
            Reserved23 => "Reserved 23",
            _ => "Unspecified",
        }
    }
}

/// A NAL unit in a bitstream.
struct NalUnit<'a> {
    nal_type: NalType,
    bytes: &'a [u8],
}

impl<'a> NalUnit<'a> {
    /// Reads a NAL unit from a slice of bytes (length-prefixed format),
    /// returning the unit and the remaining stream after that slice.
    fn from_stream(mut stream: &'a [u8], length_size: u8) -> Option<(Self, &'a [u8])> {
        if stream.len() < length_size as usize {
            return None;
        }

        let mut nal_size = 0u32;

        // Construct nal_size from first bytes in stream.
        for _ in 0..length_size {
            nal_size = (nal_size << 8) | u32::from(stream[0]);
            stream = &stream[1..];
        }

        if nal_size == 0 || stream.len() < nal_size as usize {
            return None;
        }

        let packet = &stream[..nal_size as usize];
        let nal_type = NalType::from(packet[0] & 0x1F);
        let unit = NalUnit {
            nal_type,
            bytes: packet,
        };

        stream = &stream[nal_size as usize..];

        Some((unit, stream))
    }

    const fn nal_type(&self) -> NalType {
        self.nal_type
    }

    const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
}

/// Resultado del parseo AVCC: listas de SPS y PPS
pub struct AvccInfo {
    pub sps: Vec<Vec<u8>>,
    pub pps: Vec<Vec<u8>>,
    pub length_size: u8, // bytes used for NALU length (1..4)
}

impl AvccInfo {
    pub fn from_avcc(avcc: &[u8]) -> Result<Self, Box<dyn Error>> {
        if avcc.len() < 7 {
            return Err("AVCC too short".into());
        }
        let mut rdr = Cursor::new(avcc);

        let _configuration_version = rdr.read_u8()?;
        let _profile = rdr.read_u8()?;
        let _compat = rdr.read_u8()?;
        let _level = rdr.read_u8()?;
        let length_size_byte = rdr.read_u8()?;
        let length_size_minus_one = length_size_byte & 0x03;
        let length_size = (length_size_minus_one + 1) as u8;

        let num_sps_byte = rdr.read_u8()?;
        let num_sps = (num_sps_byte & 0x1F) as usize;

        let mut sps_list = Vec::with_capacity(num_sps);
        for _ in 0..num_sps {
            let sps_len = rdr.read_u16::<BigEndian>()? as usize;
            if sps_len == 0 {
                continue;
            }
            let mut sps = vec![0u8; sps_len];
            rdr.read_exact(&mut sps)?;
            sps_list.push(sps);
        }

        let num_pps = rdr.read_u8()? as usize;
        let mut pps_list = Vec::with_capacity(num_pps);
        for _ in 0..num_pps {
            let pps_len = rdr.read_u16::<BigEndian>()? as usize;
            if pps_len == 0 {
                continue;
            }
            let mut pps = vec![0u8; pps_len];
            rdr.read_exact(&mut pps)?;
            pps_list.push(pps);
        }

        Ok(AvccInfo {
            sps: sps_list,
            pps: pps_list,
            length_size,
        })
    }
}

/// Converter from NAL units from length-prefixed format to Annex B format expected by openh264.
///
/// It also inserts SPS and PPS units into the stream when needed.
/// They are required for Annex B format to be decodable.
pub struct BitstreamConverter {
    length_size: u8,
    sps: Vec<Vec<u8>>,
    pps: Vec<Vec<u8>>,
    new_idr: bool,
    sps_seen: bool,
    pps_seen: bool,
}

impl BitstreamConverter {
    /// Create a new converter from AVCC info (from RTMP sequence header)
    pub fn from_avcc(avcc_info: &AvccInfo) -> Self {
        Self {
            length_size: avcc_info.length_size,
            sps: avcc_info.sps.clone(),
            pps: avcc_info.pps.clone(),
            new_idr: true,
            sps_seen: false,
            pps_seen: false,
        }
    }

    /// Update SPS/PPS from new AVCC info
    pub fn update_avcc(&mut self, avcc_info: &AvccInfo) {
        self.length_size = avcc_info.length_size;
        self.sps = avcc_info.sps.clone();
        self.pps = avcc_info.pps.clone();
        // Reset state when we get new parameters
        self.new_idr = true;
        self.sps_seen = false;
        self.pps_seen = false;
    }

    /// Convert a single packet from length-prefixed format to Annex B format.
    ///
    /// It clears the `out` vector and appends the converted packet to it.
    /// This automatically inserts SPS/PPS before IDR frames when needed.
    pub fn convert_packet(&mut self, packet: &[u8], out: &mut Vec<u8>) {
        let mut stream = packet;
        out.clear();

        while !stream.is_empty() {
            let Some((unit, remaining_stream)) = NalUnit::from_stream(stream, self.length_size)
            else {
                break;
            };

            stream = remaining_stream;

            match unit.nal_type() {
                NalType::Sps => self.sps_seen = true,
                NalType::Pps => self.pps_seen = true,
                NalType::IdrSlice => {
                    // If this is a new IDR picture following an IDR picture, reset the idr flag.
                    // Just check first_mb_in_slice to be 0 (new picture)
                    if !self.new_idr && unit.bytes().len() > 1 && unit.bytes()[1] & 0x80 != 0 {
                        self.new_idr = true;
                    }
                    
                    // Insert SPS & PPS NAL units if they were not seen
                    if self.new_idr && !self.sps_seen && !self.pps_seen {
                        self.new_idr = false;
                        for sps in &self.sps {
                            out.extend_from_slice(&[0, 0, 0, 1]);
                            out.extend_from_slice(sps);
                        }
                        for pps in &self.pps {
                            out.extend_from_slice(&[0, 0, 0, 1]);
                            out.extend_from_slice(pps);
                        }
                    }
                    // Insert only PPS if SPS was seen
                    else if self.new_idr && self.sps_seen && !self.pps_seen {
                        self.new_idr = false;
                        for pps in &self.pps {
                            out.extend_from_slice(&[0, 0, 0, 1]);
                            out.extend_from_slice(pps);
                        }
                    }
                }
                _ => {}
            }

            // Write the NAL unit with Annex B start code
            out.extend_from_slice(&[0, 0, 0, 1]);
            out.extend_from_slice(unit.bytes());

            // Reset flags after a non-IDR slice
            if !self.new_idr && unit.nal_type() == NalType::Slice {
                self.new_idr = true;
                self.sps_seen = false;
                self.pps_seen = false;
            }
        }
    }

    /// Get the length size (number of bytes used for NALU length prefix)
    pub const fn length_size(&self) -> u8 {
        self.length_size
    }
}

/// Convert Annex-B format back to length-prefixed, filtering out parameter sets
pub fn convert_annexb_to_length_prefixed(annexb: &[u8], length_size: u8) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0usize;

    while i < annexb.len() {
        // Look for start code (0x00 0x00 0x00 0x01 or 0x00 0x00 0x01)
        let start_code_len = if i + 3 < annexb.len() && annexb[i..i + 4] == [0, 0, 0, 1] {
            4
        } else if i + 2 < annexb.len() && annexb[i..i + 3] == [0, 0, 1] {
            3
        } else {
            i += 1;
            continue;
        };

        i += start_code_len;
        let start = i;

        // Find next start code
        let mut j = i;
        while j < annexb.len() {
            if j + 3 < annexb.len() && (annexb[j..j + 4] == [0, 0, 0, 1] || annexb[j..j + 3] == [0, 0, 1]) {
                break;
            }
            j += 1;
        }

        if start >= annexb.len() {
            break;
        }

        let nal = &annexb[start..j];
        if nal.is_empty() {
            i = j;
            continue;
        }

        let nal_type = NalType::from(nal[0] & 0x1F);

        // Skip parameter sets and AUDs - they're sent separately in RTMP sequence header
        if matches!(nal_type, NalType::Sps | NalType::Pps | NalType::Aud | NalType::Sei) {
            i = j;
            continue;
        }

        // Write length prefix
        let nal_len = nal.len() as u32;
        match length_size {
            1 => out.push(nal_len as u8),
            2 => {
                out.push((nal_len >> 8) as u8);
                out.push(nal_len as u8);
            }
            3 => {
                out.push((nal_len >> 16) as u8);
                out.push((nal_len >> 8) as u8);
                out.push(nal_len as u8);
            }
            4 => {
                out.push((nal_len >> 24) as u8);
                out.push((nal_len >> 16) as u8);
                out.push((nal_len >> 8) as u8);
                out.push(nal_len as u8);
            }
            _ => panic!("Invalid length_size: {}", length_size),
        }

        // Write NAL data
        out.extend_from_slice(nal);
        i = j;
    }

    out
}
