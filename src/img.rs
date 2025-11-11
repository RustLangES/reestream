use bytes::{BufMut, Bytes, BytesMut};
use image::{ImageBuffer, Rgba};
use openh264::Error as OpenH264Error;
use openh264::decoder::{Decoder, DecoderConfig};
use openh264::encoder::{BitRate, Encoder, EncoderConfig};
use openh264::formats::{RgbSliceU8, YUVBuffer, YUVSource};
use rml_rtmp::sessions::StreamMetadata;
use std::error::Error;
use tracing::{debug, error, info, warn};

use crate::bitstream_converter::{
    AvccInfo, BitstreamConverter, NalType, convert_annexb_to_length_prefixed,
};

/// VideoProcessor maintains decoder/encoder state and bitstream converter.
pub struct VideoProcessor {
    decoder: Decoder,
    encoder: Encoder,
    converter: Option<BitstreamConverter>,
    orig_width: Option<u32>,
    orig_height: Option<u32>,
    decoder_ready: bool,
}

impl VideoProcessor {
    pub fn new() -> Result<Self, Box<dyn Error>> {
        let decoder = Decoder::with_api_config(
            openh264::OpenH264API::from_source(),
            DecoderConfig::default(),
        )?;
        let encoder = Encoder::with_api_config(
            openh264::OpenH264API::from_source(),
            EncoderConfig::default(),
        )?;

        Ok(Self {
            decoder,
            encoder,
            converter: None,
            orig_width: None,
            orig_height: None,
            decoder_ready: false,
        })
    }

    pub fn update_metadata(&mut self, metadata: &StreamMetadata) -> Result<(), Box<dyn Error>> {
        if let Some(w) = metadata.video_width {
            self.orig_width = Some(w);
        }
        if let Some(h) = metadata.video_height {
            self.orig_height = Some(h);
        }

        let config = EncoderConfig::default()
            .bitrate(BitRate::from_bps(
                metadata.video_bitrate_kbps.unwrap_or(2500) * 1000,
            ))
            .skip_frames(false);

        self.encoder = Encoder::with_api_config(openh264::OpenH264API::from_source(), config)?;

        Ok(())
    }

    pub async fn process_rtmp_video_tag(
        &mut self,
        data: Bytes,
    ) -> Result<Option<Bytes>, Box<dyn Error>> {
        if data.len() < 5 {
            return Ok(None);
        }

        let first = data[0];
        let frame_type = (first >> 4) & 0x0F; // 1=keyframe, 2=inter frame
        let codec_id = first & 0x0F;

        // Solo procesar H.264 (codec 7)
        if codec_id != 7 {
            return Ok(None);
        }

        let avc_packet_type = data[1];
        let cts = ((data[2] as u32) << 16) | ((data[3] as u32) << 8) | (data[4] as u32);

        match avc_packet_type {
            0 => {
                // Sequence header (AVCDecoderConfigurationRecord)
                info!("📦 Recibiendo sequence header (SPS/PPS)");
                let avcc_bytes = data.slice(5..);

                match AvccInfo::from_avcc(&avcc_bytes) {
                    Ok(avcc_info) => {
                        info!(
                            "✅ AVCC parseado: {} SPS, {} PPS, length_size={}",
                            avcc_info.sps.len(),
                            avcc_info.pps.len(),
                            avcc_info.length_size
                        );

                        // Crear o actualizar el converter
                        if let Some(ref mut converter) = self.converter {
                            converter.update_avcc(&avcc_info);
                        } else {
                            self.converter = Some(BitstreamConverter::from_avcc(&avcc_info));
                        }

                        // Inicializar el decoder con un paquete vacío que forzará
                        // la inserción de SPS/PPS en el próximo IDR frame
                        self.decoder_ready = true;
                        info!("✅ Bitstream converter inicializado y listo");

                        // Reenviar el sequence header sin modificar
                        return Ok(Some(data));
                    }
                    Err(e) => {
                        error!("❌ Error parseando AVCC: {:?}", e);
                        return Ok(Some(data));
                    }
                }
            }
            1 => {
                // NALUs (frames de video)
                let Some(ref mut converter) = self.converter else {
                    warn!("⚠️  Bitstream converter no inicializado, esperando sequence header");
                    return Ok(Some(data));
                };

                if !self.decoder_ready {
                    warn!("⚠️  Decoder no está listo, esperando sequence header");
                    return Ok(Some(data));
                }

                let payload = data.slice(5..);
                let is_keyframe = frame_type == 1;

                // Convertir a Annex-B usando el BitstreamConverter
                // que automáticamente insertará SPS/PPS cuando sea necesario
                let mut annexb = Vec::new();
                converter.convert_packet(&payload, &mut annexb);

                if annexb.is_empty() {
                    warn!("⚠️  Conversión resultó en paquete vacío");
                    return Ok(Some(data));
                }

                debug!(
                    "📹 Procesando frame {} de {} bytes (annexb: {} bytes)",
                    if is_keyframe { "I (keyframe)" } else { "P/B" },
                    payload.len(),
                    annexb.len()
                );
                debug_print_nalus(&annexb);

                // Procesar frame
                let processed_annexb =
                    match Self::decode_process_reencode(&mut self.decoder, &mut self.encoder, &annexb) {
                        Ok(result) => result,
                        Err(e) => {
                            error!("❌ Error procesando frame: {:?}", e);
                            return Ok(Some(data)); // Pasar sin procesar en caso de error
                        }
                    };

                // Convertir de vuelta a length-prefixed usando la función del converter
                let length_size = converter.length_size();
                let nals_len_prefixed =
                    convert_annexb_to_length_prefixed(&processed_annexb, length_size);

                if nals_len_prefixed.is_empty() {
                    warn!("⚠️  Conversión de vuelta resultó en paquete vacío");
                    return Ok(Some(data));
                }

                let mut out = BytesMut::with_capacity(5 + nals_len_prefixed.len());
                out.put_u8(first);
                out.put_u8(1u8); // AVC NALU
                out.put_u8(((cts >> 16) & 0xff) as u8);
                out.put_u8(((cts >> 8) & 0xff) as u8);
                out.put_u8((cts & 0xff) as u8);
                out.extend_from_slice(&nals_len_prefixed);

                debug!("✅ Frame procesado: {} -> {} bytes", data.len(), out.len());

                return Ok(Some(out.freeze()));
            }
            2 => {
                // End of sequence
                info!("🏁 End of sequence recibido");
                return Ok(Some(data));
            }
            _ => {
                warn!("⚠️  AVC packet type desconocido: {}", avc_packet_type);
                return Ok(None);
            }
        }
    }

    fn decode_process_reencode(
        decoder: &mut Decoder,
        encoder: &mut Encoder,
        annexb: &[u8],
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        // Decodificar
        let yuv_frame = match decoder.decode(annexb) {
            Ok(Some(frame)) => {
                debug!("✅ Frame decodificado exitosamente");
                frame
            }
            Ok(None) => {
                debug!("⏳ Decodificador retornó None (buffering/esperando más datos)");
                // En caso de None, devolver el input sin procesar
                return Ok(annexb.to_vec());
            }
            Err(e) => {
                // Loggear el código de error específico
                error!("❌ Error decodificando - {:?}", e);

                return Err(Box::new(e));
            }
        };

        let (width, height) = yuv_frame.dimensions();
        let (stride_y, stride_u, stride_v) = yuv_frame.strides();

        debug!(
            "📐 Frame: {}x{} (strides: Y={}, U={}, V={})",
            width, height, stride_y, stride_u, stride_v
        );

        // Convertir YUV a RGBA
        let rgba = yuv420p_to_rgba(
            width,
            height,
            yuv_frame.y(),
            yuv_frame.u(),
            yuv_frame.v(),
            stride_y,
            stride_u,
            stride_v,
        );

        // Procesar la imagen
        let img_buf = ImageBuffer::<Rgba<u8>, Vec<u8>>::from_raw(width as u32, height as u32, rgba)
            .ok_or("Failed to create ImageBuffer")?;

        let dynimg = image::DynamicImage::ImageRgba8(img_buf);

        // Aplicar tu efecto (puedes cambiar esto)
        let dynimg_processed = dynimg.huerotate(24);

        // Convertir de vuelta a RGB
        let rgb_img = dynimg_processed.to_rgb8();
        let (w, h) = rgb_img.dimensions();
        let rgb = rgb_img.into_raw();

        // Re-encodificar
        let rgb_src = RgbSliceU8::new(&rgb, (w as _, h as _));
        let yuv_src = YUVBuffer::from_rgb8_source(rgb_src);

        let encoded_annexb = encoder.encode(&yuv_src)?;

        Ok(encoded_annexb.to_vec())
    }
}

fn debug_print_nalus(annexb: &[u8]) {
    let mut i = 0usize;
    let mut count = 0;

    while i + 3 < annexb.len() {
        let start_code_len = if &annexb[i..i + 4] == [0, 0, 0, 1] {
            4
        } else if i + 2 < annexb.len() && &annexb[i..i + 3] == [0, 0, 1] {
            3
        } else {
            i += 1;
            continue;
        };

        i += start_code_len;
        let start = i;
        let mut j = i;

        while j + 3 < annexb.len() {
            if &annexb[j..j + 4] == [0, 0, 0, 1]
                || (j + 2 < annexb.len() && &annexb[j..j + 3] == [0, 0, 1])
            {
                break;
            }
            j += 1;
        }

        if start < annexb.len() {
            let nal = &annexb[start..j];
            if !nal.is_empty() {
                let nal_type = NalType::from(nal[0] & 0x1F);
                debug!(
                    "  NALU #{}: type {} ({}) size {} bytes",
                    count,
                    nal_type as u8,
                    nal_type.name(),
                    nal.len()
                );
                count += 1;
            }
        }
        i = j;
    }
}

fn yuv420p_to_rgba(
    width: usize,
    height: usize,
    y_plane: &[u8],
    u_plane: &[u8],
    v_plane: &[u8],
    stride_y: usize,
    stride_u: usize,
    stride_v: usize,
) -> Vec<u8> {
    let mut out = vec![0u8; width * height * 4];

    for j in 0..height {
        for i in 0..width {
            let y = y_plane[j * stride_y + i] as f32;
            let u = u_plane[(j / 2) * stride_u + (i / 2)] as f32 - 128.0;
            let v = v_plane[(j / 2) * stride_v + (i / 2)] as f32 - 128.0;

            let r = (y + 1.402 * v).round().clamp(0.0, 255.0) as u8;
            let g = (y - 0.344136 * u - 0.714136 * v).round().clamp(0.0, 255.0) as u8;
            let b = (y + 1.772 * u).round().clamp(0.0, 255.0) as u8;

            let idx = (j * width + i) * 4;
            out[idx] = r;
            out[idx + 1] = g;
            out[idx + 2] = b;
            out[idx + 3] = 255u8;
        }
    }

    out
}
