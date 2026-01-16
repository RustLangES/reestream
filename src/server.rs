use rml_rtmp::handshake::{Handshake, HandshakeProcessResult, PeerType};
use rml_rtmp::sessions::{ServerSession, ServerSessionConfig, ServerSessionResult};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Handshake server side and create ServerSession with lower-latency config
pub async fn handshake_and_create_server_session(
    stream: &mut TcpStream,
) -> Result<(ServerSession, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
    let mut hs = Handshake::new(PeerType::Server);
    let mut buf = [0u8; 4096];

    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Err("EOF durante handshake (no se recibieron datos de cliente)".into());
        }

        match hs.process_bytes(&buf[..n])? {
            HandshakeProcessResult::InProgress { response_bytes } => {
                if !response_bytes.is_empty() {
                    stream.write_all(&response_bytes).await?;
                }
            }
            HandshakeProcessResult::Completed {
                response_bytes,
                remaining_bytes,
            } => {
                if !response_bytes.is_empty() {
                    stream.write_all(&response_bytes).await?;
                }
                return Ok((
                    {
                        // Reduce latency: use smaller chunk size and smaller ack window to have quicker acks
                        let mut config = ServerSessionConfig::new();
                        config.chunk_size = 128; // smaller chunks -> lower per-chunk latency (tradeoff CPU)
                        config.window_ack_size = 262_144; // 256KB ack window to get more frequent acks

                        let (server_session, initial_results) = ServerSession::new(config)?;
                        for res in initial_results {
                            if let ServerSessionResult::OutboundResponse(packet) = res {
                                stream.write_all(&packet.bytes).await?;
                            }
                        }
                        server_session
                    },
                    remaining_bytes,
                ));
            }
        }
    }
}
