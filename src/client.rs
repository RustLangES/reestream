mod push;

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
pub use push::PushClient;
use rml_rtmp::handshake::{Handshake, HandshakeProcessResult, PeerType};
use rml_rtmp::sessions::{ClientSessionResult, ServerSessionEvent, ServerSessionResult};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

use crate::DynStream;
use crate::config::Platform;
use crate::server::handshake_and_create_server_session;

async fn perform_client_handshake(
    stream: &mut DynStream,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut hs = Handshake::new(PeerType::Client);
    let c0_c1 = hs.generate_outbound_p0_and_p1()?;
    stream.write_all(&c0_c1).await?;

    let mut buf = [0u8; 4096];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Err("EOF during client handshake".into());
        }

        match hs.process_bytes(&buf[..n])? {
            HandshakeProcessResult::InProgress { response_bytes } => {
                if !response_bytes.is_empty() {
                    stream.write_all(&response_bytes).await?;
                }
            }
            HandshakeProcessResult::Completed { response_bytes, .. } => {
                if !response_bytes.is_empty() {
                    stream.write_all(&response_bytes).await?;
                }
                break;
            }
        }
    }
    Ok(())
}

pub async fn handle_publisher(
    mut inbound: TcpStream,
    platforms: Arc<RwLock<Vec<Platform>>>,
    stream_key_conf: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("Iniciando handshake servidor con client entrante...");
    let (mut server_session, leftover) = handshake_and_create_server_session(&mut inbound).await?;
    info!("Handshake completado; esperando publish request...");

    // Cargamos la lista de plataformas pero NO creamos conexiones push todavía.
    let pls = platforms.read().await.clone();
    // Aquí guardaremos los push clients una vez que aceptemos el publish del publisher.
    let mut push_clients: Vec<PushClient> = Vec::new();

    // Si hubo bytes sobrantes tras el handshake, procesarlos.
    // Es posible que entre esos bytes ya venga la solicitud de publish; se procesará
    // y el branch PublishStreamRequested creará los push clients cuando corresponda.

    if !leftover.is_empty() {
        let results = server_session.handle_input(&leftover)?;
        for res in results {
            match res {
                ServerSessionResult::OutboundResponse(packet) => {
                    if let Err(e) = inbound.write_all(&packet.bytes).await {
                        error!(
                            "Error escribiendo respuesta al publisher (leftover): {:?}",
                            e
                        );
                    }
                }
                ServerSessionResult::RaisedEvent(ev) => {
                    debug!("Server session event (leftover): {:?}", ev);
                }
                _ => {}
            }
        }
    }

    let mut read_buf = [0u8; 8192];
    loop {
        let n = inbound.read(&mut read_buf).await?;
        if n == 0 {
            info!("Publisher cerró la conexión");
            break;
        }

        let results = match server_session.handle_input(&read_buf[..n]) {
            Ok(r) => r,
            Err(e) => {
                error!("Error procesando bytes en ServerSession: {:?}", e);
                break;
            }
        };

        for res in results {
            match res {
                // Respuestas del ServerSession van sólo al publisher.
                ServerSessionResult::OutboundResponse(packet) => {
                    if let Err(e) = inbound.write_all(&packet.bytes).await {
                        error!("Error escribiendo al publisher: {:?}", e);
                    }
                }

                ServerSessionResult::RaisedEvent(ev) => match ev {
                    ServerSessionEvent::ConnectionRequested {
                        request_id,
                        app_name: _,
                    } => {
                        if let Ok(out) = server_session.accept_request(request_id) {
                            for r in out {
                                if let ServerSessionResult::OutboundResponse(packet) = r {
                                    let _ = inbound.write_all(&packet.bytes).await;
                                }
                            }
                        }
                    }

                    ServerSessionEvent::PublishStreamRequested {
                        request_id,
                        app_name,
                        stream_key,
                        ..
                    } => {
                        // Validamos la stream key antes de aceptar y antes de iniciar retransmisiones.
                        if stream_key == stream_key_conf {
                            // Aceptamos la petición del publisher
                            if let Ok(out) = server_session.accept_request(request_id) {
                                for r in out {
                                    if let ServerSessionResult::OutboundResponse(packet) = r {
                                        let _ = inbound.write_all(&packet.bytes).await;
                                    }
                                }
                            }
                            info!(
                                "Publisher accepted publish app='{}' stream='{}'",
                                app_name, stream_key
                            );

                            // Ahora que el publisher está autorizado, creamos los push clients
                            // (si no existen ya). Esto evita iniciar retransmisiones para keys inválidas.
                            if push_clients.is_empty() {
                                for p in pls.iter() {
                                    if !["rtmp", "rtmps"].contains(&p.url.scheme()) {
                                        info!(
                                            "Ignorando plataforma con esquema distinto a rtmp/rtmps: {}",
                                            p.url
                                        );
                                        continue;
                                    }

                                    let host = match p.url.host_str() {
                                        Some(h) => h.to_string(),
                                        None => {
                                            warn!("URL sin host válido: {}", p.url);
                                            continue;
                                        }
                                    };
                                    let port = p.url.port_or_known_default().unwrap_or(1935);
                                    let addr = format!("{host}:{port}");

                                    match timeout(
                                        Duration::from_secs(10),
                                        PushClient::connect_and_publish(&p.url, p.key.clone()),
                                    )
                                    .await
                                    {
                                        Ok(Ok(push_client)) => {
                                            info!("Push client activo hacia {addr}");
                                            push_clients.push(push_client);
                                        }
                                        Ok(Err(e)) => {
                                            warn!(
                                                "Push client falló al iniciar hacia {}: {}",
                                                p.url, e
                                            );
                                        }
                                        Err(_) => {
                                            warn!("Timeout conectando a {addr} para push");
                                        }
                                    }
                                }

                                if push_clients.is_empty() {
                                    warn!(
                                        "No se pudieron iniciar push clients tras aceptar publish; se continuará pero no habrá retransmisión."
                                    );
                                } else {
                                    info!(
                                        "Retransmisiones iniciadas a {} plataformas",
                                        push_clients.len()
                                    );
                                }
                            } else {
                                debug!("Push clients ya estaban creados; no se recrean.");
                            }
                        } else {
                            // Rechazamos la petición si la stream key no coincide con la configurada.
                            match server_session.reject_request(
                                request_id,
                                "NetStream.Publish.BadName",
                                "Invalid stream key",
                            ) {
                                Ok(out) => {
                                    for r in out {
                                        if let ServerSessionResult::OutboundResponse(packet) = r {
                                            let _ = inbound.write_all(&packet.bytes).await;
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!("Error rejecting publish request: {:?}", e);
                                }
                            }
                            info!(
                                "Publish rejected for invalid stream key '{}'; cerrando conexión.",
                                stream_key
                            );
                            // Cerrar la conexión del publisher y terminar la función: no habrá retransmisiones.
                            return Ok(());
                        }
                    }

                    ServerSessionEvent::VideoDataReceived {
                        data, timestamp, ..
                    } => {
                        for pc in push_clients.iter() {
                            if *pc.publish_ready_rx.borrow() {
                                let mut state = pc.client_state.write().await;
                                match state.session.publish_video_data(
                                    data.clone(),
                                    timestamp,
                                    true,
                                ) {
                                    Ok(ClientSessionResult::OutboundResponse(packet)) => {
                                        if let Err(e) =
                                            pc.tx_feed.try_send(Bytes::from(packet.bytes.clone()))
                                        {
                                            debug!(
                                                "Dropped publish_video_data packet for push client: {}",
                                                e
                                            );
                                        }
                                    }
                                    Ok(_) => {}
                                    Err(e) => {
                                        error!("Error publish_video_data to push client: {:?}", e);
                                    }
                                }
                                drop(state);
                            } else {
                                let mut state = pc.client_state.write().await;
                                if state.prepublish_video_buffer.len() < 128 {
                                    state.prepublish_video_buffer.push_back(data.clone());
                                } else {
                                    state.prepublish_video_buffer.pop_front();
                                    state.prepublish_video_buffer.push_back(data.clone());
                                }
                                drop(state);
                            }
                        }
                    }

                    ServerSessionEvent::AudioDataReceived {
                        data, timestamp, ..
                    } => {
                        for pc in push_clients.iter() {
                            if *pc.publish_ready_rx.borrow() {
                                let mut state = pc.client_state.write().await;
                                match state.session.publish_audio_data(
                                    data.clone(),
                                    timestamp,
                                    true,
                                ) {
                                    Ok(ClientSessionResult::OutboundResponse(packet)) => {
                                        if let Err(e) =
                                            pc.tx_feed.try_send(Bytes::from(packet.bytes.clone()))
                                        {
                                            debug!(
                                                "Dropped publish_audio_data packet for push client: {}",
                                                e
                                            );
                                        }
                                    }
                                    Ok(_) => {}
                                    Err(e) => {
                                        error!("Error publish_audio_data to push client: {:?}", e);
                                    }
                                }
                                drop(state);
                            } else {
                                let mut state = pc.client_state.write().await;
                                if state.prepublish_audio_buffer.len() < 128 {
                                    state.prepublish_audio_buffer.push_back(data.clone());
                                } else {
                                    state.prepublish_audio_buffer.pop_front();
                                    state.prepublish_audio_buffer.push_back(data.clone());
                                }
                                drop(state);
                            }
                        }
                    }

                    ServerSessionEvent::StreamMetadataChanged { metadata, .. } => {
                        for pc in push_clients.iter() {
                            if *pc.publish_ready_rx.borrow() {
                                let mut state = pc.client_state.write().await;
                                match state.session.publish_metadata(&metadata) {
                                    Ok(client_res) => {
                                        if let ClientSessionResult::OutboundResponse(packet) =
                                            client_res
                                            && let Err(e) = pc
                                                .tx_feed
                                                .try_send(Bytes::from(packet.bytes.clone()))
                                        {
                                            debug!(
                                                "Dropped publish_metadata packet for push client: {}",
                                                e
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        error!("Error publish_metadata to push client: {:?}", e);
                                    }
                                }
                                drop(state);
                            } else {
                                let mut state = pc.client_state.write().await;
                                state.prepublish_metadata = Some(metadata.clone());
                                drop(state);
                            }
                        }
                    }

                    _ => {}
                },

                other => {
                    debug!("Other server result: {:?}", other);
                }
            }
        }

        // NOTE: Do NOT feed publisher bytes into push clients' client sessions.
        // Each PushClient reads its own remote socket and advances its ClientSession there.
    }

    Ok(())
}
