use std::collections::VecDeque;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use bytes::Bytes;
use rml_rtmp::sessions::{
    ClientSession, ClientSessionConfig, ClientSessionEvent, ClientSessionResult,
    PublishRequestType, StreamMetadata,
};
use rml_rtmp::time::RtmpTimestamp;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{RwLock, mpsc, watch};
use tokio_native_tls::{TlsConnector, native_tls};
use tracing::{debug, error, info, trace, warn};
use url::Url;

use crate::DynStream;
use crate::client::perform_client_handshake;

pub struct PushClient {
    pub(crate) tx_feed: mpsc::Sender<Bytes>, // bounded to avoid unbounded memory growth
    pub(crate) client_state: Arc<RwLock<ClientStateWrapper>>,
    pub(crate) publish_ready_rx: watch::Receiver<bool>,
}

pub struct ClientStateWrapper {
    pub session: ClientSession,
    pub target_stream: String,
    pub prepublish_video_buffer: VecDeque<Bytes>,
    pub prepublish_audio_buffer: VecDeque<Bytes>,
    pub prepublish_metadata: Option<StreamMetadata>,
}

impl PushClient {
    pub async fn connect_and_publish(
        url: &Url,
        stream_key: String,
    ) -> Result<PushClient, Box<dyn std::error::Error + Send + Sync>> {
        let host = url
            .host_str()
            .ok_or_else(|| format!("URL sin host válido: {url}"))?
            .to_string();

        let port = if url.scheme() == "rtmps" {
            443
        } else {
            url.port_or_known_default().unwrap_or(1935)
        };

        let addr = format!("{host}:{port}");

        info!("Conectando push client a {addr}");

        // Connect TCP
        let tcp_stream = TcpStream::connect(&addr).await?;
        // reduce latency on TCP
        if let Err(e) = tcp_stream.set_nodelay(true) {
            warn!(
                "No se pudo set_nodelay al tcp de push client {}: {}",
                addr, e
            );
        }

        // Wrap TLS if needed
        let mut boxed: DynStream = if url.scheme() == "rtmps" {
            let native = native_tls::TlsConnector::builder()
                .danger_accept_invalid_certs(true)
                .build()?;
            let connector = TlsConnector::from(native);
            let tls_stream = connector.connect(&host, tcp_stream).await?;
            Box::new(tls_stream)
        } else {
            Box::new(tcp_stream)
        };

        perform_client_handshake(&mut boxed).await?;
        info!("Handshake cliente completo hacia {}", addr);

        // split reader/writer
        let (mut rd_half, mut wr_half) = tokio::io::split(boxed);

        // client config with lower chunk size
        let mut client_cfg = ClientSessionConfig::new();
        client_cfg.chunk_size = 128;
        let path = url.path().trim_start_matches('/');
        let app_segment = path.split('/').next().unwrap_or("");
        let tcurl = if app_segment.is_empty() {
            format!("rtmp://{}:{}/", host, port)
        } else {
            format!("rtmp://{}:{}/{}", host, port, app_segment)
        };
        client_cfg.tc_url = Some(tcurl.clone());

        let (mut client_session, initial_results) = ClientSession::new(client_cfg)?;

        // bounded channel: capacity 256 to avoid unbounded growth when a remote is slow
        let (tx, mut rx) = mpsc::channel::<Bytes>(256);
        let writer_addr = addr.clone();
        tokio::spawn(async move {
            while let Some(bytes) = rx.recv().await {
                if let Err(e) = wr_half.write_all(&bytes).await {
                    error!("Error escribiendo a push target {}: {}", writer_addr, e);
                    break;
                }
            }
            info!("Writer task terminado para push target {}", writer_addr);
        });

        // send initial results (use try_send, drop if full)
        for r in initial_results {
            if let ClientSessionResult::OutboundResponse(packet) = r
                && let Err(e) = tx.try_send(Bytes::from(packet.bytes.clone()))
            {
                debug!("Dropped initial packet for {}: {}", addr, e);
            }
        }

        // request connection (app extracted from URL)
        let app = app_segment.to_string();
        match client_session.request_connection(app.clone()) {
            Ok(ClientSessionResult::OutboundResponse(packet)) => {
                if let Err(e) = tx.try_send(Bytes::from(packet.bytes.clone())) {
                    debug!("Dropped connect packet for {}: {}", addr, e);
                }
            }
            Ok(_) => {}
            Err(e) => {
                return Err(format!("request_connection error: {:?}", e).into());
            }
        }

        let client_state = ClientStateWrapper {
            session: client_session,
            target_stream: stream_key.clone(),
            prepublish_video_buffer: VecDeque::new(),
            prepublish_audio_buffer: VecDeque::new(),
            prepublish_metadata: None,
        };

        let client_state = Arc::new(RwLock::new(client_state));
        let (publish_ready_tx, publish_ready_rx) = watch::channel(false);

        // reader task: advance client session based on remote responses
        {
            let client_state_reader = client_state.clone();
            let tx_clone = tx.clone();
            let addr_clone = addr.clone();
            let publish_ready_tx = publish_ready_tx.clone();

            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                loop {
                    match rd_half.read(&mut buf).await {
                        Ok(0) => {
                            info!("Push target {} cerró la conexión (reader)", addr_clone);
                            break;
                        }
                        Ok(n) => {
                            let mut state = client_state_reader.write().await;

                            // Protect handle_input from unwinding panics inside the library
                            let res = catch_unwind(AssertUnwindSafe(|| {
                                state.session.handle_input(&buf[..n])
                            }));
                            match res {
                                Ok(Ok(results)) => {
                                    for r in results {
                                        match r {
                                            ClientSessionResult::OutboundResponse(packet) => {
                                                if let Err(e) = tx_clone
                                                    .try_send(Bytes::from(packet.bytes.clone()))
                                                {
                                                    debug!(
                                                        "Dropped outbound packet to {}: {}",
                                                        addr_clone, e
                                                    );
                                                }
                                            }
                                            ClientSessionResult::RaisedEvent(ev) => {
                                                trace!("Push client evento: {:?}", ev);
                                                match ev {
                                                    ClientSessionEvent::ConnectionRequestAccepted => {
                                                        let stream_key = state.target_stream.clone();
                                                        match state.session.request_publishing(stream_key, PublishRequestType::Live) {
                                                            Ok(ClientSessionResult::OutboundResponse(pub_packet)) => {
                                                                if let Err(e) = tx_clone.try_send(Bytes::from(pub_packet.bytes.clone())) {
                                                                    debug!("Dropped publish request packet for {}: {}", addr_clone, e);
                                                                }
                                                            }
                                                            Ok(_) => {}
                                                            Err(e) => {
                                                                error!("request_publishing fallo: {:?}", e);
                                                            }
                                                        }
                                                    }
                                                    ClientSessionEvent::PublishRequestAccepted => {
                                                        info!("Push client publish accepted for {}", state.target_stream);
                                                        // mark ready
                                                        let _ = publish_ready_tx.send(true);

                                                        // send buffered metadata if any
                                                        if let Some(meta) = state.prepublish_metadata.take() {
                                                            match state.session.publish_metadata(&meta) {
                                                                Ok(ClientSessionResult::OutboundResponse(packet)) => {
                                                                    if let Err(e) = tx_clone.try_send(Bytes::from(packet.bytes.clone())) {
                                                                        debug!("Dropped buffered metadata packet for {}: {}", addr_clone, e);
                                                                    }
                                                                }
                                                                Ok(_) => {}
                                                                Err(e) => {
                                                                    error!("Error sending buffered metadata: {:?}", e);
                                                                }
                                                            }
                                                        }

                                                        // drain buffered video
                                                        while let Some(vframe) = state.prepublish_video_buffer.pop_front() {
                                                            match state.session.publish_video_data(vframe.clone(), RtmpTimestamp::new(0), true) {
                                                                Ok(ClientSessionResult::OutboundResponse(packet)) => {
                                                                    if let Err(e) = tx_clone.try_send(Bytes::from(packet.bytes.clone())) {
                                                                        debug!("Dropped buffered video packet for {}: {}", addr_clone, e);
                                                                    }
                                                                }
                                                                Ok(_) => {}
                                                                Err(e) => {
                                                                    error!("Error sending buffered video frame: {:?}", e);
                                                                    break;
                                                                }
                                                            }
                                                        }

                                                        // drain buffered audio
                                                        while let Some(aframe) = state.prepublish_audio_buffer.pop_front() {
                                                            match state.session.publish_audio_data(aframe.clone(), RtmpTimestamp::new(0), true) {
                                                                Ok(ClientSessionResult::OutboundResponse(packet)) => {
                                                                    if let Err(e) = tx_clone.try_send(Bytes::from(packet.bytes.clone())) {
                                                                        debug!("Dropped buffered audio packet for {}: {}", addr_clone, e);
                                                                    }
                                                                }
                                                                Ok(_) => {}
                                                                Err(e) => {
                                                                    error!("Error sending buffered audio frame: {:?}", e);
                                                                    break;
                                                                }
                                                            }
                                                        }
                                                    }
                                                    _ => {}
                                                }
                                            }
                                            other => {
                                                debug!("Push client other result: {:?}", other);
                                            }
                                        }
                                    }
                                }
                                Ok(Err(e)) => {
                                    error!(
                                        "Error manejando input en ClientSession (push): {:?}",
                                        e
                                    );
                                    break;
                                }
                                Err(panic_err) => {
                                    error!(
                                        "panic al procesar ClientSession::handle_input (push): {:?}",
                                        panic_err
                                    );
                                    break;
                                }
                            }

                            drop(state);
                        }
                        Err(e) => {
                            error!("Error leyendo desde push target {}: {}", addr_clone, e);
                            break;
                        }
                    }
                }
                info!("Reader task terminado para push target {}", addr_clone);
            });
        }

        Ok(PushClient {
            tx_feed: tx,
            client_state,
            publish_ready_rx,
        })
    }
}
