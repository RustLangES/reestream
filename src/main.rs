use bytes::Bytes;
use rml_rtmp::time::RtmpTimestamp;
use serde::Deserialize;
use std::collections::VecDeque;
use std::fs;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{RwLock, mpsc, watch};
use tokio::time::timeout;
use tokio_native_tls::{TlsConnector, native_tls};
use tracing::{debug, error, info, warn};
use tracing_subscriber::filter::LevelFilter;
use url::Url;

use rml_rtmp::handshake::{Handshake, HandshakeProcessResult, PeerType};
use rml_rtmp::sessions::{
    ClientSession, ClientSessionConfig, ClientSessionEvent, ClientSessionResult,
    PublishRequestType, ServerSession, ServerSessionConfig, ServerSessionEvent,
    ServerSessionResult, StreamMetadata,
};

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub rtmps: bool,
    pub rtmp_addr: String,
    pub rtmp_port: u16,
    pub rtmps_port: Option<u16>,
    pub stream_key: String,
    pub platform: Option<Vec<Platform>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Platform {
    pub url: Url,
    pub key: String,
    pub orientation: Orientation,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Orientation {
    #[default]
    Horizontal,
    Vertical,
}

impl Config {
    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_line_number(true)
        .with_max_level(LevelFilter::DEBUG)
        .init();

    let config = Config::from_file("config.toml")?;
    let Config {
        rtmp_addr,
        rtmp_port,
        stream_key,
        platform,
        ..
    } = &config;

    println!("Configuración cargada:");
    println!("  Listener: {rtmp_addr}:{rtmp_port}",);
    println!("  Stream key: {stream_key}");
    println!(
        "  Plataformas configuradas: {}",
        platform.clone().unwrap_or_default().len()
    );

    let addr: SocketAddr = format!("{rtmp_addr}:{rtmp_port}").parse()?;
    let listener = TcpListener::bind(addr).await?;
    info!("RTMP relay escuchando en {}", addr);

    let platforms = Arc::new(RwLock::new(platform.clone().unwrap_or_default()));

    loop {
        tokio::select! {
            biased;

            _ = tokio::signal::ctrl_c() => {
                info!("Recibida señal Ctrl+C, cerrando servidor...");
                break;
            }

            accept = listener.accept() => {
                match accept {
                    Ok((socket, peer_addr)) => {
                        info!("Nueva conexión entrante desde {}", peer_addr);
                        let platforms = platforms.clone();
                        let stream_key = stream_key.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_publisher(socket, platforms, stream_key).await {
                                error!("Error en conexión desde {}: {:#}", peer_addr, e);
                            } else {
                                info!("Conexión desde {} finalizada correctamente", peer_addr);
                            }
                        });
                    }
                    Err(e) => {
                        warn!("Error aceptando conexión: {}", e);
                    }
                }
            }
        }
    }

    Ok(())
}

async fn handshake_and_create_server_session(
    stream: &mut TcpStream,
) -> Result<(ServerSession, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
    use rml_rtmp::handshake::{Handshake, HandshakeProcessResult, PeerType};

    let mut hs = Handshake::new(PeerType::Server);
    let mut buf = [0u8; 4096];
    let mut leftover = Vec::new();

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
                leftover = remaining_bytes;
                break;
            }
        }
    }

    let config = ServerSessionConfig::new();
    let (server_session, initial_results) = ServerSession::new(config)?;
    for res in initial_results {
        if let ServerSessionResult::OutboundResponse(packet) = res {
            stream.write_all(&packet.bytes).await?;
        }
    }

    Ok((server_session, leftover))
}

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

struct PushClient {
    tx_feed: mpsc::UnboundedSender<Bytes>,
    client_state: Arc<RwLock<ClientStateWrapper>>,
    publish_ready_rx: watch::Receiver<bool>,
}

struct ClientStateWrapper {
    session: ClientSession,
    target_stream: String,

    prepublish_video_buffer: VecDeque<Bytes>,
    prepublish_audio_buffer: VecDeque<Bytes>,
    prepublish_metadata: Option<StreamMetadata>,
}

trait AsyncReadWrite: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> AsyncReadWrite for T {}

type DynStream = Box<dyn AsyncReadWrite + 'static>;

impl PushClient {
    async fn connect_and_publish(
        url: &Url,
        stream_key: String,
    ) -> Result<PushClient, Box<dyn std::error::Error + Send + Sync>> {
        let host = url
            .host_str()
            .ok_or_else(|| format!("URL sin host válido: {}", url))?
            .to_string();
        let port = url.port_or_known_default().unwrap_or(1935);
        let addr = format!("{}:{}", host, port);

        info!("Conectando push client a {}", addr);

        let tcp_stream = TcpStream::connect(&addr).await?;

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

        let (mut rd_half, mut wr_half) = tokio::io::split(boxed);

        let mut client_cfg = ClientSessionConfig::new();

        let path = url.path().trim_start_matches('/');
        let app_segment = path.split('/').next().unwrap_or("");
        let tcurl = if app_segment.is_empty() {
            format!("rtmp://{}:{}/", host, port)
        } else {
            format!("rtmp://{}:{}/{}", host, port, app_segment)
        };
        client_cfg.tc_url = Some(tcurl.clone());

        let (mut client_session, initial_results) = ClientSession::new(client_cfg)?;

        let (tx, mut rx) = mpsc::unbounded_channel::<Bytes>();
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

        for r in initial_results {
            if let ClientSessionResult::OutboundResponse(packet) = r {
                let _ = tx.send(Bytes::from(packet.bytes.clone()));
            }
        }

        let app = app_segment.to_string();
        match client_session.request_connection(app.clone()) {
            Ok(ClientSessionResult::OutboundResponse(packet)) => {
                let _ = tx.send(Bytes::from(packet.bytes.clone()));
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
                            match state.session.handle_input(&buf[..n]) {
                                Ok(results) => {
                                    for r in results {
                                        match r {
                                            ClientSessionResult::OutboundResponse(packet) => {
                                                let _ = tx_clone
                                                    .send(Bytes::from(packet.bytes.clone()));
                                            }
                                            ClientSessionResult::RaisedEvent(ev) => {
                                                debug!("Push client evento: {:?}", ev);
                                                match ev {
                                                    ClientSessionEvent::ConnectionRequestAccepted => {
                                                        let stream_key = state.target_stream.clone();
                                                        match state.session.request_publishing(stream_key, PublishRequestType::Live) {
                                                            Ok(ClientSessionResult::OutboundResponse(pub_packet)) => {
                                                                let _ = tx_clone.send(Bytes::from(pub_packet.bytes.clone()));
                                                            }
                                                            Ok(_) => {}
                                                            Err(e) => {
                                                                error!("request_publishing fallo: {:?}", e);
                                                            }
                                                        }
                                                    }
                                                    ClientSessionEvent::PublishRequestAccepted => {


            let _ = publish_ready_tx.send(true);

            // enviar metadata bufferizada si la hay
            if let Some(meta) = state.prepublish_metadata.take() {
                match state.session.publish_metadata(&meta) {
                    Ok(ClientSessionResult::OutboundResponse(packet)) => {
                        let _ = tx_clone.send(Bytes::from(packet.bytes.clone()));
                    }
                    Ok(_) => {}
                    Err(e) => {
                        error!("Error sending buffered metadata: {:?}", e);
                    }
                }
            }

            // enviar video bufferizado
            while let Some(vframe) = state.prepublish_video_buffer.pop_front() {
                match state.session.publish_video_data(vframe.clone(), RtmpTimestamp::new(0), true) {
                    Ok(ClientSessionResult::OutboundResponse(packet)) => {
                        let _ = tx_clone.send(Bytes::from(packet.bytes.clone()));
                    }
                    Ok(_) => {}
                    Err(e) => {
                        error!("Error sending buffered video frame: {:?}", e);
                        break;
                    }
                }
            }

            // enviar audio bufferizado
            while let Some(aframe) = state.prepublish_audio_buffer.pop_front() {
                match state.session.publish_audio_data(aframe.clone(), RtmpTimestamp::new(0), true) {
                    Ok(ClientSessionResult::OutboundResponse(packet)) => {
                        let _ = tx_clone.send(Bytes::from(packet.bytes.clone()));
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
                                Err(e) => {
                                    error!(
                                        "Error manejando input en ClientSession (push): {:?}",
                                        e
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

    async fn feed_bytes(&self, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let mut state = self.client_state.write().await;
        let results = state.session.handle_input(bytes)?;
        for r in results {
            match r {
                ClientSessionResult::OutboundResponse(packet) => {
                    let _ = self.tx_feed.send(Bytes::from(packet.bytes.clone()));
                }
                ClientSessionResult::RaisedEvent(ev) => {
                    debug!("Client event: {:?}", ev);
                    if let ClientSessionEvent::ConnectionRequestAccepted = ev {
                        let stream_key = state.target_stream.clone();
                        if let Ok(res) = state
                            .session
                            .request_publishing(stream_key, PublishRequestType::Live)
                        {
                            match res {
                                ClientSessionResult::OutboundResponse(packet) => {
                                    let _ = self.tx_feed.send(Bytes::from(packet.bytes.clone()));
                                }
                                _ => {}
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
}

async fn handle_publisher(
    mut inbound: TcpStream,
    platforms: Arc<RwLock<Vec<Platform>>>,
    _stream_key: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("Iniciando handshake servidor con client entrante...");
    let (mut server_session, leftover) = handshake_and_create_server_session(&mut inbound).await?;
    info!("Handshake completado; creando push clients...");

    let pls = platforms.read().await.clone();
    let mut push_clients: Vec<PushClient> = Vec::new();

    for p in pls.into_iter() {
        if !["rtmp", "rtmps"].contains(&p.url.scheme()) {
            info!(
                "Ignorando plataforma con esquema distinto a rtmp/rtmps: scheme = {} url = {}",
                p.url.scheme(),
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
        let addr = format!("{}:{}", host, port);

        match timeout(
            Duration::from_secs(10),
            PushClient::connect_and_publish(&p.url, p.key.clone()),
        )
        .await
        {
            Ok(Ok(push_client)) => {
                info!("Push client activo hacia {}", addr);
                push_clients.push(push_client);
            }
            Ok(Err(e)) => {
                warn!("Push client falló al iniciar hacia {}: {}", p.url, e);
            }
            Err(_) => {
                warn!("Timeout conectando a {} para push", addr);
            }
        }
    }

    if push_clients.is_empty() {
        warn!("No hay push clients activos; cerrando conexión del publisher.");
        return Ok(());
    }

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
                ServerSessionResult::OutboundResponse(packet) => {
                    if let Err(e) = inbound.write_all(&packet.bytes).await {
                        error!("Error escribiendo al publisher: {:?}", e);
                    }
                }
                ServerSessionResult::RaisedEvent(ev) => match ev {
                    ServerSessionEvent::ConnectionRequested { request_id, .. } => {
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
                        if let Ok(out) = server_session.accept_request(request_id) {
                            for r in out {
                                if let ServerSessionResult::OutboundResponse(packet) = r {
                                    let _ = inbound.write_all(&packet.bytes).await;
                                }
                            }
                        }
                        info!(
                            "Publisher solicitó publicar app='{}' stream='{}'",
                            app_name, stream_key
                        );
                    }
                    ServerSessionEvent::VideoDataReceived {
                        data, timestamp, ..
                    } => {
                        for pc in push_clients.iter() {
                            if *pc.publish_ready_rx.borrow() {
                                let mut state = pc.client_state.write().await;
                                match state.session.publish_video_data(
                                    data.clone(),
                                    timestamp.clone(),
                                    true,
                                ) {
                                    Ok(ClientSessionResult::OutboundResponse(packet)) => {
                                        let _ = pc.tx_feed.send(Bytes::from(packet.bytes.clone()));
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
                                    timestamp.clone(),
                                    true,
                                ) {
                                    Ok(ClientSessionResult::OutboundResponse(packet)) => {
                                        let _ = pc.tx_feed.send(Bytes::from(packet.bytes.clone()));
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
                    ServerSessionEvent::StreamMetadataChanged {
                        app_name: _,
                        stream_key: _,
                        metadata,
                    } => {
                        for pc in push_clients.iter() {
                            if *pc.publish_ready_rx.borrow() {
                                let mut state = pc.client_state.write().await;
                                match state.session.publish_metadata(&metadata) {
                                    Ok(client_res) => match client_res {
                                        ClientSessionResult::OutboundResponse(packet) => {
                                            let _ =
                                                pc.tx_feed.send(Bytes::from(packet.bytes.clone()));
                                        }
                                        _ => {}
                                    },
                                    Err(e) => {
                                        error!("Error publish_metadata to push client: {:?}", e);
                                    }
                                }
                                drop(state);
                            } else {
                                // bufferiza metadata para enviarla cuando el push acepte el publish
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

        for pc in push_clients.iter() {
            let _ = pc.feed_bytes(&read_buf[..n]).await;
        }
    }

    Ok(())
}
