use parking_lot::Mutex;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tracing::{error, info, warn};
use tracing_subscriber::filter::LevelFilter;

mod bitstream_converter;
mod client;
mod config;
mod error;
mod img;
mod provider;
mod server;

use crate::client::handle_publisher;
use crate::config::Config;

pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin> AsyncReadWrite for T {}

pub type DynStream = Box<dyn AsyncReadWrite + 'static>;

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

    let platforms = Arc::new(Mutex::new(platform.clone().unwrap_or_default()));

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
