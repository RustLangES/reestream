use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use tracing_subscriber::filter::LevelFilter;

mod client;
mod config;
mod error;
mod provider;
mod server;

use crate::client::handle_publisher;
use crate::config::Config;

pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin> AsyncReadWrite for T {}

pub type DynStream = Box<dyn AsyncReadWrite + 'static>;

#[derive(clap::Parser)]
struct Args {
    /// Define config.toml path
    #[clap(long, short, default_value = "config.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_line_number(true)
        .with_max_level(LevelFilter::DEBUG)
        .init();

    let args = Args::parse();
    let config = Config::from_file(args.config)?;
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
                        // reduce latency: disable Nagle on incoming socket
                        if let Err(e) = socket.set_nodelay(true) {
                            warn!("No se pudo set_nodelay al socket entrante: {}", e);
                        }

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
