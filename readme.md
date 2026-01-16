# Reestream - RTMP Multistream Demuxer

## Overview
RTMP relay server that receives a single stream and forwards to multiple platforms (Twitch, Facebook, Instagram, YouTube).

## Architecture

### Components
- **main.rs**: TCP listener, connection handling, config loading
- **server.rs**: RTMP handshake, server session setup (low-latency config)
- **client.rs**: Publisher connection handling, stream forwarding to platforms
- **config.rs**: TOML-based configuration parsing
- **provider.rs**: Stream key provider abstraction (OAuth2)
- **error.rs**: Centralized error types

### Flow
1. Listen on RTMP port (default 1945)
2. Accept publisher connection
3. Perform RTMP handshake
4. Validate stream key
5. Forward packets to all configured platforms (RTMP/RTMPS)

## Configuration

### config.toml
```toml
rtmp_addr = "0.0.0.0"
rtmp_port = 1945
stream_key = "your-key"

[[platform]]
url = "rtmp://live.twitch.tv/app"
key = "stream-key"
orientation = "horizontal" # or "vertical"
```

### CLI
```bash
reestream --config config.toml
```

## Specs

### Low Latency
- Chunk size: 128 bytes
- ACK window: 256KB
- TCP_NODELAY enabled

### Supported Protocols
- Input: RTMP
- Output: RTMP, RTMPS (via tokio-native-tls)

### Platforms
Pre-configured for: Twitch, Facebook, Instagram, YouTube. Extensible via config.

## Dependencies
- rml_rtmp: RTMP protocol
- tokio: Async runtime
- reqwest: HTTP client (OAuth2)
- toml: Config parsing