use std::error::Error;
use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Debug)]
#[allow(dead_code)]
#[allow(clippy::enum_variant_names)]
pub enum StreamKeyError {
    OAuthError(String),
    ApiError(String),
    ParseError(String),
    NetworkError(String),
}

impl fmt::Display for StreamKeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            StreamKeyError::OAuthError(msg) => write!(f, "OAuth Error: {msg}"),
            StreamKeyError::ApiError(msg) => write!(f, "API Error: {msg}"),
            StreamKeyError::ParseError(msg) => write!(f, "Parse Error: {msg}"),
            StreamKeyError::NetworkError(msg) => write!(f, "Network Error: {msg}"),
        }
    }
}

impl Error for StreamKeyError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct StreamKey {
    pub key: String,
    pub rtmp_url: String,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct OAuth2Config {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub access_token: Option<String>,
}

#[allow(dead_code)]
pub trait StreamKeyProvider: Send + Sync {
    const NAME: &str;

    fn get_auth_url(&self, state: &str, scopes: &[&str]) -> String;
    async fn exchange_code(&mut self, code: &str) -> Result<String, StreamKeyError>;
    async fn get_stream_key(&self) -> Result<StreamKey, StreamKeyError>;
    async fn refresh_token(&mut self, refresh_token: &str) -> Result<String, StreamKeyError>;
}
