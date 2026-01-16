use serde::Deserialize;
use std::fs;
use std::path::Path;
use url::Url;

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub rtmp_addr: String,
    pub rtmp_port: u16,
    pub stream_key: String,
    pub platform: Option<Vec<Platform>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Platform {
    pub url: Url,
    pub key: String,
    pub _orientation: Orientation,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Orientation {
    #[default]
    Horizontal,
    Vertical,
}

impl Config {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    }
}
