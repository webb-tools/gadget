use regex::Regex;
use reqwest::{Client, Url};
use std::fmt::Display;

use std::io::Read;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum UrlError {
    InvalidUrl,
    UrlPointingToLocalServer,
    InvalidUrlLength,
    InvalidImageMimeType,
    InvalidTwitterUrlRegex,
    EmptyText,
    TextTooLong,
    InvalidText,
}

impl Display for UrlError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            UrlError::InvalidUrl => write!(f, "Invalid URL"),
            UrlError::UrlPointingToLocalServer => write!(f, "URL pointing to local server"),
            UrlError::InvalidUrlLength => write!(f, "URL too long"),
            UrlError::InvalidImageMimeType => write!(f, "Invalid image MIME type"),
            UrlError::InvalidTwitterUrlRegex => write!(f, "Invalid Twitter URL"),
            UrlError::EmptyText => write!(f, "Empty text"),
            UrlError::TextTooLong => write!(f, "Text too long"),
            UrlError::InvalidText => write!(f, "Invalid text"),
        }
    }
}

pub fn is_valid_ethereum_address(address: &str) -> bool {
    let re = Regex::new(r"^0x[0-9a-fA-F]{40}$").unwrap();
    re.is_match(address)
}

pub fn check_if_url_is_valid(url: &str) -> Result<(), UrlError> {
    if url.is_empty() {
        return Err(UrlError::InvalidUrl);
    }
    if url.contains("localhost") || url.contains("127.0.0.1") {
        return Err(UrlError::UrlPointingToLocalServer);
    }
    if url.len() > 1024 {
        return Err(UrlError::InvalidUrlLength);
    }
    let parsed_url = Url::parse(url).map_err(|_| UrlError::InvalidUrl)?;
    if parsed_url.scheme().is_empty() || parsed_url.host().is_none() {
        return Err(UrlError::InvalidUrl);
    }
    Ok(())
}

pub async fn read_public_url(url: &str) -> Result<Vec<u8>, UrlError> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .map_err(|_| UrlError::InvalidUrl)?;
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|_| UrlError::InvalidUrl)?;
    if response.status().is_client_error() || response.status().is_server_error() {
        return Err(UrlError::InvalidUrl);
    }
    let data = response.bytes().await.map_err(|_| UrlError::InvalidUrl)?;
    Ok(data.to_vec())
}

pub async fn is_image_url(url: &str) -> Result<(), UrlError> {
    check_if_url_is_valid(url)?;
    let data = read_public_url(url).await?;
    let mime = tree_magic_mini::from_u8(&data);
    if mime != "image/png" {
        return Err(UrlError::InvalidImageMimeType);
    }
    Ok(())
}

pub fn check_if_valid_twitter_url(url: &str) -> Result<(), UrlError> {
    check_if_url_is_valid(url)?;
    let re =
        Regex::new(r"^(?:https?://)?(?:www\.)?(?:twitter\.com/\w+|x\.com/\w+)(?:/?|$)").unwrap();
    if !re.is_match(url) {
        return Err(UrlError::InvalidTwitterUrlRegex);
    }
    Ok(())
}

pub fn validate_text(text: &str) -> Result<(), UrlError> {
    if text.is_empty() {
        return Err(UrlError::EmptyText);
    }
    if text.len() > 500 {
        return Err(UrlError::TextTooLong);
    }
    let re = Regex::new(r"^[a-zA-Z0-9 +.,;:?!'\-_()/[\]~&#$-%]+$").unwrap();
    if !re.is_match(text) {
        return Err(UrlError::InvalidText);
    }
    Ok(())
}
