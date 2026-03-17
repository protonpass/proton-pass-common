use std::sync::Arc;

use passkey::client::{Fetcher, RelatedOriginResponse, WebauthnError as PasskeyWebauthnError};
use passkey_types::webauthn::WellKnown;
use url::Url;

pub struct WebauthnDomainsResponse {
    pub origins: Vec<String>,
}

#[derive(Debug)]
pub enum FetchError {
    CannotFetch,
    NotFound,
}

#[async_trait::async_trait(?Send)]
pub trait WebauthnClientFetcher: Send + Sync {
    async fn fetch(&self, url: String) -> Result<WebauthnDomainsResponse, FetchError>;
}

pub struct WebauthnFetcher {
    client: Option<Arc<dyn WebauthnClientFetcher>>,
}

impl WebauthnFetcher {
    pub fn new(client: Option<Arc<dyn WebauthnClientFetcher>>) -> Self {
        Self { client }
    }
}

impl Fetcher for WebauthnFetcher {
    async fn fetch_related_origins(&self, url: Url) -> Result<RelatedOriginResponse, PasskeyWebauthnError> {
        let fetcher = self.client.as_ref().ok_or(PasskeyWebauthnError::FetcherError)?;
        let resp = fetcher
            .fetch(url.to_string())
            .await
            .map_err(|_| PasskeyWebauthnError::FetcherError)?;
        let origins: Vec<Url> = resp.origins.iter().filter_map(|s| Url::parse(s).ok()).collect();
        Ok(RelatedOriginResponse {
            payload: WellKnown { origins },
            final_url: url,
        })
    }
}
