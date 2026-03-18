use std::sync::Arc;

use proton_pass_common::passkey::{FetchError, WebauthnClientFetcher, WebauthnDomainsResponse};

#[derive(Debug, uniffi::Record)]
pub struct MobileWebauthnDomainsResponse {
    pub origins: Vec<String>,
}

#[derive(Clone, Debug, proton_pass_derive::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum MobileFetchError {
    CannotFetch(String),
    NotFound(String),
}

#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait MobileWebauthnClientFetcher: Send + Sync {
    async fn fetch(&self, url: String) -> Result<MobileWebauthnDomainsResponse, MobileFetchError>;
}

pub(crate) struct MobileWebauthnFetcherAdapter {
    inner: Arc<dyn MobileWebauthnClientFetcher>,
}

#[async_trait::async_trait(?Send)]
impl WebauthnClientFetcher for MobileWebauthnFetcherAdapter {
    async fn fetch(&self, url: String) -> Result<WebauthnDomainsResponse, FetchError> {
        self.inner
            .fetch(url)
            .await
            .map(|r| WebauthnDomainsResponse {
                origins: r.origins,
                final_url: None,
            })
            .map_err(|e| match e {
                MobileFetchError::NotFound(_) => FetchError::NotFound,
                MobileFetchError::CannotFetch(_) => FetchError::CannotFetch,
            })
    }
}

pub(crate) fn make_webauthn_client(fetcher: Arc<dyn MobileWebauthnClientFetcher>) -> Arc<dyn WebauthnClientFetcher> {
    Arc::new(MobileWebauthnFetcherAdapter { inner: fetcher }) as Arc<dyn WebauthnClientFetcher>
}
