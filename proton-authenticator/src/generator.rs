use crate::{AuthenticatorClient, AuthenticatorCodeResponse, AuthenticatorEntry};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

//
// Core traits and types
//
pub trait GeneratorCurrentTimeProvider: Send + Sync {
    fn now(&self) -> u64;
}

// Use Arc pointers so the dependencies can be cloned into the worker thread.
#[derive(Clone)]
pub struct TotpGeneratorDependencies {
    pub current_time_provider: Arc<dyn GeneratorCurrentTimeProvider>,
}

pub trait TotpGeneratorCallback: Send + Sync + 'static {
    fn on_codes(&self, codes: Vec<AuthenticatorCodeResponse>);
}

//
// The TOTP generator and its cancellation handle.
//
pub struct TotpGenerator {
    dependencies: TotpGeneratorDependencies,
    period: u32,
}

impl TotpGenerator {
    const MAX_ERRORS: usize = 3;

    pub fn new(dependencies: TotpGeneratorDependencies, period: u32) -> Self {
        Self { dependencies, period }
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub async fn start_async(
        &self,
        entries: Vec<AuthenticatorEntry>,
        callback: impl TotpGeneratorCallback,
    ) -> TotpGenerationHandle {
        let cancelled = Arc::new(AtomicBool::new(false));

        let join_handle = {
            let cancelled_cloned = cancelled.clone();
            let time_provider = self.dependencies.current_time_provider.clone();
            let period = self.period;
            Some(tokio::spawn(async move {
                Self::generate_codes_loop(entries, callback, time_provider, cancelled_cloned, || async move {
                    tokio::time::sleep(tokio::time::Duration::from_millis(period as u64)).await;
                })
                .await;
            }))
        };
        TotpGenerationHandle { cancelled, join_handle }
    }

    #[cfg(target_arch = "wasm32")]
    pub async fn start_async(
        &self,
        entries: Vec<AuthenticatorEntry>,
        callback: impl TotpGeneratorCallback,
    ) -> TotpGenerationHandle {
        let cancelled = Arc::new(AtomicBool::new(false));
        let time_provider = self.dependencies.current_time_provider.clone();
        let period = self.period;

        let cancelled_cloned = cancelled.clone();
        wasm_bindgen_futures::spawn_local(async move {
            Self::generate_codes_loop(entries, callback, time_provider, cancelled_cloned, || async move {
                gloo_timers::future::TimeoutFuture::new(period).await;
            })
            .await;
        });
        TotpGenerationHandle { cancelled }
    }

    async fn generate_codes_loop<Fut>(
        entries: Vec<AuthenticatorEntry>,
        callback: impl TotpGeneratorCallback,
        time_provider: Arc<dyn GeneratorCurrentTimeProvider>,
        cancelled: Arc<AtomicBool>,
        delayer: impl Fn() -> Fut,
    ) where
        Fut: std::future::Future<Output = ()>,
    {
        let client = AuthenticatorClient;
        let prefix = "[TOTP_GENERATOR]";
        let mut error_count = 0;
        while !cancelled.load(Ordering::Relaxed) {
            info!("{prefix} Started TOTP generator");
            let now = time_provider.now();
            debug!("{prefix} Got now {now}");
            match client.generate_codes(&entries, now) {
                Ok(codes) => {
                    info!("{prefix} Got codes size={}", codes.len());
                    callback.on_codes(codes);
                }
                Err(e) => {
                    warn!("{prefix} Failed to generate codes: {e}");
                    error_count += 1;
                    if error_count > Self::MAX_ERRORS {
                        break;
                    }
                }
            }

            delayer().await
        }
    }
}

pub struct TotpGenerationHandle {
    cancelled: Arc<AtomicBool>,
    #[cfg(not(target_arch = "wasm32"))]
    join_handle: Option<tokio::task::JoinHandle<()>>,
}

impl TotpGenerationHandle {
    /// Cancels the generation loop and waits for the thread to finish.
    pub fn cancel(&mut self) {
        self.cancelled.store(true, Ordering::Relaxed);
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(handle) = self.join_handle.take() {
            handle.abort();
        }
    }
}
