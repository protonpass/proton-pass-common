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
    period: u32
}

impl TotpGenerator {
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
        let time_provider = self.dependencies.current_time_provider.clone();
        let entries = entries.clone();
        let cb = callback;
        let period = self.period;

        let join_handle = {
            let cancelled_cloned = cancelled.clone();
            Some(tokio::spawn(async move {
                let client = AuthenticatorClient;
                while !cancelled_cloned.load(Ordering::Relaxed) {
                    let now = time_provider.now();
                    let codes = client.generate_codes(&entries, now).expect("todo: fix me");

                    cb.on_codes(codes);
                    tokio::time::sleep(tokio::time::Duration::from_millis(period as u64)).await;
                }
            }))
        };
        TotpGenerationHandle {
            cancelled,
            join_handle,
        }
    }


    #[cfg(target_arch = "wasm32")]
    pub async fn start_async(
        &self,
        entries: Vec<AuthenticatorEntry>,
        callback: impl TotpGeneratorCallback,
    ) -> TotpGenerationHandle {
        let cancelled = Arc::new(AtomicBool::new(false));
        let time_provider = self.dependencies.current_time_provider.clone();
        let entries = entries.clone();
        let cb = callback;
        let period = self.period;

        let cancelled_cloned = cancelled.clone();
        wasm_bindgen_futures::spawn_local(async move {
            let client = AuthenticatorClient;
            while !cancelled_cloned.load(Ordering::Relaxed) {
                let now = time_provider.now();
                let codes = client.generate_codes(&entries, now).expect("todo: fix me");

                cb.on_codes(codes);
                // Wait 1 second (using the provided delay).
                gloo_timers::future::TimeoutFuture::new(period).await;
            }
        });
        TotpGenerationHandle {
            cancelled,
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
