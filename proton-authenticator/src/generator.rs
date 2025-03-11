use crate::{AuthenticatorClient, AuthenticatorCodeResponse, AuthenticatorEntry};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;

//
// Core traits and types
//
pub trait GeneratorDelay: Send + Sync {
    fn delay(&self, millis: u64);
}

pub trait GeneratorCurrentTimeProvider: Send + Sync {
    fn now(&self) -> u64;
}

// Use Arc pointers so the dependencies can be cloned into the worker thread.
#[derive(Clone)]
pub struct TotpGeneratorDependencies {
    pub delay: Arc<dyn GeneratorDelay>,
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
}

impl TotpGenerator {
    pub fn new(dependencies: TotpGeneratorDependencies) -> Self {
        Self { dependencies }
    }

    /// Starts a background thread that periodically computes codes.
    /// Returns a handle that can cancel further callbacks.
    pub fn start(
        &self,
        entries: Vec<AuthenticatorEntry>,
        callback: impl TotpGeneratorCallback,
    ) -> TotpGenerationHandle {
        let cancelled = Arc::new(AtomicBool::new(false));
        let delay = self.dependencies.delay.clone();
        let time_provider = self.dependencies.current_time_provider.clone();

        // Spawn a thread that loops until cancelled.
        let cancelled_cloned = cancelled.clone();
        let join_handle = thread::spawn(move || {
            let client = AuthenticatorClient;
            while !cancelled_cloned.load(Ordering::Relaxed) {
                let now = time_provider.now();
                let codes = client.generate_codes(&entries, now).expect("todo: fix me");

                callback.on_codes(codes);
                // Wait 1 second (using the provided delay).
                delay.delay(1000);
            }
        });

        TotpGenerationHandle {
            cancelled,
            join_handle: Some(join_handle),
        }
    }
}

pub struct TotpGenerationHandle {
    cancelled: Arc<AtomicBool>,
    join_handle: Option<thread::JoinHandle<()>>,
}

impl TotpGenerationHandle {
    /// Cancels the generation loop and waits for the thread to finish.
    pub fn cancel(&mut self) {
        self.cancelled.store(true, Ordering::Relaxed);
        if let Some(handle) = self.join_handle.take() {
            let _ = handle.join();
        }
    }
}
