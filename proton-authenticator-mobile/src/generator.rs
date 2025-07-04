use crate::{AuthenticatorCodeResponse, AuthenticatorEntryModel, AuthenticatorError};
use proton_authenticator::generator::{
    GeneratorCurrentTimeProvider, TotpGenerationHandle, TotpGenerator as CoreTotpGenerator, TotpGeneratorCallback,
    TotpGeneratorDependencies,
};
use std::sync::{Arc, Mutex};

// Current Time Provider
pub trait MobileCurrentTimeProvider: Send + Sync {
    fn now(&self) -> u64;
}

pub struct MobileTimeAdapter {
    inner: Arc<dyn MobileCurrentTimeProvider>,
}

impl GeneratorCurrentTimeProvider for MobileTimeAdapter {
    fn now(&self) -> u64 {
        self.inner.now()
    }
}

// TotpGenerationHandle
pub trait MobileTotpGenerationHandle: Send + Sync {
    fn cancel(&self);
}

pub struct MobileTotpGenerationHandleAdapter {
    inner: Arc<Mutex<TotpGenerationHandle>>,
}

impl MobileTotpGenerationHandle for MobileTotpGenerationHandleAdapter {
    fn cancel(&self) {
        if let Ok(mut handle) = self.inner.lock() {
            handle.cancel();
        }
    }
}

// TotpGeneratorCallback
pub trait MobileTotpGeneratorCallback: Send + Sync {
    fn on_codes(&self, codes: Vec<AuthenticatorCodeResponse>);
}

pub struct MobileTotpGeneratorCallbackAdapter {
    inner: Arc<dyn MobileTotpGeneratorCallback>,
}

impl TotpGeneratorCallback for MobileTotpGeneratorCallbackAdapter {
    fn on_codes(&self, codes: Vec<proton_authenticator::AuthenticatorCodeResponse>) {
        let mapped = codes
            .into_iter()
            .map(|c| AuthenticatorCodeResponse {
                current_code: c.current_code,
                next_code: c.next_code,
                entry: AuthenticatorEntryModel::from(c.entry),
            })
            .collect();
        self.inner.on_codes(mapped);
    }
}

/// Callback-based TOTP generator that allows the caller to subscribe to TOTP code changes, and
/// to get notified of changes in a configurable manner
pub struct MobileTotpGenerator {
    inner: CoreTotpGenerator,
    rt: tokio::runtime::Runtime,
}

impl MobileTotpGenerator {
    const RUNTIME_THREADS: usize = 1;

    /// Create a new instance of the TOTP generator
    /// - period_ms: how often the generator should check if the codes have changed. Time in ms
    /// - only_on_code_change: if true, only invoke the callback if the codes have changed. If false, it will always be called
    /// - current_time_provider: callback that will be invoked to get the current time
    pub fn new(
        period_ms: u32,
        only_on_code_change: bool,
        current_time: Arc<dyn MobileCurrentTimeProvider>,
    ) -> Result<Self, AuthenticatorError> {
        let dependencies = TotpGeneratorDependencies {
            current_time_provider: Arc::new(MobileTimeAdapter { inner: current_time }),
        };
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(Self::RUNTIME_THREADS)
            .enable_time()
            .build()
            .map_err(|e| proton_authenticator::AuthenticatorError::Unknown(format!("Cannot start runtime: {e:?}")))?;
        Ok(Self {
            inner: CoreTotpGenerator::new(dependencies, only_on_code_change, period_ms),
            rt,
        })
    }

    /// Start generating the codes.
    ///  - entries: Entries to generate codes for
    ///  - callback: callback that will be invoked when new codes are generated
    pub fn start(
        &self,
        entries: Vec<AuthenticatorEntryModel>,
        callback: Arc<dyn MobileTotpGeneratorCallback>,
    ) -> Result<Arc<dyn MobileTotpGenerationHandle>, AuthenticatorError> {
        let mut as_entries = vec![];
        for entry in entries {
            as_entries.push(entry.to_entry()?);
        }
        let adapted_callback = MobileTotpGeneratorCallbackAdapter { inner: callback };
        Ok(self.rt.handle().block_on(async move {
            let res = self.inner.start_async(as_entries, adapted_callback).await;

            Arc::new(MobileTotpGenerationHandleAdapter {
                inner: Arc::new(Mutex::new(res)),
            })
        }))
    }
}
