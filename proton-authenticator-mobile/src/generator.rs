use crate::{AuthenticatorCodeResponse, AuthenticatorEntryModel};
use proton_authenticator::generator::{
    GeneratorCurrentTimeProvider, TotpGenerationHandle, TotpGenerator as CoreTotpGenerator,
    TotpGeneratorCallback, TotpGeneratorDependencies,
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

// Totp Generator
pub struct MobileTotpGenerator {
    inner: CoreTotpGenerator,
    rt: tokio::runtime::Runtime,
}

impl MobileTotpGenerator {
    pub fn new(period: u32, current_time: Arc<dyn MobileCurrentTimeProvider>) -> Self {
        let dependencies = TotpGeneratorDependencies {
            current_time_provider: Arc::new(MobileTimeAdapter { inner: current_time }),
        };
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        Self {
            inner: CoreTotpGenerator::new(dependencies, period),
            rt,
        }
    }

    pub fn start(
        &self,
        entries: Vec<AuthenticatorEntryModel>,
        callback: Arc<dyn MobileTotpGeneratorCallback>,
    ) -> Arc<dyn MobileTotpGenerationHandle> {
        let as_entries = entries
            .into_iter()
            .map(|e| e.to_entry().expect("todo: fixme"))
            .collect();
        let adapted_callback = MobileTotpGeneratorCallbackAdapter { inner: callback };
        self.rt.handle().block_on(async move {
            let res = self.inner.start_async(as_entries, adapted_callback).await;

            Arc::new(MobileTotpGenerationHandleAdapter {
                inner: Arc::new(Mutex::new(res)),
            })
        })
    }
}
