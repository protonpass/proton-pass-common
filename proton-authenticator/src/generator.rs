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
    only_on_code_change: bool,
    period_ms: u32,
}

impl TotpGenerator {
    const MAX_ERRORS: usize = 3;

    pub fn new(dependencies: TotpGeneratorDependencies, only_on_code_change: bool, period_ms: u32) -> Self {
        Self {
            dependencies,
            only_on_code_change,
            period_ms,
        }
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
            let period = self.period_ms;
            let only_on_code_change = self.only_on_code_change;
            Some(tokio::spawn(async move {
                Self::generate_codes_loop(
                    entries,
                    only_on_code_change,
                    callback,
                    time_provider,
                    cancelled_cloned,
                    || async move {
                        tokio::time::sleep(tokio::time::Duration::from_millis(period as u64)).await;
                    },
                )
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
        let period = self.period_ms;
        let only_on_code_change = self.only_on_code_change;

        let cancelled_cloned = cancelled.clone();
        wasm_bindgen_futures::spawn_local(async move {
            Self::generate_codes_loop(
                entries,
                only_on_code_change,
                callback,
                time_provider,
                cancelled_cloned,
                || async move {
                    gloo_timers::future::TimeoutFuture::new(period).await;
                },
            )
            .await;
        });
        TotpGenerationHandle { cancelled }
    }

    async fn generate_codes_loop<Fut>(
        entries: Vec<AuthenticatorEntry>,
        only_on_code_change: bool,
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
        let mut has_generated = false;
        info!("{prefix} Started TOTP generator");

        let mut last_state: Option<String> = None;
        while !cancelled.load(Ordering::Relaxed) {
            let now = time_provider.now();
            debug!("{prefix} Got now {now}");
            let should_generate = if !has_generated {
                true
            } else if only_on_code_change {
                entries.iter().any(|e| now % e.period() as u64 == 0)
            } else {
                true
            };
            if should_generate {
                trace!("{prefix} Generating codes");
                match client.generate_codes(&entries, now) {
                    Ok(codes) => {
                        let should_invoke = if only_on_code_change {
                            let codes_as_str = codes
                                .iter()
                                .map(|c| c.current_code.as_str())
                                .collect::<Vec<&str>>()
                                .join("");
                            let res = match last_state {
                                Some(ref last) => codes_as_str != last.as_str(),
                                None => true,
                            };
                            last_state = Some(codes_as_str);
                            res
                        } else {
                            true
                        };

                        if should_invoke {
                            trace!("{prefix} Got codes size={}", codes.len());
                            callback.on_codes(codes);
                        } else {
                            trace!("{prefix} Callback not invoked");
                        }
                    }
                    Err(e) => {
                        warn!("{prefix} Failed to generate codes: {e}");
                        error_count += 1;
                        if error_count > Self::MAX_ERRORS {
                            break;
                        }
                    }
                }
                has_generated = true;
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
        info!("[TOTP_GENERATOR] Canceled");
        self.cancelled.store(true, Ordering::Relaxed);
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(ref handle) = self.join_handle {
            handle.abort();
        }
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn get_entry(uri: &str) -> AuthenticatorEntry {
        AuthenticatorEntry::from_uri(uri, None).expect("Failed to parse authenticator entry")
    }

    struct TestCurrentTimeProvider {
        values: Vec<u64>,
        idx: Mutex<usize>,
    }

    impl TestCurrentTimeProvider {
        pub fn new(values: Vec<u64>) -> Self {
            Self {
                idx: Mutex::new(0),
                values,
            }
        }
    }

    impl GeneratorCurrentTimeProvider for TestCurrentTimeProvider {
        fn now(&self) -> u64 {
            let mut current_idx = self.idx.lock().unwrap();
            let res = self.values.get(*current_idx).expect("could not get time");
            *current_idx += 1;

            *res
        }
    }

    struct TestTotpGeneratorCallbackAccumulator {
        values: Mutex<Vec<Vec<AuthenticatorCodeResponse>>>,
    }

    impl TestTotpGeneratorCallbackAccumulator {
        pub fn new() -> Self {
            Self {
                values: Mutex::new(Vec::new()),
            }
        }

        pub fn get_values(&self) -> Vec<Vec<AuthenticatorCodeResponse>> {
            let list_ref = self.values.lock().unwrap();
            (*list_ref).clone()
        }

        fn on_codes_callback(&self, codes: Vec<AuthenticatorCodeResponse>) {
            let mut values_ref = self.values.lock().unwrap();
            values_ref.push(codes);
        }
    }

    impl TotpGeneratorCallback for TestTotpGeneratorCallbackAccumulator {
        fn on_codes(&self, codes: Vec<AuthenticatorCodeResponse>) {
            self.on_codes_callback(codes)
        }
    }

    impl TotpGeneratorCallback for Arc<TestTotpGeneratorCallbackAccumulator> {
        fn on_codes(&self, codes: Vec<AuthenticatorCodeResponse>) {
            self.on_codes_callback(codes)
        }
    }

    #[tokio::test]
    async fn can_generate_codes() {
        let entry1 =
            get_entry("otpauth://totp/MYLABEL?secret=MYSECRET&issuer=MYISSUER&algorithm=SHA256&digits=8&period=15");
        let entry2 =
            get_entry("otpauth://totp/MYLABEL?secret=MYSECRET123&issuer=MYISSUER&algorithm=SHA256&digits=8&period=15");

        let current_time_provider = TestCurrentTimeProvider::new(vec![1741764120, 1741789012, 1741890123]);

        let period = 10;
        let dependencies = TotpGeneratorDependencies {
            current_time_provider: Arc::new(current_time_provider),
        };
        let generator = TotpGenerator::new(dependencies, false, period);

        let accumulator_callback = Arc::new(TestTotpGeneratorCallbackAccumulator::new());

        let accumulator_clone = accumulator_callback.clone();
        let mut handle = generator.start_async(vec![entry1, entry2], accumulator_clone).await;

        let times = 3;
        tokio::time::sleep(tokio::time::Duration::from_millis((period * times) as u64)).await;

        {
            let accumulated_ref = accumulator_callback.get_values();
            assert_eq!(accumulated_ref.len(), times as usize);
        }

        handle.cancel();
        tokio::time::sleep(tokio::time::Duration::from_millis((period * 2) as u64)).await;

        let accumulated_ref = accumulator_callback.get_values();
        assert_eq!(accumulated_ref.len(), times as usize);

        assert_eq!(2, accumulated_ref[0].len());
        assert_eq!("55894277", accumulated_ref[0][0].current_code);
        assert_eq!("32755418", accumulated_ref[0][0].next_code);
        assert_eq!("03271278", accumulated_ref[0][1].current_code);
        assert_eq!("94297675", accumulated_ref[0][1].next_code);

        assert_eq!("74506379", accumulated_ref[1][0].current_code);
        assert_eq!("66003564", accumulated_ref[1][0].next_code);
        assert_eq!("66986124", accumulated_ref[1][1].current_code);
        assert_eq!("11675313", accumulated_ref[1][1].next_code);

        assert_eq!("07871325", accumulated_ref[2][0].current_code);
        assert_eq!("49179669", accumulated_ref[2][0].next_code);
        assert_eq!("77812358", accumulated_ref[2][1].current_code);
        assert_eq!("54935379", accumulated_ref[2][1].next_code);

        let handle_err = handle
            .join_handle
            .unwrap()
            .await
            .expect_err("should have an error (Cancelled)");
        assert!(handle_err.is_cancelled());
    }

    #[tokio::test]
    async fn can_generate_codes_only_on_code_change() {
        let entry =
            get_entry("otpauth://totp/MYLABEL?secret=MYSECRET&issuer=MYISSUER&algorithm=SHA256&digits=8&period=15");

        let times_to_return = vec![
            1741764120, // Generate
            1741764121, // Don't generate
            1741764122, // Don't generate
            1741890120, // Generate
        ];
        let times = times_to_return.len();
        let current_time_provider = TestCurrentTimeProvider::new(times_to_return);

        let period = 10;
        let dependencies = TotpGeneratorDependencies {
            current_time_provider: Arc::new(current_time_provider),
        };
        let generator = TotpGenerator::new(dependencies, true, period);

        let accumulator_callback = Arc::new(TestTotpGeneratorCallbackAccumulator::new());

        let accumulator_clone = accumulator_callback.clone();
        let mut handle = generator.start_async(vec![entry], accumulator_clone).await;

        // Proceed to run all 4 ticks
        tokio::time::sleep(tokio::time::Duration::from_millis((period * times as u32) as u64)).await;

        // Should have generated only 2
        let accumulated_ref = accumulator_callback.get_values();
        assert_eq!(2, accumulated_ref.len());

        assert_eq!("55894277", accumulated_ref[0][0].current_code);
        assert_eq!("32755418", accumulated_ref[0][0].next_code);
        assert_eq!("07871325", accumulated_ref[1][0].current_code);
        assert_eq!("49179669", accumulated_ref[1][0].next_code);

        handle.cancel();
        let handle_err = handle
            .join_handle
            .unwrap()
            .await
            .expect_err("should have an error (Cancelled)");
        assert!(handle_err.is_cancelled());
    }
}
