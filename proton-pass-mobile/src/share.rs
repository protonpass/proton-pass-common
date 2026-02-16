use proton_pass_common::share::{visible_share_ids, Share};

// Re-export core types that now have uniffi bindings
pub use proton_pass_common::share::{Share as MobileShare, TargetType as MobileTargetType};

#[derive(uniffi::Object)]
pub struct ShareOverrideCalculator;

#[uniffi::export]
impl ShareOverrideCalculator {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self
    }

    pub fn get_visible_shares(&self, shares: Vec<Share>, filter_hidden: bool) -> Vec<String> {
        visible_share_ids(&shares, filter_hidden)
            .into_iter()
            .map(|s| s.to_string())
            .collect()
    }
}
