use super::{PasskeyError, PasskeyResult};
use passkey_client::UnverifiedAssetLink;
use url::Url;

const SHA256_FINGERPRINT_LENGTH: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AndroidAppOrigin {
    pub package_name: String,
    pub sha256_cert_fingerprint: Vec<u8>,
    pub rp_id: String,
}

impl AndroidAppOrigin {
    pub(crate) fn asset_link(&self) -> PasskeyResult<UnverifiedAssetLink<'_>> {
        if self.package_name.is_empty() {
            return Err(PasskeyError::InvalidUri(
                "Android app package name is empty".to_string(),
            ));
        }
        if self.sha256_cert_fingerprint.len() != SHA256_FINGERPRINT_LENGTH {
            return Err(PasskeyError::InvalidUri(format!(
                "Android app certificate fingerprint must be {SHA256_FINGERPRINT_LENGTH} bytes, got {}",
                self.sha256_cert_fingerprint.len()
            )));
        }
        let asset_link_url = Url::parse(&format!("https://{}/.well-known/assetlinks.json", self.rp_id))
            .map_err(|e| PasskeyError::InvalidUri(format!("Invalid rp id for Android app origin: {e:?}")))?;

        UnverifiedAssetLink::new(
            self.package_name.as_str(),
            &self.fingerprint_hex(),
            self.rp_id.as_str(),
            asset_link_url,
        )
        .map_err(|e| PasskeyError::InvalidUri(format!("Invalid Android app origin: {e:?}")))
    }

    fn fingerprint_hex(&self) -> String {
        self.sha256_cert_fingerprint
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origin(fingerprint: Vec<u8>, rp_id: &str) -> AndroidAppOrigin {
        AndroidAppOrigin {
            package_name: "com.example.app".to_string(),
            sha256_cert_fingerprint: fingerprint,
            rp_id: rp_id.to_string(),
        }
    }

    #[test]
    fn builds_asset_link_for_valid_origin() {
        let fingerprint: Vec<u8> = (0..32).map(|i| i * 7).collect();
        let app = origin(fingerprint.clone(), "example.com");

        let link = app.asset_link().expect("Should build asset link");

        assert_eq!(link.package_name(), "com.example.app");
        assert_eq!(link.host(), "example.com");
        assert_eq!(link.sha256_cert_fingerprint(), fingerprint.as_slice());
        assert_eq!(
            link.asset_link_url().as_str(),
            "https://example.com/.well-known/assetlinks.json"
        );
    }

    #[test]
    fn rejects_fingerprint_with_wrong_length() {
        assert!(origin(vec![0xAB; 31], "example.com").asset_link().is_err());
        assert!(origin(vec![0xAB; 33], "example.com").asset_link().is_err());
    }

    #[test]
    fn rejects_empty_package_name() {
        let mut app = origin(vec![0xAB; 32], "example.com");
        app.package_name = String::new();

        assert!(app.asset_link().is_err());
    }

    #[test]
    fn rejects_rp_id_that_changes_asset_link_path() {
        assert!(origin(vec![0xAB; 32], "example.com/evil").asset_link().is_err());
    }
}
