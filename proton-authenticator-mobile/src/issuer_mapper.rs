use proton_authenticator::TOTPIssuerMapper;

#[derive(uniffi::Object)]
pub struct AuthenticatorIssuerMapper {
    inner: TOTPIssuerMapper,
}

#[derive(uniffi::Record)]
pub struct IssuerInfo {
    pub domain: String,
    pub icon_url: String,
}

impl From<proton_authenticator::issuer_mapper::IssuerInfo> for IssuerInfo {
    fn from(value: proton_authenticator::issuer_mapper::IssuerInfo) -> Self {
        Self {
            domain: value.domain,
            icon_url: value.icon_url,
        }
    }
}

#[uniffi::export]
impl AuthenticatorIssuerMapper {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self {
            inner: TOTPIssuerMapper::new(),
        }
    }

    pub fn lookup(&self, issuer: String) -> Option<IssuerInfo> {
        self.inner.lookup(&issuer).map(IssuerInfo::from)
    }
}
