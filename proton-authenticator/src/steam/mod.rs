use base64::Engine;
use url::Url;

pub static PERIOD: u16 = 30;
static CODE_DIGITS: usize = 5;
static STEAM_CHARS: [char; 26] = [
    '2', '3', '4', '5', '6', '7', '8', '9', 'B', 'C', 'D', 'F', 'G', 'H', 'J', 'K', 'M', 'N', 'P', 'Q', 'R', 'T', 'V',
    'W', 'X', 'Y',
];

#[derive(Debug)]
pub enum SteamTotpError {
    BadSecret,
    BadUrl,
}

#[derive(Clone, Debug)]
pub struct SteamTotp {
    secret: Vec<u8>,
}

impl SteamTotp {
    pub fn new(secret: &str) -> Result<SteamTotp, SteamTotpError> {
        if secret.is_empty() {
            return Err(SteamTotpError::BadSecret);
        }
        match base64::engine::general_purpose::STANDARD.decode(secret) {
            Ok(secret) => Ok(SteamTotp { secret }),
            Err(_) => Err(SteamTotpError::BadSecret),
        }
    }

    pub fn new_from_uri(uri: &str) -> Result<SteamTotp, SteamTotpError> {
        let parsed = Url::parse(uri).map_err(|_| SteamTotpError::BadUrl)?;
        Self::new_from_parsed_uri(&parsed, true)
    }

    pub fn new_from_parsed_uri(uri: &Url, check_scheme: bool) -> Result<SteamTotp, SteamTotpError> {
        if uri.scheme() != "steam" && check_scheme {
            return Err(SteamTotpError::BadUrl);
        }

        match uri.host_str() {
            Some(host) => Self::new(host),
            None => Err(SteamTotpError::BadUrl),
        }
    }

    pub fn new_from_otp_uri(uri: &Url) -> Result<SteamTotp, SteamTotpError> {
        if uri.scheme() != "otpauth" {
            return Err(SteamTotpError::BadUrl);
        }

        let secret = uri
            .query_pairs()
            .filter(|(k, _)| k == "secret")
            .map(|(_, v)| v.to_string())
            .next()
            .ok_or(SteamTotpError::BadUrl)?;

        Self::new(&secret)
    }

    pub fn new_from_raw(secret: Vec<u8>) -> Self {
        SteamTotp { secret }
    }

    pub fn generate(&self, time: i64) -> String {
        // 8-byte big-endian representation of the current interval
        let interval = Self::code_interval(time).to_be_bytes();

        // Calculate HMAC-SHA1
        let mac = hmac_sha1::hmac_sha1(&self.secret, &interval);

        // Dynamic offset in the last byte
        let start = (mac[19] & 0x0f) as usize;
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&mac[start..start + 4]);

        // Truncate to 31 bits
        let full_code = u32::from_be_bytes(bytes) & 0x7fffffff;

        // Convert into STEAM_CHARS
        let mut code = String::new();
        let mut temp_code = full_code;
        for _ in 0..CODE_DIGITS {
            let idx = (temp_code % (STEAM_CHARS.len() as u32)) as usize;
            code.push(STEAM_CHARS[idx]);
            temp_code /= STEAM_CHARS.len() as u32;
        }
        code
    }

    pub fn uri(&self) -> String {
        let encoded_secret = base64::engine::general_purpose::STANDARD.encode(&self.secret);
        format!("steam://{encoded_secret}")
    }

    fn code_interval(time: i64) -> u64 {
        (time / ((PERIOD * 1000) as i64)) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    fn generate_code() -> Vec<u8> {
        let mut rng = rand::rng();
        let mut code = Vec::new();
        for _ in 0..10 {
            let bytes = rng.next_u64().to_be_bytes();
            for b in bytes.into_iter() {
                code.push(b);
            }
        }

        code
    }

    #[test]
    fn generates_correct_code() {
        let secret ="5Mmi0hvgpxaToJ3qcRG7ErLgMAXbWLYBYNm8MjLpHV4wIfiLRnwi1oEsZYBMk5GcmEBDlSCRueibOtHJP7t9DOJv7JDXY5kH12KIF0HHTnE=";
        let totp = SteamTotp::new(secret).expect("should be able to create");
        let result = totp.generate(1737960861);
        assert_eq!("X45DW", result);
    }

    #[test]
    fn generate_generates_correct_format() {
        let totp = SteamTotp::new_from_raw(generate_code());
        let result = totp.generate(1737960861);

        // Check it outputs the correct length
        assert_eq!(result.len(), CODE_DIGITS);

        // Check it uses the correct dictionary
        for ch in result.chars() {
            assert!(STEAM_CHARS.contains(&ch));
        }
    }

    #[test]
    fn fails_if_bad_secret() {
        let res = SteamTotp::new("invalid base64");
        assert!(res.is_err());
    }

    #[test]
    fn test_code_generation_is_deterministic_for_fixed_interval() {
        let secret = generate_code();
        let totp1 = SteamTotp::new_from_raw(secret.clone());
        let totp2 = SteamTotp::new_from_raw(secret);

        let code1 = totp1.generate(1737960861);
        let code2 = totp2.generate(1737960861);
        assert_eq!(code1, code2, "Code should be deterministic for the same interval");
    }
}
