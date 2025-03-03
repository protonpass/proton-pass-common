use proton_pass_totp::TOTP;

const TEST_TIMESTAMP: u64 = 1741011292;

macro_rules! totp_test {
    ($($name:ident: $params:expr,)*) => {
    $(
        #[test]
        fn $name() {
            let (is_valid, expected, uri) = $params;

            let res = TOTP::from_uri(uri);

            if is_valid {
                assert!(res.is_ok());
                let totp = res.expect("should be able to parse");
                let code = totp.generate_token(TEST_TIMESTAMP).expect("should be able to generate token");
                assert_eq!(code, expected);
            } else {
                assert!(res.is_err());
            }
        }
    )*
    }
}

totp_test! {

    normal_code: (true, "419231", "otpauth://totp/issuer%3Aaccount%20name?secret=QWERTYUIOP&digits=6&issuer=issuer&algorithm=SHA1&period=30"),
    one_digit_code_300_second_period: (true, "7", "otpauth://totp/issuer%3Aaccount%20name?secret=QWERTYUIOP&digits=1&issuer=issuer&algorithm=SHA1&period=300"),
    sha_256_algorithm: (true, "878984", "otpauth://totp/issuer%3Aaccount%20name?secret=QWERTYUIOP&digits=6&issuer=issuer&algorithm=SHA256&period=30"),
    sha_512_algorithm: (true, "560428", "otpauth://totp/issuer%3Aaccount%20name?secret=QWERTYUIOP&digits=6&issuer=issuer&algorithm=SHA512&period=30"),
    invalid_code_negative_period: (false, "", "otpauth://totp/issuer%3Aaccount%20name?secret=QWERTYUIOP&digits=6&issuer=issuer&algorithm=SHA1&period=-30"),
    no_issuer_in_label: (true, "419231", "otpauth://totp/test%40example.com?secret=QWERTYUIOP&digits=6&issuer=&algorithm=SHA1&period=30"),
    separate_issuer: (true, "419231", "otpauth://totp/test%40example.com?secret=QWERTYUIOP&digits=6&issuer=example.org&algorithm=SHA1&period=30"),
    no_secret: (false, "", "otpauth://totp/test%40example.com?secret=&digits=6&issuer=example.org&algorithm=SHA1&period=30"),
    no_label: (true, "419231", "otpauth://totp/?secret=QWERTYUIOP&digits=6&issuer=&algorithm=SHA1&period=30"),
    non_ascii_account: (true, "419231", "otpauth://totp/%E8%8E%8E%E5%A3%AB%E6%AF%94%E4%BA%9A?secret=QWERTYUIOP&digits=6&issuer=&algorithm=SHA1&period=30"),
    non_ascii_account_not_url_encoded: (true, "419231", "otpauth://totp/莎士比亚?secret=QWERTYUIOP&digits=6&issuer=&algorithm=SHA1&period=30"),
    emoji_label_not_url_encoded: (true, "419231", "otpauth://totp/🏴‍☠️:🏳️‍🌈?secret=QWERTYUIOP&digits=6&issuer=&algorithm=SHA1&period=30"),
    extra_colon_in_label: (true, "419231", "otpauth://totp/Matrix:@edent_:matrix.org?secret=QWERTYUIOP&digits=6&issuer=&algorithm=SHA1&period=30"),
    extra_spaces_in_label: (true, "419231", "otpauth://totp/Example%20Website%3A%20%20%20%20%20%20%20%20%20%20%20%20test%40example.com?secret=QWERTYUIOP&digits=6&issuer=&algorithm=SHA1&period=30"),
    invalid_algorthm_sha1_not_sha_hyphen_1: (false, "", "otpauth://totp/issuer%3Aaccount%20name?secret=QWERTYUIOP&digits=6&issuer=issuer&algorithm=SHA-1&period=30"),
    secret_with_padding: (true, "419231", "otpauth://totp/issuer%3Aaccount%20name?secret=QWERTYUIOP======&digits=6&issuer=issuer&algorithm=SHA1&period=30"),
    zero_second_period: (false, "", "otpauth://totp/issuer%3Aaccount%20name?secret=QWERTYUIOP&digits=6&issuer=issuer&algorithm=SHA1&period=0"),
    issuer_mismatch: (true, "419231", "otpauth://totp/example.com%3Aaccount%20name?secret=QWERTYUIOP&digits=6&issuer=microsoft.com&algorithm=SHA1&period=30"),

    // Ignored ones

    // We allow for a max digits of 9, otherwise it will overflow
    // ten_digit_code_3_second_period: (true, "0411324415", "otpauth://totp/issuer%3Aaccount%20name?secret=QWERTYUIOP&digits=10&issuer=issuer&algorithm=SHA1&period=3"),

    // We allow for a max of 2^16 period
    // one_billion_second_period: (true, "011217", "otpauth://totp/issuer%3Aaccount%20name?secret=QWERTYUIOP&digits=6&issuer=issuer&algorithm=SHA1&period=1000000000"),

    // We allow for 2^8 digits
    // invalid_code_too_many_digits: (false, "", "otpauth://totp/issuer%3Aaccount%20name?secret=QWERTYUIOP&digits=100&issuer=issuer&algorithm=SHA1&period=30"),

    // We try to generate a TOTP even if it's not a valid secret
    // invalid_secret: (false, "", "otpauth://totp/test%40example.com?secret=QWERT!£$%^&*(YUIOP&digits=6&issuer=example.org&algorithm=SHA1&period=30"),

    // We set a default value of 6
    // no_digit_length: (false, "", "otpauth://totp/Example%20Website%3Atest%40example.com?secret=QWERTYUIOP&digits=&issuer=&algorithm=SHA1&period=30"),

    // We don't support apple specific scheme
    // apple_otpauth_schema: (true, "419231", "apple-otpauth://totp/Example%20Website%3Atest%40example.com?secret=QWERTYUIOP&digits=6&issuer=&algorithm=SHA1&period=30"),
}
