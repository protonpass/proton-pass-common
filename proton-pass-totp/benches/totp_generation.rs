use criterion::{black_box, criterion_group, criterion_main, Criterion};
use proton_pass_totp::TOTP;

fn totp_generator(c: &mut Criterion) {
    let totp_sha1 =
        TOTP::from_uri("otpauth://totp/MYLABEL?secret=MYSECRET&issuer=MYISSUER&algorithm=SHA1&digits=8&period=15")
            .unwrap();
    let totp_sha256 =
        TOTP::from_uri("otpauth://totp/MYLABEL?secret=MYSECRET&issuer=MYISSUER&algorithm=SHA256&digits=8&period=15")
            .unwrap();
    let totp_sha512 =
        TOTP::from_uri("otpauth://totp/MYLABEL?secret=MYSECRET&issuer=MYISSUER&algorithm=SHA512&digits=8&period=15")
            .unwrap();
    c.bench_function("SHA1", |b| b.iter(|| black_box(totp_sha1.generate_token(123456789))));
    c.bench_function("SHA256", |b| {
        b.iter(|| black_box(totp_sha256.generate_token(123456789)))
    });
    c.bench_function("SHA512", |b| {
        b.iter(|| black_box(totp_sha512.generate_token(123456789)))
    });
}

criterion_group!(benches, totp_generator);
criterion_main!(benches);
