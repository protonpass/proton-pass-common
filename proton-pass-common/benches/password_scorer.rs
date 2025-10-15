use criterion::{criterion_group, criterion_main, Criterion};
use proton_pass_common::password::check_score;
use std::hint::black_box;

fn password_scorer(c: &mut Criterion) {
    c.bench_function("score weak password", |b| b.iter(|| black_box(check_score("qwerty"))));
    c.bench_function("score strong password", |b| {
        b.iter(|| black_box(check_score("o4L7^_*[Ai!9Hf4-_5g^T")))
    });
}

criterion_group!(benches, password_scorer);
criterion_main!(benches);
