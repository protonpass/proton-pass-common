use criterion::{black_box, criterion_group, criterion_main, Criterion};
use proton_pass_common::creditcard::CreditCardDetector;

fn card_detector(c: &mut Criterion) {
    let detector = CreditCardDetector::default();
    c.bench_function("detect unknown card", |b| b.iter(|| black_box(detector.detect("1"))));
    c.bench_function("detect visa card", |b| {
        b.iter(|| black_box(detector.detect("4111111111111111")))
    });
}

criterion_group!(benches, card_detector);
criterion_main!(benches);
