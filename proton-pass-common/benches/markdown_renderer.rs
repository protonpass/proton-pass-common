use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use proton_pass_common::markdown::{parse_markdown_document, parse_markdown_document_with_limits, MarkdownParseLimits};
use std::hint::black_box;

#[path = "../test_support/markdown_perf_shapes.rs"]
mod markdown_perf_shapes;

fn markdown_renderer(c: &mut Criterion) {
    let small = "# Title\n\nHello **world** with [link](https://example.com).\n";
    let fixture = include_str!("../test_data/markdown/shared_renderer.md");
    let large = markdown_perf_shapes::repeated_note(512);
    let adversarial = markdown_perf_shapes::adversarial_but_in_budget();
    let many_links = markdown_perf_shapes::link_heavy_note(1_000);
    let many_inline_nodes = markdown_perf_shapes::inline_heavy_note(1_500);
    let deep_structure = markdown_perf_shapes::deep_in_budget_structure();
    let large_code_block = markdown_perf_shapes::large_code_block_note(120 * 1024);

    let mut group = c.benchmark_group("markdown_renderer_parse");

    group.throughput(Throughput::Bytes(small.len() as u64));
    group.bench_function("small_note", |b| {
        b.iter(|| black_box(parse_markdown_document(black_box(small)).unwrap()))
    });

    group.throughput(Throughput::Bytes(fixture.len() as u64));
    group.bench_function("fixture_contract_note", |b| {
        b.iter(|| black_box(parse_markdown_document(black_box(fixture)).unwrap()))
    });

    group.throughput(Throughput::Bytes(large.len() as u64));
    group.bench_function("large_in_budget_note", |b| {
        b.iter_batched(
            || large.clone(),
            |text| black_box(parse_markdown_document(black_box(&text)).unwrap()),
            BatchSize::SmallInput,
        )
    });

    group.throughput(Throughput::Bytes(adversarial.len() as u64));
    group.bench_function("adversarial_in_budget_nesting", |b| {
        b.iter_batched(
            || adversarial.clone(),
            |text| {
                black_box(
                    parse_markdown_document_with_limits(black_box(&text), MarkdownParseLimits::default()).unwrap(),
                )
            },
            BatchSize::SmallInput,
        )
    });

    group.throughput(Throughput::Bytes(many_links.len() as u64));
    group.bench_function("many_safe_and_unsafe_links", |b| {
        b.iter_batched(
            || many_links.clone(),
            |text| black_box(parse_markdown_document(black_box(&text)).unwrap()),
            BatchSize::SmallInput,
        )
    });

    group.throughput(Throughput::Bytes(many_inline_nodes.len() as u64));
    group.bench_function("many_small_inline_nodes", |b| {
        b.iter_batched(
            || many_inline_nodes.clone(),
            |text| black_box(parse_markdown_document(black_box(&text)).unwrap()),
            BatchSize::SmallInput,
        )
    });

    group.throughput(Throughput::Bytes(deep_structure.len() as u64));
    group.bench_function("deep_in_budget_structure", |b| {
        b.iter_batched(
            || deep_structure.clone(),
            |text| {
                black_box(
                    parse_markdown_document_with_limits(black_box(&text), MarkdownParseLimits::default()).unwrap(),
                )
            },
            BatchSize::SmallInput,
        )
    });

    group.throughput(Throughput::Bytes(large_code_block.len() as u64));
    group.bench_function("large_code_block_near_budget", |b| {
        b.iter_batched(
            || large_code_block.clone(),
            |text| black_box(parse_markdown_document(black_box(&text)).unwrap()),
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

criterion_group!(benches, markdown_renderer);
criterion_main!(benches);
