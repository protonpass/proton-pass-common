use proton_pass_common::markdown::{parse_markdown_document, parse_markdown_document_with_limits, MarkdownParseLimits};
use std::hint::black_box;
use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicU64, Ordering},
};

#[path = "../test_support/markdown_perf_shapes.rs"]
mod markdown_perf_shapes;

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

static ALLOCATED_BYTES: AtomicU64 = AtomicU64::new(0);
static DEALLOCATED_BYTES: AtomicU64 = AtomicU64::new(0);
static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static REALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static DEALLOCATIONS: AtomicU64 = AtomicU64::new(0);

struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        ALLOCATED_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        DEALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        DEALLOCATED_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        REALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        DEALLOCATED_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        ALLOCATED_BYTES.fetch_add(new_size as u64, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[derive(Clone, Copy)]
struct AllocationStats {
    allocated_bytes: u64,
    deallocated_bytes: u64,
    allocations: u64,
    reallocations: u64,
    deallocations: u64,
}

impl AllocationStats {
    fn live_bytes(self) -> u64 {
        self.allocated_bytes.saturating_sub(self.deallocated_bytes)
    }
}

#[derive(Clone, Copy)]
struct AllocationCase<'a> {
    name: &'static str,
    markdown: &'a str,
    parse_with_limits: bool,
}

fn main() {
    let small = "# Title\n\nHello **world** with [link](https://example.com).\n";
    let fixture = include_str!("../test_data/markdown/shared_renderer.md");
    let large = markdown_perf_shapes::repeated_note(512);
    let adversarial = markdown_perf_shapes::adversarial_but_in_budget();
    let many_links = markdown_perf_shapes::link_heavy_note(1_000);
    let many_inline_nodes = markdown_perf_shapes::inline_heavy_note(1_500);
    let deep_structure = markdown_perf_shapes::deep_in_budget_structure();
    let large_code_block = markdown_perf_shapes::large_code_block_note(120 * 1024);

    report_allocation_profile(&[
        AllocationCase {
            name: "small_note",
            markdown: small,
            parse_with_limits: false,
        },
        AllocationCase {
            name: "fixture_contract_note",
            markdown: fixture,
            parse_with_limits: false,
        },
        AllocationCase {
            name: "large_in_budget_note",
            markdown: &large,
            parse_with_limits: false,
        },
        AllocationCase {
            name: "adversarial_in_budget_nesting",
            markdown: &adversarial,
            parse_with_limits: true,
        },
        AllocationCase {
            name: "many_safe_and_unsafe_links",
            markdown: &many_links,
            parse_with_limits: false,
        },
        AllocationCase {
            name: "many_small_inline_nodes",
            markdown: &many_inline_nodes,
            parse_with_limits: false,
        },
        AllocationCase {
            name: "deep_in_budget_structure",
            markdown: &deep_structure,
            parse_with_limits: true,
        },
        AllocationCase {
            name: "large_code_block_near_budget",
            markdown: &large_code_block,
            parse_with_limits: false,
        },
    ]);
}

fn report_allocation_profile(cases: &[AllocationCase<'_>]) {
    println!();
    println!("markdown_renderer_parse allocation diagnostic");
    println!("Counting allocator profile for a single parse. This is not a Criterion timing benchmark.");
    println!("Input construction/cloning is excluded; allocator timings are not representative of production.");
    println!("| Benchmark | Allocations | Reallocations | Deallocations | Allocated Bytes | Live Bytes After Parse |");
    println!("| --- | ---: | ---: | ---: | ---: | ---: |");

    for case in cases {
        let stats = measure_parse_allocations(*case);
        println!(
            "| `{}` | {} | {} | {} | {} | {} |",
            case.name,
            stats.allocations,
            stats.reallocations,
            stats.deallocations,
            stats.allocated_bytes,
            stats.live_bytes()
        );
    }
    println!();
}

fn measure_parse_allocations(case: AllocationCase<'_>) -> AllocationStats {
    reset_allocation_stats();
    let document = if case.parse_with_limits {
        parse_markdown_document_with_limits(black_box(case.markdown), MarkdownParseLimits::default()).unwrap()
    } else {
        parse_markdown_document(black_box(case.markdown)).unwrap()
    };
    black_box(&document);
    let stats = allocation_stats();
    drop(document);
    stats
}

fn reset_allocation_stats() {
    ALLOCATED_BYTES.store(0, Ordering::Relaxed);
    DEALLOCATED_BYTES.store(0, Ordering::Relaxed);
    ALLOCATIONS.store(0, Ordering::Relaxed);
    REALLOCATIONS.store(0, Ordering::Relaxed);
    DEALLOCATIONS.store(0, Ordering::Relaxed);
}

fn allocation_stats() -> AllocationStats {
    AllocationStats {
        allocated_bytes: ALLOCATED_BYTES.load(Ordering::Relaxed),
        deallocated_bytes: DEALLOCATED_BYTES.load(Ordering::Relaxed),
        allocations: ALLOCATIONS.load(Ordering::Relaxed),
        reallocations: REALLOCATIONS.load(Ordering::Relaxed),
        deallocations: DEALLOCATIONS.load(Ordering::Relaxed),
    }
}
