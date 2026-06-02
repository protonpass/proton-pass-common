# Markdown Renderer Benchmark Baseline

Timing command:

```bash
rtk cargo bench -p proton-pass-common --bench markdown_renderer
```

Allocation diagnostic command:

```bash
rtk cargo bench -p proton-pass-common --bench markdown_renderer_allocations
```

Recorded on 2026-06-02 from the local development machine. Criterion used the
plotters backend because `gnuplot` was not installed.

| Benchmark | Time Range | Throughput |
| --- | ---: | ---: |
| `small_note` | 1.1419-1.1503 us | 48.916-49.276 MiB/s |
| `fixture_contract_note` | 2.9718-2.9929 us | 87.945-88.572 MiB/s |
| `large_in_budget_note` | 536.63-549.10 us | 113.63-116.27 MiB/s |
| `adversarial_in_budget_nesting` | 3.7026-3.7551 us | 79.999-81.134 MiB/s |
| `many_safe_and_unsafe_links` | 707.70-716.21 us | 99.427-100.62 MiB/s |
| `many_small_inline_nodes` | 884.63-892.07 us | 52.983-53.428 MiB/s |
| `deep_in_budget_structure` | 5.1030-5.1779 us | 93.012-94.377 MiB/s |
| `large_code_block_near_budget` | 4.1407-4.2410 us | 26.987-27.640 GiB/s |

The allocation diagnostic is an opt-in profile, not a Criterion timing
benchmark. It installs a counting global allocator in the diagnostic binary, so
its timing behavior is not representative of production. Use these numbers only
to compare allocation shape changes under the same harness. Each shape is parsed
once, and input construction/cloning is excluded from the reported counts.
Timing numbers above are from the normal allocator benchmark, not this counting
allocator diagnostic.

| Benchmark | Allocations | Reallocations | Deallocations | Allocated Bytes | Live Bytes After Parse |
| --- | ---: | ---: | ---: | ---: | ---: |
| `small_note` | 17 | 2 | 7 | 17,847 | 1,150 |
| `fixture_contract_note` | 31 | 8 | 9 | 24,418 | 5,144 |
| `large_in_budget_note` | 3,591 | 1,046 | 5 | 3,158,898 | 863,634 |
| `adversarial_in_budget_nesting` | 21 | 7 | 4 | 24,956 | 5,260 |
| `many_safe_and_unsafe_links` | 7,007 | 27 | 1,005 | 2,801,247 | 869,501 |
| `many_small_inline_nodes` | 12,008 | 39 | 6 | 11,243,479 | 3,242,839 |
| `deep_in_budget_structure` | 30 | 7 | 4 | 28,544 | 7,696 |
| `large_code_block_near_budget` | 9 | 0 | 5 | 317,993 | 123,289 |

These allocation numbers are not CI thresholds and are not a performance gate.
Use them as a comparison point when parser or IR changes materially alter memory
behavior. CI-facing growth checks live in the markdown tests and assert that
representative benchmark shapes stay inside expected parser budgets and
node-count envelopes.
