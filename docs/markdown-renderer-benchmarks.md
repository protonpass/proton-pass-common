# Markdown Renderer Performance Notes

Timing benchmark target:

```bash
rtk cargo bench -p proton-pass-common --bench markdown_renderer
```

Allocation diagnostic target:

```bash
rtk cargo bench -p proton-pass-common --bench markdown_renderer_allocations
```

Scenarios:

- `small_note`: short heading, paragraph, strong text, and safe link.
- `fixture_contract_note`: checked-in shared renderer fixture with safe/unsafe links, raw HTML-as-text, lists, blockquote, inline code, and fenced code.
- `large_in_budget_note`: repeated realistic note sections below default input and node budgets.
- `adversarial_in_budget_nesting`: nested list structure intended to exercise depth tracking without exceeding default limits.
- `many_safe_and_unsafe_links`: link-heavy note with allowed and rejected schemes.
- `many_small_inline_nodes`: inline-heavy note with many emphasis/strong/code nodes.
- `deep_in_budget_structure`: deeply nested but valid structure near depth-budget paths.
- `large_code_block_near_budget`: large fenced code block below payload limits.

The timing benchmark records parser throughput over the shared display IR path
with the normal allocator. The allocation diagnostic uses a counting global
allocator and should be used only for comparing allocation shape changes under
the same harness; its timings are not representative of production. These
commands do not enforce allocator-level assertions. Node-count, emitted-text,
code-block, and input-size budgets are enforced in tests and parser code.

Baseline from this branch on 2026-06-02:

| Scenario | Median-ish time | Throughput |
| --- | ---: | ---: |
| `small_note` | 1.1460 us | 49.098 MiB/s |
| `fixture_contract_note` | 2.9822 us | 88.263 MiB/s |
| `large_in_budget_note` | 541.70 us | 115.18 MiB/s |
| `adversarial_in_budget_nesting` | 3.7261 us | 80.622 MiB/s |
| `many_safe_and_unsafe_links` | 711.45 us | 100.09 MiB/s |
| `many_small_inline_nodes` | 887.97 us | 53.227 MiB/s |
| `deep_in_budget_structure` | 5.1323 us | 93.839 MiB/s |
| `large_code_block_near_budget` | 4.1804 us | 27.378 GiB/s |
