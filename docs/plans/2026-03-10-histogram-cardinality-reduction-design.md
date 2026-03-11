# Histogram Cardinality Reduction Design

**Date:** 2026-03-10
**Author:** Xiaoxi Chen
**Status:** Approved

## Problem Statement

HomeStore currently exports ~17,000 Prometheus time series from histogram metrics. This high cardinality creates:
- Storage and query performance issues in monitoring infrastructure
- Higher operational costs
- Slower dashboard queries

The sisl library PR #296 introduces `publish_as_sum_count` mode that reduces histogram cardinality from 30+ time series per metric down to 2 (sum + count), while maintaining full bucket data locally via JSON API.

## Decision Criteria

**Keep as full histogram:** Component boundary metrics representing user-facing operations
- External APIs (LogStore read/write, ReplDev write)
- Hardware boundaries (physical device I/O)
- System-level operations (checkpoint)
- I/O pattern analysis (size distributions)

**Convert to sum/count:** Internal implementation details
- Pipeline stage breakdowns (when end-to-end latency already exists)
- Data structure internals (BTree node operations)
- Implementation-specific metrics (flush internals, fragmentation tracking)

## Metric Decisions

### Keep as Histogram (12 metrics -> 2,841 time series)

| Component | Metric | Entity Count | Buckets | Time Series | Reason |
|-----------|--------|--------------|---------|-------------|--------|
| pdev | `drive_write_latency` | 1 | 36 | 36 | Hardware boundary |
| pdev | `drive_read_latency` | 1 | 36 | 36 | Hardware boundary |
| pdev | `write_io_sizes` | 1 | 11 | 11 | I/O pattern analysis |
| pdev | `read_io_sizes` | 1 | 11 | 11 | I/O pattern analysis |
| logstore | `logstore_op_latency{write}` | 1 | 36 | 36 | LogStore API boundary |
| logstore | `logstore_op_latency{read}` | 1 | 36 | 36 | LogStore API boundary |
| logstore | `logdev_flush_time_us` | 1 | 36 | 36 | Critical flush performance |
| logstore | `logdev_flush_size_distribution` | 1 | 11 | 11 | Flush I/O pattern |
| rdev | `rreq_total_data_write_latency_us` | 24 PGs | 36 | 864 | ReplDev end-to-end write |
| rdev | `rreq_data_write_latency_us` | 24 PGs | 36 | 864 | Write stage bottleneck analysis |
| rdev | `rreq_data_fetch_latency_us` | 24 PGs | 36 | 864 | Fetch stage bottleneck analysis |
| cp | `cp_latency` | 1 | 36 | 36 | System checkpoint operation |
| **Subtotal** | | | | **2,841** | |

### Convert to Sum/Count (19 metrics)

| Component | Metric | Entity Count | Current (Histogram) | After (Sum/Count) | Reduction | Reason |
|-----------|--------|--------------|---------------------|-------------------|-----------|--------|
| **BTree (6 metrics)** | | | | | | |
| Index | `btree_int_node_occupancy` | 24 PGs | 792 (24x33) | 48 (24x2) | -744 | Internal node metrics |
| Index | `btree_leaf_node_occupancy` | 24 PGs | 792 (24x33) | 48 (24x2) | -744 | Internal node metrics |
| Index | `btree_exclusive_time_in_int_node` | 24 PGs | 864 (24x36) | 48 (24x2) | -816 | Internal lock timing |
| Index | `btree_exclusive_time_in_leaf_node` | 24 PGs | 864 (24x36) | 48 (24x2) | -816 | Internal lock timing |
| Index | `btree_inclusive_time_in_int_node` | 24 PGs | 864 (24x36) | 48 (24x2) | -816 | Internal lock timing |
| Index | `btree_inclusive_time_in_leaf_node` | 24 PGs | 864 (24x36) | 48 (24x2) | -816 | Internal lock timing |
| **ReplDev (6 metrics)** | | | | | | |
| rdev | `rreq_push_data_latency_us` | 24 PGs | 864 (24x36) | 48 (24x2) | -816 | Stage detail (write exists) |
| rdev | `rreq_pieces_per_write` | 24 PGs | 864 (24x36) | 48 (24x2) | -816 | Write pattern detail |
| rdev | `blk_diff_with_proposer` | 24 PGs | 864 (24x36) | 48 (24x2) | -816 | Internal raft detail |
| rdev | `raft_end_of_append_batch_latency_us` | 24 PGs | 864 (24x36) | 48 (24x2) | -816 | Internal raft detail |
| rdev | `data_channel_wait_latency_us` | 24 PGs | 864 (24x36) | 48 (24x2) | -816 | Internal queue detail |
| **LogDev (3 metrics)** | | | | | | |
| logstore | `logdev_flush_records_distribution` | 1 | 33 (1x33) | 2 (1x2) | -31 | Internal flush detail |
| logstore | `logstore_record_size` | 1 | 11 (1x11) | 2 (1x2) | -9 | Internal record detail |
| logstore | `logdev_post_flush_processing_latency` | 1 | 36 (1x36) | 2 (1x2) | -34 | Internal flush stage |
| **Other (3 metrics)** | | | | | | |
| allocator | `frag_pct_distribution` | 58 chunks | 986 (58x17) | 116 (58x2) | -870 | Allocator health monitoring |
| vdev | `blk_alloc_latency` | 1 | 36 (1x36) | 2 (1x2) | -34 | Minimal latency |
| meta | `compress_ratio_percent` | 1 | 36 (1x36) | 2 (1x2) | -34 | Compression efficiency |
| **Subtotal** | | | **14,086** | **782** | **-13,304** | |

### Debug-Only Metrics (Not in Production)

| Component | Metric | Reason |
|-----------|--------|--------|
| logstore | `logstore_stream_tracker_lock_latency` | Internal lock detail (_PRERELEASE only) |
| blkdata | `blktrack_erase_blk_rescheduled_latency` | Debug metric (_PRERELEASE only) |

### Impact Summary

| Category | Time Series |
|----------|-------------|
| Keep as Histogram (12 metrics) | 2,841 |
| Convert to Sum/Count (19 metrics) | 782 |
| Debug-Only Metrics (2 metrics, _PRERELEASE only) | 0 (production) |
| **Total After Conversion** | **3,623** |
| **Original Total** | **~17,000** |
| **Reduction** | **~79%** |

## Implementation

### Code Changes

Modify 19 histogram registrations across 6 files to use conditional compilation with the `REGISTER_HISTOGRAM_WITH_CARDINALITY_REDUCTION` macro:

**Macro Definition** (in `src/include/homestore/homestore_decl.hpp`):
```cpp
#ifdef _PRERELEASE
#define REGISTER_HISTOGRAM_WITH_CARDINALITY_REDUCTION(...) REGISTER_HISTOGRAM(__VA_ARGS__)
#else
#define REGISTER_HISTOGRAM_WITH_CARDINALITY_REDUCTION(...) \
    REGISTER_HISTOGRAM(__VA_ARGS__, sisl::_publish_as::publish_as_sum_count)
#endif
```

**Usage Pattern:**
```cpp
// Before (verbose):
#ifdef _PRERELEASE
    REGISTER_HISTOGRAM(metric_name, "Description", HistogramBucketsType(OpLatecyBuckets));
#else
    REGISTER_HISTOGRAM(metric_name, "Description", HistogramBucketsType(OpLatecyBuckets),
                       _publish_as::publish_as_sum_count);
#endif

// After (using macro):
REGISTER_HISTOGRAM_WITH_CARDINALITY_REDUCTION(metric_name, "Description",
                                              HistogramBucketsType(OpLatecyBuckets));
```

### Files to Modify

1. **src/include/homestore/btree/detail/btree_internal.hpp** (6 metrics)
   - `btree_int_node_occupancy`
   - `btree_leaf_node_occupancy`
   - `btree_exclusive_time_in_int_node`
   - `btree_exclusive_time_in_leaf_node`
   - `btree_inclusive_time_in_int_node`
   - `btree_inclusive_time_in_leaf_node`

2. **src/lib/replication/repl_dev/raft_repl_dev.h** (5 metrics)
   - `rreq_push_data_latency_us`
   - `rreq_pieces_per_write`
   - `blk_diff_with_proposer`
   - `raft_end_of_append_batch_latency_us`
   - `data_channel_wait_latency_us`

3. **src/lib/logstore/log_store_service.cpp** (3 metrics)
   - `logdev_flush_records_distribution`
   - `logstore_record_size`
   - `logdev_post_flush_processing_latency`

4. **src/lib/blkalloc/varsize_blk_allocator.h** (1 metric)
   - `frag_pct_distribution`

5. **src/lib/device/virtual_dev.hpp** (1 metric)
   - `blk_alloc_latency`

6. **src/include/homestore/meta_service.hpp** (1 metric)
   - `compress_ratio_percent`

### Dependencies

- Requires sisl version bump after PR #296 merges (https://github.com/eBay/sisl/pull/296)

### Result

- **Production builds:** ~3,695 time series (79% reduction)
- **Debug builds (_PRERELEASE):** ~17,000 time series (unchanged, full percentile data for troubleshooting)

## Notes

- Sum/count mode still collects full bucket data in memory, accessible via JSON API
- Existing dashboards using average (sum/count) calculations will continue working
- Dashboards using percentiles (p50/p95/p99) on converted metrics will break in production builds but work in debug builds
- Converted metrics represent internal implementation details with likely minimal dashboard usage
