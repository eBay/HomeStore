# Replication Service Checkpoint Implementation

## Overview
RaftReplService implements checkpoint (CP) callbacks to persist replication state across all ReplDev instances during HomeStore checkpoint operations.

## Key Classes

### 1. ReplSvcCPContext
**Location**: `HomeStore/src/lib/replication/service/raft_repl_service.h:132-141`

```cpp
class ReplSvcCPContext : public CPContext {
    std::shared_mutex m_cp_map_mtx;  // ⚠️ DECLARED BUT NEVER USED!
    std::map<ReplDev*, cshared<ReplDevCPContext>> m_cp_ctx_map;  // Raw pointer as key

public:
    ReplSvcCPContext(CP* cp) : CPContext(cp){};
    virtual ~ReplSvcCPContext() = default;

    int add_repl_dev_ctx(ReplDev* dev, cshared<ReplDevCPContext> dev_ctx);
    cshared<ReplDevCPContext> get_repl_dev_ctx(ReplDev* dev);
};
```

**Critical Bug**: `m_cp_map_mtx` is declared but never locked in `add_repl_dev_ctx()` or `get_repl_dev_ctx()`!

**Implementation** (`raft_repl_service.cpp:760-770`):
```cpp
int ReplSvcCPContext::add_repl_dev_ctx(ReplDev* dev, cshared<ReplDevCPContext> dev_ctx) {
    m_cp_ctx_map.emplace(dev, dev_ctx);  // ⚠️ NO LOCK PROTECTION!
    return 0;
}

cshared<ReplDevCPContext> ReplSvcCPContext::get_repl_dev_ctx(ReplDev* dev) {
    if (m_cp_ctx_map.count(dev) == 0) {
        return std::make_shared<ReplDevCPContext>();
    }
    return m_cp_ctx_map[dev];  // ⚠️ NO LOCK PROTECTION!
}
```

**Data Structure**: `m_cp_ctx_map` is a `std::map` (red-black tree) with:
- **Key**: Raw `ReplDev*` pointer
- **Value**: `shared_ptr<ReplDevCPContext>`

### 2. ReplDevCPContext
**Purpose**: Holds per-ReplDev checkpoint state (LSN, etc.)

```cpp
struct ReplDevCPContext {
    repl_lsn_t lsn;  // Last LSN to checkpoint
    // Other repl_dev specific CP state
};
```

### 3. RaftReplServiceCPHandler
**Location**: `HomeStore/src/lib/replication/service/raft_repl_service.h:143-153`

Implements the CPCallbacks interface for REPLICATION_SVC consumer.

## CP Callback Implementations

### on_switchover_cp()
**Location**: `raft_repl_service.cpp:773-790`

```cpp
std::unique_ptr<CPContext> RaftReplServiceCPHandler::on_switchover_cp(CP* cur_cp, CP* new_cp) {
    // checking if cur_cp == nullptr as on_switchover_cp will be called when registering the cp handler
    if (cur_cp != nullptr) {
        // Add cp info from all devices to current cp.
        // We dont need taking cp_guard as cp_mgr already taken it in do_trigger_cp_flush
        auto cur_cp_ctx = s_cast<ReplSvcCPContext*>(cur_cp->context(cp_consumer_t::REPLICATION_SVC));

        repl_service().iterate_repl_devs([cur_cp, cur_cp_ctx](cshared<ReplDev>& repl_dev) {
            // Collect the LSN of each repl dev and put it into current CP
            auto dev_ctx = std::static_pointer_cast<RaftReplDev>(repl_dev)->get_cp_ctx(cur_cp);
            cur_cp_ctx->add_repl_dev_ctx(repl_dev.get(), std::move(dev_ctx));  // Line 784
        });
    }
    // create new ctx for new_cp
    auto ctx = std::make_unique<ReplSvcCPContext>(new_cp);
    return ctx;
}
```

**Key Points**:
- Called during `do_trigger_cp_flush` while holding `m_trigger_cp_mtx`
- Populates **cur_cp's** m_cp_ctx_map, not new_cp's
- Iterates all repl_devs and collects their CP state
- Comment says "We dont need taking cp_guard" - assumes CPManager lock provides protection

**Execution Context**: Runs on thread calling `trigger_cp_flush`, protected by `m_trigger_cp_mtx`

### cp_flush()
**Location**: `raft_repl_service.cpp:792-799`

```cpp
folly::Future<bool> RaftReplServiceCPHandler::cp_flush(CP* cp) {
    auto cp_ctx = s_cast<ReplSvcCPContext*>(cp->context(cp_consumer_t::REPLICATION_SVC));

    repl_service().iterate_repl_devs([cp, cp_ctx](cshared<ReplDev>& repl_dev) {
        auto dev_ctx = cp_ctx->get_repl_dev_ctx(repl_dev.get());  // Line 795
        std::static_pointer_cast<RaftReplDev>(repl_dev)->cp_flush(cp, dev_ctx);
    });

    return folly::makeFuture<bool>(true);  // ⚠️ BUG: Should return cp_ctx->get_future()
}
```

**Known Bug**: Returns immediate future instead of `cp_ctx->get_future()`. However:
- All work is actually completed synchronously before return
- `RaftReplDev::cp_flush()` is synchronous
- Returning `true` is semantically correct for this implementation

**Why It Works**: Unlike async implementations, this handler completes all flush work before returning, so immediate `true` is safe.

### cp_cleanup()
**Location**: `raft_repl_service.cpp:801-804`

```cpp
void RaftReplServiceCPHandler::cp_cleanup(CP* cp) {
    repl_service().iterate_repl_devs(
        [cp](cshared<ReplDev>& repl_dev) {
            std::static_pointer_cast<RaftReplDev>(repl_dev)->cp_cleanup(cp);
        });
}
```

**Execution Context**: Called from `CPManager::cleanup_cp()` which runs on `pick_blocking_io_fiber()`.

## Critical Race Condition (Unconfirmed)

### Hypothetical Scenario
```
Thread A (do_trigger_cp_flush):
  ├─ Acquires m_trigger_cp_mtx
  ├─ on_switchover_cp(CP=444, CP=445)
  │   └─ cur_cp_ctx->add_repl_dev_ctx(...)  // Modifies CP=444's m_cp_ctx_map
  ├─ Releases m_trigger_cp_mtx
  └─ cp_start_flush(444)

Thread B (on_cp_flush_done for CP=443):
  ├─ run_on_forget(pick_blocking_io_fiber(), [...])
  │   ├─ cleanup_cp(443)
  │   ├─ delete CP=443
  │   ├─ Sets m_in_flush_phase = false
  │   └─ trigger_cp_flush(false) → Starts CP=444
  │       └─ Acquires m_trigger_cp_mtx
  │           └─ on_switchover_cp(444, 445)
  │               └─ add_repl_dev_ctx(...)  // ⚠️ Concurrent access?
```

**Why This May Not Be a Race**:
- `m_trigger_cp_mtx` serializes all `do_trigger_cp_flush` calls
- `on_switchover_cp` only runs while holding this lock
- `cleanup_cp` runs AFTER CP flush completes, when switchover for next CP already done
- **However**: With 2 cp_io fibers, cleanup can run concurrently with next CP's switchover

### Actual Issue: Memory Corruption During Destruction

**Observed Evidence** (from GDB):
```
CP=445 destruction:
  ~m_contexts[0] (INDEX_SVC)     → OK
  ~m_contexts[1] (BLK_DATA_SVC)  → Triggers folly::collectAll::Context cleanup
                                 → Corrupts memory (ASan markers appear)
  ~m_contexts[2] (LOG_SVC)       → OK
  ~m_contexts[3] (REPLICATION_SVC) → m_cp_ctx_map already corrupted
                                   → CRASH in ~Promise()
```

**Red-Black Tree Corruption**:
- `m_cp_ctx_map` uses `std::map` (red-black tree)
- Tree nodes found with ASan markers: `0x0000610000000000` (heap-left-redzone)
- Parent pointers corrupted: `0x2252feb743377eb5` (invalid)

## ReplDev Lifecycle vs CP

### ReplDev Destruction
**Location**: `HomeObject/src/lib/homestore_backend/hs_pg_manager.cpp:589-613`

```cpp
bool HSHomeObject::pg_destroy(pg_id_t pg_id, bool need_to_pause_pg_state_machine) {
    mark_pg_destroyed(pg_id);
    destroy_shards(pg_id);
    destroy_hs_resources(pg_id);
    destroy_pg_index_table(pg_id);
    destroy_pg_superblk(pg_id);  // Triggers CP flush with force=true

    // ⚠️ NOTE: Does NOT destroy ReplDev or remove from m_rd_map!
    return true;
}
```

**Key Point**: PG destroy does NOT destroy ReplDev. The ReplDev pointer remains valid and in `m_rd_map`.

**Implication**: Using `ReplDev*` as map key is safe during CP lifecycle, no dangling pointers.

### When ReplDev is Actually Destroyed
**Location**: `HomeStore/src/lib/replication/service/raft_repl_service.cpp:699-735`

```cpp
void RaftReplService::gc_repl_devs() {
    std::vector<group_id_t> groups_to_leave;
    {
        std::shared_lock lg(m_rd_map_mtx);
        for (auto it = m_rd_map.begin(); it != m_rd_map.end(); ++it) {
            auto rdev = std::dynamic_pointer_cast<RaftReplDev>(it->second);
            if (rdev->is_destroy_pending() &&
                (get_elapsed_time_sec(rdev->destroyed_time()) >=
                 HS_DYNAMIC_CONFIG(generic.repl_dev_cleanup_interval_sec))) {
                groups_to_leave.push_back(rdev->group_id());
            }
        }
    }

    for (const auto& group_id : groups_to_leave) {
        m_msg_mgr->leave_group(group_id);
        m_repl_app->destroy_repl_dev_listener(group_id);
        {
            std::unique_lock lg(m_rd_map_mtx);
            m_rd_map.erase(group_id);  // Finally remove from map
        }
    }
}
```

**Timing**: ReplDev destroyed after configurable delay (default: seconds), long after PG destroy completes.

## Synchronization Analysis

### Protection Mechanisms

1. **m_trigger_cp_mtx**: Serializes CP trigger operations
   - Held during entire `on_switchover_cp` execution
   - Prevents concurrent switchover calls

2. **m_in_flush_phase**: Prevents concurrent CP flushes
   - Set to `true` at start of `do_trigger_cp_flush`
   - Set to `false` in `on_cp_flush_done`

3. **RCU for m_cur_cp**: Lock-free read access
   - `rcu_xchg_pointer` + `synchronize_rcu` for safe pointer swap
   - Guarantees no readers accessing old CP without reference

4. **NOT Protected**: `m_cp_ctx_map` access
   - `add_repl_dev_ctx()`: No lock
   - `get_repl_dev_ctx()`: No lock
   - `m_cp_map_mtx` declared but never used

### Why It (Mostly) Works

**Assumption**: `m_trigger_cp_mtx` provides implicit protection because:
- `on_switchover_cp` only modifies **cur_cp's** context, not new_cp's
- `cp_flush` reads **same CP's** context that was populated in switchover
- `cleanup_cp` only called after CP flush completes

**Single-Threaded Access Pattern**:
```
do_trigger_cp_flush(N):
  [Hold m_trigger_cp_mtx]
  ├─ on_switchover_cp(N, N+1)
  │   └─ Populate CP=N's m_cp_ctx_map
  [Release m_trigger_cp_mtx]
  └─ cp_start_flush(N)
      └─ cp_flush(N)
          └─ Read CP=N's m_cp_ctx_map

on_cp_flush_done(N):
  └─ cleanup_cp(N)
      └─ Read CP=N's m_cp_ctx_map
```

**Why No Race**: Each CP's context is only accessed by operations on that specific CP, and CP operations are serialized.

## Potential Issues

### Issue 1: Unused Mutex
**Code**: `std::shared_mutex m_cp_map_mtx` declared but never locked

**Risk**: Low - current access pattern is single-threaded per CP

**Recommendation**: Either remove unused mutex or add proper locking for defense-in-depth

### Issue 2: Raw Pointer as Map Key
**Code**: `std::map<ReplDev*, shared_ptr<ReplDevCPContext>>`

**Risk**: Low - ReplDev destroyed long after CP completes

**Benefit**: Avoids shared_ptr overhead for key comparisons

### Issue 3: Returning Immediate Future
**Code**: `return folly::makeFuture<bool>(true)` instead of `cp_ctx->get_future()`

**Risk**: Low - work completes synchronously before return

**Confusion**: Other consumers may expect to return the context's future

## Interaction with Other Services

### During Baseline Resync

**Scenario**: Destroy old PG → Create new PG

```
Timeline:
T1: destroy_pg(pg_id=1)
    ├─ destroy_pg_superblk(1)
    │   └─ trigger_cp_flush(force=true) → Queues CP=444
    ├─ ReplDev for pg=1 still exists in m_rd_map
    └─ Returns

T2: CP=443 completes
    └─ Auto-triggers CP=444

T3: CP=444 switchover
    ├─ on_switchover_cp(444, 445)
    │   └─ iterate_repl_devs([...])  // Includes ReplDev for pg=1
    │       └─ add_repl_dev_ctx(repl_dev.get(), ...)
    └─ cp_start_flush(444)

T4: destroy_pg(pg_id=2)
    └─ trigger_cp_flush(force=true) → Queues CP=445

T5: CP=444 completes (all rdevs skip flush)
    └─ Auto-triggers CP=445

T6: CP=445 runs, completes, destructs
    └─ CRASH during m_cp_ctx_map destruction
```

**Key**: ReplDevs persist across PG destroy, remain in CP context.

## Related Configuration

- `generic.repl_dev_cleanup_interval_sec`: Delay before destroying ReplDev after marking for destruction
- `consensus.flush_durable_commit_interval_ms`: Interval for flushing durable commit LSN
- `consensus.replace_member_sync_check_interval_ms`: Interval for monitoring replace_member status

## Common Misconceptions

1. **"ReplDev is destroyed when PG is destroyed"**: FALSE - ReplDev destroyed later by GC thread
2. **"m_cp_map_mtx protects the map"**: FALSE - mutex is never locked
3. **"Returning wrong future causes bug"**: UNCLEAR - work completes synchronously
4. **"Raw pointers cause dangling"**: FALSE - ReplDev lifetime exceeds CP lifetime

## Debug Tips

### Check m_cp_ctx_map State
```gdb
# Get CP context
set $cp = (homestore::CP*)0x...
set $ctx = (homestore::ReplSvcCPContext*)$cp->m_contexts[3].get()

# Examine map
p $ctx->m_cp_ctx_map
p $ctx->m_cp_ctx_map._M_t._M_impl._M_node_count

# Check red-black tree integrity
set $root = $ctx->m_cp_ctx_map._M_t._M_impl._M_header._M_parent
x/32gx $root
```

### Check ReplDev Validity
```gdb
# Check if ReplDev still in map
set $rdev_ptr = (homestore::ReplDev*)0x...
p homestore::repl_service().get_repl_dev(...)

# Verify refcount
p $rdev_ptr.use_count()
```

### Monitor CP Lifecycle
Add breakpoints:
- `RaftReplServiceCPHandler::on_switchover_cp`
- `RaftReplServiceCPHandler::cp_flush`
- `RaftReplServiceCPHandler::cp_cleanup`
- `ReplSvcCPContext::~ReplSvcCPContext`
