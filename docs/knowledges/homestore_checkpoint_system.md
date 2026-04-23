# HomeStore Checkpoint (CP) System Architecture

## Overview
HomeStore's checkpoint system provides transactional consistency by coordinating flush operations across multiple consumers (INDEX_SVC, REPLICATION_SVC, BLK_DATA_SVC, LOG_SVC, SEALER).

## Key Components

### 1. CP (Checkpoint) Object
**Location**: `HomeStore/src/include/homestore/checkpoint/cp.hpp`

**Structure**:
```cpp
class CP {
    cp_id_t m_cp_id;
    std::atomic<cp_status_t> m_cp_status;
    CPManager* m_cp_mgr;
    std::array<std::unique_ptr<CPContext>, (size_t)cp_consumer_t::SENTINEL> m_contexts;
    folly::SharedPromise<bool> m_comp_promise;
    Clock::time_point m_cp_start_time;
};
```

**CP States**:
- `cp_trigger`: CP flush triggered
- `cp_flush_prepare`: Switchover completed, preparing to flush
- `cp_io_ready`: New CP ready for IO operations
- `cp_flushing`: Currently flushing
- `cp_flush_done`: Flush completed
- `cp_cleaning`: Cleanup in progress

### 2. CPContext Base Class
**Location**: `HomeStore/src/include/homestore/checkpoint/cp_mgr.hpp`

```cpp
class CPContext {
protected:
    CP* m_cp;
    folly::Promise<bool> m_flush_comp;  // Used by collectAll in cp_flush
public:
    CPContext(CP* cp) : m_cp{cp} {}
    void complete(bool status) { m_flush_comp.setValue(status); }
    folly::Future<bool> get_future() { return m_flush_comp.getFuture(); }
    virtual ~CPContext() = default;
};
```

**Important**: Each consumer creates its own CPContext subclass to hold consumer-specific CP state.

### 3. CPManager
**Location**: `HomeStore/src/lib/checkpoint/cp_mgr.cpp`

**Key Members**:
```cpp
class CPManager {
    CP* m_cur_cp;  // RCU-protected pointer
    std::mutex m_trigger_cp_mtx;  // Serializes CP trigger operations
    std::atomic<bool> m_in_flush_phase;  // Prevents concurrent flushes
    bool m_pending_trigger_cp;  // Back-to-back CP flag
    folly::SharedPromise<bool> m_pending_trigger_cp_comp;  // For queued CP
    std::vector<iomgr::io_fiber_t> m_cp_io_fibers;  // 2 blocking IO fibers
    std::array<std::unique_ptr<CPCallbacks>, SENTINEL> m_cp_cb_table;
};
```

## CP Lifecycle

### Phase 1: Trigger (do_trigger_cp_flush)
**File**: `cp_mgr.cpp:201-270`

```cpp
folly::Future<bool> CPManager::do_trigger_cp_flush(bool force, bool flush_on_shutdown) {
    std::unique_lock<std::mutex> lk(m_trigger_cp_mtx);

    // Back-to-back CP handling
    if (m_in_flush_phase) {
        if (force && (!m_cp_shutdown_initiated || flush_on_shutdown)) {
            if (!m_pending_trigger_cp) {
                m_pending_trigger_cp = true;
                m_pending_trigger_cp_comp = std::move(folly::SharedPromise<bool>{});
            }
            return m_pending_trigger_cp_comp.getFuture();
        }
        return folly::makeFuture<bool>(false);
    }
    m_in_flush_phase = true;

    auto cur_cp = cp_guard();  // Get current CP
    auto new_cp = new CP(this);
    new_cp->m_cp_id = cur_cp->m_cp_id + 1;

    // Phase 1a: Switchover SEALER first
    auto& sealer_cp = m_cp_cb_table[(size_t)cp_consumer_t::SEALER];
    if (sealer_cp) {
        new_cp->m_contexts[(size_t)cp_consumer_t::SEALER] =
            std::move(sealer_cp->on_switchover_cp(cur_cp.get(), new_cp));
    }

    // Phase 1b: Switchover other consumers
    for (size_t svcid = 0; svcid < (size_t)cp_consumer_t::SENTINEL; svcid++) {
        if (svcid == (size_t)cp_consumer_t::SEALER) continue;
        auto& consumer = m_cp_cb_table[svcid];
        if (consumer) {
            new_cp->m_contexts[svcid] = std::move(consumer->on_switchover_cp(cur_cp.get(), new_cp));
        }
    }

    // Phase 1c: Setup promise and switch m_cur_cp pointer
    if (m_pending_trigger_cp) {
        cur_cp->m_comp_promise = std::move(m_pending_trigger_cp_comp);
        m_pending_trigger_cp = false;
    } else {
        cur_cp->m_comp_promise = std::move(folly::SharedPromise<bool>{});
    }
    ret_fut = cur_cp->m_comp_promise.getFuture();

    cur_cp->m_cp_status = cp_status_t::cp_flush_prepare;
    new_cp->m_cp_status = cp_status_t::cp_io_ready;

    // RCU pointer swap - guarantees all readers see new CP
    rcu_xchg_pointer(&m_cur_cp, new_cp);
    synchronize_rcu();  // Wait for all RCU readers to finish

    lk.unlock();
    return ret_fut;
}
```

**Key Synchronization**:
- `m_trigger_cp_mtx`: Serializes all CP trigger operations
- `m_in_flush_phase`: Set to `true` during entire CP flush, prevents concurrent triggers
- `rcu_xchg_pointer` + `synchronize_rcu()`: Safe pointer switching without locking read path

### Phase 2: Flush (cp_start_flush)
**File**: `cp_mgr.cpp:272-293`

```cpp
void CPManager::cp_start_flush(CP* cp) {
    std::vector<folly::Future<bool>> futs;
    cp->m_cp_status = cp_status_t::cp_flushing;

    // Collect futures from all consumers (except SEALER)
    for (size_t svcid = 0; svcid < (size_t)cp_consumer_t::SENTINEL; svcid++) {
        if (svcid == (size_t)cp_consumer_t::SEALER) continue;
        auto& consumer = m_cp_cb_table[svcid];
        bool participated = (cp->m_contexts[svcid] != nullptr);
        if (consumer && participated) {
            futs.emplace_back(std::move(consumer->cp_flush(cp)));
        }
    }

    // Wait for all consumers to flush
    folly::collectAllUnsafe(futs).thenValue([this, cp](auto) {
        // SEALER (REPLICATION_SVC) flushes last synchronously
        auto& sealer_cp = m_cp_cb_table[(size_t)cp_consumer_t::SEALER];
        bool participated = (cp->m_contexts[(size_t)cp_consumer_t::SEALER] != nullptr);
        if (sealer_cp && participated) {
            sealer_cp->cp_flush(cp).wait();
        }
        on_cp_flush_done(cp);
    });
}
```

**Important**:
- `collectAllUnsafe` holds references to futures from `cp->m_contexts[]->get_future()`
- SEALER flushes last because it updates cp_lsn (other components must flush up to this LSN)

### Phase 3: Completion (on_cp_flush_done)
**File**: `cp_mgr.cpp:295-331`

```cpp
void CPManager::on_cp_flush_done(CP* cp) {
    cp->m_cp_status = cp_status_t::cp_flush_done;

    iomanager.run_on_forget(pick_blocking_io_fiber(), [this, cp]() {
        ++(m_sb->m_last_flushed_cp);
        m_sb.write();

        cleanup_cp(cp);  // Call all consumers' cp_cleanup()

        auto promise = std::move(cp->m_comp_promise);
        delete cp;  // Destructs m_contexts[] in array order: [0]→[1]→[2]→[3]

        bool trigger_back_2_back_cp{false};
        {
            std::unique_lock<std::mutex> lk(m_trigger_cp_mtx);
            m_in_flush_phase = false;  // Release flush lock
            trigger_back_2_back_cp = m_pending_trigger_cp;
        }

        promise.setValue(true);  // Notify waiters

        if (trigger_back_2_back_cp) {
            trigger_cp_flush(false);  // Start queued CP
        }
    });
}
```

**Critical Details**:
- Runs on `pick_blocking_io_fiber()` - randomly picks 1 of 2 cp_io fibers
- `delete cp` destructs `m_contexts[]` in array index order
- `m_in_flush_phase = false` allows next CP to proceed
- Promise is set AFTER releasing lock to avoid race

### Phase 4: Cleanup
**File**: `cp_mgr.cpp:333-338`

```cpp
void CPManager::cleanup_cp(CP* cp) {
    cp->m_cp_status = cp_status_t::cp_cleaning;
    for (auto& consumer : m_cp_cb_table) {
        if (consumer) { consumer->cp_cleanup(cp); }
    }
}
```

## Back-to-Back CP Mechanism

**Scenario**: Multiple `trigger_cp_flush(force=true)` calls while CP is flushing

**Behavior**:
1. First call starts CP=N, sets `m_in_flush_phase = true`
2. Second call (while CP=N flushing) sets `m_pending_trigger_cp = true`, queues CP=N+1
3. Third call (while still flushing) reuses same `m_pending_trigger_cp_comp` promise
4. When CP=N completes, `on_cp_flush_done` checks `m_pending_trigger_cp` and auto-triggers CP=N+1
5. Only the LAST queued CP is triggered (earlier ones are merged)

**Code Flow**:
```
T1: trigger_cp_flush(force=true)  → Start CP=443
T2: trigger_cp_flush(force=true)  → Queue CP=444 (m_pending_trigger_cp = true)
T3: trigger_cp_flush(force=true)  → Reuse CP=444 promise (still m_pending_trigger_cp = true)
T4: CP=443 completes → on_cp_flush_done → trigger_cp_flush(false) → Start CP=444
```

## CP IO Fibers

**Creation**: `cp_mgr.cpp:340-372`

```cpp
void CPManager::start_cp_thread() {
    auto const num_fibers = HS_DYNAMIC_CONFIG(generic.cp_io_fibers); // default: 2
    iomanager.create_reactor("cp_io", iomgr::INTERRUPT_LOOP, num_fibers, [this, ctx](bool is_started) {
        if (is_started) {
            auto v = iomanager.sync_io_capable_fibers();
            m_cp_io_fibers.insert(m_cp_io_fibers.end(), v.begin(), v.end());
        }
    });
}

iomgr::io_fiber_t CPManager::pick_blocking_io_fiber() const {
    static thread_local std::random_device s_rd{};
    static thread_local std::default_random_engine s_re{s_rd()};
    static auto rand_fiber = std::uniform_int_distribution<size_t>(0, m_cp_io_fibers.size() - 1);
    return m_cp_io_fibers[rand_fiber(s_re)];  // Randomly pick one of 2 fibers
}
```

**Key Points**:
- 2 fibers by default (configurable via `generic.cp_io_fibers`)
- Created with `INTERRUPT_LOOP` mode for blocking IO operations
- `pick_blocking_io_fiber()` randomly distributes tasks across fibers
- **Implication**: Multiple CPs' `on_cp_flush_done` can execute concurrently on different fibers

## RCU (Read-Copy-Update) for m_cur_cp

**Purpose**: Lock-free read access to current CP pointer

**Read Path** (`cp_mgr.cpp:160-171`):
```cpp
CP* CPManager::cp_io_enter() {
    rcu_read_lock();
    auto cp = get_cur_cp();  // Read m_cur_cp
    if (!cp) {
        rcu_read_unlock();
        return nullptr;
    }
    cp_ref(cp);  // Increment refcount
    rcu_read_unlock();
    return cp;
}
```

**Write Path** (`cp_mgr.cpp:260-261`):
```cpp
rcu_xchg_pointer(&m_cur_cp, new_cp);
synchronize_rcu();  // Wait for all readers in RCU critical section to exit
```

**Guarantee**: After `synchronize_rcu()` returns, no thread is accessing old CP without holding a reference (via `cp_ref()`).

## Consumer Order

### Switchover Order (on_switchover_cp)
1. **SEALER** (REPLICATION_SVC) - First
2. Other consumers: INDEX_SVC, BLK_DATA_SVC, LOG_SVC

### Flush Order (cp_flush)
1. INDEX_SVC, BLK_DATA_SVC, LOG_SVC - Parallel (via `collectAllUnsafe`)
2. **SEALER** (REPLICATION_SVC) - Last, synchronous

### Cleanup Order (cp_cleanup)
- All consumers in `m_cp_cb_table` order

### Destruction Order (CP::~CP)
- `m_contexts[]` destructs in array index order:
  - [0] INDEX_SVC
  - [1] BLK_DATA_SVC
  - [2] LOG_SVC
  - [3] REPLICATION_SVC (SEALER)

## Important Invariants

1. **No Concurrent Flushes**: `m_trigger_cp_mtx` + `m_in_flush_phase` ensure only one CP flushes at a time
2. **No Concurrent Triggers**: `m_trigger_cp_mtx` serializes all `do_trigger_cp_flush` calls
3. **Safe CP Pointer Switch**: RCU + refcounting ensure old CP not accessed after switchover
4. **Back-to-Back Merging**: Only last queued force-flush CP is triggered
5. **SEALER Last**: REPLICATION_SVC always flushes last to establish cp_lsn watermark

## Common Issues

### Issue 1: Returning Wrong Future in cp_flush
**Symptom**: CP completes immediately even if work is pending
**Cause**: Returning `folly::makeFuture<bool>(true)` instead of `CPContext::get_future()`
**Impact**: `collectAllUnsafe` completes prematurely, may trigger cleanup while work ongoing

### Issue 2: Concurrent Access to CPContext
**Symptom**: Use-after-free, memory corruption
**Cause**: `pick_blocking_io_fiber()` schedules cleanup on different fiber than switchover
**Solution**: Ensure synchronization between `on_switchover_cp` and `cp_cleanup`

### Issue 3: Deadlock in Signal Handler
**Symptom**: Process hangs instead of exiting on crash
**Cause**: Signal handler calls malloc-dependent logging (spdlog) while malloc holds arena lock
**Solution**: Use async-signal-safe functions only in signal handlers

## Related Configuration

- `generic.cp_io_fibers`: Number of CP IO fibers (default: 2)
- `generic.repl_dev_cleanup_interval_sec`: Interval for repl_dev GC timer
- Various consumer-specific CP flush intervals

## Example Timeline (Back-to-Back CP)

```
T0: CP=443 working
T1: destroy_pg(1) → trigger_cp_flush(force=true)
    → m_in_flush_phase=true, queue CP=444

T2: CP=443 flush done
    → on_cp_flush_done(443) on Fiber A
       → cleanup_cp(443)
       → delete CP=443
       → m_in_flush_phase = false
       → trigger_cp_flush(false) → Start CP=444

T3: do_trigger_cp_flush(444)
    → on_switchover_cp(444, 445)  // CRITICAL: Happens BEFORE CP=444 starts flushing!
       → Creates CP=445 contexts
       → RaftReplServiceCPHandler::on_switchover_cp(444, 445)
          → Accesses CP=444's m_cp_ctx_map to save state
    → cp_start_flush(444)

T4: destroy_pg(2) → trigger_cp_flush(force=true)
    → m_in_flush_phase=true, queue CP=445

T5: CP=444 flush done (all consumers skip)
    → on_cp_flush_done(444) on Fiber B  // May be different fiber!
       → cleanup_cp(444)
       → delete CP=444
       → m_in_flush_phase = false
       → trigger CP=445

T6: CP=445 starts, completes, cleanup
    → delete CP=445
       → ~m_contexts[0] (INDEX_SVC)
       → ~m_contexts[1] (BLK_DATA_SVC)  // May corrupt memory here
       → ~m_contexts[2] (LOG_SVC)
       → ~m_contexts[3] (REPLICATION_SVC)  // CRASH: m_cp_ctx_map corrupted
```
