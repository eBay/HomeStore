# RCA: LogDev Crash on Restart — Truncation Chunk/Meta Inconsistency

**Date:** 2026-05-22
**Component:** HomeStore / LogStore / JournalVirtualDev
**Severity:** Critical (crash on restart, blocks recovery)

---

## Symptom

After a SIGKILL, the process crashes during restart at `log_dev.cpp:234`:

```
Assertion failure: Expected '473577' to be == to '460780'
log indx is not the expected one
```

`do_load` reads the first log group from the persisted start dev_offset
(`0x54BC8000`) and finds `start_idx=473577`, but the logdev superblock says
`log_idx=460780`.

---

## Root Cause Chain

### Condition 1: `m_vdev_jd->truncate()` persists chunk metadata synchronously

`JournalVirtualDev::Descriptor::truncate()` calls `update_chunk_private()` for
every chunk it modifies. The call chain:

```
update_chunk_private()
  → chunk->set_user_private()
    → write_chunk_info()
      → physical_dev->write_super_block()
        → m_drive_iface->sync_write()   ← synchronous disk write
```

Specifically, truncation:
1. Marks the new head chunk `is_head=true` — **sync_write**
2. Calls `release_chunk_to_pool()` on each removed chunk, which clears its
   private data — **sync_write** per chunk

All writes complete before `truncate()` returns.
**Evidence:** `physical_dev.cpp:122` — `sync_write` call, no async path.

### Condition 2: `m_logdev_meta.persist()` is called after `m_vdev_jd->truncate()` returns

`LogDev::truncate()` (`log_dev.cpp:665–688`):

```cpp
m_vdev_jd->truncate(min_safe_ld_key.dev_offset);   // chunk state durable

// ← SIGKILL WINDOW OPENS HERE

m_logdev_meta.set_start_dev_offset(..., false);     // in-memory only
m_logdev_meta.unreserve_store(..., false);           // in-memory only
m_logdev_meta.remove_rollback_record_upto(..., false); // in-memory only

m_logdev_meta.persist();    // ← logdev superblock written; never reached
```

When `stopping=false` (normal operation), all intermediate calls use
`persist_now=false`. Only the final `persist()` writes to disk.
**Evidence:** code structure, `log_dev.cpp:665–688`.

### Condition 3: On restart, stale logdev meta is interpreted against a new chunk list

`JournalVirtualDev::init()` rebuilds the chunk list from on-disk chunk private
data (not from logdev meta). After the truncation in Condition 1, the new head
chunk is persisted. On restart:

- **Chunk list (from disk):** `[Chunk B (is_head=true), ...]`
  (Chunk A was released and its private data cleared/persisted to disk)
- **Logdev meta (from disk):** `(dev_offset=0x54BC8000, log_idx=460780)`
  (old value, persist never ran)

`LogDev::start()` calls:
```cpp
m_vdev_jd->update_data_start_offset(0x54BC8000);  // set from stale meta
m_log_idx = 460780;
do_load(0x54BC8000);
```

### Condition 4: `offset_to_chunk(0x54BC8000)` maps to Chunk B in the new list

`journal_vdev.cpp:727`:
```cpp
chunk_aligned_offset = round_down(m_data_start_offset, chunk_size);
off_l = 0x54BC8000 - chunk_aligned_offset;
// Iterates [Chunk B, ...] → maps to Chunk B at offset off_l
```

The old offset `0x54BC8000` is now interpreted against the new chunk list. It
maps to a physical position inside Chunk B, where log data starting at
`start_idx=473577` resides.

### Condition 5: `do_load` has no handler for `header->start_idx() > m_log_idx`

`log_dev.cpp:225–234`:
```cpp
if (loaded_from == -1 && header->start_idx() < m_log_idx) {
    // handles: journal fully truncated → break
}
// No handling for start_idx > m_log_idx ← the actual case (473577 > 460780)
HS_REL_ASSERT_EQ(header->start_idx(), m_log_idx.load(), ...);  // CRASH
```

The assert fires because the gap case (truncation advanced further than what
is recorded in meta) is unhandled.

---

## Trigger Conditions

The following sequence must all occur:

1. LogDev has at least two chunks in its journal chunk list
2. A truncation is triggered (raft compact or resource pressure) where
   `min_safe_ld_key.dev_offset` falls in chunk N+1 or later (i.e., the
   truncation point crosses a chunk boundary, causing chunk N to be released)
3. SIGKILL arrives after `m_vdev_jd->truncate()` returns but before
   `m_logdev_meta.persist()` executes

The window is narrow (microseconds to low milliseconds) but non-zero, and
SIGKILL is unblockable.

**Observed instance (2026-05-10):**
- `log_dev=1`, pre-kill flush at `log_idx=490277`
- Truncation with `min_safe_ld_key.idx=475195`
- Persisted meta: `(dev_offset=0x54BC8000, log_idx=460780)`
- First log in new chunk list: `start_idx=473577`

---

## Skipped Conditions

None. All four conditions confirmed via static code analysis and log evidence.
The chunk list change (Condition 3) is proven by the crash itself via proof by
contradiction: if the chunk list had not changed, `offset_to_chunk(0x54BC8000)`
would map to the original Chunk A and recover log 460780 correctly; the
observed mismatch is impossible without a chunk list change.
