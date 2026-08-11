# Index Write-Back Cache and Checkpoint Flush Mechanism

This document describes the structure and flow of HomeStore's index write-back cache (WBC) and checkpoint (CP) flush mechanism.

## 0. Glossary

| Term                             | Definition                                                                                                                 |
|----------------------------------|----------------------------------------------------------------------------------------------------------------------------|
| **IndexWBCache**                 | Write-back cache managing all index node buffers, handling allocation, dirty tracking, and flush orchestration             |
| **IndexBuffer**                  | In-memory representation of a B-tree node with metadata (blkid, dirty CP, creation CP, state, parent/child links)          |
| **MetaIndexBuffer**              | Special buffer for index table superblock, inherits from IndexBuffer, always flushed last                                  |
| **Ordinal**                      | Unique identifier (uint32_t) for each IndexTable within IndexService, used to map buffers to their tables                  |
| **BlkId**                        | Block ID - physical location of a node on the virtual device (vdev)                                                        |
| **CP (Checkpoint)**              | Periodic flush operation that persists all dirty index buffers to disk atomically                                          |
| **DAG (Directed Acyclic Graph)** | Dependency structure where parent buffers depend on child buffers being flushed first                                      |
| **m_wait_for_down_buffers**      | Counter tracking how many child buffers must flush before this parent buffer can flush                                     |
| **m_up_buffer**                  | Pointer from child to parent buffer in the dependency chain                                                                |
| **Journal**                      | Write-ahead log (WAL) recording structural changes (splits/merges) during a CP for crash recovery                          |
| **Temporary MetaBuffer**         | MetaIndexBuffer created during recovery from journal, used only for dependency tracking, has dangling superblock reference |
| **Real MetaBuffer**              | MetaIndexBuffer owned by IndexTable (m_sb_buffer), has valid superblock reference, used during normal operation            |
| **Committed node**               | Node whose m_dirtied_cp_id matches the CP being recovered, indicating it was successfully written before crash             |
| **Repair**                       | Process of fixing B-tree node structure during recovery (fixing links, removing stale children, etc.)                      |

## 0.1 Architecture Overview

## 0.2 Additional Reading

- [Index B-Tree Nodes (Concepts and On-Disk Layout)](index_btree_nodes.md)
- [Index CP Flush and Recovery (Ordering, Journal, and Root Handling)](index_cp_and_recovery.md)
- [RCA: Root Split Crash Leaves SB Pointing to Old Root](rca_root_split_recovery.md)



### System Context
```
┌─────────────────────────────────────────────────────────────────┐
│                         HomeStore                                │
│  ┌────────────┐  ┌──────────────┐  ┌─────────────────────────┐ │
│  │   Repl     │  │  Log Store   │  │    Index Service        │ │
│  │  Service   │  │   Service    │  │  (Multiple IndexTables) │ │
│  └────────────┘  └──────────────┘  └───────────┬─────────────┘ │
│                                                 │                │
│                           ┌─────────────────────▼─────────────┐ │
│                           │      IndexWBCache                 │ │
│                           │  - Buffer allocation/lifecycle    │ │
│                           │  - Dirty tracking                 │ │
│                           │  - Dependency management (DAG)    │ │
│                           │  - CP flush orchestration         │ │
│                           └─────────────┬───────────────────┬─┘ │
│                                         │                   │    │
│                           ┌─────────────▼─────────┐  ┌──────▼──┐│
│                           │   Virtual Device      │  │  Meta   ││
│                           │   (Block storage)     │  │ Service ││
│                           └───────────────────────┘  └─────────┘│
└─────────────────────────────────────────────────────────────────┘
```

### Key Design Principles

1. **Write-Back Caching**: Modifications stay in memory until CP flush, enabling batching and reducing I/O
2. **Dependency-Ordered Flush**: Parent nodes flush only after all children, ensuring crash consistency
3. **Copy-on-Write (COW) for CP**: Buffers modified in new CP while old CP is flushing get copied
4. **Journal-Based Recovery**: WAL records structural changes, enabling reconstruction of dependency DAG after crash
5. **Meta Buffer Isolation**: Superblock updates are separate from B-tree node updates, flushed last

### Problem Being Solved

**Without WBC**: Every B-tree modification would require:
- Immediate disk write (slow)
- Complex coordination for atomic updates across multiple nodes
- Poor performance for write-heavy workloads

**With WBC**:
- Batch multiple modifications in memory
- Flush atomically during CP with dependency ordering
- Recover partial flushes using journal
- Achieve both performance and crash consistency

## 1. Core Components

### 1.1 IndexWBCache
The write-back cache that manages all index node buffers. It handles:
- Buffer allocation and lifecycle
- Buffer dirty tracking
- Flush orchestration with dependency management

### 1.2 IndexCPContext
Checkpoint context for a single CP cycle. Manages:
- List of dirty buffers pending flush
- Journal of transactions in this CP
- Completion signaling (Future/Promise)

### 1.3 IndexBuffer
The buffer structure for each index node. Key members:
- `m_blkid` - Block ID where this buffer is persisted
- `m_dirtied_cp_id` - CP that last modified this buffer
- `m_created_cp_id` - CP when this buffer was created
- `m_state` - CLEAN, DIRTY, or FLUSHING
- `m_up_buffer` - Pointer to parent buffer in dependency chain
- `m_wait_for_down_buffers` - Counter: how many children must flush before this buffer
- `m_is_meta_buf` - Whether this is the meta (super block) buffer
- `m_node_freed` - Whether this node was freed

### 1.4 MetaIndexBuffer
Special buffer for the index table super block. Inherits from IndexBuffer and:
- Holds a reference to `superblk<index_table_sb>`
- Must be the last buffer flushed in a CP

### 1.5 Buffer State Machine

```
                    ┌──────────────┐
                    │    CLEAN     │ (Initial state after flush or allocation)
                    └───────┬──────┘
                            │
                            │ write_buf() called
                            │ (node modified in current CP)
                            │
                    ┌───────▼──────┐
                    │    DIRTY     │ (In dirty list, waiting for CP flush)
                    └───────┬──────┘
                            │
                            │ CP starts, m_wait_for_down_buffers == 0
                            │ do_flush_one_buf() called
                            │
                    ┌───────▼──────┐
                    │  FLUSHING    │ (Write to disk in progress)
                    └───────┬──────┘
                            │
                            │ Write completion callback
                            │ process_write_completion() called
                            │
                    ┌───────▼──────┐
                    │    CLEAN     │ (Flush complete, may be evicted from cache)
                    └──────────────┘

Special transitions:
- DIRTY → DIRTY (new CP): If modified again in new CP while old CP flushing
- CLEAN → Evicted: Cache eviction removes buffer from memory
- Any → Recovery: Crash recovery creates temporary buffers from journal
```

## 2. Dependency Chain (DAG)

Buffers form a directed acyclic graph (DAG) based on parent-child relationships in the B-tree:

```
Meta Buffer (super block)
    │
    ├── Interior Node A
    │       │
    │       ├── Leaf Node A1
    │       └── Leaf Node A2
    │
    └── Interior Node B
            │
            └── Leaf Node B1
```

### 2.1 Key Rules
1. A child buffer's `m_up_buffer` points to its parent
2. A parent buffer's `m_wait_for_down_buffers` = number of children linked to it
3. **A buffer can only be flushed when `m_wait_for_down_buffers == 0`**
4. After a child flushes, its parent's `m_wait_for_down_buffers` is decremented

### 2.2 Link Buffer (`link_buf`)
Establishes parent-child relationship between buffers:

```cpp
void link_buf(IndexBufferPtr up_buf, IndexBufferPtr down_buf, bool is_sibling_link) {
    // Remove from old parent if exists
    if (down_buf->m_up_buffer) {
        down_buf->m_up_buffer->remove_down_buffer(down_buf);
    }

    // Link to new parent
    down_buf->m_up_buffer = up_buf;
    up_buf->add_down_buffer(down_buf);  // Increments up_buf->m_wait_for_down_buffers
}
```

## 3. Flush Flow

### 3.1 Triggering Flush
`async_cp_flush()` is called when checkpoint timer fires:

```cpp
folly::Future<bool> IndexWBCache::async_cp_flush(IndexCPContext* cp_ctx)
```

### 3.2 Steps in Flush

1. **Journal Update**: Write CP journal to meta block
2. **Prepare Iteration**: Reset iterator for dirty buffer list
3. **Parallel Flush**: Multiple fibers (`m_cp_flush_fibers`) concurrently flush buffers
4. **Dependency Resolution**: Buffers flushed in order: children → parents → meta
5. **Completion**: When all buffers done, call `m_vdev->cp_flush()` then `cp_ctx->complete()`

### 3.3 Getting Next Buffer to Flush

`get_next_bufs_internal()` retrieves the next buffer to flush:

```cpp
// 1. First, try to flush the parent of the just-flushed buffer
if (prev_flushed_buf && prev_flushed_buf->m_up_buffer) {
    if (prev_flushed_buf->m_up_buffer->m_wait_for_down_buffers.decrement_testz()) {
        // Parent's wait count reached 0, can flush it now
    }
}

// 2. Then, get buffers from the dirty list
// A buffer can be flushed if:
// - State is DIRTY
// - m_dirtied_cp_id == current cp_id
// - m_wait_for_down_buffers == 0
```

### 3.4 Flush One Buffer

`do_flush_one_buf()` handles individual buffer flush:

```cpp
void do_flush_one_buf(IndexCPContext* cp_ctx, IndexBufferPtr buf, bool part_of_batch) {
    buf->set_state(FLUSHING);

    if (buf->is_meta_buf()) {
        // Meta buffer: directly update super block
        meta_service().update_sub_sb(buf->m_bytes, sb.size(), sb.meta_blk());
        process_write_completion(cp_ctx, buf);  // Meta completes immediately (no async write)
    } else if (buf->m_node_freed) {
        // Freed node: no need to write
        process_write_completion(cp_ctx, buf);
    } else {
        // Normal node: async write to vdev
        m_vdev->async_write(buf->raw_buffer(), m_node_size, buf->m_blkid)
            .thenValue([buf, cp_ctx](auto) {
                process_write_completion(cp_ctx, buf);
            });
    }
}
```

### 3.5 Write Completion

`process_write_completion()` handles buffer flush completion:

```cpp
void process_write_completion(IndexCPContext* cp_ctx, IndexBufferPtr buf) {
    resource_mgr().dec_dirty_buf_size(m_node_size);

    auto [next_buf, has_more] = on_buf_flush_done(cp_ctx, buf);

    if (next_buf) {
        do_flush_one_buf(cp_ctx, next_buf, false);
    } else if (!has_more) {
        // All buffers done, now flush vdev metadata
        iomanager.run_on_forget(cp_mgr().pick_blocking_io_fiber(), [this, cp_ctx]() {
            m_vdev->cp_flush(cp_ctx);  // Blocking IO
            cp_ctx->complete(true);
        });
    }
}
```

### 3.6 Buffer Flush Done

`on_buf_flush_done_internal()` decrements dependency counters:

```cpp
std::pair<IndexBufferPtr, bool> on_buf_flush_done_internal(IndexCPContext* cp_ctx,
                                                              IndexBufferPtr buf) {
    // Clear debug down_buffers list
    buf->m_down_buffers.clear();

    if (cp_ctx->m_dirty_buf_count.decrement_testz()) {
        // Count reached 0, this was the last buffer
        buf->set_state(CLEAN);
        return {nullptr, false};
    } else {
        // Count still > 0, get parent's next buffer
        get_next_bufs_internal(cp_ctx, 1u, buf, buf_list);
        buf->set_state(CLEAN);
        return {buf_list[0], true};
    }
}
```

## 4. Key Call Paths

### 4.1 B-tree Split → Root Change

When a B-tree root node splits:

1. `split_root_node()` allocates new root
2. `on_root_changed()` is called:
   ```cpp
   btree_status_t on_root_changed(BtreeNodePtr new_root, void* context) {
       // 1. Update super block with new root info
       wb_cache().refresh_meta_buf(m_sb_buffer, cp_ctx);

       // 2. Link new_root → meta and flush in order
       wb_cache().transact_bufs(ordinal(), m_sb_buffer, root_buf, {}, {}, cp_ctx);
       return success;
   }
   ```

3. `transact_bufs()` establishes dependencies:
   ```cpp
   void transact_bufs(ordinal, parent_buf, child_buf, new_nodes, freed_nodes, cp_ctx) {
       if (parent_buf) {
           link_buf(parent_buf, child_buf, false);  // child → parent
       }
       // Link new nodes as children of child_buf
       for (buf : new_nodes) {
           link_buf(child_buf, buf, true);
       }
       // Add all to dirty list
       add_to_dirty_list(...);
   }
   ```

### 4.2 Normal Node Split

When a non-root node splits:

1. `split_node()` is called
2. `transact_nodes()` is called with:
   - `new_nodes`: [new_sibling_node]
   - `left_child_node`: original_node (now left sibling)
   - `parent_node`: parent of original_node
3. This creates chain: new_sibling → original_node → parent → ...

## 5. Meta Buffer Flush Specifics

The meta buffer has special handling:

1. **No Async Write**: Unlike normal nodes, meta buffer writes directly to meta service:
   ```cpp
   if (buf->is_meta_buf()) {
       meta_service().update_sub_sb(buf->m_bytes, sb.size(), sb.meta_blk());
       process_write_completion(cp_ctx, buf);  // Immediate completion
   }
   ```

2. **Must Be Last**: Meta buffer should have `m_wait_for_down_buffers == 0` before flushing, meaning all other buffers (including root) must complete first.

3. **Super Block Update**: After all buffers flush, `process_write_completion()` calls:
   ```cpp
   for (ordinal : m_updated_ordinals) {
       index_service().write_sb(ordinal);  // Write index table super blocks
   }
   ```

## 6. Important Invariants

1. **Dirty Buffer Count**: `m_dirty_buf_count` must equal the number of dirty buffers pending flush
2. **Dependency Consistency**: If `m_wait_for_down_buffers > 0`, there must be buffers in `m_down_buffers`
3. **Flush Order**: No buffer can be flushed before all its children (`m_wait_for_down_buffers == 0`)
4. **Meta Dependency**: Meta buffer can only be flushed when all other buffers in this CP are done

## 7. Common Bug Patterns

### 7.1 Orphaned Down Wait
**Symptom**: Meta buffer has `m_wait_for_down_buffers > 0` but no child's `up` points to it.

**Cause**: `link_buf()` was called to add a child to meta, but later:
- The child's `up` was changed to point elsewhere
- The child was freed/overwritten without cleaning up the link

### 7.2 Buffer Overwrite During Flush
**Symptom**: A buffer expected in dirty list is missing, causing dependency chain to break.

**Cause**: Next CP triggers before current CP completes, and operations in the new CP overwrite buffers from the previous CP.

### 7.3 Race in Multi-Fiber Flush
**Symptom**: Intermittent failures with `m_dirty_buf_count` mismatch.

**Cause**: When `m_cp_flush_fibers > 1`, buffers are flushed in parallel. Proper locking in `get_next_bufs_internal()` is required.

## 8. Recovery Flow

### 8.1 Recovery Entry Point
`IndexWBCache::recover(sisl::byte_view sb)` called from `IndexService::start()` after all index tables are loaded from meta service.

### 8.2 Recovery Steps

1. **Load Buffers from Journal**: `IndexCPContext::recover()` reads journal and reconstructs buffer dependency DAG
   - Creates temporary `IndexBuffer` objects for all dirty buffers from prior CP
   - Creates temporary `MetaIndexBuffer` for parent buffers marked as meta
   - Links buffers with `m_up_buffer` pointers to reconstruct dependency chain
   - Performs sanity check to ensure all dependencies are valid (no freed up_buffers, proper ordinals, etc.)

2. **Two Recovery Passes**:
   - **Pass 1**: Handle new nodes and freed nodes (iterate through `bufs` map)
     - For new nodes: commit their block IDs if both current and up buffer committed, otherwise remove from up buffer's dependency and prune
     - For freed nodes:
       - If committed: mark as deleted, write to disk, add up buffer to pending list for repair
       - If not committed: either keep (if created before current CP) or delete (if created in current CP), remove from up buffer dependency and prune
   - **Pass 2**: Repair parent nodes and pending buffers
     - First repair `potential_parent_recovered_bufs` via `parent_recover()` - these are interior nodes that may have stale links
     - Then call `recover_buf()` recursively on all pending buffers (buffers whose children were new/freed)
     - For uncommitted nodes, call `repair_index_node()` to fix their content
     - For committed nodes with meta parent, call `update_root()` to update super block
     - Finally repair `pruned_bufs_to_repair` via `repair_index_node()` - these are parents whose dependencies became zero

3. **Prune Up Buffers**: When a child buffer is removed (e.g., freed), call `prune_up_buffers()` to clean up dependency
   - Decrements up buffer's `m_wait_for_down_buffers` via `update_up_buffer_counters()` recursively
   - Adds up buffer to `pruned_bufs_to_repair` list if dependency reaches zero
   - Adds grand-up buffer to repair list if not meta and also has zero dependency

4. **Sanity Check**: After recovery, verify all repaired buffers via `index_service().sanity_check()` for each ordinal

5. **Completion**: `m_in_recovery = false`, temporary buffers destroyed, `m_vdev->recovery_completed()` called

### 8.3 Recovery vs Normal Operation Differences

| Aspect           | Normal Operation                     | Recovery                            |
|------------------|--------------------------------------|-------------------------------------|
| Buffer source    | Runtime allocation                   | Created from journal                |
| Meta buffer type | IndexTable::m_sb_buffer (persistent) | Temporary MetaIndexBuffer           |
| Write method     | Add to dirty list, async CP flush    | Immediate sync_write (via write_buf)|
| Buffer lifecycle | Cached in memory, may be evicted     | Temporary, destroyed after recovery |
| Cache usage      | Buffers inserted into cache          | Cache operations skipped            |

## 9. Meta Buffer Dual Paths

### 9.1 Path 1: Normal Operation (Persistent Path)

**Entry**: `IndexTable::on_root_changed()`

**Flow**:
1. `IndexTable::m_sb_buffer` (persistent, lives with IndexTable object)
2. Update `m_sb` fields (root_node, root_link_version, btree_depth, node counts)
3. `refresh_meta_buf(m_sb_buffer, cp_ctx)` - creates new meta buffer via COW if needed (wb_cache.cpp:200-220)
   - If `m_dirtied_cp_id > cp_ctx->id()`: return false (CP mismatch)
   - If `m_dirtied_cp_id == cp_ctx->id()`: copy superblk to buffer via `copy_sb_to_buf()`
   - Else: create new `MetaIndexBuffer` via COW, set `m_dirtied_cp_id = cp_ctx->id()`, add to dirty list
4. `transact_bufs(ordinal, m_sb_buffer, root_buf, {}, {})` - establishes root→meta dependency
5. `link_buf(m_sb_buffer, root_buf, false)` - sets `root_buf->m_up_buffer = m_sb_buffer`
6. CP flush: `do_flush_one_buf()` writes to metadata service via `meta_service().update_sub_sb()`

**Key**: This path uses the IndexTable's real meta buffer reference.

### 9.2 Path 2: Recovery (Temporary Path)

**Entry**: `IndexCPContext::process_txn_record()` during recover

**Flow**:
1. Create temporary `MetaIndexBuffer` with empty local `superblk< index_table_sb > tmp_sb` (dangling reference bug - see Bug 11.2)
2. `m_up_buffer = temporary_meta` - set on child buffers during `rec_to_buf()` lambda
3. `m_wait_for_down_buffers++` - counts pending children via `add_down_buffer()`
4. Purpose: Only for dependency tracking, ensuring correct repair order (children before parents)
5. Lifecycle: Created in `process_txn_record()`, stored in `buf_map`, destroyed when no ref exists

**Key**: This path creates temporary meta buffers that are never flushed. During recovery:
- `repair_root_node()` does NOT update `m_sb->root_node` in the superblock
- Instead, it fixes the old root node to point to new root via edge_value (if root changed)
- The superblock continues to point to the old root, which now has a valid edge to the new root
- Superblock updates only happen during normal operation via `on_root_changed()` → `m_sb->root_node = new_root->node_id()`

## 10. Root Change Flow

### 10.1 Root Change from B-tree Operations

**Trigger**: Split, merge, or other operations that create new root

**Flow**:
```
Btree operation (split/merge)
  └─> IndexTable::on_root_changed(new_root, cp_ctx)
      ├─> Update m_sb->root_node, depth, node counts
      ├─> wb_cache().refresh_meta_buf(m_sb_buffer, cp_ctx)
      │    └─> May create new m_sb_buffer via COW
      │
      └─> wb_cache().transact_bufs(ordinal, m_sb_buffer, root_buf, {}, {}, cp_ctx)
           └─> wb_cache().link_buf(m_sb_buffer, root_buf, false, cp_ctx)
                ├─> root_buf->m_up_buffer = m_sb_buffer  ✅
                ├─> m_sb_buffer->add_down_buffer(root_buf)
                └─> add_to_txn_journal() to record operation
```

**Result**: Root node now has `m_up_buffer = m_sb_buffer`, establishing flush order dependency.

### 10.2 Root Change During Recovery

**Trigger**: Recovery detects root change from journal

**Flow**:
```
recover_buf(root_buf)  // wb_cache.cpp:788-812
  └─> If all down buffers flushed (m_wait_for_down_buffers == 0):
      ├─> If !was_node_committed(buf):
      │   └─> index_service().repair_index_node(ordinal, buf)
      │
      └─> If was_node_committed(buf) && m_up_buffer && m_up_buffer->is_meta_buf():
          └─> index_service().update_root(ordinal, buf)
              └─> table->repair_root_node(buf)
                  ├─> Check if buf->blkid() == m_sb->root_node (is this the old root?)
                  ├─> If yes, get edge_id from node->next_bnode()
                  ├─> Clear next_bnode and set edge_value to edge_id
                  └─> write_node_impl() to persist the fixed root node (not superblock)
```

**Key**: When root changes during recovery, `update_root()` is called for committed roots with meta parent. **Important**: This does NOT update the superblock. Instead:
- It calls `repair_root_node()` which checks if the buffer is the old root
- If yes, it reads the new root ID from `node->next_bnode()` 
- It then clears next_bnode and sets edge_value to point to the new root
- The old root node is written back with the edge updated
- The superblock (`m_sb->root_node`) is NOT changed - it still points to the old root
- The btree will follow the edge from old root to find the new root during normal access
- The superblock is only updated during normal operation when `on_root_changed()` is called

### 10.3 Setting Root's Up Buffer

**Normal Path** (only on root change):
- `on_root_changed()` → `transact_bufs()` → `link_buf()` sets `root_buf->m_up_buffer = m_sb_buffer`
- Done only when root object changes (new root node created), not for normal root node updates
- `link_buf()` also handles the case where up_buffer was created in same CP (uses real_up_buf = up_buf->m_up_buffer)

**Recovery Path**:
- Sets `root_buf->m_up_buffer` to temporary meta buffer during `process_txn_record()`
- Temporary meta buffer reference has dangling superblk, but only used as pointer for dependency tracking
- After recovery, these temporary buffers and dependencies are discarded

## 11. Known Bugs

### 11.1 Meta Buffer Prune Bug (FIXED)

**Location**: `IndexWBCache::prune_up_buffers()` 

**Trigger Scenario**: An IndexTable (ordinal=7) was destroyed (e.g., deleted or failed mid-initialization), but the journal from a prior CP still contains records for it. During recovery:
1. Journal is replayed — a temporary `MetaIndexBuffer` is created for ordinal=7
2. The child buffer (which was a new/uncommitted node for ordinal=7) is found to be uncommitted
3. The child is removed from the dependency chain, triggering `prune_up_buffers()`
4. The temporary MetaIndexBuffer (ordinal=7's `up_buf`) gets unconditionally added to `pruned_bufs_to_repair`
5. Later, `repair_index_node(ordinal=7, meta_buf)` is called → `get_index_table(7)` returns nullptr → **CRASH**

The key insight: `prune_up_buffers()` is only called during recovery when discarding uncommitted nodes. A temporary MetaIndexBuffer is never a real B-tree node — it's a placeholder for dependency tracking only and must never be repaired.

**Buggy Code** (wb_cache.cpp:533-550):
```cpp
void IndexWBCache::prune_up_buffers(IndexBufferPtr const& buf, std::vector< IndexBufferPtr >& pruned_bufs_to_repair) {
    auto up_buf = buf->m_up_buffer;
    auto grand_up_buf = up_buf->m_up_buffer;
    if (!up_buf || !up_buf->m_wait_for_down_buffers.testz()) { return; }

    update_up_buffer_counters(up_buf);

    pruned_bufs_to_repair.push_back(up_buf);  // ❌ BUG: no is_meta_buf() check
    if (grand_up_buf && !grand_up_buf->is_meta_buf() && grand_up_buf->m_wait_for_down_buffers.testz()) {
        pruned_bufs_to_repair.push_back(grand_up_buf);  // ✅ correctly skips meta
    }
}
```

**Fix**: Add the same `is_meta_buf()` guard that already exists for `grand_up_buf`:
```cpp
    if (!up_buf->is_meta_buf()) {
        pruned_bufs_to_repair.push_back(up_buf);
    }
```

**Why This Is Safe**: Temporary MetaIndexBuffers are dependency tracking placeholders created from journal records with empty superblocks. They are never real B-tree nodes and carry no state that needs repairing. Real superblock state lives in `IndexTable::m_sb_buffer` and is restored through `update_root()` / `IndexTable::write_sb()`, not through the repair path.

### 11.2 Dangling Reference in Temporary Meta Buffers

**Location**: `IndexCPContext::process_txn_record()`

**Bug**: Temporary meta buffers hold reference to local `superblk` variable that goes out of scope.

**Current Code** (index_cp.cpp:328-375):
```cpp
void IndexCPContext::process_txn_record(txn_record const* rec, std::map< BlkId, IndexBufferPtr >& buf_map) {
    auto cpg = cp_mgr().cp_guard();

    auto const rec_to_buf = [&buf_map, &cpg](txn_record const* rec, bool is_meta, BlkId const& bid,
                                             IndexBufferPtr const& up_buf) -> IndexBufferPtr {
        IndexBufferPtr buf;
        auto it = buf_map.find(bid);
        if (it == buf_map.end()) {
            if (is_meta) {
                superblk< index_table_sb > tmp_sb;  // ❌ Local variable
                buf = std::make_shared< MetaIndexBuffer >(tmp_sb);  // ❌ Dangling reference
            } else {
                buf = std::make_shared< IndexBuffer >(nullptr, bid);
            }
            // ...
        }
        // ...
    };
    // tmp_sb destroyed here, but buf->m_sb still references it
}
```

**Impact**: Currently not triggered in normal recovery flow because:
1. Recovery never calls `write_buf()` on temporary meta buffers (only on freed real nodes at line 622)
2. The only access to `m_sb` is in `write_buf()` at line 130-132 when calling `meta_service().update_sub_sb()`
3. Recovery uses meta buffers purely as dependency tracking pointers

**Why Not Crashing**: The dangling reference exists but is never dereferenced during normal recovery.

**Status**: Latent bug - if future code tries to flush/write temporary meta buffers during recovery, it would crash with segfault or data corruption.

### 11.3 Root Up Buffer Lifecycle

**Behavior**: Root nodes only get `m_up_buffer` set during explicit root change via `on_root_changed()`, not on regular updates.

**Scenario**:
1. Recovery completes, root loaded but temporary meta buffer and dependencies are discarded
2. First modification of root after recovery: buffer becomes dirty and flushes without meta dependency
3. Root change (new root node created): `on_root_changed()` called, establishes root→meta dependency

**Current Behavior**: By design - meta dependency only needed when superblock changes (root_node, depth, link_version update). Regular root modifications don't require superblock update, so no meta dependency needed.

## 13. Configuration

- `m_cp_flush_fibers`: Number of fibers for parallel buffer flushing (default: 1)
- `m_node_size`: Size of each index node buffer
- Cache capacity controlled by `sisl::SimpleCache`