# Index CP Flush and Recovery (Ordering, Journal, and Root Handling)

This document explains:

- How IndexWBCache tracks dirty index nodes
- How dependency ordering (DAG) is built
- What the CP transaction journal records and its ordering
- How recovery reconstructs the DAG and decides what to repair
- When index superblocks (SB) are updated

It is intended to provide enough context to understand crash-consistency issues around root changes.

---

## 1. Key components

### 1.1 IndexWBCache
The write-back cache that owns `IndexBuffer` objects and orchestrates CP flush.

Source:
- `src/lib/index/wb_cache.cpp`
- `src/lib/index/wb_cache.hpp`

### 1.2 IndexBuffer
A buffer representing a btree node.
It tracks:

- Block id (`m_blkid`)
- State (`CLEAN`, `DIRTY`, `FLUSHING`)
- CP ids (`m_created_cp_id`, `m_dirtied_cp_id`)
- Dependency links:
  - `m_up_buffer` (child -> parent)
  - `m_wait_for_down_buffers` (parent wait-count)

### 1.3 MetaIndexBuffer
Special buffer that represents the index table superblock (SB) during normal operation.

Important: during **recovery**, temporary meta buffers can be created from the txn journal, and are used only for dependency tracking.

---

## 2. How dependency ordering works (DAG)

IndexWBCache enforces a flush order:

- Children must flush before parents.

This is encoded as:

- `down_buf->m_up_buffer = up_buf`
- `up_buf->add_down_buffer(down_buf)` which increments `up_buf->m_wait_for_down_buffers`

Source:
- `IndexWBCache::link_buf(...)` in `src/lib/index/wb_cache.cpp`

A buffer can be flushed only when:

- `state == DIRTY`
- `m_dirtied_cp_id == current_cp`
- `m_wait_for_down_buffers == 0`

Source:
- `IndexWBCache::get_next_bufs_internal(...)` in `src/lib/index/wb_cache.cpp`

---

## 3. Mutation commit path: `write_node_impl` and `transact_bufs`

### 3.1 Dirtying nodes
When a btree node is modified, `IndexTable::write_node_impl` is called.

Key behavior:

- Marks `IndexBuffer` state to `DIRTY`
- Sets persistent header `modified_cp_id`
- Adds buffer into CP dirty list via `wb_cache().write_buf(...)`

Source:
- `IndexTable::write_node_impl` in `src/include/homestore/index/index_table.hpp`

### 3.2 Transaction boundary
Structural operations (split/merge) call `IndexTable::transact_nodes(...)`.

This does:

1. `write_node_impl` for:
   - newly created nodes
   - left child
   - parent (if any)
2. `wb_cache().transact_bufs(...)` to link dependencies and append to journal

Source:
- `IndexTable::transact_nodes` in `src/include/homestore/index/index_table.hpp`

---

## 4. Root changes and `on_root_changed`

When the root changes, `IndexTable::on_root_changed(new_root)` is called.

It:

- Updates in-memory SB fields (`index_table_sb`) including `root_node` and `btree_depth`
- Ensures the meta buffer is writable (`refresh_meta_buf`)
- Calls `wb_cache().transact_bufs(meta_buf, root_buf, {}, {})`
  - This creates a dependency `meta -> root` and also appends a **meta/root transaction record** to the journal.

Source:
- `IndexTable::on_root_changed` in `src/include/homestore/index/index_table.hpp`

---

## 5. Transaction journal (what it records and ordering)

The journal is managed by `IndexCPContext`.

The record ordering is deterministic:

1. Parent (in-place) buffer id (optional; can be meta)
2. Child (in-place) buffer id (optional)
3. Newly created child buffers (0..N)
4. Freed child buffers (0..N)

This ordering is enforced in `txn_record::append(...)`.

Source:
- `src/lib/index/index_cp.hpp`
- `src/lib/index/index_cp.cpp` (`IndexCPContext::add_to_txn_journal`)

### 5.1 How meta/root transactions are recorded
In `IndexWBCache::transact_bufs`:

- When `new_node_bufs` and `freed_node_bufs` are empty, it is treated as a **meta/root transaction**.
- It appends a txn record that includes meta as parent and root as child.

Source:
- `IndexWBCache::transact_bufs` in `src/lib/index/wb_cache.cpp`.

---

## 6. CP flush ordering and SB update timing

### 6.1 Flush start
`IndexWBCache::async_cp_flush(cp_ctx)` does:

1. Writes the txn journal into meta-service first (`update_sub_sb` / `add_sub_sb`).
2. Starts flush fibers that select eligible buffers from the dirty list.

Source:
- `IndexWBCache::async_cp_flush` in `src/lib/index/wb_cache.cpp`

### 6.2 Buffer writes
`do_flush_one_buf`:

- Meta buffers are written to meta service and completed immediately.
- Normal buffers are async-written to vdev.

Source:
- `IndexWBCache::do_flush_one_buf` in `src/lib/index/wb_cache.cpp`

### 6.3 When SB is written
After the last dirty buffer completes, `process_write_completion` calls:

- `index_service().write_sb(ordinal)` for each updated ordinal

This is an important detail:

> **Index table SB persistence is performed at the end of CP flush, after all buffers complete.**

Source:
- `IndexWBCache::process_write_completion` in `src/lib/index/wb_cache.cpp`

---

## 7. Recovery flow overview

Entry point:

- `IndexWBCache::recover(sb)` called from `IndexService::start()`.

High-level steps:

1. Set `m_in_recovery = true`.
2. Reconstruct DAG from persisted journal:
   - `IndexCPContext::recover(...)` returns a map of buffers with `m_up_buffer` links.
3. Two-pass processing:
   - Pass 1: handle new/freed nodes (commit/free decisions)
   - Pass 2: repair needed parents and recursively repair up-buffers (`recover_buf`)
4. Run sanity check
5. Exit recovery mode

Source:
- `IndexWBCache::recover` and `recover_buf` in `src/lib/index/wb_cache.cpp`
- `IndexCPContext::recover` in `src/lib/index/index_cp.cpp`

### 7.1 What "committed" means in recovery
Recovery uses the node's persistent `modified_cp_id`:

- `was_node_committed(buf)` returns true when:
  - node header is valid
  - `buf->m_dirtied_cp_id == current_cp_id`

The header field is read via `BtreeNode::get_modified_cp_id`.

---

## 8. Root handling during recovery

During `recover_buf(buf)`:

- If the node is committed and `buf->m_up_buffer` is a meta buffer, recovery calls:
  - `index_service().update_root(ordinal, buf)`
  - which calls `IndexTable::repair_root_node(buf)`

`repair_root_node` is intended to fix cases where SB still points to an old root by converting a root-change marker into `edge_info`.

Source:
- `IndexWBCache::recover_buf` in `src/lib/index/wb_cache.cpp`
- `IndexTable::repair_root_node` in `src/include/homestore/index/index_table.hpp`

---

## 9. Important debug signal: CLEAN buffer dependency warning

`IndexWBCache::link_buf` logs when a CLEAN down buffer is added as a dependency:

- `CLEAN_BUF_DEBUG: Adding CLEAN down_buf ... to up_buf ...`

This warns about a potential CP hang scenario because CLEAN buffers do not normally participate in the CP dirty list.

Source:
- `IndexWBCache::link_buf` in `src/lib/index/wb_cache.cpp`

---

## 10. Relevant code pointers

- Flush: `src/lib/index/wb_cache.cpp`
  - `async_cp_flush`, `do_flush_one_buf`, `process_write_completion`, `get_next_bufs_internal`

- Journal: `src/lib/index/index_cp.hpp`, `src/lib/index/index_cp.cpp`

- Root SB update: `src/include/homestore/index/index_table.hpp`
  - `on_root_changed`, `write_node_impl`, `transact_nodes`, `repair_root_node`
