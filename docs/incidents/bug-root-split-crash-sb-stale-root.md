# RCA: Root Split Crash Leaves SB Pointing to Old Root

**Date:** 2026-05-22
**Component:** HomeStore / IndexTable / BTree / IndexWBCache
**Severity:** Critical (crash on restart, blocks index recovery)

---

## Symptom

After a SIGKILL, the process crashes during restart with a B-tree sanity failure.

In release builds:

```
Child node level mismatch ... child level: 1, expected: 0
```

In debug builds, recovery may abort earlier inside `IndexTable::repair_root_node`:

```
root already has a valid edge ..., so we should have found the new root node
```

---

## Root Cause Chain

### Condition 1: `on_root_changed` is called before `split_node` completes

`Btree::check_split_root` (`src/include/homestore/btree/detail/btree_mutate_impl.ipp`):

```
1. Allocate new_root (level=2)
2. Call on_root_changed(new_root)      ← SB and journal updated here
3. split_node(new_root, old_root, ...) ← old root modified here
```

`IndexTable::on_root_changed` updates the in-memory SB (`index_table_sb.root_node`,
`btree_depth`) and calls `wb_cache().transact_bufs(meta_buf, new_root_buf)`, which
links `meta_buf → new_root_buf` in the CP flush DAG and appends a meta/root
transaction to the journal.

After step 3, `split_node` calls `transact_nodes({child_node2}, {}, old_root, new_root)`,
which invokes `link_buf(new_root_buf, old_root_buf)`. Because `new_root_buf` was
allocated in the current CP (`m_created_cp_id == icp_ctx->id()`), `link_buf`'s
Condition 1 (`wb_cache.cpp:373`) bypasses new_root_buf and substitutes
`new_root_buf->m_up_buffer = meta_buf` as the real up-buffer. As a result,
old_root_buf links **directly to meta_buf**, not through new_root_buf.

**Final CP flush DAG:**

```
meta_buf [wait=2]
  ├── new_root_buf  [independent flush]
  └── old_root_buf [wait=1]
        └── child_node2_buf
```

new_root_buf and old_root_buf are siblings under meta_buf and can flush in any order.

### Condition 2: split_node writes old_root into a transient disk state with empty `edge_info`

`split_node` modifies old_root in memory:

- `child_node1->set_next_bnode(child_node2->node_id())` — old_root.next_bnode = child_node2.blkid
- `move_out_to_right_by_size(...)` → `invalidate_edge()` — old_root.edge_info = EMPTY
- `parent_node->update(parent_ind, child_node2->link_info())` — new_root.edge_info = child_node2

old_root_buf is then flushed to disk as a direct down-buffer of meta_buf (see Condition 1).
On-disk state of old_root after flush:

- `old_root.level = 1`
- `old_root.edge_info = EMPTY`
- `old_root.next_bnode = child_node2.blkid` (child_node2 is a level=1 interior node)

This transient state is only valid within the full tree structure; it is resolved
when new_root takes ownership. If the process crashes here and recovery restarts from
old_root in this state, the structure is misinterpreted (see Condition 5).

### Condition 3: SB persistence is deferred to end-of-CP flush

Even though `on_root_changed` updated the in-memory SB, the persisted superblock
write happens only after the last buffer completes during CP flush
(`IndexWBCache::process_write_completion` → `index_service().write_sb(ordinal)`
in `src/lib/index/wb_cache.cpp`).

A SIGKILL after Condition 2 but before this deferred write leaves the on-disk SB still
pointing to the old root.
**Evidence (gdb):** `index_table_sb.root_node=1125904201810030, btree_depth=1`
— matches the old root, not the new level-2 root.

### Condition 4: A new level-2 root exists on disk but is not referenced by the SB

Recovery DAG logs show: `id=1407379178523696 ... INTERIOR level=2 ... NEW`

The new root was written and is present on disk, but the persisted SB still points
to old_root (Condition 3). Recovery therefore starts from the old root.

From gdb on coredump:

- `index_table_sb.root_node = 1125904201810030`
- `index_table_sb.btree_depth = 1`

### Condition 5: `repair_root_node` incorrectly writes old root's `edge_info` from `next_bnode`

`IndexWBCache::recover_buf` → `IndexService::update_root` → `IndexTable::repair_root_node`
(`src/include/homestore/index/index_table.hpp`).

`repair_root_node` is designed to repair a root-change marker by converting `next_bnode`
into `edge_info`. With old_root's on-disk state from Condition 2
(`edge_info=EMPTY`, `next_bnode=child_node2.blkid`), it executes:

```cpp
auto edge_id = n->next_bnode();               // = child_node2.blkid (level=1 interior)
n->set_next_bnode(empty_bnodeid);
n->set_edge_value(BtreeLinkInfo{edge_id, 0}); // sets old_root.edge_info = child_node2 (level=1)!
write_node_impl(n, cp_ctx);
```

This writes `old_root.edge_info = child_node2.blkid` where child_node2 is a level=1
interior node — violating the invariant that a level=1 parent's edge child must be level=0.

**Evidence (gdb on coredump, state captured after repair_root_node ran):**

- `node_id = 1125904201810030` (old_root)
- `level = 1`
- `edge_info.m_bnodeid = 1125904201813044` (confirmed level=1 interior node)

Subsequent B-tree validation (`validate_node`) finds a level=1 parent with a level=1 edge
child and aborts with:

```
Child node level mismatch ... child level: 1, expected: 0
```

In debug builds, `repair_root_node` additionally asserts when it finds `has_valid_edge()`
already true on the SB root (it expects to find the new root instead), triggering:

```
root already has a valid edge ..., so we should have found the new root node
```

---

## Trigger Conditions

The following sequence must all occur:

1. A B-tree root split is triggered (tree height increases from level=1 to level=2)
2. `on_root_changed` runs and links `meta_buf → new_root_buf` in the CP flush DAG
3. `split_node` completes: old_root.edge_info is invalidated, old_root.next_bnode = child_node2.blkid; old_root_buf is flushed to disk
4. SIGKILL arrives after step 3 but before CP flush completes and writes the updated SB

