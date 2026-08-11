# Index B-Tree Nodes (Concepts and On-Disk Layout)

This document explains the **node model** used by HomeStore's index B-tree implementation, focusing on:

- What *root / interior / leaf* mean
- The meaning of *level*
- The meaning of *edge* vs *next_node*
- The persistent on-disk header (`persistent_hdr_t`)
- Key structural invariants (what the sanity check validates)

This is meant as background for understanding checkpoint (CP) flush and recovery.

---

## 1. Node types and levels

HomeStore stores an index as a B-tree where every node has a **level**:

- **Leaf node**: `level == 0`
  - Stores *key -> user value* entries.
- **Interior node**: `level > 0`
  - Stores *separator keys* and *child pointers* (as `BtreeLinkInfo`).

The **root** is simply the node currently referenced by the index table superblock (`index_table_sb.root_node`).
Depending on tree size, root may be a leaf (small tree) or an interior node.

### 1.1 Level invariant
For every parent/child relationship:

- `child.level == parent.level - 1`

This is the invariant that failed in the reported incident.

---

## 2. Persistent vs transient headers

Each node buffer consists of:

- A **persistent header** stored on disk (`persistent_hdr_t`)
- A **node body** (key/value entries)
- A **transient header** stored only in memory (`transient_hdr_t`) used for locking and runtime thresholds

### 2.1 Persistent header (`persistent_hdr_t`)
Source: `src/include/homestore/btree/detail/btree_node.hpp`

`persistent_hdr_t` is placed at the start of every node buffer (packed layout). Important fields:

| Field | Meaning |
|---|---|
| `magic`, `version`, `checksum` | On-disk format verification (`BtreeNode::is_valid_node`) |
| `nentries` | Number of entries in the node body |
| `leaf` | 1-bit flag: leaf vs interior |
| `node_deleted` | 1-bit tombstone; deleted nodes may still exist on disk during recovery |
| `node_id` | Persistent node identifier (`bnodeid_t`); for index this is the block id |
| `next_node` | Persistent sibling pointer (`next_bnode()`) |
| `node_gen` | Generation number; incremented on updates (used by lock/refresh logic) |
| `link_version` | Version of the link from parent -> this node (`BtreeLinkInfo`) |
| `edge_info` | The rightmost child pointer + link_version (see section 3) |
| `modified_cp_id` | CP id of last modification; used by recovery to decide whether a node was committed |
| `level` | Node level within the tree |
| `node_size` | Physical size of the node buffer |
| `node_type` | Node layout variant (simple/prefix/varlen) |

You can print these fields directly from a core dump by casting the node buffer:

```gdb
set $hdr = (homestore::persistent_hdr_t*)node->m_phys_node_buf
p *$hdr
```

---

## 3. Child pointers: entries vs edge

Interior nodes contain child pointers in two forms:

1. **Regular children** stored as the value associated with each separator key in the node body.
2. The **edge child** stored separately in `persistent_hdr_t::edge_info`.

### 3.1 What is the edge child?
For an interior node, imagine the children as:

```
C0, C1, C2, ... , Cn
```

and separator keys:

```
K0, K1, ... , K(n-1)
```

The node body stores `(Ki -> Ci)` for `i in [0..n-1]`.
The rightmost child `Cn` is stored separately as **edge**.

In code, this is handled by treating index `total_entries()` as a valid child index only when edge is present.

Key call sites:

- `BtreeNode::find(...)` (child selection)
- `Btree::get_child_and_lock_node(...)` (read child at index)

### 3.2 `has_valid_edge()`
Definition:

- For leaf nodes: always false
- For interior nodes: true if `edge_id() != empty_bnodeid`

So an **"edge node"** in logs means: an interior node with `has_valid_edge() == true`.

---

## 4. Sibling linkage: `next_node` / `next_bnode()`

`persistent_hdr_t::next_node` is a persistent forward pointer:

- For **leaf nodes**: links leaves in key order to support range scans.
- For **interior nodes**: used to maintain ordering/relationship expectations among children (and validated by sanity checks).

### 4.1 How split updates sibling pointers
On split, the code does:

- new right node takes old `next_bnode`
- old (left) node's `next_bnode` updated to point to the new right node

Source: `src/include/homestore/btree/detail/btree_mutate_impl.ipp` (`split_node`).

---

## 5. Structural invariants validated by sanity checks

The validation functions live in:

- `src/include/homestore/btree/detail/btree_common.ipp`

Key invariants relevant to the incident:

1. **Level invariant**
   - `child.level == parent.level - 1`

2. **Leaf nodes cannot have edge children**

3. **A node cannot have both a valid edge and a non-empty next_node**
   - (validation expects `has_valid_edge() -> next_node == empty_bnodeid`)

4. **Child sibling linkage**
   - When iterating children of a parent, validation expects:
     - `previous_child.next_bnode == current_child.node_id`

5. **Key ordering in node body**

These invariants are what make the flush/recovery mechanisms safe: parent pointers and ordering assumptions must be consistent.

---

## 6. Notes on terminology in logs

- **LIVE**: `node_deleted == 0`
- **Deleted**: `node_deleted == 1`
- **LEAF / INTERIOR**: from the persistent `leaf` bit
- **level=N**: from persistent header
- **edge=X.Y**: `edge_info.m_bnodeid = X` and `edge_info.m_link_version = Y`
- **next=...**: `next_node` is not empty

---

## 7. Pointers to code

- Persistent header definition and accessors:
  - `src/include/homestore/btree/detail/btree_node.hpp`

- Validation logic:
  - `src/include/homestore/btree/detail/btree_common.ipp`

- Split logic updating next pointers:
  - `src/include/homestore/btree/detail/btree_mutate_impl.ipp`
