# HomeStore

[![Conan Build](https://github.com/eBay/HomeStore/actions/workflows/merge_build.yml/badge.svg?branch=master)](https://github.com/eBay/HomeStore/actions/workflows/merge_build.yml)
[![CodeCov](https://codecov.io/gh/eBay/homestore/branch/master/graph/badge.svg)](https://codecov.io/gh/eBay/homestore)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

> A modern storage engine for Linux - crash-consistent storage services over a C++23 coroutine, non-blocking-reactor I/O stack.

HomeStore is a generic **storage engine** on which different storage solutions - Block, K/V, Object, or
Database - are built. It hands an application a small set of composable, crash-resilient **services**
(metadata, index, data, log, replication) and runs them with **non-blocking** async I/O on
[IOManager](https://github.com/eBay/IOManager) reactors, so a storage solution never hands work off to a
separate thread pool. A reference Object solution is [HomeObject](https://github.com/eBay/HomeObject).

The data and replication paths are stackless coroutines that `co_await` an [`iomgr::io_result`](https://github.com/eBay/IOManager),
composed on the sisl `async` substrate over [NVIDIA stdexec](https://github.com/NVIDIA/stdexec).

## 🚀 Features

- **Composable services** - bring up only what a solution needs: `with_index_service`,
  `with_log_service`, `with_data_service`, `with_repl_data_service`, `with_fault_containment`.
- **Non-blocking, reactor-local I/O** - the device layer drives `io_uring` through IOManager reactors;
  the reactor never blocks, and devices on the same reactor interact without locks — no executor queue or
  thread hop. (A `co_await` is still a suspension point: state is stable across a synchronous segment, not
  across an await.)
- **Coroutine data path** - `BlkDataService` / `ReplDev` reads and writes are awaitables; `co_await`
  yields an `iomgr::io_result` (`std::expected<size_t, std::error_condition>`).
- **Replication** - replicated devices over Raft via [nuraft_mesg](https://github.com/eBay/nuraft_mesg),
  plus a single-node *solo* repl dev that shares the same journaled write path.
- **Crash consistency** - a checkpoint manager flushes consistent points across services; superblocks
  avoid torn pages, log streams replay on recovery, and replication is journaled.
- **Fast-read B+Tree index**, append-only truncatable **log streams**, and a torn-page-safe **meta** K/V.

## 📋 Table of Contents

- [Quick Start](#-quick-start)
- [Architecture](#️-architecture)
- [Services](#-services)
- [Asynchronous Model](#-asynchronous-model)
- [Usage](#️-usage)
- [Development](#️-development)
- [Testing](#-testing)
- [Dependencies](#-dependencies)
- [License](#-license)

## 🏃 Quick Start

### Prerequisites

- Linux kernel with `io_uring` (5.6+)
- Conan 1.x (`pipx install 'conan~=1'`; recipe requires `>=1.60`)
- CMake 3.13+
- C++23 compiler (GCC 13+, Clang 17+)
- `uuid-dev` (Ubuntu)
- The `sisl`, `iomgr`, and `nuraft_mesg` recipes available in your Conan cache or a configured remote

### Build & Test

```bash
git clone https://github.com/eBay/HomeStore
cd HomeStore
conan build -s:h build_type=Debug --build missing .
# the build runs the ctest suite (epoll_mode) automatically
```

To create the package for downstream consumers:

```bash
conan create -s:h build_type=Release --build missing .
```

### Build Options

```bash
# Release
conan build -s:h build_type=Release --build missing .

# AddressSanitizer
conan build -s:h build_type=Debug -o homestore/*:sanitize=True --build missing .

# Coverage
conan build -s:h build_type=Debug -o homestore/*:coverage=True --build missing .

# Test scope: full | min | epoll_mode (default) | off
conan build -s:h build_type=Debug -o homestore/*:testing=full --build missing .
```

## 🏗️ Architecture

```
HomeStore/
├── src/
│   ├── include/homestore/        # Public headers (installed)
│   │   ├── homestore.hpp           # HomeStore singleton + service builder (with_*_service), start/format
│   │   ├── meta_service.hpp        # MetaSvc - torn-page-safe superblock K/V
│   │   ├── index_service.hpp       # IndexSvc - crash-consistent B+Tree (btree/, index/)
│   │   ├── blkdata_service.hpp     # DataSvc - block allocation + co_await-able data I/O
│   │   ├── logstore_service.hpp    # LogSvc - append-only, truncatable log streams (logstore/)
│   │   ├── replication_service.hpp # ReplicationSvc - raft / solo replicated devices (replication/)
│   │   ├── fault_cmt_service.hpp   # Fault-containment service
│   │   └── checkpoint/             # CP manager - consistent cross-service flush points
│   └── lib/                      # Implementation (NOT installed)
│       ├── device/                 # vdev + physical device layer (io_uring via IOManager)
│       ├── blkalloc/               # block allocators (append / variable-size bitmap)
│       ├── blkdata_svc/  logstore/  index/  meta/  checkpoint/  replication/
│       └── homestore.cpp           # service bring-up + shutdown ordering
├── CMakeLists.txt
└── conanfile.py
```

```text
   application / storage solution  (e.g. HomeObject)
        │   with_index_service · with_log_service · with_data_service
        │   with_repl_data_service · with_fault_containment
        ▼
   HomeStore  (hs())
   ├─ MetaSvc · IndexSvc · DataSvc · LogSvc · ReplicationSvc · FaultContainment
   ├─ CPManager ── consistent checkpoints across services
        │   data/replication paths: co_await → iomgr::io_result
        ▼
   IOManager v13 reactors ── io_uring drive backend (non-blocking)
        ▼
   block devices / files
```

### Core Abstractions

| Type / entry point | Role |
|---|---|
| `HomeStore` (via the `hs()` accessor) | Singleton; composes services and owns start / format / shutdown |
| `MetaBlkService` | Torn-page-safe superblock K/V; re-initializes application state after reboot |
| `IndexService` / `Btree` | Crash-consistent B+Tree tuned for fast reads |
| `BlkDataService` | Block allocation plus `co_await`-able async data read / write |
| `LogStoreService` / `LogStore` | Append-only, truncatable log streams (crash-recovery building block) |
| `ReplicationService` / `ReplDev` | Replicated devices - Raft (`RaftReplDev`) or single-node (`SoloReplDev`) |
| `CPManager` | Checkpoint manager; flushes a consistent point across every service |
| `iomgr::io_result` | `std::expected<size_t, std::error_condition>` - the one async error type |

## 🧱 Services

Each service is a crash-resilient, persistent form of a familiar data structure. Compose only the ones a
solution needs.

- **MetaSvc** (`std::map`) - a K/V store that avoids *torn pages*, used for superblocks and other state
  that must re-initialize application structures after reboot.
- **IndexSvc** (`std::unordered_map`) - a B+Tree optimized for *fast* reads; values are typically
  allocations handed out by the DataSvc.
- **DataSvc** (`new`/`delete`) - flat block-allocation space with `co_await`-able read/write; allocation
  hooks let a solution impose a particular pattern (e.g. heap).
- **LogSvc** (`std::list`) - a random-access circular buffer; rarely used directly, but leveraged by other
  services (and replication) to provide crash recovery.
- **ReplicationSvc** - replicates a DataSvc across application instances. `RaftReplDev` uses Raft
  consensus (nuraft_mesg) for multi-replica groups; `SoloReplDev` is the single-node variant on the same
  journaled write path.
- **FaultContainmentSvc** - isolates faults at the ReplDev / LogStore / LogDev layers.

## 🧬 Asynchronous Model

The data and replication paths are stackless coroutines. Read/write calls return an awaitable that yields
an `iomgr::io_result` - bytes transferred on success, a `std::error_condition` on failure - so control
flow stays linear and there are no callback chains:

```cpp
using iomgr::io_result;

// ReplDev / BlkDataService read and write are co_await-able.
io_result r = co_await repl_dev->async_read(blkid, sgs, size);
if (!r) {
    // r.error() is a std::error_condition
}
```

the underlying stdexec sender/receiver machinery is hidden - consumers never depend on stdexec
directly. Errors propagate as `std::error_condition`; exceptions are reserved for precondition bugs.

## 🖥️ Usage

```cpp
#include <homestore/homestore.hpp>
using namespace homestore;

// Compose the services this storage solution needs, then bring HomeStore up over IOManager.
HomeStore::instance()
    ->with_index_service(std::move(index_cbs))
    .with_log_service()
    .with_data_service(custom_chunk_selector);

// start() returns true on first-ever boot (no on-disk layout yet) -> lay out the vdevs and start.
if (hs()->start(input_params)) {
    hs()->format_and_start({ /* per-service capacity split */ });
}

// ... application runs on IOManager reactors, issuing co_await data/replication I/O ...

hs()->shutdown();
```

A reference end-to-end consumer is [HomeObject](https://github.com/eBay/HomeObject); the suites under
`src/tests/` show service bring-up, replication, and recovery in practice.

## 🛠️ Development

### Code Style

- **Indentation:** 4 spaces  ·  **Line length:** 120  ·  **Standard:** C++23  ·  **Headers:** `#pragma once`
- Run `./apply-clang-format.sh` before submitting.

### Conventions

| Element | Convention | Example |
|---|---|---|
| Classes / services | `PascalCase` | `BlkDataService`, `RaftReplDev`, `IndexService`, `CPManager` |
| Functions / methods | `snake_case` | `async_alloc_write`, `async_read`, `format_and_start` |
| Members | `m_snake_case` | `m_repl_svc`, `m_data_journal` |
| Async error type | `iomgr::io_result` | `std::expected<size_t, std::error_condition>` |

### Error Handling

The async surface uses one error type - bytes transferred on success, a `std::error_condition` on
failure. Reserve exceptions for precondition bugs; check and propagate `r.error()` for I/O failures.

## 🧪 Testing

Tests are GoogleTest suites under `src/tests/` and run as part of `conan build`. They cover the device
manager, block allocation, the meta / index / log / checkpoint services, and replication
(`test_solo_repl_dev`, `test_raft_repl_dev`, …).

```bash
# Build + run the suite (epoll_mode)
conan build -s:h build_type=Debug --build missing .

# Run a single binary directly (note: some require flags encoded in src/tests/CMakeLists.txt,
# e.g. solo replay must be forced)
./build/Debug/src/tests/test_solo_repl_dev --solo_force_replay=true
```

> The multi-process `test_raft_repl_dev` spawns replica children on ports `4000 + replica_num`; ensure
> those ports are free between runs.

## 📦 Dependencies

### Core

- **[IOManager](https://github.com/eBay/IOManager)** (v13+) - non-blocking reactors and the
  `io_uring` coroutine drive path (`iomgr::io_result`).
- **[sisl](https://github.com/eBay/sisl)** (v14+) - logging, options, metrics, the `async` coroutine
  substrate, and FDS containers.
- **[nuraft_mesg](https://github.com/eBay/nuraft_mesg)** (v5+) - Raft consensus + gRPC data service for
  the replication layer.
- **isa-l** (x86) - CRC / erasure-coding acceleration · **farmhash** - hashing.

### Test / Tooling

- **gtest**, **benchmark** - test dependencies.
- **Conan** 1.x (`>=1.60`), **CMake** 3.13+, **GCC 13+ / Clang 17+**, **clang-format**.

## 🤝 Contributing

We welcome contributions - bug reports, edge cases, improvements, and feature ideas. Please open an issue
or pull request. Contact: [Brian Szmyd](mailto:bszmyd@ebay.com).

## 📄 License

Copyright 2021 eBay Inc. Original Author: [Harihara Kadayam](https://github.com/hkadayam)

Primary Developers:
[Brian Szmyd](https://github.com/szmyd)

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
compliance with the License. You may obtain a copy of the License at
https://www.apache.org/licenses/LICENSE-2.0.

Unless required by applicable law or agreed to in writing, software distributed under the License is
distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
