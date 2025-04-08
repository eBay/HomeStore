/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *    https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 *********************************************************************************/
#pragma once

#include <boost/intrusive_ptr.hpp>

#include <homestore/replication/repl_decls.h>
#include <homestore/replication_service.hpp>
#include <homestore/replication/repl_dev.h>
#include <homestore/logstore/log_store.hpp>
#include <homestore/superblk_handler.hpp>

namespace homestore {

#pragma pack(1)
struct repl_journal_entry {
    static constexpr uint16_t JOURNAL_ENTRY_MAJOR = 1;
    static constexpr uint16_t JOURNAL_ENTRY_MINOR = 1;

    // Major and minor version. For each major version underlying structures could change. Minor versions can only add
    // fields, not change any existing fields.
    uint16_t major_version{JOURNAL_ENTRY_MAJOR};
    uint16_t minor_version{JOURNAL_ENTRY_MINOR};

    journal_type_t code;
    trace_id_t traceID; // traceID provided by application, mostly for consolidate logs.
    int32_t server_id;  // Server id from where journal entry is originated
    uint64_t dsn;       // Data seq number
    uint32_t user_header_size;
    uint32_t key_size;
    uint32_t value_size;
    // Followed by user_header, then key, then MultiBlkId/value

    std::string to_string() const {
        return fmt::format("version={}.{}, code={}, server_id={}, dsn={}, header_size={}, key_size={}, value_size={}",
                           major_version, minor_version, enum_name(code), server_id, dsn, user_header_size, key_size,
                           value_size);
    }

    std::string to_compact_string() const {
        return fmt::format("dsn={}, header_size={}, key_size={}, value_size={}", major_version, minor_version,
                           enum_name(code), server_id, dsn, user_header_size, key_size, value_size);
    }
};

struct repl_dev_superblk {
    static constexpr uint64_t REPL_DEV_SB_MAGIC = 0xABCDF00D;
    static constexpr uint32_t REPL_DEV_SB_VERSION = 1;
    static constexpr size_t max_name_len = 64;

    uint64_t magic{REPL_DEV_SB_MAGIC};
    uint32_t version{REPL_DEV_SB_VERSION};
    uuid_t group_id; // group_id of this replica set
    logdev_id_t logdev_id;
    logstore_id_t logstore_id;     // Logstore id for the data journal
    repl_lsn_t durable_commit_lsn; // LSN upto which this replica has committed
    repl_lsn_t checkpoint_lsn;     // LSN upto which this replica have checkpointed the Data
    repl_lsn_t compact_lsn;        // maximum LSN that can be compacted to
    uint64_t group_ordinal;        // Ordinal number which will be used to indicate the rdevXYZ for debugging
    char rdev_name[max_name_len];  // Short name for the group for easy debugging

    uint64_t get_magic() const { return magic; }
    uint32_t get_version() const { return version; }
    void set_rdev_name(std::string const& name) {
        std::strncpy(rdev_name, name.c_str(), max_name_len - 1);
        rdev_name[max_name_len - 1] = '\0';
    }
};
#pragma pack()

template < class V = folly::Unit >
auto make_async_error(ReplServiceError err) {
    return folly::makeSemiFuture< ReplResult< V > >(folly::makeUnexpected(err));
}

template < class V >
auto make_async_success(V v) {
    return folly::makeSemiFuture< ReplResult< V > >(std::move(v));
}

template < class V = folly::Unit >
auto make_async_success() {
    return folly::makeSemiFuture< ReplResult< folly::Unit > >(folly::Unit{});
}

} // namespace homestore
