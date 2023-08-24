#pragma once
#include <boost/uuid/uuid.hpp>
#include <sisl/utility/enum.hpp>
#include <sisl/fds/buffer.hpp>
#include <home_replication/repl_decls.h>

namespace homestore {
VENUM(journal_type_t, uint16_t, DATA = 0);
using raft_buf_ptr_t = nuraft::ptr< nuraft::buffer >;

static constexpr uint16_t JOURNAL_ENTRY_MAJOR{1};
static constexpr uint16_t JOURNAL_ENTRY_MINOR{0};

struct repl_journal_entry {
    // Major and minor version. For each major version underlying structures could change. Minor versions can only add
    // fields, not change any existing fields.
    uint16_t major_version{JOURNAL_ENTRY_MAJOR};
    uint16_t minor_version{JOURNAL_ENTRY_MINOR};

    journal_type_t code;
    uint16_t n_pbas;
    uint32_t replica_id;
    uint32_t user_header_size;
    uint32_t key_size;
    // Followed by user_header, then key, then pbas

public:
    uint32_t total_size() const {
        return sizeof(repl_journal_entry) + (n_pbas * sizeof(pba_t)) + user_header_size + key_size;
    }
};

struct repl_req {
    sisl::blob header;                           // User header
    sisl::blob key;                              // Key to replicate
    sisl::sg_list value;                         // Raw value - applicable only to leader req
    fq_pba_list_t remote_fq_pbas;                // List of remote pbas for the value
    pba_list_t local_pbas;                       // List of corresponding local pbas for the value
    void* user_ctx{nullptr};                     // User context passed with replica_set::write, valie for leader only
    int64_t lsn{0};                              // Lsn for this replication req
    raft_buf_ptr_t journal_entry;                // Journal entry info
    std::atomic< uint32_t > num_pbas_written{0}; // Total pbas persisted in store
    std::atomic< bool > is_raft_written{false};  // Has data to raft is flushed
};

} // namespace homestore