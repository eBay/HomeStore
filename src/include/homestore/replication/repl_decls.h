#pragma once
#include <iostream>
#include <string>

#include <folly/small_vector.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wuninitialized"
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#include <folly/futures/Future.h>
#pragma GCC diagnostic pop

#include <sisl/logging/logging.h>
#include <homestore/homestore_decl.hpp>
#include <homestore/blk.h>
#include <sisl/fds/buffer.hpp>

SISL_LOGGING_DECL(replication)

#define REPL_LOG_MODS grpc_server, HOMESTORE_LOG_MODS, nuraft_mesg, nuraft, replication

namespace homestore {
// clang-format off
VENUM(ReplServiceError, int32_t,
      OK = 0,         // Everything OK
      CANCELLED = -1, // Request was cancelled
      TIMEOUT = -2,
      NOT_LEADER = -3,
      BAD_REQUEST = -4,
      SERVER_ALREADY_EXISTS = -5,
      CONFIG_CHANGING = -6,
      SERVER_IS_JOINING = -7,
      SERVER_NOT_FOUND = -8,
      CANNOT_REMOVE_LEADER = -9,
      SERVER_IS_LEAVING = -10,
      TERM_MISMATCH = -11,
      RETRY_REQUEST = -12,
      STOPPING = -13,
      RESULT_NOT_EXIST_YET = -10000,
      NOT_IMPLEMENTED = -10001,
      NO_SPACE_LEFT = -20000,
      DRIVE_WRITE_ERROR = -20001,
      DATA_DUPLICATED = -20002,
      QUIENCE_STATE = -20003,
      QUORUM_NOT_MET = -20004,
      REPLACE_MEMBER_TASK_MISMATCH = -20005,
      UNREADY_STATE = -20006,
      FAILED = -32768);

VENUM(ReplaceMemberStatus, int32_t,
      COMPLETED = 0,
      IN_PROGRESS = 1,
      NOT_LEADER = 2,
      TASK_ID_MISMATCH = 3,
      TASK_NOT_FOUND = 4,
      UNKNOWN = 5);
// clang-format on

template < typename V, typename E >
using Result = folly::Expected< V, E >;

template < class V >
using ReplResult = Result< V, ReplServiceError >;

template < class V, class E >
using AsyncResult = folly::SemiFuture< Result< V, E > >;

template < class V = folly::Unit >
using AsyncReplResult = AsyncResult< V, ReplServiceError >;

using blkid_list_t = folly::small_vector< BlkId, 4 >;

// Fully qualified domain pba, unique pba id across replica set
struct RemoteBlkId {
    RemoteBlkId() = default;
    RemoteBlkId(int32_t s, const MultiBlkId& b) : server_id{s}, blkid{b} {}
    int32_t server_id{0};
    MultiBlkId blkid;

    bool operator==(RemoteBlkId const& o) const { return (server_id == o.server_id) && (blkid == o.blkid); }
};

using remote_blkid_list_t = folly::small_vector< RemoteBlkId, 4 >;

using replica_id_t = uuid_t;
using group_id_t = uuid_t;

using store_lsn_t = int64_t;
using repl_lsn_t = int64_t;

struct peer_info {
    // Peer ID.
    replica_id_t id_;
    // The last replication index that the peer has, from this server's point of view.
    uint64_t replication_idx_ = 0;
    // The elapsed time since the last successful response from this peer, set to 0 on leader
    uint64_t last_succ_resp_us_ = 0;
    // The priority for leader election
    uint32_t priority_ = 0;
    // Whether the peer can vote. If a peer is learner, this will be false. Hide the raft details.
    bool can_vote = true;
};

struct replica_member_info {
    static constexpr uint64_t max_name_len = 128;
    replica_id_t id;
    char name[max_name_len];
    int32_t priority{0};
};

struct replace_member_task {
    std::string task_id;      // Unique task id for this replace member operation
    replica_id_t replica_out; // The replica which is going to be replaced
    replica_id_t replica_in;  // The replica which is going to be added in place of replica_out
};

// Context for replace member operations (used in callbacks)
static constexpr size_t max_replace_member_task_id_len = 64;
struct replace_member_ctx {
    char task_id[max_replace_member_task_id_len];
    replica_member_info replica_out;
    replica_member_info replica_in;

    replace_member_ctx() = default;
    replace_member_ctx(const std::string& id, const replica_member_info& out, const replica_member_info& in) {
        auto len = std::min(id.length(), max_replace_member_task_id_len - 1);
        std::strncpy(task_id, id.c_str(), len);
        task_id[len] = '\0';
        replica_out = out;
        replica_in = in;
    }
};

} // namespace homestore

// hash function definitions
namespace std {
template <>
struct hash< homestore::RemoteBlkId > {
    size_t operator()(homestore::RemoteBlkId const& fqbid) const noexcept {
        return std::hash< uint64_t >()(fqbid.server_id) + std::hash< homestore::MultiBlkId >()(fqbid.blkid);
    }
};
} // namespace std
