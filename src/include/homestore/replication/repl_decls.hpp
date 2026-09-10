#pragma once
#include <iostream>
#include <string>

#include <expected>
#include <variant>

#include <boost/container/small_vector.hpp>

#include <sisl/async/task.hpp>
#include <sisl/logging/logging.h>
#include <system_error>
#include <homestore/homestore_decl.hpp>
#include <homestore/blk.hpp>
#include <homestore/error.hpp>
#include <sisl/fds/buffer.hpp>

SISL_LOGGING_DECL(replication)

#define REPL_LOG_MODS grpc_server, HOMESTORE_LOG_MODS, nuraft_mesg, nuraft, replication

namespace homestore {
// clang-format off
ENUM(ReplServiceError, int32_t,
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
      QUIESCENCE_STATE = -20003,
      QUORUM_NOT_MET = -20004,
      REPLACE_MEMBER_TASK_MISMATCH = -20005,
      UNREADY_STATE = -20006,
      FAILED = -32768);

ENUM(ReplaceMemberStatus, int32_t,
      COMPLETED = 0,
      IN_PROGRESS = 1,
      NOT_LEADER = 2,
      TASK_ID_MISMATCH = 3,
      TASK_NOT_FOUND = 4,
      UNKNOWN = 5);
// clang-format on

// Register ReplServiceError as a std::error_condition enum so replication failures flow through the one
// homestore::result<T> error surface (std::error_condition) while staying branchable at the call site:
//     if (r.error() == ReplServiceError::NOT_LEADER) { ... }
class repl_error_category : public std::error_category {
public:
    const char* name() const noexcept override { return "homestore.replication"; }
    std::string message(int ev) const override { return std::string{enum_name(static_cast< ReplServiceError >(ev))}; }
};
inline std::error_category const& repl_error_category_inst() noexcept {
    static repl_error_category inst;
    return inst;
}
inline std::error_condition make_error_condition(ReplServiceError e) noexcept {
    return std::error_condition{static_cast< int >(e), repl_error_category_inst()};
}
} // namespace homestore

template <>
struct std::is_error_condition_enum< homestore::ReplServiceError > : std::true_type {};

namespace homestore {

// Replication reports through homestore's one error surface: result<V> / async_result<V> (error ==
// std::error_condition). ReplServiceError's codes ride inside the error_condition, so callers still branch on
// `r.error() == ReplServiceError::NOT_LEADER`. (Result/AsyncResult remain for the data-rpc surface, which still
// carries repl_data_rpc_error_code.)
template < typename V, typename E >
using Result = std::expected< V, E >;

template < class V, class E >
using AsyncResult = sisl::async::task< Result< V, E > >;

using blkid_list_t = boost::container::small_vector< blk_id, 4 >;

// Fully qualified domain pba, unique pba id across replica set
struct remote_blk_id {
    remote_blk_id() = default;
    remote_blk_id(int32_t s, const multi_blk_id& b) : server_id{s}, blkid{b} {}
    int32_t server_id{0};
    multi_blk_id blkid;

    bool operator==(remote_blk_id const& o) const { return (server_id == o.server_id) && (blkid == o.blkid); }
};

using remote_blkid_list_t = boost::container::small_vector< remote_blk_id, 4 >;

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

} // namespace homestore

// hash function definitions
namespace std {
template <>
struct hash< homestore::remote_blk_id > {
    size_t operator()(homestore::remote_blk_id const& fqbid) const noexcept {
        return std::hash< uint64_t >()(fqbid.server_id) + std::hash< homestore::multi_blk_id >()(fqbid.blkid);
    }
};
} // namespace std
