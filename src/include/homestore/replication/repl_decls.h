#pragma once
#include <iostream>
#include <string>

#include <folly/small_vector.h>
#include <folly/futures/Future.h>

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
      RESULT_NOT_EXIST_YET = -10000, 
      NOT_IMPLEMENTED = -10001,
      NO_SPACE_LEFT = -20000,
      DRIVE_WRITE_ERROR = -20001,
      FAILED = -32768);
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
    uint64_t replication_idx_;
    // The elapsed time since the last successful response from this peer, set to 0 on leader
    uint64_t last_succ_resp_us_;
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
