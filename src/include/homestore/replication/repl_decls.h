#pragma once
#include <iostream>
#include <string>

#include <folly/small_vector.h>
#include <sisl/logging/logging.h>
#include <homestore/homestore_decl.hpp>
#include <homestore/blk.h>
#include <sisl/fds/buffer.hpp>

SISL_LOGGING_DECL(replication)

#define REPL_LOG_MODS grpc_server, HOMESTORE_LOG_MODS, nuraft_mesg, nuraft, replication

namespace homestore {
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
