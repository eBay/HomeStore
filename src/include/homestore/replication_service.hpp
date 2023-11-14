#pragma once
#include <functional>
#include <memory>
#include <string>
#include <variant>

#include <folly/futures/Future.h>
#include <sisl/utility/enum.hpp>
#include <homestore/replication/repl_decls.h>
#include <homestore/meta_service.hpp>

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
      FAILED = -32768);
// clang-format on

class ReplDev;
class ReplDevListener;
struct hs_stats;

template < typename V, typename E >
using Result = folly::Expected< V, E >;

template < class V >
using ReplResult = Result< V, ReplServiceError >;

template < class V, class E >
using AsyncResult = folly::SemiFuture< Result< V, E > >;

template < class V = folly::Unit >
using AsyncReplResult = AsyncResult< V, ReplServiceError >;

VENUM(repl_impl_type, uint8_t,
      server_side,     // Completely homestore controlled replication
      client_assisted, // Client assisting in replication
      solo             // For single node - no replication
);

class ReplApplication;

class ReplicationService {
public:
    ReplicationService() = default;
    virtual ~ReplicationService() = default;

    /// @brief Creates the Repl Device to which eventually user can read locally and write to the quorom of the members
    /// @param group_id Unique ID indicating the group. This is the key for several lookup structures
    /// @param members List of members to form this group
    /// @param listener state machine listener of all the events happening on the repl_dev (commit, precommit etc)
    /// @return A Future ReplDev on success or Future ReplServiceError upon error
    virtual AsyncReplResult< shared< ReplDev > > create_repl_dev(group_id_t group_id,
                                                                 std::set< replica_id_t, std::less<> >&& members) = 0;

    virtual AsyncReplResult<> replace_member(group_id_t group_id, replica_id_t member_out,
                                             replica_id_t member_in) const = 0;

    /// @brief Get the repl dev for a given group id if it is already created or opened
    /// @param group_id Group id interested in
    /// @return ReplDev is opened or ReplServiceError::SERVER_NOT_FOUND if it doesn't exist
    virtual ReplResult< shared< ReplDev > > get_repl_dev(group_id_t group_id) const = 0;

    /// @brief Iterate over all repl devs and then call the callback provided
    /// @param cb Callback with repl dev
    virtual void iterate_repl_devs(std::function< void(cshared< ReplDev >&) > const& cb) = 0;

    /// @brief get the capacity stats form underlying backend;
    /// @return the capacity stats;
    virtual hs_stats get_cap_stats() const = 0;

    virtual meta_sub_type get_meta_blk_name() const = 0;
};

//////////////// Application which uses Replication needs to be provide the following callbacks ////////////////
class ReplApplication {
public:
    // Returns the required implementation type of replication
    virtual repl_impl_type get_impl_type() const = 0;

    // Is the replica recovery needs timeline consistency. This is used to determine if the replica needs to be
    // recovered by key or by block of data. At present only non-timeline consistent replication is supported.
    virtual bool need_timeline_consistency() const = 0;

    // Called when the repl dev is found upon restart of the homestore instance. The caller should return an instance of
    // Listener corresponding to the ReplDev which will be used to perform the precommit/commit/rollback.
    virtual std::unique_ptr< ReplDevListener > create_repl_dev_listener(group_id_t group_id) = 0;

    // Given the uuid of the peer, get their address and port
    virtual std::pair< std::string, uint16_t > lookup_peer(replica_id_t uuid) const = 0;

    // Get the current application/server repl uuid
    virtual replica_id_t get_my_repl_id() const = 0;
};

} // namespace homestore
