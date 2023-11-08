#pragma once
#include <functional>
#include <memory>
#include <string>
#include <variant>

#include <folly/futures/Future.h>

#include <homestore/replication/repl_decls.h>

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

template < class V, class E >
using AsyncResult = folly::Future< Result< V, E > >;

template < class V >
using ReplResult = Result< V, ReplServiceError >;

template < class V >
using AsyncReplResult = AsyncResult< V, ReplServiceError >;

class ReplicationService {
public:
    ReplicationService() = default;
    virtual ~ReplicationService() = default;

    /// @brief Creates the Repl Device to which eventually user can read locally and write to the quorom of the members
    /// @param group_id Unique ID indicating the group. This is the key for several lookup structures
    /// @param members List of members to form this group
    /// @param listener state machine listener of all the events happening on the repl_dev (commit, precommit etc)
    /// @return A Future ReplDev on success or Future ReplServiceError upon error
    virtual AsyncReplResult< shared< ReplDev > > create_repl_dev(uuid_t group_id,
                                                                 std::set< std::string, std::less<> >&& members,
                                                                 std::unique_ptr< ReplDevListener > listener) = 0;

    /// @brief Opens the Repl Device for a given group id. It is expected that the repl dev is already created and used
    /// this method for recovering. It is possible that repl_dev is not ready and in that case it will provide Repl
    /// Device after it is ready and thus returns a Future.
    ///
    /// NOTE 1: If callers does an open for a repl device which was not created before, then at the end of
    /// initialization an error is returned saying ReplServiceError::SERVER_NOT_FOUND
    ///
    /// NOTE 2: If the open repl device is called after Replication service is started, then it returns an error
    /// ReplServiceError::BAD_REQUEST
    /// @param group_id Group id to open the repl device with
    /// @param listener state machine listener of all the events happening on the repl_dev (commit, precommit etc)
    /// @return A Future ReplDev on successful open of ReplDev or Future ReplServiceError upon error
    virtual AsyncReplResult< shared< ReplDev > > open_repl_dev(uuid_t group_id,
                                                               std::unique_ptr< ReplDevListener > listener) = 0;

    virtual folly::Future< ReplServiceError > replace_member(uuid_t group_id, std::string const& member_out,
                                                             std::string const& member_in) const = 0;

    /// @brief Get the repl dev for a given group id if it is already created or opened
    /// @param group_id Group id interested in
    /// @return ReplDev is opened or ReplServiceError::SERVER_NOT_FOUND if it doesn't exist
    virtual ReplResult< shared< ReplDev > > get_repl_dev(uuid_t group_id) const = 0;

    /// @brief Iterate over all repl devs and then call the callback provided
    /// @param cb Callback with repl dev
    virtual void iterate_repl_devs(std::function< void(cshared< ReplDev >&) > const& cb) = 0;

    /// @brief Get the current term of the repl dev
    virtual hs_stats get_cap_stats() const = 0;
};
} // namespace homestore
