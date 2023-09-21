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

template < typename V, typename E >
using Result = folly::Expected< V, E >;

template < class V, class E >
using AsyncResult = folly::SemiFuture< Result< V, E > >;

template < class V >
using ReplResult = Result< V, ReplServiceError >;

template < class V >
using AsyncReplResult = AsyncResult< V, ReplServiceError >;

class ReplServiceCallbacks {
public:
    virtual ~ReplServiceCallbacks() = default;
    virtual std::unique_ptr< ReplDevListener > on_repl_dev_init(cshared< ReplDev >& rs) = 0;
};

class ReplicationService {
public:
    ReplicationService() = default;
    virtual ~ReplicationService() = default;

    /// Sync APIs
    virtual ReplResult< shared< ReplDev > > get_replica_dev(uuid_t group_id) const = 0;
    virtual void iterate_replica_devs(std::function< void(cshared< ReplDev >&) > const& cb) = 0;

    /// Async APIs
    virtual AsyncReplResult< shared< ReplDev > > create_replica_dev(uuid_t group_id,
                                                                    std::set< std::string, std::less<> >&& members) = 0;

    virtual folly::SemiFuture< ReplServiceError > replace_member(uuid_t group_id, std::string const& member_out,
                                                                 std::string const& member_in) const = 0;
};
} // namespace homestore
