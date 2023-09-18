#pragma once
#include <functional>
#include <memory>
#include <string>
#include <variant>

#include <folly/futures/Future.h>

#include "repl_decls.h"
#include "repl_set.h"

namespace nuraft {
class state_machine;
}

namespace homestore {

class ReplDev;
using ReplServiceError = nuraft::cmd_result_code;
using on_replica_dev_init_t = std::function< std::unique_ptr< ReplicaDevListener >(cshared< ReplDev >& rd) >;

template < typename V, typename E >
using Result = folly::Expected< V, E >;

template < class V, class E >
using AsyncResult = folly::SemiFuture< Result< V, E > >;

template < class V >
using ReplResult = Result< V, ReplServiceError >;

template < class V >
using ReplAsyncResult = AsyncResult< V, ReplServiceError >;

class ReplicationService {
public:
    ReplicationService() = default;
    virtual ~ReplicationService() = default;

    // using set_var = std::variant< shared< ReplDev >, ReplServiceError >;

    /// Sync APIs
    virtual shared< ReplDev > get_replica_dev(std::string const& group_id) const = 0;
    virtual void iterate_replica_devs(std::function< void(cshared< ReplDev >&) > cb) const = 0;

    /// Async APIs
    virtual ReplAsyncResult< shared< ReplDev > > create_replica_dev(std::string const& group_id,
                                                                    std::set< std::string, std::less<> >&& members) = 0;

    virtual folly::SemiFuture< ReplServiceError >
    replace_member(std::string const& group_id, std::string const& member_out, std::string const& member_in) const = 0;
};
} // namespace homestore
