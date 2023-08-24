#include <home_replication/repl_service.h>

#include <boost/uuid/string_generator.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <nuraft_mesg/messaging_if.hpp>
#include <sisl/logging/logging.h>

#include <home_replication/repl_set.h>
#include "service/repl_backend.h"
#include "service/home_repl_backend.h"

namespace homestore {
ReplicationService::ReplicationService(cshared< nuraft_mesg::consensus_component >& messaging,
                                       on_replica_dev_init_t cb) :
        m_on_rd_init_cb{std::move(cb)}, m_messaging(messaging) {
    // FIXME: RAFT server parameters, should be a config and reviewed!!!
    nuraft::raft_params r_params;
    r_params.with_election_timeout_lower(900)
        .with_election_timeout_upper(1400)
        .with_hb_interval(250)
        .with_max_append_size(10)
        .with_rpc_failure_backoff(250)
        .with_auto_forwarding(true)
        .with_snapshot_enabled(1);

    // This closure is where we initialize new ReplicaSet instances. When NuRaft Messging is asked to join a new group
    // either through direct creation or gRPC request it will use this callback to initialize a new state_manager and
    // state_machine for the raft_server it constructs.
    auto group_type_params = nuraft_mesg::consensus_component::register_params{
        r_params, [this](int32_t const, std::string const& group_id) mutable {
            auto v = create_replica_dev(group_id, std::set< std::string, std::less<> >())
                         .via(&folly::QueuedImmediateExecutor::instance())
                         .get();
            RELEASE_ASSERT(std::holds_alternative< shared< ReplDev > >(v), "Could Not Create ReplicaSet!");
            return std::get< shared< ReplDev > >(v);
        }};
    // m_messaging->register_mgr_type("homestore", group_type_params);
}

ReplicationService::~ReplicationService() = default;

shared< ReplDev > ReplicationService::lookup_replica_dev(uuid_t uuid) {
    std::unique_lock lg(m_rd_map_mtx);
    auto it = m_rd_map.find(uuid);
    return (it == m_rd_map.end() ? nullptr : it->second);
}

shared< ReplDev > ReplicationService::create_replica_dev(uuid_t uuid) {
    auto log_store = std::make_shared< HomeRaftLogStore >();
    return open_replica_dev(uuid, log_store);
}

shared< ReplDev > ReplicationService::open_replica_dev(uuid_t uuid, cshared< HomeRaftLogStore >& log_store) {
    auto it = m_rd_map.end();
    bool happened = false;

    {
        std::unique_lock lg(m_rd_map_mtx);
        std::tie(it, happened) = m_rd_map.emplace(std::make_pair(uuid, nullptr));
    }
    DEBUG_ASSERT(m_rd_map.end() != it, "Could not insert into map!");
    if (!happened) { return it->second };

    auto repl_dev = std::make_shared< ReplDev >(boost::uuids::to_string(uuid), log_store);
    it->second = repl_dev;
    repl_dev->attach_listener(std::move(m_on_repl_dev_init_cb(repl_dev)));
    repl_dev->attach_log_store(log_store);

    return repl_dev;
}

void ReplicationService::iterate_replica_devs(const std::function< void(const cshared< ReplDev >&) >& cb) {
    std::unique_lock lg(m_rd_map_mtx);
    for (const auto& [uuid, rd] : m_rd_map) {
        cb(rd);
    }
}
} // namespace homestore
