#include <home_replication/repl_service.h>

#include <boost/uuid/string_generator.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <nuraft_mesg/messaging_if.hpp>
#include <sisl/logging/logging.h>

#include <home_replication/repl_set.h>
#include "service/repl_backend.h"
#include "service/home_repl_backend.h"

namespace homestore {
ReplicationServiceImpl::ReplicationServiceImpl(std::unique_ptr< ReplServiceCallbacks > cbs) :
        m_svc_cbs{std::move(cbs)} {
    m_messaging = std::make_shared< nuraft_mesg::service >();

    // FIXME: RAFT server parameters, should be a config and reviewed!!!
    nuraft::raft_params r_params;
    r_params.with_election_timeout_lower(900)
        .with_election_timeout_upper(1400)
        .with_hb_interval(250)
        .with_max_append_size(10)
        .with_rpc_failure_backoff(250)
        .with_auto_forwarding(true)
        .with_snapshot_enabled(1);

    meta_service().register_handler(
        "replication",
        [this](meta_blk* mblk, sisl::byte_view buf, size_t) { rd_super_blk_found(std::move(buf), voidptr_cast(mblk)); },
        nullptr);

    // This closure is where we initialize new ReplicaSet instances. When NuRaft Messging is asked to join a new group
    // either through direct creation or gRPC request it will use this callback to initialize a new state_manager and
    // state_machine for the raft_server it constructs.
    auto group_type_params = nuraft_mesg::consensus_component::register_params{
        r_params, [this](int32_t const, std::string const& group_id) mutable {
            return create_replica_dev(group_id, std::set< std::string, std::less<> >())
                .via(&folly::QueuedImmediateExecutor::instance())
                .get();
            // RELEASE_ASSERT(std::holds_alternative< shared< ReplDev > >(v), "Could Not Create ReplicaSet!");
            // return std::get< shared< ReplDev > >(v);
        }};
    // m_messaging->register_mgr_type("homestore", group_type_params);
}

void ReplicationServiceImpl::create_vdev(uint64_t size) {
    auto const atomic_page_size = hs()->device_mgr()->atomic_page_size(HSDevType::Data);
    hs_vdev_context vdev_ctx;
    vdev_ctx.type = hs_vdev_type_t::REPL_DATA_VDEV;

    hs()->device_mgr()->create_vdev(vdev_parameters{.vdev_name = "index",
                                                    .vdev_size = size,
                                                    .num_chunks = 1,
                                                    .blk_size = atomic_page_size,
                                                    .dev_type = HSDevType::Data,
                                                    .multi_pdev_opts = vdev_multi_pdev_opts_t::ALL_PDEV_STRIPED,
                                                    .context_data = vdev_ctx.to_blob()});
}

shared< VirtualDev > ReplicationServiceImpl::open_vdev(const vdev_info& vinfo, bool load_existing) {
    m_vdev = std::make_shared< VirtualDev >(*(hs()->device_mgr()), vinfo, m_svc_cbs->blk_allocator_type(),
                                            m_svc_cbs->chunk_selector(), nullptr, true /* auto_recovery */);
    return m_vdev;
}

ReplAsyncResult< shared< ReplDev > >
ReplicationServiceImpl::create_replica_dev(std::string const& group_id,
                                           std::set< std::string, std::less<> >&& members) {
    superblk< repl_dev_superblk > rd_sb;
    rd_sb.create(sizeof(repl_dev_superblk));
    rd_sb->gid = group_id;
    return folly::makeSemiFuture< shared< ReplDev > >(open_replica_dev(rd_sb, false /* load_existing */));
}

folly::SemiFuture< ReplServiceError > ReplicationServiceImpl::replace_member(std::string const& group_id,
                                                                             std::string const& member_out,
                                                                             std::string const& member_in) const {
    return folly::makeSemiFuture(ReplServiceError::CANCELLED);
}

ReplAsyncResult< shared< ReplDev > > ReplicationServiceImpl::get_replica_dev(std::string const& group_id) const {
    std::unique_lock lg(m_rd_map_mtx);
    if (auto it = m_rd_map.find(group_id); it != m_rd_map.end()) { return it->second; }
    return ReplServiceError::SERVER_NOT_FOUND;
}

void ReplicationServiceImpl::iterate_replica_devs(std::function< void(cshared< ReplDev >&) > const& cb) {
    std::unique_lock lg(m_rd_map_mtx);
    for (const auto& [uuid, rd] : m_rd_map) {
        cb(rd);
    }
}

shared< ReplDev > ReplicationServiceImpl::open_replica_dev(superblk< repl_dev_superblk > const& rd_sb,
                                                           bool load_existing) {
    auto it = m_rd_map.end();
    bool happened = false;

    {
        std::unique_lock lg(m_rd_map_mtx);
        std::tie(it, happened) = m_rd_map.emplace(std::make_pair(gid, nullptr));
    }
    DEBUG_ASSERT(m_rd_map.end() != it, "Could not insert into map!");
    if (!happened) { return it->second };

    auto repl_dev = std::make_shared< ReplDevImpl >(rd_sb, load_existing);
    it->second = repl_dev;
    repl_dev->attach_listener(std::move(m_svc_cbs->on_repl_dev_init(repl_dev)));

    return repl_dev;
}

void ReplicationServiceImpl::rd_super_blk_found(sisl::byte_view const& buf, void* meta_cookie) {
    superblk< repl_dev_superblk > rd_sb;
    rd_sb.load(buf, meta_cookie);
    DEBUG_ASSERT_EQ(rd_sb->get_magic(), home_rs_superblk::REPLICA_DEV_SB_MAGIC, "Invalid rdev metablk, magic mismatch");
    DEBUG_ASSERT_EQ(rd_sb->get_version(), home_rs_superblk::REPLICA_DEV_SB_VERSION, "Invalid version of rdev metablk");

    open_replica_dev(rd_sb, true /* load_existing */);
}

} // namespace homestore
