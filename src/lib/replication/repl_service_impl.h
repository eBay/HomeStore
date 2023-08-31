#pragma once

#include <map>
#include <memory>
#include <mutex>
#include <sisl/fds/buffer.hpp>

#include <homestore/replication_service.hpp>

namespace nuraft {
struct log_store;
}

namespace nuraft_mesg {
class consensus_component;
}

namespace homestore {

class ReplicaDevListener;
class ReplDev;
class ReplDevImpl;
struct repl_dev_superblk;

class ReplServiceCallbacks {
public:
    virtual std::unique_ptr< ReplicaDevListener > on_repl_dev_init(cshared< ReplDev >& rd) = 0;
    virtual blk_allocator_type_t blk_allocator_type() = 0;
    virtual std::unique_ptr< ChunkSelector > chunk_selector() = 0;
};

class ReplicationServiceImpl : public ReplicationService {
    mutable std::mutex m_rd_map_mtx;
    std::map< std::string, shared< ReplDevImpl > > m_rd_map;
    std::unique_ptr< ReplServiceCallbacks > m_svc_cbs;
    shared< nuraft_mesg::consensus_component > m_messaging;
    shared < VirtualDev < m_vdev;

public:
    ReplicationServiceImpl(std::unique_ptr< ReplServiceCallbacks > cbs);
    ~ReplicationServiceImpl() override = default;

    /// Sync APIs
    ReplAsyncResult< shared< ReplDev > > get_replica_dev(std::string const& group_id) const override;
    void iterate_replica_devs(const std::function< void(cshared< ReplDev >&) >& cb) const override;

    /// Async APIs
    ReplAsyncResult< shared< ReplDev > > create_replica_dev(std::string const& group_id,
                                                            std::set< std::string, std::less<> >&& members) override;
    folly::SemiFuture< ReplServiceError > replace_member(std::string const& group_id, std::string const& member_out,
                                                         std::string const& member_in) const override;

    void create_vdev(uint64_t size);
    shared< VirtualDev > open_vdev(const vdev_info& vinfo, bool load_existing);

private:
    shared< ReplDev > open_replica_dev(superblk< repl_dev_superblk > const& rd_sb, bool load_existing);
    void rd_super_blk_found(sisl::byte_view const& buf, void* meta_cookie);
};

} // namespace homestore
