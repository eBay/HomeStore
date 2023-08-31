#pragma once

#include <string>

#include <folly/concurrency/ConcurrentHashMap.h>
#include <nuraft_mesg/messaging_if.hpp>
#include <sisl/fds/buffer.hpp>
#include <homestore/replication/repl_dev.h>

namespace homestore {

class ReplicaStateMachine;
class StateMachineStore;

#pragma pack(1)
struct repl_dev_superblk {
    static constexpr uint64_t REPL_DEV_SB_MAGIC = 0xABCDF00D;
    static constexpr uint32_t REPL_DEV_SB_MAGIC = 1;

    uint64_t magic{REPL_DEV_SB_MAGIC};
    uint32_t version{REPL_DEV_SB_MAGIC};
    std::string gid;                    // gid of this repl device
    logstore_id_t free_blks_journal_id; // Logstore id for storing free blkid records
    logstore_id_t data_journal_id;      // Logstore id for the data journal
    repl_lsn_t commit_lsn;              // LSN upto which this replica has committed
    repl_lsn_t checkpoint_lsn;          // LSN upto which this replica have checkpointed the data

    uint64_t get_magic() const { return magic; }
    uint32_t get_version() const { return version; }
};
#pragma pack()

class ReplDevImpl : public ReplDev, nuraft_mesg::mesg_state_mgr {
public:
    friend class ReplicaStateMachine;

    ReplDevImpl(superblk< repl_dev_superblk > const& rd_sb, bool load_existing);
    virtual ~ReplDevImpl() = default;

    void destroy();
    void async_alloc_write(const sisl::blob& header, const sisl::blob& key, const sisl::sg_list& value,
                           blk_alloc_hints&& hints, void* user_ctx) override;

    folly::Future< bool > async_read(const BlkId& bid, sisl::sg_list& sgs, uint32_t size, bool part_of_batch = false);

    void async_free_blks(int64_t lsn, const blkid_list_t& blkids) override;

    bool is_leader() const override;

    /// @brief Register server side implimentation callbacks to data service apis
    /// @param messaging - messaging service pointer
    /// @return false indicates error in the data service registration
    bool register_data_service_apis(std::shared_ptr< nuraft_mesg::consensus_component >& messaging);

    /// @brief Send data to followers
    /// @param blkids - blkids to be sent
    /// @param value - data to be sent
    void send_in_data_channel(const blkid_list_t& blkids, const sisl::sg_list& value);

    /// @brief Fetch blkid data from the leader
    /// @param remote_blkids - list of remote blkids for which data is needed from the leader
    void fetch_blkid_data_from_leader(const blkid_list_t& remote_blkids);

    std::shared_ptr< nuraft::state_machine > get_state_machine() override;

    std::string group_id() const override { return m_group_id; }

protected:
    uint32_t get_logstore_id() const override { return 0; }

    shared< nuraft::log_store > data_journal() { return m_data_journal; }

    void permanent_destroy() override {}

    void leave() override {}

private:
    void on_store_created(shared< HomeLogStore > store);

private:
    nuraft::ptr< nuraft::cluster_config > load_config() override { return nullptr; }
    void save_config(const nuraft::cluster_config&) override {}
    void save_state(const nuraft::srv_state&) override {}
    nuraft::ptr< nuraft::srv_state > read_state() override { return nullptr; }
    nuraft::ptr< nuraft::log_store > load_log_store() override { return nullptr; }
    int32_t server_id() override { return 0; }
    void system_exit(const int) override {}

    void after_precommit_in_leader(const nuraft::raft_server::req_ext_cb_params& cb_params);

private:
    shared< ReplicaStateMachine > m_state_machine;
    std::unique_ptr< ReplDevListener > m_listener;

    uint64_t m_group_id; // Replication Group id

    shared< ReplLogStore > m_data_journal;
    shared< HomeLogStore > m_free_blkid_journal;

    superblk< repl_dev_superblk > m_sb;                // Superblk where we store the state machine etc
    mutable folly::SharedMutexWritePriority m_sb_lock; // Lock to protect staged sb and persisting sb
    repl_dev_superblk m_sb_in_mem;                     // Cached version which is used to read and for staging

    std::atomic< repl_lsn_t > m_last_write_lsn{0}; // LSN which was lastly written, to track flushes
    repl_lsn_t m_last_flushed_commit_lsn{0};       // LSN upto which it was flushed to persistent store
    iomgr::timer_handle_t m_sb_flush_timer_hdl;
};

} // namespace homestore
