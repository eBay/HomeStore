#pragma once

#include <string>

#include <nuraft_mesg/nuraft_mesg.hpp>
#include <nuraft_mesg/mesg_state_mgr.hpp>
#include <sisl/fds/buffer.hpp>
#include <homestore/replication/repl_dev.h>
#include <homestore/superblk_handler.hpp>
#include <homestore/logstore/log_store.hpp>
#include "replication/repl_dev/common.h"
#include "replication/repl_dev/raft_state_machine.h"
#include "replication/log_store/repl_log_store.h"

namespace homestore {

#pragma pack(1)
struct raft_repl_dev_superblk : public repl_dev_superblk {
    static constexpr uint32_t RAFT_REPL_DEV_SB_VERSION = 1;

    uint32_t raft_sb_version{RAFT_REPL_DEV_SB_VERSION};
    logstore_id_t free_blks_journal_id; // Logstore id for storing free blkid records
    uint8_t is_timeline_consistent; // Flag to indicate whether the recovery of followers need to be timeline consistent
    uint64_t last_applied_dsn;      // Last applied data sequence number

    uint32_t get_raft_sb_version() const { return raft_sb_version; }
};
#pragma pack()

using raft_buf_ptr_t = nuraft::ptr< nuraft::buffer >;

class RaftReplService;
class CP;
class RaftReplDev : public ReplDev,
                    public nuraft_mesg::mesg_state_mgr,
                    public std::enable_shared_from_this< RaftReplDev > {
private:
    shared< RaftStateMachine > m_state_machine;
    RaftReplService& m_repl_svc;
    folly::ConcurrentHashMap< repl_key, repl_req_ptr_t, repl_key::Hasher > m_repl_key_req_map;
    nuraft_mesg::Manager& m_msg_mgr;
    group_id_t m_group_id;     // Replication Group id
    std::string m_rdev_name;   // Short name for the group for easy debugging
    replica_id_t m_my_repl_id; // This replica's uuid
    int32_t m_raft_server_id;  // Server ID used by raft (unique within raft group)
    shared< ReplLogStore > m_data_journal;
    shared< HomeLogStore > m_free_blks_journal;

    std::mutex m_config_mtx;
    superblk< raft_repl_dev_superblk > m_rd_sb;        // Superblk where we store the state machine etc
    json_superblk m_raft_config_sb;                    // Raft Context and Config data information stored
    mutable folly::SharedMutexWritePriority m_sb_lock; // Lock to protect staged sb and persisting sb
    raft_repl_dev_superblk m_sb_in_mem;                // Cached version which is used to read and for staging

    std::atomic< repl_lsn_t > m_commit_upto_lsn{0}; // LSN which was lastly written, to track flushes
    repl_lsn_t m_last_flushed_commit_lsn{0};        // LSN upto which it was flushed to persistent store
    iomgr::timer_handle_t m_sb_flush_timer_hdl;

    std::atomic< uint64_t > m_next_dsn{0}; // Data Sequence Number that will keep incrementing for each data entry
                                           //
    iomgr::timer_handle_t m_wait_data_timer_hdl{iomgr::null_timer_handle};
    bool m_resync_mode{false};

    static std::atomic< uint64_t > s_next_group_ordinal;

public:
    friend class RaftStateMachine;

    RaftReplDev(RaftReplService& svc, superblk< raft_repl_dev_superblk >&& rd_sb, bool load_existing);
    virtual ~RaftReplDev() = default;

    bool join_group();
    void destroy();

    //////////////// All ReplDev overrides/implementation ///////////////////////
    void async_alloc_write(sisl::blob const& header, sisl::blob const& key, sisl::sg_list const& value,
                           repl_req_ptr_t ctx) override;
    folly::Future< std::error_code > async_read(MultiBlkId const& blkid, sisl::sg_list& sgs, uint32_t size,
                                                bool part_of_batch = false) override;
    void async_free_blks(int64_t lsn, MultiBlkId const& blkid) override;
    AsyncReplResult<> become_leader() override;
    bool is_leader() const override;
    group_id_t group_id() const override { return m_group_id; }
    std::string group_id_str() const { return boost::uuids::to_string(m_group_id); }
    std::string rdev_name() const { return m_rdev_name; }
    std::string my_replica_id_str() const { return boost::uuids::to_string(m_my_repl_id); }
    uint32_t get_blk_size() const override;
    repl_lsn_t get_last_commit_lsn() const { return m_commit_upto_lsn.load(); }

    //////////////// Accessor/shortcut methods ///////////////////////
    nuraft_mesg::repl_service_ctx* group_msg_service();
    nuraft::raft_server* raft_server();

    //////////////// Methods needed for other Raft classes to access /////////////////
    void use_config(json_superblk raft_config_sb);
    void report_committed(repl_req_ptr_t rreq);
    repl_req_ptr_t follower_create_req(repl_key const& rkey, sisl::blob const& user_header, sisl::blob const& user_key,
                                       uint32_t data_size);
    AsyncNotify notify_after_data_written(std::vector< repl_req_ptr_t >* rreqs);
    void cp_flush(CP* cp);
    void cp_cleanup(CP* cp);

protected:
    //////////////// All nuraft::state_mgr overrides ///////////////////////
    nuraft::ptr< nuraft::cluster_config > load_config() override;
    void save_config(const nuraft::cluster_config& config) override;
    void save_state(const nuraft::srv_state& state) override;
    nuraft::ptr< nuraft::srv_state > read_state() override;
    nuraft::ptr< nuraft::log_store > load_log_store() override;
    int32_t server_id() override;
    void system_exit(const int exit_code) override { LOGINFO("System exiting with code [{}]", exit_code); }

    //////////////// All nuraft_mesg::mesg_state_mgr overrides ///////////////////////
    uint32_t get_logstore_id() const override;
    std::shared_ptr< nuraft::state_machine > get_state_machine() override;
    void permanent_destroy() override;
    void leave() override;

private:
    shared< nuraft::log_store > data_journal() { return m_data_journal; }
    void push_data_to_all_followers(repl_req_ptr_t rreq);
    void on_push_data_received(intrusive< sisl::GenericRpcData >& rpc_data);
    void on_fetch_data_received(intrusive< sisl::GenericRpcData >& rpc_data);
    void check_and_fetch_remote_data(std::vector< repl_req_ptr_t >* rreqs);
    void fetch_data_from_remote(std::vector< repl_req_ptr_t >* rreqs);

    bool is_resync_mode() { return m_resync_mode; }
    void handle_error(repl_req_ptr_t const& rreq, ReplServiceError err);
};

} // namespace homestore
