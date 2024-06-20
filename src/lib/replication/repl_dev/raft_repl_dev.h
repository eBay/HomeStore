#pragma once

#include <string>

#include <libnuraft/ptr.hxx>
#include <nuraft_mesg/nuraft_mesg.hpp>
#include <nuraft_mesg/mesg_state_mgr.hpp>
#include <sisl/fds/buffer.hpp>
#include <sisl/fds/utils.hpp>
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
    uint8_t destroy_pending;        // Flag to indicate whether the group is in destroy pending state

    uint32_t get_raft_sb_version() const { return raft_sb_version; }
};
#pragma pack()

using raft_buf_ptr_t = nuraft::ptr< nuraft::buffer >;

ENUM(repl_dev_stage_t, uint8_t, INIT, ACTIVE, DESTROYING, DESTROYED, PERMANENT_DESTROYED);

class RaftReplDevMetrics : public sisl::MetricsGroup {
public:
    explicit RaftReplDevMetrics(const char* inst_name) : sisl::MetricsGroup("RaftReplDev", inst_name) {
        REGISTER_COUNTER(read_err_cnt, "total read error count", "read_err_cnt", {"op", "read"});
        REGISTER_COUNTER(write_err_cnt, "total write error count", "write_err_cnt", {"op", "write"});
        REGISTER_COUNTER(fetch_err_cnt, "total fetch data error count", "fetch_err_cnt", {"op", "fetch"});

        REGISTER_COUNTER(fetch_rreq_cnt, "total fetch data count", "fetch_data_req_cnt", {"op", "fetch"});
        REGISTER_COUNTER(fetch_total_blk_size, "total fetch data blocks size", "fetch_total_blk_size", {"op", "fetch"});
        REGISTER_COUNTER(fetch_total_entries_cnt, "total fetch total entries count", "fetch_total_entries_cnt",
                         {"op", "fetch"});

        // TODO: do we want to put this under _PRERELEASE only?
        REGISTER_COUNTER(total_read_cnt, "total write count", "total_write_cnt", {"op", "read"}); // placeholder
        REGISTER_COUNTER(total_write_cnt, "total read count", "total_read_cnt", {"op", "write"});
        REGISTER_COUNTER(outstanding_data_read_cnt, "Total data outstanding read cnt",
                         sisl::_publish_as::publish_as_gauge); // placeholder
        REGISTER_COUNTER(outstanding_data_write_cnt, "Total data outstanding write cnt",
                         sisl::_publish_as::publish_as_gauge);
        REGISTER_COUNTER(outstanding_data_fetch_cnt, "Total data outstanding fetch cnt",
                         sisl::_publish_as::publish_as_gauge);

        // leader: data write latency;
        // follower: from rreq push data received to data write completion;
        REGISTER_HISTOGRAM(rreq_data_write_latency_us, "rreq data write latency in us", "rreq_data_op_latency",
                           {"op", "write"});
        REGISTER_HISTOGRAM(rreq_data_read_latency_us, "rreq data read latency in us", "rreq_data_op_latency",
                           {"op", "read"}); // placeholder
        // latency from follower->originator->follower, not including actual data write on follower;
        REGISTER_HISTOGRAM(rreq_data_fetch_latency_us, "rreq data fetch latency in us", "rreq_data_op_latency",
                           {"op", "fetch"});

        /* from rreq creation to data ops completion */
        REGISTER_HISTOGRAM(rreq_total_data_read_latency_us, "rreq data read latency in us", "rdev_data_op_latency",
                           {"op", "read"}); // placeholder
        REGISTER_HISTOGRAM(rreq_total_data_write_latency_us, "rreq data write latency in us", "rdev_data_op_latency",
                           {"op", "write"});

        REGISTER_HISTOGRAM(rreq_pieces_per_write, "Number of individual pieces per write",
                           HistogramBucketsType(LinearUpto64Buckets));

        register_me_to_farm();
    }

    RaftReplDevMetrics(const RaftReplDevMetrics&) = delete;
    RaftReplDevMetrics(RaftReplDevMetrics&&) noexcept = delete;
    RaftReplDevMetrics& operator=(const RaftReplDevMetrics&) = delete;
    RaftReplDevMetrics& operator=(RaftReplDevMetrics&&) noexcept = delete;
    ~RaftReplDevMetrics() { deregister_me_from_farm(); }
};

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
    sisl::urcu_scoped_ptr< repl_dev_stage_t > m_stage;

    std::mutex m_config_mtx;
    superblk< raft_repl_dev_superblk > m_rd_sb;        // Superblk where we store the state machine etc
    json_superblk m_raft_config_sb;                    // Raft Context and Config data information stored
    mutable folly::SharedMutexWritePriority m_sb_lock; // Lock to protect staged sb and persisting sb
    raft_repl_dev_superblk m_sb_in_mem;                // Cached version which is used to read and for staging

    std::atomic< repl_lsn_t > m_commit_upto_lsn{0}; // LSN which was lastly written, to track flushes
    std::atomic< repl_lsn_t > m_compact_lsn{0};     // LSN upto which it was compacted, it is used to track where to

    std::mutex m_sb_mtx; // Lock to protect the repl dev superblock

    repl_lsn_t m_last_flushed_commit_lsn{0}; // LSN upto which it was flushed to persistent store
    iomgr::timer_handle_t m_sb_flush_timer_hdl;

    std::atomic< uint64_t > m_next_dsn{0}; // Data Sequence Number that will keep incrementing for each data entry

    iomgr::timer_handle_t m_wait_data_timer_hdl{
        iomgr::null_timer_handle}; // non-recurring timer doesn't need to be cancelled on shutdown;
    bool m_resync_mode{false};
    Clock::time_point m_destroyed_time;
    folly::Promise< ReplServiceError > m_destroy_promise;
    RaftReplDevMetrics m_metrics;

    nuraft::ptr< nuraft::snapshot > m_last_snapshot{nullptr};

    static std::atomic< uint64_t > s_next_group_ordinal;
    bool m_log_store_replay_done{false};

public:
    friend class RaftStateMachine;

    RaftReplDev(RaftReplService& svc, superblk< raft_repl_dev_superblk >&& rd_sb, bool load_existing);
    virtual ~RaftReplDev() = default;

    bool join_group();
    folly::SemiFuture< ReplServiceError > destroy_group();

    //////////////// All ReplDev overrides/implementation ///////////////////////
    void async_alloc_write(sisl::blob const& header, sisl::blob const& key, sisl::sg_list const& value,
                           repl_req_ptr_t ctx) override;
    folly::Future< std::error_code > async_read(MultiBlkId const& blkid, sisl::sg_list& sgs, uint32_t size,
                                                bool part_of_batch = false) override;
    void async_free_blks(int64_t lsn, MultiBlkId const& blkid) override;
    AsyncReplResult<> become_leader() override;
    bool is_leader() const override;
    replica_id_t get_leader_id() const override;
    std::vector< peer_info > get_replication_status() const override;
    group_id_t group_id() const override { return m_group_id; }
    std::string group_id_str() const { return boost::uuids::to_string(m_group_id); }
    std::string rdev_name() const { return m_rdev_name; }
    std::string my_replica_id_str() const { return boost::uuids::to_string(m_my_repl_id); }
    uint32_t get_blk_size() const override;
    repl_lsn_t get_last_commit_lsn() const { return m_commit_upto_lsn.load(); }
    bool is_destroy_pending() const;
    bool is_destroyed() const;
    Clock::time_point destroyed_time() const { return m_destroyed_time; }

    //////////////// Accessor/shortcut methods ///////////////////////
    nuraft_mesg::repl_service_ctx* group_msg_service();
    nuraft::raft_server* raft_server();

    //////////////// Methods needed for other Raft classes to access /////////////////
    void use_config(json_superblk raft_config_sb);
    void handle_commit(repl_req_ptr_t rreq);
    repl_req_ptr_t repl_key_to_req(repl_key const& rkey) const;
    repl_req_ptr_t applier_create_req(repl_key const& rkey, journal_type_t code, sisl::blob const& user_header,
                                      sisl::blob const& key, uint32_t data_size, bool is_data_channel);
    folly::Future< folly::Unit > notify_after_data_written(std::vector< repl_req_ptr_t >* rreqs);
    void check_and_fetch_remote_data(std::vector< repl_req_ptr_t > rreqs);
    void cp_flush(CP* cp);
    void cp_cleanup(CP* cp);
    void become_ready();

    /// @brief This method is called when the data journal is compacted
    ///
    /// @param upto_lsn : LSN upto which the data journal was compacted
    void on_compact(repl_lsn_t upto_lsn) { m_compact_lsn.store(upto_lsn); }

    /**
     * \brief Handles the creation of a snapshot.
     *
     * This function is called when a snapshot needs to be created in the replication process.
     * It takes a reference to a `nuraft::snapshot` object and a handler for the asynchronous result.
     * The handler will be called when the snapshot creation is completed.
     *
     * \param s The snapshot object to be created.
     * \param when_done The handler to be called when the snapshot creation is completed.
     */
    void on_create_snapshot(nuraft::snapshot& s, nuraft::async_result< bool >::handler_type& when_done);

    /**
     * Truncates the replication log by providing a specified number of reserved entries.
     *
     * @param num_reserved_entries The number of reserved entries of the replication log.
     */
    void truncate(uint32_t num_reserved_entries) {
        m_data_journal->truncate(num_reserved_entries, m_compact_lsn.load());
    }

    nuraft::ptr< nuraft::snapshot > get_last_snapshot() { return m_last_snapshot; }

    void wait_for_logstore_ready() { m_data_journal->wait_for_log_store_ready(); }

    void gc_repl_reqs();

    /**
     * Flush the durable commit LSN to the superblock
     */
    void flush_durable_commit_lsn();

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
    std::pair< bool, nuraft::cb_func::ReturnCode > handle_raft_event(nuraft::cb_func::Type,
                                                                     nuraft::cb_func::Param*) override;

private:
    shared< nuraft::log_store > data_journal() { return m_data_journal; }
    void push_data_to_all_followers(repl_req_ptr_t rreq, sisl::sg_list const& data);
    void on_push_data_received(intrusive< sisl::GenericRpcData >& rpc_data);
    void on_fetch_data_received(intrusive< sisl::GenericRpcData >& rpc_data);
    void fetch_data_from_remote(std::vector< repl_req_ptr_t > rreqs);
    void handle_fetch_data_response(sisl::GenericClientResponse response, std::vector< repl_req_ptr_t > rreqs);
    bool is_resync_mode() { return m_resync_mode; }
    void handle_error(repl_req_ptr_t const& rreq, ReplServiceError err);
    bool wait_for_data_receive(std::vector< repl_req_ptr_t > const& rreqs, uint64_t timeout_ms);
    void on_log_found(logstore_seq_num_t lsn, log_buffer buf, void* ctx);
};

} // namespace homestore
