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
    repl_lsn_t last_snapshot_lsn;   // Last snapshot LSN follower received from leader

    uint32_t get_raft_sb_version() const { return raft_sb_version; }
};
#pragma pack()

using raft_buf_ptr_t = nuraft::ptr< nuraft::buffer >;
using raft_cluster_config_ptr_t = nuraft::ptr< nuraft::cluster_config >;

ENUM(repl_dev_stage_t, uint8_t, INIT, ACTIVE, DESTROYING, DESTROYED, PERMANENT_DESTROYED);

struct replace_members_ctx {
    replica_member_info replica_out;
    replica_member_info replica_in;
};

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
        REGISTER_HISTOGRAM(rreq_push_data_latency_us, "rreq data write latency in us", "rreq_data_op_latency",
                           {"op", "push"});
        // latency from req received to sending response
        REGISTER_HISTOGRAM(rreq_data_write_respond_latency_us, "rreq data write and respond latency in us",
                           "rreq_data_op_latency", {"op", "respond"});
        // latency from req received to rpc complete
        REGISTER_HISTOGRAM(rreq_data_write_complete_latency_us, "rreq data rpc complete latency in us",
                           "rreq_data_op_latency", {"op", "complete"});
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

        // In the identical layout chunk, the blk num of the follower and leader is expected to be the same.
        // However, due to the concurrency between the data channel and the raft channel, there might be some
        // allocation differences on the same lsn. When a leader switch occurs, these differences could become garbage.
        // This metric can partially reflect the potential amount of garbage.
        REGISTER_HISTOGRAM(blk_diff_with_proposer,
                           "allocated blk num diff on the same lsn with proposer when chunk usage >= 0.9");

        // Raft channel metrics
        REGISTER_HISTOGRAM(raft_end_of_append_batch_latency_us, "Raft end_of_append_batch latency in us",
                           "raft_logstore_append_latency", {"op", "end_of_append_batch"});
        REGISTER_HISTOGRAM(data_channel_wait_latency_us, "Data channel wait latency in us",
                           "raft_logstore_append_latency", {"op", "wait_for_data"});

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
struct ReplDevCPContext {
    repl_lsn_t cp_lsn;
    repl_lsn_t compacted_to_lsn;
    uint64_t last_applied_dsn;
};

class nuraft_snapshot_context : public snapshot_context {
public:
    nuraft_snapshot_context(nuraft::snapshot& snp) : snapshot_context(snp.get_last_log_idx()) {
        auto snp_buf = snp.serialize();
        snapshot_ = nuraft::snapshot::deserialize(*snp_buf);
    }

    nuraft_snapshot_context(sisl::io_blob_safe const& snp_ctx) : snapshot_context(0) { deserialize(snp_ctx); }

    sisl::io_blob_safe serialize() override {
        // Dump the context from nuraft buffer to the io blob.
        auto snp_buf = snapshot_->serialize();
        sisl::io_blob_safe blob{s_cast< size_t >(snp_buf->size())};
        std::memcpy(blob.bytes(), snp_buf->data_begin(), snp_buf->size());
        return blob;
    }

    void deserialize(const sisl::io_blob_safe& snp_ctx) {
        // Load the context from the io blob to nuraft buffer.
        auto snp_buf = nuraft::buffer::alloc(snp_ctx.size());
        snp_buf->put_raw(snp_ctx.cbytes(), snp_ctx.size());
        snp_buf->pos(0);
        snapshot_ = nuraft::snapshot::deserialize(*snp_buf);
        lsn_ = snapshot_->get_last_log_idx();
    }

    nuraft::ptr< nuraft::snapshot > nuraft_snapshot() { return snapshot_; }

private:
    nuraft::ptr< nuraft::snapshot > snapshot_;
};

class RaftReplDev : public ReplDev,
                    public nuraft_mesg::mesg_state_mgr,
                    public std::enable_shared_from_this< RaftReplDev > {
private:
    class init_req_counter {
    public:
        init_req_counter(std::atomic_uint64_t& counter) : my_counter(counter) {
            my_counter.fetch_add(1, std::memory_order_acq_rel);
        }

        ~init_req_counter() { my_counter.fetch_sub(1, std::memory_order_acq_rel); }

    private:
        std::atomic_uint64_t& my_counter;
    };

private:
    shared< RaftStateMachine > m_state_machine;
    RaftReplService& m_repl_svc;
    folly::ConcurrentHashMap< repl_key, repl_req_ptr_t, repl_key::Hasher > m_repl_key_req_map;
    nuraft_mesg::Manager& m_msg_mgr;
    group_id_t m_group_id;      // Replication Group id
    std::string m_rdev_name;    // Short name for the group for easy debugging
    std::string m_identify_str; // combination of rdev_name:group_id
    replica_id_t m_my_repl_id;  // This replica's uuid
    int32_t m_raft_server_id;   // Server ID used by raft (unique within raft group)
    shared< ReplLogStore > m_data_journal;
    shared< HomeLogStore > m_free_blks_journal;
    sisl::urcu_scoped_ptr< repl_dev_stage_t > m_stage;

    std::mutex m_config_mtx;
    superblk< raft_repl_dev_superblk > m_rd_sb;        // Superblk where we store the state machine etc
    json_superblk m_raft_config_sb;                    // Raft Context and Config data information stored
    mutable folly::SharedMutexWritePriority m_sb_lock; // Lock to protect staged sb and persisting sb
    raft_repl_dev_superblk m_sb_in_mem;                // Cached version which is used to read and for staging

    std::atomic< repl_lsn_t > m_commit_upto_lsn{0}; // LSN which was lastly committed, to track flushes
    std::atomic< repl_lsn_t > m_compact_lsn{0};     // LSN upto which it was compacted, it is used to track where to
    // The `traffic_ready_lsn` variable holds the Log Sequence Number (LSN) up to which
    // the state machine should committed to before accepting traffic. This threshold ensures that
    // all potential committed log be committed before handling incoming requests.
    std::atomic< repl_lsn_t > m_traffic_ready_lsn{0};

    std::mutex m_sb_mtx; // Lock to protect the repl dev superblock

    repl_lsn_t m_last_flushed_commit_lsn{0}; // LSN upto which it was flushed to persistent store
    iomgr::timer_handle_t m_sb_flush_timer_hdl;

    std::atomic< uint64_t > m_next_dsn{0}; // Data Sequence Number that will keep incrementing for each data entry

    iomgr::timer_handle_t m_wait_data_timer_hdl{
        iomgr::null_timer_handle}; // non-recurring timer doesn't need to be cancelled on shutdown;
    Clock::time_point m_destroyed_time;
    folly::Promise< ReplServiceError > m_destroy_promise;
    RaftReplDevMetrics m_metrics;

    static std::atomic< uint64_t > s_next_group_ordinal;
    bool m_log_store_replay_done{false};

    // pending create requests, including both raft and data channel
    std::atomic_uint64_t m_pending_init_req_num;
    std::atomic< bool > m_in_quience;

public:
    friend class RaftStateMachine;

    RaftReplDev(RaftReplService& svc, superblk< raft_repl_dev_superblk >&& rd_sb, bool load_existing);
    virtual ~RaftReplDev() = default;

    bool bind_data_service();
    bool join_group();
    AsyncReplResult<> replace_member(const replica_member_info& member_out, const replica_member_info& member_in,
                                     uint32_t commit_quorum);
    folly::SemiFuture< ReplServiceError > destroy_group();

    //////////////// All ReplDev overrides/implementation ///////////////////////
    void async_alloc_write(sisl::blob const& header, sisl::blob const& key, sisl::sg_list const& value,
                           repl_req_ptr_t ctx, trace_id_t tid = 0) override;
    folly::Future< std::error_code > async_read(MultiBlkId const& blkid, sisl::sg_list& sgs, uint32_t size,
                                                bool part_of_batch = false, trace_id_t tid = 0) override;
    folly::Future< std::error_code > async_free_blks(int64_t lsn, MultiBlkId const& blkid, trace_id_t tid = 0) override;
    AsyncReplResult<> become_leader() override;
    bool is_leader() const override;
    replica_id_t get_leader_id() const override;
    std::vector< peer_info > get_replication_status() const override;
    std::set< replica_id_t > get_active_peers() const;
    group_id_t group_id() const override { return m_group_id; }
    void set_custom_rdev_name(std::string const& name) override {
        RD_LOGI(NO_TRACE_ID, "Resetting repl dev name from {} to {}", m_rdev_name, name);
        m_rdev_name = name;
        m_identify_str = name + ":" + group_id_str();
        m_rd_sb->set_rdev_name(m_rdev_name);
    }
    std::string group_id_str() const { return boost::uuids::to_string(m_group_id); }
    std::string rdev_name() const { return m_rd_sb->rdev_name; };
    std::string identify_str() const { return m_identify_str; };
    std::string my_replica_id_str() const { return boost::uuids::to_string(m_my_repl_id); }
    uint32_t get_blk_size() const override;
    repl_lsn_t get_last_commit_lsn() const override { return m_commit_upto_lsn.load(); }
    void set_last_commit_lsn(repl_lsn_t lsn) { m_commit_upto_lsn.store(lsn); }
    repl_lsn_t get_last_append_lsn() override { return raft_server()->get_last_log_idx() + 1; /*to_repl_lsn*/ }
    bool is_destroy_pending() const;
    bool is_destroyed() const;

    Clock::time_point destroyed_time() const { return m_destroyed_time; }
    bool is_ready_for_traffic() const override;
    // purge all resources (e.g., logs in logstore) is a very dangerous operation, it is not supported yet.
    void purge() override { RD_REL_ASSERT(false, "NOT SUPPORTED YET"); }

    std::shared_ptr< snapshot_context > deserialize_snapshot_context(sisl::io_blob_safe& snp_ctx) override {
        return std::make_shared< nuraft_snapshot_context >(snp_ctx);
    }

    //////////////// Accessor/shortcut methods ///////////////////////
    nuraft_mesg::repl_service_ctx* group_msg_service();

    nuraft::raft_server* raft_server();
    RaftReplDevMetrics& metrics() { return m_metrics; }

    //////////////// Methods needed for other Raft classes to access /////////////////
    void use_config(json_superblk raft_config_sb);
    void handle_commit(repl_req_ptr_t rreq, bool recovery = false);
    void handle_config_commit(const repl_lsn_t lsn, raft_cluster_config_ptr_t& new_conf);
    void handle_rollback(repl_req_ptr_t rreq);
    repl_req_ptr_t repl_key_to_req(repl_key const& rkey) const;
    repl_req_ptr_t applier_create_req(repl_key const& rkey, journal_type_t code, sisl::blob const& user_header,
                                      sisl::blob const& key, uint32_t data_size, bool is_data_channel,
                                      int64_t lsn = -1 /*init lsn*/);
    folly::Future< folly::Unit > notify_after_data_written(std::vector< repl_req_ptr_t >* rreqs);
    void check_and_fetch_remote_data(std::vector< repl_req_ptr_t > rreqs);
    void cp_flush(CP* cp, cshared< ReplDevCPContext > ctx);
    cshared< ReplDevCPContext > get_cp_ctx(CP* cp);
    void cp_cleanup(CP* cp);
    void become_ready();

    void become_leader_cb();

    void become_follower_cb() {
        // m_traffic_ready_lsn should be zero on follower.
        m_traffic_ready_lsn.store(0);
        RD_LOGD(NO_TRACE_ID, "become_follower_cb setting  traffic_ready_lsn to 0");
    }

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

#if 0
    /**
     * Truncates the replication log by providing a specified number of reserved entries.
     *
     * @param num_reserved_entries The number of reserved entries of the replication log.
     */
    void truncate(uint32_t num_reserved_entries) {
        m_data_journal->truncate(num_reserved_entries, m_compact_lsn.load());
    }
#endif

    void wait_for_logstore_ready() { m_data_journal->wait_for_log_store_ready(); }

    void gc_repl_reqs();

    /**
     * Flush the durable commit LSN to the superblock
     */
    void flush_durable_commit_lsn();

    /**
     * \brief This method is called during restart to notify the upper layer
     */
    void on_restart();

    /**
     * \brief This method is called to force leave the group without waiting for committing the destroy message.
     * it is used when the repl_dev is a stale member of a destroyed group. this stable member does not receive the
     * destroy message. but the group is already destroyed, so no leader will send this message again to this stale
     * member. we need to force leave the group to avoid the stale member to be a part of the group.
     */
    void force_leave() { leave(); }

    /**
     * \brief This method is called to check if the given LSN is within the last snapshot LSN received from the leader.
     * All logs with LSN less than or equal to the last snapshot LSN are considered as part of the baseline resync,
     * which doesn't need any more operations (e.g., replay, commit).
     *
     * \param lsn The LSN to be checked.
     * \return true if the LSN is within the last snapshot LSN, false otherwise.
     */
    bool need_skip_processing(const repl_lsn_t lsn) { return lsn <= m_rd_sb->last_snapshot_lsn; }

    // pause/resume statemachine(commiting thread)
    void pause_statemachine();
    void resume_statemachine();

    void quiesce_reqs();
    void resume_accepting_reqs();

    // clear reqs that has allocated blks on the given chunk.
    void clear_chunk_req(chunk_num_t chunk_id);

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

    nuraft::cb_func::ReturnCode raft_event(nuraft::cb_func::Type, nuraft::cb_func::Param*) override;

private:
    shared< nuraft::log_store > data_journal() { return m_data_journal; }
    void push_data_to_all_followers(repl_req_ptr_t rreq, sisl::sg_list const& data);
    void on_push_data_received(intrusive< sisl::GenericRpcData >& rpc_data);
    void on_fetch_data_received(intrusive< sisl::GenericRpcData >& rpc_data);
    void fetch_data_from_remote(std::vector< repl_req_ptr_t > rreqs);
    void handle_fetch_data_response(sisl::GenericClientResponse response, std::vector< repl_req_ptr_t > rreqs);
    bool is_resync_mode();

    /**
     * \brief This method handles errors that occur during append entries or data receiving.
     * It should not be called after the append entries phase.
     */
    void handle_error(repl_req_ptr_t const& rreq, ReplServiceError err);

    bool wait_for_data_receive(std::vector< repl_req_ptr_t > const& rreqs, uint64_t timeout_ms,
                               std::vector< repl_req_ptr_t >* timeout_rreqs = nullptr);
    void on_log_found(logstore_seq_num_t lsn, log_buffer buf, void* ctx);
    void set_log_store_last_durable_lsn(store_lsn_t lsn);
    void commit_blk(repl_req_ptr_t rreq);
    void replace_member(repl_req_ptr_t rreq);
    void reset_quorum_size(uint32_t commit_quorum, uint64_t trace_id);
    void create_snp_resync_data(raft_buf_ptr_t& data_out);
    bool save_snp_resync_data(nuraft::buffer& data, nuraft::snapshot& s);

    void report_blk_metrics_if_needed(repl_req_ptr_t rreq);
    ReplServiceError init_req_ctx(repl_req_ptr_t rreq, repl_key rkey, journal_type_t op_code, bool is_proposer,
                                  sisl::blob const& user_header, sisl::blob const& key, uint32_t data_size,
                                  cshared< ReplDevListener >& listener);

    bool is_in_quience() { return m_in_quience.load(std::memory_order_acquire); }

    uint64_t get_pending_init_req_num() { return m_pending_init_req_num.load(std::memory_order_acquire); }
};

} // namespace homestore
