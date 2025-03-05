#pragma once

#include <variant>

#include <boost/intrusive_ptr.hpp>
#include <boost/smart_ptr/intrusive_ref_counter.hpp>
#include <flatbuffers/flatbuffers.h>
#include <folly/futures/Future.h>
#include <sisl/fds/buffer.hpp>
#include <sisl/fds/utils.hpp>
#include <sisl/grpc/generic_service.hpp>
#include <sisl/grpc/rpc_client.hpp>
#include <homestore/replication/repl_decls.h>
#include <libnuraft/snapshot.hxx>

namespace nuraft {
template < typename T >
using ptr = std::shared_ptr< T >;

class buffer;
class log_entry;
} // namespace nuraft

namespace homestore {
class ReplDev;
class ReplDevListener;
struct repl_req_ctx;
using raft_buf_ptr_t = nuraft::ptr< nuraft::buffer >;
using raft_cluster_config_ptr_t = nuraft::ptr< nuraft::cluster_config >;
using repl_req_ptr_t = boost::intrusive_ptr< repl_req_ctx >;

VENUM(repl_req_state_t, uint32_t,
      INIT = 0,               // Initial state
      BLK_ALLOCATED = 1 << 0, // Local block is allocated
      DATA_RECEIVED = 1 << 1, // Data has been received and being written to the storage
      DATA_WRITTEN = 1 << 2,  // Data has been written to the storage
      LOG_RECEIVED = 1 << 3,  // Log is received and waiting for data
      LOG_FLUSHED = 1 << 4,   // Log has been flushed
      ERRORED = 1 << 5,       // Error has happened and cleaned up
      DATA_COMMITTED = 1 << 6 // Data has already been committed, used in duplication handling, will skip commit_blk
)

VENUM(journal_type_t, uint16_t,
      HS_DATA_LINKED = 0,  // Linked data where each entry will store physical blkid where data reside
      HS_DATA_INLINED = 1, // Data is inlined in the header of journal entry
      HS_CTRL_DESTROY = 2, // Control message to destroy the repl_dev
      HS_CTRL_REPLACE = 3, // Control message to replace a member
)

// some events need to be handled by upper layer
VENUM(event_type_t, uint8_t,
      RD_FETCH_DATA = 0,      // fetch data
      RD_NO_SPACE_LEFT = 1,   // no space left error
      RD_LOG_REPLAY_DONE = 2, // log replay done
                              // add more if needed for other applications.
)

using fetch_data_handler_t = folly::Future< std::error_code > (*)(int64_t lsn, const sisl::blob& header,
                                                                  std::vector< sisl::sg_list >& sgs_vec);
using no_space_left_handler_t = folly::Future< folly::Unit > (*)(uint32_t pdev_id, chunk_num_t chunk_id);

using log_replay_done_handler_t = void (*)();

// magic num comes from the first 8 bytes of 'echo homestore_resync_data | md5sum'
static constexpr uint64_t HOMESTORE_RESYNC_DATA_MAGIC = 0xa65dbd27c213f327;
static constexpr uint32_t HOMESTORE_RESYNC_DATA_PROTOCOL_VERSION_V1 = 0x01;

struct repl_key {
    int32_t server_id{0}; // Server Id which this req is originated from
    uint64_t term;        // RAFT term number
    uint64_t dsn{0};      // Data sequence number to tie the data with the raft journal entry

    struct Hasher {
        size_t operator()(repl_key const& rk) const {
            return std::hash< int32_t >()(rk.server_id) ^ std::hash< uint64_t >()(rk.term) ^
                std::hash< uint64_t >()(rk.dsn);
        }
    };

    bool operator==(repl_key const& other) const = default;
    std::string to_string() const {
        return fmt::format("server={}, term={}, dsn={}, hash={}", server_id, term, dsn, Hasher()(*this));
    }
};

using repl_snapshot = nuraft::snapshot;
using repl_snapshot_ptr = nuraft::ptr< nuraft::snapshot >;

// Consumers of ReplDevListener don't have to know what underlying snapshot context implementation is used by the
// ReplDev. The state of the snapshot can be exported with serialize() and loaded with
// repl_dev.deserialize_snapshot_context().
class snapshot_context {
public:
    snapshot_context(int64_t lsn) : lsn_(lsn) {}
    virtual ~snapshot_context() = default;
    virtual sisl::io_blob_safe serialize() = 0;
    int64_t get_lsn() { return lsn_; }

protected:
    int64_t lsn_;
};

struct snapshot_obj {
    void* user_ctx{nullptr};
    uint64_t offset{0};
    sisl::io_blob_safe blob;
    bool is_first_obj{false};
    bool is_last_obj{false};
};

// HomeStore has some meta information to be transmitted during the baseline resync,
// Although now only dsn needs to be synced, this structure is defined as a general message, and we can easily add data
// if needed in the future.
struct snp_repl_dev_data {
    uint64_t magic_num{HOMESTORE_RESYNC_DATA_MAGIC};
    uint32_t protocol_version{HOMESTORE_RESYNC_DATA_PROTOCOL_VERSION_V1};
    uint32_t crc{0};
    uint64_t dsn{0};
};

struct repl_journal_entry;
struct repl_req_ctx : public boost::intrusive_ref_counter< repl_req_ctx, boost::thread_safe_counter >,
                      sisl::ObjLifeCounter< repl_req_ctx > {
    friend class SoloReplDev;

public:
    repl_req_ctx() { m_start_time = Clock::now(); }
    virtual ~repl_req_ctx();
    ReplServiceError init(repl_key rkey, journal_type_t op_code, bool is_proposer, sisl::blob const& user_header,
                          sisl::blob const& key, uint32_t data_size, cshared< ReplDevListener >& listener);

    /////////////////////// All getters ///////////////////////
    repl_key const& rkey() const { return m_rkey; }
    uint64_t dsn() const { return m_rkey.dsn; }
    uint64_t term() const { return m_rkey.term; }
    int64_t lsn() const { return m_lsn; }
    bool is_proposer() const { return m_is_proposer; }
    journal_type_t op_code() const { return m_op_code; }
    bool is_volatile() const { return m_is_volatile.load(); }

    sisl::blob const& header() const { return m_header; }
    sisl::blob const& key() const { return m_key; }
    MultiBlkId const& local_blkid() const { return m_local_blkid; }
    RemoteBlkId const& remote_blkid() const { return m_remote_blkid; }
    const char* data() const {
        DEBUG_ASSERT(m_data != nullptr,
                     "m_data is nullptr, use before save_pushed/fetched_data or after release_data()");
        return r_cast< const char* >(m_data);
    }
    repl_req_state_t state() const { return repl_req_state_t(m_state.load()); }
    bool has_state(repl_req_state_t s) const { return m_state.load() & uint32_cast(s); }
    repl_journal_entry const* journal_entry() const { return m_journal_entry; }
    uint32_t journal_entry_size() const;
    bool is_localize_pending() const { return m_is_jentry_localize_pending; }
    bool is_data_inlined() const { return (m_op_code == journal_type_t::HS_DATA_INLINED); }
    bool has_linked_data() const { return (m_op_code == journal_type_t::HS_DATA_LINKED); }

    raft_buf_ptr_t& raft_journal_buf();
    uint8_t* raw_journal_buf();
    /////////////////////// Non modifiers methods //////////////////
    std::string to_string() const;
    std::string to_compact_string() const;
    Clock::time_point created_time() const { return m_start_time; }
    void set_created_time() { m_start_time = Clock::now(); }
    bool is_expired() const;

    /////////////////////// All Modifiers methods //////////////////

    /// @brief Anytime a request needs to allocate blks for the data locally, this method needs to be called. This will
    /// call the listener blk_alloc_hints and then allocate the blks from data service and update the state.
    /// @param listener Listener associated with the repl_dev
    /// @param data_size Size of the data for which blks are to be allocated
    /// @return Any error in getting hints or allocating blkids
    ReplServiceError alloc_local_blks(cshared< ReplDevListener >& listener, uint32_t data_size);

    /// @brief  This method creates the journal entry for the repl_req. It will allocate the buffer for the journal
    /// entry and build the basic journal entry
    /// @param is_raft_buf Is the journal entry buffer has to be raft_buf or plain buf. For Raft repl service, it will
    /// have to be true
    /// @param server_id Server id which is originating this request
    void create_journal_entry(bool is_raft_buf, int32_t server_id);

    /// @brief Change the journal entry buffer to new_buf and adjust the header and key if adjust_hdr_key is true. It is
    /// expected that the original buffer is already created as raft buffer type.
    /// @param new_buf New raft buffer to be used
    /// @param adjust_hdr_key If the header, key of this request has to be adjusted to the new buffer
    void change_raft_journal_buf(raft_buf_ptr_t new_buf, bool adjust_hdr_key);

    /// @brief Save the data that was pushed by the remote node for this request. When a push data rpc is called with
    /// the data, this method is called to save them to the request and make it shareable. This method makes a copy of
    /// the data in case the buffer is not aligned.
    /// @param pushed_data Data that was received from the RPC. This is used to keep the data alive
    /// @param data Data pointer
    /// @param data_size Size of the data
    /// @return true if the request didn't receive the data already, false otherwise
    bool save_pushed_data(intrusive< sisl::GenericRpcData > const& pushed_data, uint8_t const* data,
                          uint32_t data_size);

    /// @brief Save the data that was fetched from the remote node for this request. When a fetch data rpc is called
    /// with the data, this method is called to save them to the request and make it shareable. This method makes a copy
    /// of the data in case the buffer is not aligned.
    /// @param fetched_data Data from RPC which fetched the data. This is used to keep the data alive
    /// @param data Data pointer
    /// @param data_size Size of the data
    /// @return true if the request didn't receive the data already, false otherwise
    bool save_fetched_data(sisl::GenericClientResponse const& fetched_data, uint8_t const* data, uint32_t data_size);

    void set_remote_blkid(RemoteBlkId const& rbid) { m_remote_blkid = rbid; }
    void set_local_blkid(MultiBlkId const& lbid) { m_local_blkid = lbid; } // Only used during recovery
    void set_is_volatile(bool is_volatile) { m_is_volatile.store(is_volatile); }
    void set_lsn(int64_t lsn);
    void add_state(repl_req_state_t s);
    bool add_state_if_not_already(repl_req_state_t s);
    void set_lentry(nuraft::ptr< nuraft::log_entry > const& lentry) { m_lentry = lentry; }
    void clear();
    void release_data();
    flatbuffers::FlatBufferBuilder& create_fb_builder() { return m_fb_builder; }
    void release_fb_builder() { m_fb_builder.Release(); }

public:
    // IMPORTANT: Avoid declaring variables public, since this structure carries various entries and try to work in
    // lockless way. As a result, we keep only those which are considered thread safe and others are accessed with
    // methods.
    folly::Promise< folly::Unit > m_data_received_promise; // Promise to be fulfilled when data is received
    folly::Promise< folly::Unit > m_data_written_promise;  // Promise to be fulfilled when data is written
    sisl::io_blob_list_t m_pkts;                           // Pkts used for sending data
    std::mutex m_state_mtx;

private:
    repl_key m_rkey;                                           // Unique key for the request
    sisl::blob m_header;                                       // User header
    sisl::blob m_key;                                          // User supplied key for this req
    int64_t m_lsn{-1};                                         // Lsn for this replication req
    bool m_is_proposer{false};                                 // Is the repl_req proposed by this node
    Clock::time_point m_start_time;                            // Start time of the request
    journal_type_t m_op_code{journal_type_t::HS_DATA_INLINED}; // Operation code for this request
    std::atomic< bool > m_is_volatile{true};                   // Is the log still in memory and not flushed to disk yet

    /////////////// Data related section /////////////////
    MultiBlkId m_local_blkid;   // Local BlkId for the data
    RemoteBlkId m_remote_blkid; // Corresponding remote blkid for the data
    uint8_t const* m_data;      // Raw data pointer containing the actual data

    /////////////// Journal/Buf related section /////////////////
    std::variant< std::unique_ptr< uint8_t[] >, raft_buf_ptr_t > m_journal_buf; // Buf for the journal entry
    repl_journal_entry* m_journal_entry{nullptr};                               // pointer to the journal entry
    bool m_is_jentry_localize_pending{false}; // Is the journal entry needs to be localized from remote
    nuraft::ptr< nuraft::log_entry > m_lentry;

    /////////////// Replication state related section /////////////////
    std::atomic< uint32_t > m_state{uint32_cast(repl_req_state_t::INIT)}; // State of the replication request

    /////////////// Communication packet/builder section /////////////////
    flatbuffers::FlatBufferBuilder m_fb_builder;
    sisl::io_blob_safe m_buf_for_unaligned_data;
    intrusive< sisl::GenericRpcData > m_pushed_data;
    sisl::GenericClientResponse m_fetched_data;
};

//
// Callbacks to be implemented by ReplDev users.
//
class ReplDevListener {
public:
    virtual ~ReplDevListener() = default;

    void set_repl_dev(shared< ReplDev > rdev) { m_repl_dev = rdev; }
    shared< ReplDev > repl_dev() { return m_repl_dev.lock(); }

    /// @brief Called when the log entry has been committed in the replica set.
    ///
    /// This function is called from a dedicated commit thread which is different from the original thread calling
    /// replica_set::write(). There is only one commit thread, and lsn is guaranteed to be monotonically increasing.
    ///
    /// @param lsn - The log sequence number
    /// @param header - Header originally passed with replica_set::write() api
    /// @param key - Key originally passed with replica_set::write() api
    /// @param blkids - List of blkids where data is written to the storage engine.
    /// @param ctx - Context passed as part of the replica_set::write() api
    ///
    virtual void on_commit(int64_t lsn, sisl::blob const& header, sisl::blob const& key, MultiBlkId const& blkids,
                           cintrusive< repl_req_ctx >& ctx) = 0;

    /// @brief Called when the log entry has been received by the replica dev.
    ///
    /// On recovery, this is called from a random worker thread before the raft server is started. It is
    /// guaranteed to be serialized in log index order.
    ///
    /// On the leader, this is called from the same thread that replica_set::write() was called.
    ///
    /// On the follower, this is called when the follower has received the log entry. It is guaranteed to be serialized
    /// in log sequence order.
    ///
    /// NOTE: Listener can choose to ignore this pre commit, however, typical use case of maintaining this is in-case
    /// replica set needs to support strong consistent reads and follower needs to ignore any keys which are not being
    /// currently in pre-commit, but yet to be committed.
    ///
    /// @param lsn - The log sequence number
    /// @param header - Header originally passed with repl_dev::write() api
    /// @param key - Key originally passed with repl_dev::write() api
    /// @param ctx - Context passed as part of the replica_set::write() api
    virtual bool on_pre_commit(int64_t lsn, const sisl::blob& header, const sisl::blob& key,
                               cintrusive< repl_req_ctx >& ctx) = 0;

    /// @brief Called when the log entry has been rolled back by the replica set.
    ///
    /// This function is called on followers only when the log entry is going to be overwritten. This function is called
    /// from a random worker thread, but is guaranteed to be serialized.
    ///
    /// For each log index, it is guaranteed that either on_commit() or on_rollback() is called but not both.
    ///
    /// NOTE: Listener should do the free any resources created as part of pre-commit.
    ///
    /// @param lsn - The log sequence number getting rolled back
    /// @param header - Header originally passed with ReplDev::async_alloc_write() api
    /// @param key - Key originally passed with ReplDev::async_alloc_write() api
    /// @param ctx - Context passed as part of the ReplDev::async_alloc_write() api
    virtual void on_rollback(int64_t lsn, const sisl::blob& header, const sisl::blob& key,
                             cintrusive< repl_req_ctx >& ctx) = 0;

    /// @brief Called when the replDev is created after restart. The consumer is expected to recover all the modules
    /// necessary to replay/commit the logs.
    virtual void on_restart() = 0;

    /// @brief Called when the async_alloc_write call failed to initiate replication
    ///
    /// Called only on the node which called async_alloc_write
    ///
    ///
    /// NOTE: Listener should do the free any resources created as part of pre-commit.
    ///
    /// @param header - Header originally passed with ReplDev::async_alloc_write() api
    /// @param key - Key originally passed with ReplDev::async_alloc_write() api
    /// @param ctx - Context passed as part of the ReplDev::async_alloc_write() api
    virtual void on_error(ReplServiceError error, const sisl::blob& header, const sisl::blob& key,
                          cintrusive< repl_req_ctx >& ctx) = 0;

    /// @brief Called when replication module is trying to allocate a block to write the value
    ///
    /// This function can be called both on leader and follower when it is trying to allocate a block to write the
    /// value. Caller is expected to provide hints for allocation based on the header supplied as part of original
    /// write. In cases where caller don't care about the hints can return default blk_alloc_hints.
    ///
    /// @param header Header originally passed with repl_dev::async_alloc_write() api on the leader
    /// @param data_size Size needed to be allocated for
    /// @return Expected to return blk_alloc_hints for this write. If the hints are not available, then return the
    /// error. It is to be noted this method should return error only in very abnornal cases as in some code flow, an
    /// error would result in a crash or stall of the entire commit thread.
    virtual ReplResult< blk_alloc_hints > get_blk_alloc_hints(sisl::blob const& header, uint32_t data_size) = 0;

    /// @brief Called when the repl_dev is being destroyed. The consumer is expected to clean up any related resources.
    /// However, it is expected that this call be idempotent. It is possible in rare scenarios that this can be called
    /// after restart in case crash happened during the destroy.
    virtual void on_destroy(const group_id_t& group_id) = 0;

    /// @brief Called when replace member is performed.
    virtual void on_replace_member(const replica_member_info& member_out, const replica_member_info& member_in) = 0;

    /// @brief Called when the snapshot is being created by nuraft
    virtual AsyncReplResult<> create_snapshot(shared< snapshot_context > context) = 0;

    /// @brief Called when nuraft does the baseline resync and in the end apply snapshot.
    virtual bool apply_snapshot(shared< snapshot_context > context) = 0;

    /// @brief Get the last snapshot saved.
    virtual shared< snapshot_context > last_snapshot() = 0;

    /// @brief Called on the leader side when the follower wants to do baseline resync and leader
    /// uses offset given by the follower to the know the current state of the follower.
    /// Leader sends the snapshot data to the follower in batch. This callback is called multiple
    /// times on the leader till all the data is transferred to the follower. is_last_obj in
    /// snapshot_obj will be true once all the data has been trasnferred. After this the raft on
    /// the follower side can do the incremental resync.
    virtual int read_snapshot_obj(shared< snapshot_context > context, shared< snapshot_obj > snp_obj) = 0;

    /// @brief Called on the follower when the leader sends the data during the baseline resyc.
    /// is_last_obj in in snapshot_obj will be true once all the data has been transfered.
    /// After this the raft on the follower side can do the incremental resync.
    virtual void write_snapshot_obj(shared< snapshot_context > context, shared< snapshot_obj > snp_obj) = 0;

    /// @brief Free up user-defined context inside the snapshot_obj that is allocated during read_snapshot_obj.
    virtual void free_user_snp_ctx(void*& user_snp_ctx) = 0;

    /// @brief some repl_dev event might be handle by upper layer. This is where homestore gets the callbacks for these
    /// events.
    virtual void* get_event_handler(event_type_t event_type) { return nullptr; }

private:
    std::weak_ptr< ReplDev > m_repl_dev;
};

class ReplDev {
public:
    ReplDev() = default;
    virtual ~ReplDev() { detach_listener(); }

    /// @brief Replicate the data to the replica set. This method goes through the
    /// following steps:
    /// Step 1: Allocates blkid from the storage engine to write the value into. Storage
    /// engine returns a blkid_list in cases where single contiguous blocks are not
    /// available. For convenience, the comment will continue to refer blkid_list as blkids.
    /// Step 2: Uses data channel to send the <blkids, value> to all replicas
    /// Step 3: Creates a log/journal entry with <header, key, blkid> and calls nuraft to
    /// append the entry and replicate using nuraft channel (also called header_channel).
    /// Step 4: Writes the data into the allocated blk_id
    ///
    /// @param header - Blob representing the header (it is opaque and will be copied
    /// as-is to the journal entry)
    /// @param key - Blob representing the key (it is opaque and will be copied as-is to
    /// the journal entry). We are tracking this seperately to support consistent read use
    /// cases
    /// @param value - vector of io buffers that contain value for the key. It is an optional field and if the value
    /// list size is 0, then only key is written to replicadev without data.
    /// @param ctx - User supplied context which will be passed to listener
    /// callbacks
    virtual void async_alloc_write(sisl::blob const& header, sisl::blob const& key, sisl::sg_list const& value,
                                   repl_req_ptr_t ctx) = 0;

    /// @brief Reads the data and returns a future to continue on
    /// @param bid Block id to read
    /// @param sgs Scatter gather buffer list to which blkids are to be read into
    /// @param size Total size of the data read
    /// @param part_of_batch Is read is part of a batch. If part of the batch, then submit_batch needs to be called at
    /// the end
    /// @return A Future with std::error_code to notify if it has successfully read the data or any error code in case
    /// of failure
    virtual folly::Future< std::error_code > async_read(MultiBlkId const& blkid, sisl::sg_list& sgs, uint32_t size,
                                                        bool part_of_batch = false) = 0;

    /// @brief After data is replicated and on_commit to the listener is called. the blkids can be freed.
    ///
    /// @param lsn - LSN of the old blkids that is being freed
    /// @param blkids - blkids to be freed.
    virtual folly::Future< std::error_code > async_free_blks(int64_t lsn, MultiBlkId const& blkid) = 0;

    /// @brief Try to switch the current replica where this method called to become a leader.
    /// @return True if it is successful, false otherwise.
    virtual AsyncReplResult<> become_leader() = 0;

    /// @brief Checks if this replica is the leader in this ReplDev
    /// @return true or false
    virtual bool is_leader() const = 0;

    /// @brief get the leader replica_id of given group
    virtual replica_id_t get_leader_id() const = 0;

    /// @brief get replication status. If called on follower member
    /// this API can return empty result.
    virtual std::vector< peer_info > get_replication_status() const = 0;

    /// @brief Gets the group_id this repldev is working for
    /// @return group_id
    virtual group_id_t group_id() const = 0;

    /// @brief Gets the block size with which IO will happen on this device
    /// @return Block size
    virtual uint32_t get_blk_size() const = 0;

    /// @brief Gets the last commit lsn of this repldev
    /// @return last_commit_lsn
    virtual repl_lsn_t get_last_commit_lsn() const = 0;

    /// @brief if this replica is ready for accepting client IO.
    /// @return true if ready, false otherwise
    virtual bool is_ready_for_traffic() const = 0;

    /// @brief Clean up resources on this repl dev.
    virtual void purge() = 0;

    virtual std::shared_ptr< snapshot_context > deserialize_snapshot_context(sisl::io_blob_safe& snp_ctx) = 0;

    virtual void attach_listener(shared< ReplDevListener > listener) { m_listener = std::move(listener); }

    virtual void detach_listener() {
        if (m_listener) {
            m_listener->set_repl_dev(nullptr);
            m_listener.reset();
        }
    }

    virtual shared< ReplDevListener > get_listener() { return m_listener; }

    // we have no shutdown for repl_dev, since shutdown repl_dev is done by repl_service
    void stop() {
        start_stopping();
        while (true) {
            auto pending_request_num = get_pending_request_num();
            if (!pending_request_num) break;

            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        }
    }

protected:
    shared< ReplDevListener > m_listener;

    // graceful shutdown related
protected:
    std::atomic_bool m_stopping{false};
    mutable std::atomic_uint64_t pending_request_num{0};

    bool is_stopping() const { return m_stopping.load(); }
    void start_stopping() { m_stopping = true; }

    uint64_t get_pending_request_num() const { return pending_request_num.load(); }

    void incr_pending_request_num() const { pending_request_num++; }
    void decr_pending_request_num() const { pending_request_num--; }
};

} // namespace homestore

template <>
struct fmt::formatter< homestore::repl_key > : fmt::formatter< std::string > {
    auto format(const homestore::repl_key& a, format_context& ctx) const {
        return fmt::formatter< std::string >::format(a.to_string(), ctx);
    }
};
