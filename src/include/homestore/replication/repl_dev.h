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
} // namespace nuraft

namespace homestore {
class ReplDev;
class ReplDevListener;
struct repl_req_ctx;
using raft_buf_ptr_t = nuraft::ptr< nuraft::buffer >;
using repl_req_ptr_t = boost::intrusive_ptr< repl_req_ctx >;

VENUM(repl_req_state_t, uint32_t,
      INIT = 0,               // Initial state
      BLK_ALLOCATED = 1 << 0, // Local block is allocated
      DATA_RECEIVED = 1 << 1, // Data has been received and being written to the storage
      DATA_WRITTEN = 1 << 2,  // Data has been written to the storage
      LOG_RECEIVED = 1 << 3,  // Log is received and waiting for data
      LOG_FLUSHED = 1 << 4,   // Log has been flushed
      ERRORED = 1 << 5        // Error has happened and cleaned up
)

VENUM(journal_type_t, uint16_t,
      HS_DATA_LINKED = 0,  // Linked data where each entry will store physical blkid where data reside
      HS_DATA_INLINED = 1, // Data is inlined in the header of journal entry
      HS_CTRL_DESTROY = 2  // Control message to destroy the repl_dev
)

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
    std::string to_string() const { return fmt::format("server={}, term={}, dsn={}", server_id, term, dsn); }
};

struct repl_snapshot {
    uint64_t last_log_idx_{0};
    uint64_t last_log_term_{0};
};

struct repl_journal_entry;
struct repl_req_ctx : public boost::intrusive_ref_counter< repl_req_ctx, boost::thread_safe_counter > {
    friend class SoloReplDev;

public:
    repl_req_ctx() { m_start_time = Clock::now(); }
    virtual ~repl_req_ctx();
    void init(repl_key rkey, journal_type_t op_code, bool is_proposer, sisl::blob const& user_header,
              sisl::blob const& key, uint32_t data_size);

    /////////////////////// All getters ///////////////////////
    repl_key const& rkey() const { return m_rkey; }
    uint64_t dsn() const { return m_rkey.dsn; }
    uint64_t term() const { return m_rkey.term; }
    int64_t lsn() const { return m_lsn; }
    bool is_proposer() const { return m_is_proposer; }
    journal_type_t op_code() const { return m_op_code; }

    sisl::blob const& header() const { return m_header; }
    sisl::blob const& key() const { return m_key; }
    MultiBlkId const& local_blkid() const { return m_local_blkid; }
    RemoteBlkId const& remote_blkid() const { return m_remote_blkid; }
    const char* data() const { return r_cast< const char* >(m_data); }
    repl_req_state_t state() const { return repl_req_state_t(m_state.load()); }
    bool has_state(repl_req_state_t s) const { return m_state.load() & uint32_cast(s); }
    repl_journal_entry const* journal_entry() const { return m_journal_entry; }
    uint32_t journal_entry_size() const;
    bool is_localize_pending() const { return m_is_jentry_localize_pending; }
    bool is_data_inlined() const { return (m_op_code == journal_type_t::HS_DATA_INLINED); }
    bool has_linked_data() const { return (m_op_code == journal_type_t::HS_DATA_LINKED); }

    raft_buf_ptr_t& raft_journal_buf();
    uint8_t* raw_journal_buf();
    flatbuffers::FlatBufferBuilder& create_fb_builder() { return m_fb_builder; }
    void release_fb_builder() { m_fb_builder.Release(); }

    /////////////////////// Non modifiers methods //////////////////
    std::string to_string() const;
    std::string to_compact_string() const;
    Clock::time_point created_time() const { return m_start_time; }

    /////////////////////// All Modifiers methods //////////////////
    ReplServiceError alloc_local_blks(cshared< ReplDevListener >& listener, uint32_t data_size);
    void create_journal_entry(bool is_raft_buf, int32_t server_id);
    void change_raft_journal_buf(raft_buf_ptr_t new_buf, bool adjust_hdr_key);
    void set_remote_blkid(RemoteBlkId const& rbid) { m_remote_blkid = rbid; }
    void set_lsn(int64_t lsn);
    bool save_pushed_data(intrusive< sisl::GenericRpcData > const& pushed_data, uint8_t const* data,
                          uint32_t data_size);
    bool save_fetched_data(sisl::GenericClientResponse const& fetched_data, uint8_t const* data, uint32_t data_size);
    void add_state(repl_req_state_t s);
    bool add_state_if_not_already(repl_req_state_t s);
    void clear();

public:
    // We keep this public since they are considered thread safe
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

    /////////////// Data related section /////////////////
    MultiBlkId m_local_blkid;   // Local BlkId for the data
    RemoteBlkId m_remote_blkid; // Corresponding remote blkid for the data
    uint8_t const* m_data;      // Raw data pointer containing the actual data

    /////////////// Journal/Buf related section /////////////////
    std::variant< std::unique_ptr< uint8_t[] >, raft_buf_ptr_t > m_journal_buf; // Buf for the journal entry
    repl_journal_entry* m_journal_entry{nullptr};                               // pointer to the journal entry
    bool m_is_jentry_localize_pending{false}; // Is the journal entry needs to be localized from remote

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
    virtual void on_destroy() = 0;

    /// @brief Called when the snapshot is being created by nuraft;
    virtual AsyncReplResult<> create_snapshot(repl_snapshot& s) = 0;

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
    virtual void async_free_blks(int64_t lsn, MultiBlkId const& blkid) = 0;

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

    virtual void attach_listener(shared< ReplDevListener > listener) { m_listener = std::move(listener); }

    virtual void detach_listener() {
        if (m_listener) {
            m_listener->set_repl_dev(nullptr);
            m_listener.reset();
        }
    }

protected:
    shared< ReplDevListener > m_listener;
};

} // namespace homestore

template <>
struct fmt::formatter< homestore::repl_key > : fmt::formatter< std::string > {
    auto format(const homestore::repl_key& a, format_context& ctx) const {
        return fmt::formatter< std::string >::format(a.to_string(), ctx);
    }
};
