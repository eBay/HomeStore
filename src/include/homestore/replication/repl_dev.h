#pragma once

#include <variant>

#include <boost/intrusive_ptr.hpp>
#include <boost/smart_ptr/intrusive_ref_counter.hpp>
#include <flatbuffers/flatbuffers.h>
#include <folly/futures/Future.h>
#include <sisl/fds/buffer.hpp>
#include <sisl/grpc/generic_service.hpp>
#include <homestore/replication/repl_decls.h>

namespace nuraft {
template < typename T >
using ptr = std::shared_ptr< T >;

class buffer;
} // namespace nuraft

namespace homestore {
class ReplDev;
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

struct repl_journal_entry;
struct repl_req_ctx : public boost::intrusive_ref_counter< repl_req_ctx, boost::thread_safe_counter > {
    friend class SoloReplDev;

public:
    virtual ~repl_req_ctx();
    int64_t get_lsn() const { return lsn; }
    MultiBlkId const& get_local_blkid() const { return local_blkid; }

    uint64_t dsn() const { return rkey.dsn; }
    uint64_t term() const { return rkey.term; }
    void alloc_journal_entry(uint32_t size, bool is_raft_buf);
    raft_buf_ptr_t& raft_journal_buf();
    uint8_t* raw_journal_buf();

    std::string to_string() const;
    std::string to_compact_string() const;

public:
    repl_key rkey;           // Unique key for the request
    sisl::blob header;       // User header
    sisl::blob key;          // User supplied key for this req
    int64_t lsn{0};          // Lsn for this replication req
    bool is_proposer{false}; // Is the repl_req proposed by this node

    //////////////// Value related section /////////////////
    sisl::sg_list value;      // Raw value - applicable only to leader req
    MultiBlkId local_blkid;   // Local BlkId for the value
    RemoteBlkId remote_blkid; // Corresponding remote blkid for the value

    //////////////// Journal/Buf related section /////////////////
    std::variant< std::unique_ptr< uint8_t[] >, raft_buf_ptr_t > journal_buf; // Buf for the journal entry
    repl_journal_entry* journal_entry{nullptr};                               // pointer to the journal entry

    //////////////// Replication state related section /////////////////
    std::mutex state_mtx;
    std::atomic< uint32_t > state{uint32_cast(repl_req_state_t::INIT)}; // State of the replication request
    folly::Promise< folly::Unit > data_written_promise;                 // Promise to be fulfilled when data is written

    //////////////// Communication packet/builder section /////////////////
    sisl::io_blob_list_t pkts;
    flatbuffers::FlatBufferBuilder fb_builder;
    sisl::io_blob_safe buf_for_unaligned_data;
    intrusive< sisl::GenericRpcData > rpc_data;
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
    /// @return Expected to return blk_alloc_hints for this write
    virtual blk_alloc_hints get_blk_alloc_hints(sisl::blob const& header, uint32_t data_size) = 0;

    /// @brief Called when the replica set is being stopped
    virtual void on_replica_stop() = 0;

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
