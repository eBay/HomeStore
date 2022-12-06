
#if 0
1. repl store interface and init  2 week
2. state machine and state manager 3 weeks
3. logstore 2 weeks
4. recovery  2 weeks
5. Testing :- 4 weeks
6. integrating HS with replication
#endif

class ReplMgr {
    void start(); // it is sync call

    std::error_condition create_raft_group(std::string const& group_id,
                                           const std::vector< std::string >& peer_ids); // it is async call
    repl_req* add_new_member(std::string& to_dst_srv_id); // does AM pass the raft group name ??
};

// create raft group
// send/recv data over data channel
// precommit callback on client side
// commit callback on both sides
// resync data send/receive from the logstore
// resync data send/receive from the snapshots
// migrate volume

class ReplStorCallbacks {
    virtual void raft_group_created(std::string server_id, repl_store_ptr* ptr, bool is_msg_forward = false) = 0;

    virtual void write_data(repl_req* req, int64_t term, std::vector< iovec >& iov, void* ctx) = 0;
    virtual void data_mutation_happening(sisl::blob k, int64_t term) = 0;

    virtual bool read_data(repl_req* req, std::vector< iovec >& iov, void* ctx, sisl::blob k) = 0;
    virtual bool is_data_available(sisl::blob k, int64_t term) = 0;

    virtual void commit_data(void* ctx, int64_t seq_num, bool status) = 0;
    virtual void forward_rqst_completed(void* ctx, bool status) = 0;

    virtual sisl::blob get_logstore_transform_data(void* ctx) = 0;

    virtual void connection_broken(int64_t term) = 0;
    virtual void create_snapshot(snapshot& s, snapshot_create_cb& cb) = 0;
    virtual void delete_snapshot(snapshot& s, snapshot_delete_cb& cb) = 0;

    virtual void apply_snapshot(std::vector< iovec >& iov, sisl::blob k, snapshot& s, snapshot_apply_cb& cb);
    virtual void read_snapshot(snapshot& s, snapshot_read_cb& cb);

    virtual sisl::blob get_logstore_entry(void* ctx);
};

class repl_req {
public:
};

typedef data_read_cb(sisl::blob& b, bool end_of_batch = false);

class ReplStor_Interface {

public:
    // Send a client request to the cluster
    std::error_condition append_entry(sisl::blob& b);
    void data_pre_committed(repl_req* req, void* ctx);

    void write(const sisl::blob k, const std::vector< iovec >& buf, void* ctx, bool is_forward_primary);
    void on_write_data_completed(void* ctx, repl_req* req);

    void data_read(sisl::blob k, std::vector< iovec >& buf, void* ctx);
    void on_read_data_completed(void* ctx, repl_req* req);

    void get_data_from_journal(uint64_t from_lsn, uint64_t to_lsn, data_read_cb&);


private:
    repl_req* push_data(std::vector< iovec >& iov);
};

class repl_storage_logstore : nuraft_logstore {
public:
    /**
     * The first available slot of the store, starts with 1
     *
     * @return Last log index number + 1
     */
    virtual ulong next_slot() const = 0;

    /**
     * The start index of the log store, at the very beginning, it must be 1.
     * However, after some compact actions, this could be anything equal to or
     * greater than or equal to one
     */
    virtual ulong start_index() const = 0;

    /**
     * The last log entry in store.
     *
     * @return If no log entry exists: a dummy constant entry with
     *         value set to null and term set to zero.
     */
    virtual ptr< log_entry > last_entry() const = 0;

    /**
     * Append a log entry to store.
     *
     * @param entry Log entry
     * @return Log index number.
     */
    virtual ulong append(ptr< log_entry >& entry) = 0;

    /**
     * Overwrite a log entry at the given `index`.
     * This API should make sure that all log entries
     * after the given `index` should be truncated (if exist),
     * as a result of this function call.
     *
     * @param index Log index number to overwrite.
     * @param entry New log entry to overwrite.
     */
    virtual void write_at(ulong index, ptr< log_entry >& entry) = 0;

    /**
     * Invoked after a batch of logs is written as a part of
     * a single append_entries request.
     *
     * @param start The start log index number (inclusive)
     * @param cnt The number of log entries written.
     */
    virtual void end_of_append_batch(ulong start, ulong cnt) {}

    /**
     * Get log entries with index [start, end).
     *
     * Return nullptr to indicate error if any log entry within the requested range
     * could not be retrieved (e.g. due to external log truncation).
     *
     * @param start The start log index number (inclusive).
     * @param end The end log index number (exclusive).
     * @return The log entries between [start, end).
     */
    virtual ptr< std::vector< ptr< log_entry > > > log_entries(ulong start, ulong end) = 0;


    /**
     * Get the log entry at the specified log index number.
     *
     * @param index Should be equal to or greater than 1.
     * @return The log entry or null if index >= this->next_slot().
     */
    virtual ptr< log_entry > entry_at(ulong index) = 0;

    /**
     * Get the term for the log entry at the specified index.
     * Suggest to stop the system if the index >= this->next_slot()
     *
     * @param index Should be equal to or greater than 1.
     * @return The term for the specified log entry, or
     *         0 if index < this->start_index().
     */
    virtual ulong term_at(ulong index) = 0;

    /**
     * Pack the given number of log items starting from the given index.
     *
     * @param index The start log index number (inclusive).
     * @param cnt The number of logs to pack.
     * @return Packed (encoded) logs.
     */
    virtual ptr< buffer > pack(ulong index, int32 cnt) = 0;

    /**
     * Apply the log pack to current log store, starting from index.
     *
     * @param index The start log index number (inclusive).
     * @param Packed logs.
     */
    virtual void apply_pack(ulong index, buffer& pack) = 0;

    /**
     * Compact the log store by purging all log entries,
     * including the given log index number.
     *
     * If current maximum log index is smaller than given `last_log_index`,
     * set start log index to `last_log_index + 1`.
     *
     * @param last_log_index Log index number that will be purged up to (inclusive).
     * @return `true` on success.
     */
    virtual bool compact(ulong last_log_index) = 0;

    /**
     * Synchronously flush all log entries in this log store to the backing storage
     * so that all log entries are guaranteed to be durable upon process crash.
     *
     * @return `true` on success.
     */
    virtual bool flush() = 0;
};

class ReplState {
    virtual ptr< buffer > commit(const ulong log_idx, buffer& data) {}


    /**
     * (Optional)
     * Handler on the commit of a configuration change.
     *
     * @param log_idx Raft log number of the configuration change.
     * @param new_conf New cluster configuration.
     */
    virtual void commit_config(const ulong log_idx, ptr< cluster_config >& new_conf) {}

    /**
     * Pre-commit the given Raft log.
     *
     * Pre-commit is called after appending Raft log,
     * before getting acks from quorum nodes.
     * Users can ignore this function if not needed.
     *
     * Same as `commit()`, memory buffer is owned by caller.
     *
     * @param log_idx Raft log number to commit.
     * @param data Payload of the Raft log.
     * @return Result value of state machine.
     */
    virtual ptr< buffer > pre_commit(const ulong log_idx, buffer& data) { return nullptr; }

    /**
     * (Optional)
     * Extended version of `pre_commit`, for users want to keep
     * the data without any extra memory copy.
     */
    virtual ptr< buffer > pre_commit_ext(const ext_op_params& params) { // is it on the client side or server side
        return pre_commit(params.log_idx, *params.data);
    }

    /**
     * Rollback the state machine to given Raft log number.
     *
     * It will be called for uncommitted Raft logs only,
     * so that users can ignore this function if they don't
     * do anything on pre-commit.
     *
     * Same as `commit()`, memory buffer is owned by caller.
     *
     * @param log_idx Raft log number to commit.
     * @param data Payload of the Raft log.
     */
    virtual void rollback(const ulong log_idx, buffer& data) {}

    /**
     * Save the given snapshot object to local snapshot.
     * This API is for snapshot receiver (i.e., follower).
     *
     * This is an optional API for users who want to use logical
     * snapshot. Instead of splitting a snapshot into multiple
     * physical chunks, this API uses logical objects corresponding
     * to a unique object ID. Users are responsible for defining
     * what object is: it can be a key-value pair, a set of
     * key-value pairs, or whatever.
     *
     * Same as `commit()`, memory buffer is owned by caller.
     *
     * @param s Snapshot instance to save.
     * @param obj_id[in,out]
     *     Object ID.
     *     As a result of this API call, the next object ID
     *     that reciever wants to get should be set to
     *     this parameter.
     * @param data Payload of given object.
     * @param is_first_obj `true` if this is the first object.
     * @param is_last_obj `true` if this is the last object.
     */
    virtual void save_logical_snp_obj(snapshot& s, ulong& obj_id, buffer& data, bool is_first_obj, bool is_last_obj) {}

    /**
     * Apply received snapshot to state machine.
     *
     * @param s Snapshot instance to apply.
     * @returm `true` on success.
     */
    virtual bool apply_snapshot(snapshot& s) = 0;


    /**
     * Read the given snapshot object.
     * This API is for snapshot sender (i.e., leader).
     *
     * Same as above, this is an optional API for users who want to
     * use logical snapshot.
     *
     * @param s Snapshot instance to read.
     * @param[in,out] user_snp_ctx
     *     User-defined instance that needs to be passed through
     *     the entire snapshot read. It can be a pointer to
     *     state machine specific iterators, or whatever.
     *     On the first `read_logical_snp_obj` call, it will be
     *     set to `null`, and this API may return a new pointer if necessary.
     *     Returned pointer will be passed to next `read_logical_snp_obj`
     *     call.
     * @param obj_id Object ID to read.
     * @param[out] data Buffer where the read object will be stored.
     * @param[out] is_last_obj Set `true` if this is the last object.
     * @return Negative number if failed.
     */
    virtual int read_logical_snp_obj(snapshot& s, void*& user_snp_ctx, ulong obj_id, ptr< buffer >& data_out,
                                     bool& is_last_obj) {
        data_out = buffer::alloc(4); // A dummy buffer.
        is_last_obj = true;
        return 0;
    }

    /**
     * Free user-defined instance that is allocated by
     * `read_logical_snp_obj`.
     * This is an optional API for users who want to use logical snapshot.
     *
     * @param user_snp_ctx User-defined instance to free.
     */
    virtual void free_user_snp_ctx(void*& user_snp_ctx) {}

    /**
     * Get the latest snapshot instance.
     *
     * This API will be invoked at the initialization of Raft server,
     * so that the last last snapshot should be durable for server restart,
     * if you want to avoid unnecessary catch-up.
     *
     * @return Pointer to the latest snapshot.
     */
    virtual ptr< snapshot > last_snapshot() = 0;

    /**
     * Get the last committed Raft log number.
     *
     * This API will be invoked at the initialization of Raft server
     * to identify what the last committed point is, so that the last
     * committed index number should be durable for server restart,
     * if you want to avoid unnecessary catch-up.
     *
     * @return Last committed Raft log number.
     */
    virtual ulong last_commit_index() = 0;

    /**
     * Create a snapshot corresponding to the given info.
     *
     * @param s Snapshot info to create.
     * @param when_done Callback function that will be called after
     *                  snapshot creation is done.
     */
    virtual void create_snapshot(snapshot& s, async_result< bool >::handler_type& when_done) = 0;

    /**
     * Decide to create snapshot or not.
     * Once the pre-defined condition is satisfied, Raft core will invoke
     * this function to ask if it needs to create a new snapshot.
     * If user-defined state machine does not want to create snapshot
     * at this time, this function will return `false`.
     *
     * @return `true` if wants to create snapshot.
     *         `false` if does not want to create snapshot.
     */
    virtual bool chk_create_snapshot() { return true; }

    /**
     * Decide to transfer leadership.
     * Once the other conditions are met, Raft core will invoke
     * this function to ask if it is allowed to transfer the
     * leadership to other member.
     *
     * @return `true` if wants to transfer leadership.
     *         `false` if not.
     */
    virtual bool allow_leadership_transfer() { return true; }

    /**
     * Parameters for `adjust_commit_index` API.
     */
    struct adjust_commit_index_params {
        adjust_commit_index_params() : current_commit_index_(0), expected_commit_index_(0) {}

        /**
         * The current committed index.
         */
        uint64_t current_commit_index_;

        /**
         * The new target commit index determined by Raft.
         */
        uint64_t expected_commit_index_;

        /**
         * A map of <peer ID, peer's log index>, including the
         * leader and learners.
         */
        std::unordered_map< int, uint64_t > peer_index_map_;
    };

    /**
     * This function will be called when Raft succeeds in replicating logs
     * to an arbitrary follower and attempts to commit logs. Users can manually
     * adjust the commit index. The adjusted commit index should be equal to
     * or greater than the given `current_commit_index`. Otherwise, no log
     * will be committed.
     *
     * @param params Parameters.
     * @return Adjusted commit index.
     */
    virtual uint64_t adjust_commit_index(const adjust_commit_index_params& params) {
        return params.expected_commit_index_;
    }
};

class ReplStateMgr {
    /**
     * Load the last saved cluster config.
     * This function will be invoked on initialization of
     * Raft server.
     *
     * Even at the very first initialization, it should
     * return proper initial cluster config, not `nullptr`.
     * The initial cluster config must include the server itself.
     *
     * @return Cluster config.
     */
    virtual ptr< cluster_config > load_config() = 0;

    /**
     * Save given cluster config.
     *
     * @param config Cluster config to save.
     */
    virtual void save_config(const cluster_config& config) = 0;

    /**
     * Save given server state.
     *
     * @param state Server state to save.
     */
    virtual void save_state(const srv_state& state) = 0;

    /**
     * Load the last saved server state.
     * This function will be invoked on initialization of
     * Raft server
     *
     * At the very first initialization, it should return
     * `nullptr`.
     *
     * @param Server state.
     */
    virtual ptr< srv_state > read_state() = 0;

    /**
     * Get instance of user-defined Raft log store.
     *
     * @param Raft log store instance.
     */
    virtual ptr< log_store > load_log_store() = 0;

    /**
     * Get ID of this Raft server.
     *
     * @return Server ID.
     */
    virtual int32 server_id() = 0;

    /**
     * System exit handler. This function will be invoked on
     * abnormal termination of Raft server.
     *
     * @param exit_code Error code.
     */
    virtual void system_exit(const int exit_code) = 0;
};
