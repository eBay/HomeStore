#pragma once
#include <functional>
#include <memory>
#include <string>
#include <variant>

#include <sisl/utility/enum.hpp>
#include <homestore/replication/repl_decls.h>
#include <homestore/meta_service.hpp>

namespace homestore {

class ReplDev;
class ReplDevListener;
struct hs_stats;

VENUM(repl_impl_type, uint8_t,
      server_side,     // Completely homestore controlled replication
      client_assisted, // Client assisting in replication
      solo             // For single node - no replication
);

class ReplApplication;

class ReplicationService {
public:
    ReplicationService() = default;
    virtual ~ReplicationService() = default;

    /// @brief Creates the Repl Device to which eventually user can read locally and write to the quorom of the members
    /// @param group_id Unique ID indicating the group. This is the key for several lookup structures
    /// @param members List of members to form this group
    /// @param listener state machine listener of all the events happening on the repl_dev (commit, precommit etc)
    /// @return A Future ReplDev on success or Future ReplServiceError upon error
    virtual AsyncReplResult< shared< ReplDev > > create_repl_dev(group_id_t group_id,
                                                                 std::set< replica_id_t > const& members) = 0;

    /// @brief Removes the entire Repl Device. The underlying replica group is marked as destroy_pending and all its
    /// resources are not released until garbage collection of repl devices kick in.
    /// @param group_id Group ID to be removed
    /// @return A Future which gets called after schedule to release (before garbage collection is kicked in)
    virtual folly::SemiFuture< ReplServiceError > remove_repl_dev(group_id_t group_id) = 0;

    /// @brief Replace one of the members with a new one.
    /// @param group_id Group where the replace member happens
    /// @param task_id Id of the task which is going to be used for this operation. This is used to track the replace
    /// member.
    /// @param member_out The member which is going to be replaced
    /// @param member_in The member which is going to be added in place of member_out
    /// @param commit_quorum Commit quorum to be used for this operation. If 0, it will use the default commit quorum.
    /// @return A Future on replace the member accepted or Future ReplServiceError upon error
    virtual AsyncReplResult<> replace_member(group_id_t group_id, std::string& task_id,
                                             const replica_member_info& member_out,
                                             const replica_member_info& member_in, uint32_t commit_quorum = 0,
                                             uint64_t trace_id = 0) const = 0;

    /// @brief Flips the learner flag for a specific replica member in the group.
    /// @param group_id The ID of the replica group.
    /// @param member The replica whose learner flag is to be changed.
    /// @param target The target value for the learner flag (true to set as learner, false otherwise).
    /// @param commit_quorum The commit quorum required for this operation.
    /// @param wait_and_verify Whether to wait and verify the operation (default: true).
    /// @param trace_id Optional trace ID for tracking (default: 0).
    /// @return A future result indicating success or error.
    virtual AsyncReplResult<> flip_learner_flag(group_id_t group_id, const replica_member_info& member, bool target,
                                                uint32_t commit_quorum, bool wait_and_verify = true,
                                                uint64_t trace_id = 0) const = 0;

    /// @brief Remove th specific replica member from the group.
    /// @param group_id The ID of the replica group.
    /// @param member The replica id to be removed.
    /// @param commit_quorum The commit quorum required for this operation.
    /// @param wait_and_verify Whether to wait and verify the operation (default: true).
    /// @param trace_id Optional trace ID for tracking (default: 0).
    /// @return A future result indicating success or error.
    virtual AsyncReplResult<> remove_member(group_id_t group_id, const replica_id_t& member, uint32_t commit_quorum,
                                            bool wait_and_verify = true, uint64_t trace_id = 0) const = 0;

    /// @brief Clean the replace member task.
    /// @param group_id The ID of the replica group.
    /// @param task_id The task to be cleaned.
    /// @param commit_quorum The commit quorum required for this operation.
    /// @param trace_id Optional trace ID for tracking (default: 0).
    /// @return A future result indicating success or error.
    virtual AsyncReplResult<> clean_replace_member_task(group_id_t group_id, const std::string& task_id,
                                                        uint32_t commit_quorum, uint64_t trace_id = 0) const = 0;

    /// @brief Lists all replace member tasks.
    /// @param trace_id Optional trace ID for tracking (default: 0).
    /// @return A result containing a vector of replace_member_task objects.
    virtual ReplResult< std::vector< replace_member_task > > list_replace_member_tasks(uint64_t trace_id = 0) const = 0;

    /// @brief Get status of member replacement.
    /// @param group_id Group where the replace member happens
    /// @param task_id Id of the replace member task. This is used to track the replace
    /// @param member_out The member which is going to be replaced
    /// @param member_in The member which is going to be added in place of member_out
    /// @param others Other members excluding member_out, member_in
    /// @return ReplaceMemberStatus
    virtual ReplaceMemberStatus get_replace_member_status(group_id_t group_id, std::string& task_id,
                                                          const replica_member_info& member_out,
                                                          const replica_member_info& member_in,
                                                          const std::vector< replica_member_info >& others,
                                                          uint64_t trace_id = 0) const = 0;

    /// @brief Get the repl dev for a given group id if it is already created or opened
    /// @param group_id Group id interested in
    /// @return ReplDev is opened or ReplServiceError::SERVER_NOT_FOUND if it doesn't exist
    virtual ReplResult< shared< ReplDev > > get_repl_dev(group_id_t group_id) const = 0;

    /// @brief Iterate over all repl devs and then call the callback provided
    /// @param cb Callback with repl dev
    virtual void iterate_repl_devs(std::function< void(cshared< ReplDev >&) > const& cb) = 0;

    /// @brief get the capacity stats form underlying backend;
    /// @return the capacity stats;
    virtual hs_stats get_cap_stats() const = 0;

    virtual meta_sub_type get_meta_blk_name() const = 0;
};

//////////////// Application which uses Replication needs to be provide the following callbacks ////////////////
class ReplApplication {
public:
    // Returns the required implementation type of replication
    virtual repl_impl_type get_impl_type() const = 0;

    // Is the replica recovery needs timeline consistency. This is used to determine if the replica needs to be
    // recovered by key or by block of data. At present only non-timeline consistent replication is supported.
    virtual bool need_timeline_consistency() const = 0;

    // Called when the repl dev is found upon restart of the homestore instance. The caller should return an instance of
    // Listener corresponding to the ReplDev which will be used to perform the precommit/commit/rollback.
    virtual shared< ReplDevListener > create_repl_dev_listener(group_id_t group_id) = 0;

    // Called when the repl dev is destroyed. This interface provides the application a chance to cleanup any resources
    // assocated with this listener;
    virtual void destroy_repl_dev_listener(group_id_t group_id) = 0;

    // Called after all the repl devs are found upon restart of the homestore instance.
    // it is a nice place for upper layer to recovery anything depends on repl_devs
    virtual void on_repl_devs_init_completed() = 0;

    // Given the uuid of the peer, get their address and port
    virtual std::pair< std::string, uint16_t > lookup_peer(replica_id_t uuid) const = 0;

    // Get the current application/server repl uuid
    virtual replica_id_t get_my_repl_id() const = 0;

    // Get the current replication service port
    virtual uint32_t get_my_repl_svc_port() const = 0;
};

} // namespace homestore
