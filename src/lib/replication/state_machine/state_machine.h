#pragma once

#include <vector>
#include <functional>
#include <iomgr/iomgr.hpp>
#include <folly/concurrency/ConcurrentHashMap.h>
#include <sisl/utility/enum.hpp>
#include <home_replication/repl_decls.h>

#if defined __clang__ or defined __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#endif
#include <libnuraft/nuraft.hxx>
#if defined __clang__ or defined __GNUC__
#pragma GCC diagnostic pop
#endif
#undef auto_lock

namespace home_replication {
class ReplicaSet;
class StateMachineStore;

#define RS_LOG(level, msg, ...)                                                                                        \
    LOG##level##MOD_FMT(home_replication, ([&](fmt::memory_buffer& buf, const char* msgcb, auto&&... args) -> bool {   \
                            fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[{}:{}] "},                          \
                                            fmt::make_format_args(file_name(__FILE__), __LINE__));                     \
                            fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[{}={}] "},                          \
                                            fmt::make_format_args("rs", m_group_id));                                  \
                            fmt::vformat_to(fmt::appender{buf}, fmt::string_view{msgcb},                               \
                                            fmt::make_format_args(std::forward< decltype(args) >(args)...));           \
                            return true;                                                                               \
                        }),                                                                                            \
                        msg, ##__VA_ARGS__);

#define RS_ASSERT_CMP(assert_type, val1, cmp, val2, ...)                                                               \
    {                                                                                                                  \
        assert_type##_ASSERT_CMP(                                                                                      \
            val1, cmp, val2,                                                                                           \
            [&](fmt::memory_buffer& buf, const char* const msgcb, auto&&... args) -> bool {                            \
                fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[{}:{}] "},                                      \
                                fmt::make_format_args(file_name(__FILE__), __LINE__));                                 \
                sisl::logging::default_cmp_assert_formatter(buf, msgcb, std::forward< decltype(args) >(args)...);      \
                fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[{}={}] "},                                      \
                                fmt::make_format_args("rs", m_group_id));                                              \
                return true;                                                                                           \
            },                                                                                                         \
            ##__VA_ARGS__);                                                                                            \
    }
#define RS_ASSERT(assert_type, cond, ...)                                                                              \
    {                                                                                                                  \
        assert_type##_ASSERT_FMT(cond,                                                                                 \
                                 ([&](fmt::memory_buffer& buf, const char* const msgcb, auto&&... args) -> bool {      \
                                     fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[{}={}] "},                 \
                                                     fmt::make_format_args("rs", m_group_id));                         \
                                     fmt::vformat_to(fmt::appender{buf}, fmt::string_view{msgcb},                      \
                                                     fmt::make_format_args(std::forward< decltype(args) >(args)...));  \
                                     return true;                                                                      \
                                 }),                                                                                   \
                                 ##__VA_ARGS__);                                                                       \
    }

#define RS_DBG_ASSERT(cond, ...) RS_ASSERT(DEBUG, cond, ##__VA_ARGS__)
#define RS_DBG_ASSERT_EQ(val1, val2, ...) RS_ASSERT_CMP(DEBUG, val1, ==, val2, ##__VA_ARGS__)
#define RS_DBG_ASSERT_NE(val1, val2, ...) RS_ASSERT_CMP(DEBUG, val1, !=, val2, ##__VA_ARGS__)
#define RS_DBG_ASSERT_LT(val1, val2, ...) RS_ASSERT_CMP(DEBUG, val1, <, val2, ##__VA_ARGS__)
#define RS_DBG_ASSERT_LE(val1, val2, ...) RS_ASSERT_CMP(DEBUG, val1, <=, val2, ##__VA_ARGS__)
#define RS_DBG_ASSERT_GT(val1, val2, ...) RS_ASSERT_CMP(DEBUG, val1, >, val2, ##__VA_ARGS__)
#define RS_DBG_ASSERT_GE(val1, val2, ...) RS_ASSERT_CMP(DEBUG, val1, >=, val2, ##__VA_ARGS__)

#define RS_REL_ASSERT(cond, ...) RS_ASSERT(RELEASE, cond, ##__VA_ARGS__)
#define RS_REL_ASSERT_EQ(val1, val2, ...) RS_ASSERT_CMP(RELEASE, val1, ==, val2, ##__VA_ARGS__)
#define RS_REL_ASSERT_NE(val1, val2, ...) RS_ASSERT_CMP(RELEASE, val1, !=, val2, ##__VA_ARGS__)
#define RS_REL_ASSERT_LT(val1, val2, ...) RS_ASSERT_CMP(RELEASE, val1, <, val2, ##__VA_ARGS__)
#define RS_REL_ASSERT_LE(val1, val2, ...) RS_ASSERT_CMP(RELEASE, val1, <=, val2, ##__VA_ARGS__)
#define RS_REL_ASSERT_GT(val1, val2, ...) RS_ASSERT_CMP(RELEASE, val1, >, val2, ##__VA_ARGS__)
#define RS_REL_ASSERT_GE(val1, val2, ...) RS_ASSERT_CMP(RELEASE, val1, >=, val2, ##__VA_ARGS__)

struct repl_req;
using raft_buf_ptr_t = nuraft::ptr< nuraft::buffer >;

ENUM(pba_state_t, uint32_t, unknown, allocated, written, completed);

using batch_completion_cb_t = std::function< void(void) >;

struct pba_waiter {
    pba_waiter(batch_completion_cb_t&& cb) : m_cb{std::move(cb)} {}
    ~pba_waiter() { m_cb(); }
    batch_completion_cb_t m_cb;
};

using pba_waiter_ptr = std::shared_ptr< pba_waiter >;

//
// Requirements:
// 0. waiter can only be called after all the pbas are completed on write;
// 1. Same waiter can wait on multiple pbas,
// 2. A pba can't be waited on multiple waiters (no waiter or one waiter);
// 3. On each pba completion (state change to "pba_state_t::cmopleted"), it deref
// waiter by 1 (if there is a waiter) by removing the waiter; and the waiter's cb will be called when the last pba
// finishes its write
// 4. Waiter can be nullptr, meaning no waiter is waiting on this pba to complete its write;
//
// async_fetch_write_pbas:
// 1. if all fq_pbas are found in map (most common cases for non-resync-mode), apply waiter to all the local pbas whose
// state is not completed, if all states are completed, return false (false means no-wait, no need to trigger callback),
// otherwise just return true (means caller needs to wait), callback will be triggered after last pba is completed;
// 2. if none (resync-mode) or part of fq_pbas can be found, wait for certain mount (MAP_PBA_WAITER_TIMER) of time to
// see if all of the pbas can be found in map,
//     2.a if yes, go to step 1;
//     2.b if no, apply waiters to those pbas that are not completed yet, and mark those fq_pbas that are not found in
//     map, trigger fetch pba from remote (by calling try_map_pba, which will create entry in map with local_pba),
//          2.b.1 if it returns true, meaning fq_pba is found (data channel received this fq_pba after
//          MAP_PBA_WAITER_TIMER), apply waiter to it;
//          2.b.2 if it returns false, the local pba is newly allocated, we should call new api
//          "fetch_pba_data_from_leader" (TODO) to fill this data to this local_pba and apply waiter on it;
//          - In phase 1 we can do it in current thread;
//          - In phase 2 we might need to move it to a dedicated thread (or pool of threads) to fetch data from remote;
//                       use boost::intrusive_ptr;
//
// 3. at this point, local_pba for every fq_pba is created in the map, and callback should be called already or after
// last pba write is completd;
//
// Assumption for try_map_pba and update_map_pba:
// 0. two callers will call try_map_pba
//    - async_fetch_write_pbas
//    - data channel on data received api;
// 1. the caller who got return value as false in std::pair should take the responsibility to call update_map_pba;
// 2. caller who got return true in std::pair of try_map_pba should not call update_map_pba;
//
// try_map_pba:
// 1. if fq_pba is found, return local_pba and true in std::pair;
// 2. if fq_pba is not found, allocate local pbas and return to caller with false in std::pair, meaning data is not
// filled yet, it is caller's responsibility to fill the data (via "fetch_pba_data_from_leader");
//
// Corner case:
// If data channel comes in to fill this fq_pba at this point (try_map_pba returned false - not found to caller), we can
// choose to either:
// 1. skip write and just return success or
// 2. go ahead to fill the data on existing local_lba that was already there this operation is idomponent
// even though data is already started to fetch from leader;
//
// update_map_pba:
// 1. will update from allocated to written state when write is sent;
// 2. will update frmo written to completed state when write is completed;
//
// remove_map_pba:
// 1. when commit is about to finish, it should remove the fq_pba from the map via this api;
//

// if ref_cnt drops to zero, remove this waiter;
// The last one who remove the waiter will trigger callback to caller, because same waiter can be associated with
// multiple fq_pbas (hence wait on multiple sets of local pbas;);
struct local_pba_info {
    local_pba_info(const pba_list_t& l, pba_state_t s, const pba_waiter_ptr w) :
            m_pbas{std::move(l)}, m_state{s}, m_waiter{w} {}

    pba_list_t m_pbas;       // a remote pba can map to multiple local pbas
    pba_state_t m_state;     // state applies to all of the local pbas
    pba_waiter_ptr m_waiter; // only one waiter can wait on same pba;
};

using local_pba_info_ptr = std::shared_ptr< local_pba_info >;

class ReplicaStateMachine : public nuraft::state_machine {
public:
    ReplicaStateMachine(const std::shared_ptr< StateMachineStore >& state_store, ReplicaSet* rs);
    ~ReplicaStateMachine() override = default;
    ReplicaStateMachine(ReplicaStateMachine const&) = delete;
    ReplicaStateMachine& operator=(ReplicaStateMachine const&) = delete;

    /// NuRaft overrides
    uint64_t last_commit_index() override;
    raft_buf_ptr_t pre_commit_ext(const nuraft::state_machine::ext_op_params& params) override;
    raft_buf_ptr_t commit_ext(const nuraft::state_machine::ext_op_params& params) override;
    void rollback(uint64_t lsn, nuraft::buffer&) override { LOGCRITICAL("Unimplemented rollback on: [{}]", lsn); }

    bool apply_snapshot(nuraft::snapshot&) override { return false; }
    void create_snapshot(nuraft::snapshot& s, nuraft::async_result< bool >::handler_type& when_done) override;
    nuraft::ptr< nuraft::snapshot > last_snapshot() override { return nullptr; }

    ////////// APIs outside of nuraft::state_machine requirements ////////////////////
    void propose(const sisl::blob& header, const sisl::blob& key, const sisl::sg_list& value, void* user_ctx);

    repl_req* transform_journal_entry(const raft_buf_ptr_t& raft_buf);

    ///
    /// @brief : Map the fully qualified pba (possibly remote pba) and get the local pba if available. If its not
    /// available it will allocate a local pba and create a map entry for remote_pba to local_pba and its associated
    /// repl_req instance. The local_pba will be immediately returned.
    ///
    /// @param fq_pba:  Fully qualified pba to be fetched and mapped to local pba_t
    /// @return : Returns the state of the local_pba.
    ///
    std::pair< pba_list_t, pba_state_t > try_map_pba(const fully_qualified_pba& fq_pba);

    ///
    /// @brief : update a fq_pba's state to the state specified by this API;
    ///
    /// @param pba : The fq_pba that this api wants to update its state
    /// @param to_state : The state that will be updated to
    ///
    /// @return : current state before this api is called;
    ///
    pba_state_t update_map_pba(const fully_qualified_pba& pba, const pba_state_t& to_state);

    ///
    /// @brief : remove fq_pba entry from map
    ///
    /// @param pba : pba that is going to be removed;
    ///
    /// @return: number of elements removed;
    ///
    std::size_t remove_map_pba(const fully_qualified_pba& pba);

    ///
    /// @brief : First try to map the pbas if available. If not available in local map, wait for some time (based on if
    /// it is in resync mode or not) and then reach out to remote replica and fetch the actual data, write to the local
    /// storage engine and update the map. It then calls callback after all pbas in the list are fetched.
    ///
    /// @param fq_pbas : Vector of fq_pbas that needs to mapped
    /// @param cb : completion callback called after all pbas are fetched if that is needed.
    /// @return : Returns if all fq_pbas have their corresponding map is readily available.
    /// if return false /* no need to wait */, no cb will be triggered;
    /// if return true /* need to wait */ , cb will be triggered after all local pbas completed writting;
    ///
    bool async_fetch_write_pbas(const std::vector< fully_qualified_pba >& fq_pbas, batch_completion_cb_t cb);

    ///
    /// @brief : check the input fq_pba_list that if anyone is still not completed its write.
    /// if yes, save all of the fq_pbas that in not-completed state to a list and fetch them from remote leader;
    /// if no, nothing needs to be done, it means data channel arrived and completed writing data before wait-timer
    /// timeout;
    ///
    /// @param fq_pba_list : the input fq pba list that needs to be checked for completion;
    ///
    void check_and_fetch_remote_pbas(std::vector< fully_qualified_pba > fq_pba_list);

    ///
    /// @brief : fetch data specified by the fq_pba_list from remote leader;
    ///
    /// @param fq_pba_list : the fq_pba list that should be fetched from remote leader;
    ///
    void fetch_pba_data_from_leader(std::unique_ptr< std::vector< fully_qualified_pba > > fq_pba_list);

    void stop_write_wait_timer();

    void link_lsn_to_req(repl_req* req, int64_t lsn);
    repl_req* lsn_to_req(int64_t lsn);

private:
    void after_precommit_in_leader(const nuraft::raft_server::req_ext_cb_params& params);
    void check_and_commit(repl_req* req);

private:
    std::shared_ptr< StateMachineStore > m_state_store;
    folly::ConcurrentHashMap< std::string, local_pba_info_ptr > m_pba_map; // fully_qualified_pba to local pba mapping;
    folly::ConcurrentHashMap< int64_t, repl_req* > m_lsn_req_map;
    ReplicaSet* m_rs;
    std::string m_group_id;
    uint32_t m_server_id;                        // TODO: Populate the value from replica set/RAFT
    nuraft::ptr< nuraft::buffer > m_success_ptr; // Preallocate the success return to raft
    iomgr::timer_handle_t m_wait_pba_write_timer_hdl{iomgr::null_timer_handle};
    bool resync_mode{false};
};

} // namespace home_replication
