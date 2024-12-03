#pragma once

#include <vector>
#include <functional>
#include <iomgr/iomgr.hpp>
#include <folly/concurrency/ConcurrentHashMap.h>
#include <sisl/utility/enum.hpp>
#include <nuraft_mesg/mesg_state_mgr.hpp>
#include <homestore/replication/repl_decls.h>

#include "replication/repl_dev/common.h"

#if defined __clang__ or defined __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#endif
#include <libnuraft/nuraft.hxx>
#if defined __clang__ or defined __GNUC__
#pragma GCC diagnostic pop
#endif
#undef auto_lock

namespace homestore {
class ReplicaSetImpl;
class StateMachineStore;

#define RD_LOG(level, msg, ...)                                                                                        \
    LOG##level##MOD_FMT(replication, ([&](fmt::memory_buffer& buf, const char* msgcb, auto&&... args) -> bool {        \
                            fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[{}:{}] "},                          \
                                            fmt::make_format_args(file_name(__FILE__), __LINE__));                     \
                            fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[{}={}] "},                          \
                                            fmt::make_format_args("rd", rdev_name()));                                 \
                            fmt::vformat_to(fmt::appender{buf}, fmt::string_view{msgcb},                               \
                                            fmt::make_format_args(std::forward< decltype(args) >(args)...));           \
                            return true;                                                                               \
                        }),                                                                                            \
                        msg, ##__VA_ARGS__);

#define RD_ASSERT_CMP(assert_type, val1, cmp, val2, ...)                                                               \
    {                                                                                                                  \
        assert_type##_ASSERT_CMP(                                                                                      \
            val1, cmp, val2,                                                                                           \
            [&](fmt::memory_buffer& buf, const char* const msgcb, auto&&... args) -> bool {                            \
                fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[{}:{}] "},                                      \
                                fmt::make_format_args(file_name(__FILE__), __LINE__));                                 \
                sisl::logging::default_cmp_assert_formatter(buf, msgcb, std::forward< decltype(args) >(args)...);      \
                fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[{}={}] "},                                      \
                                fmt::make_format_args("rd", rdev_name()));                                             \
                return true;                                                                                           \
            },                                                                                                         \
            ##__VA_ARGS__);                                                                                            \
    }
#define RD_ASSERT(assert_type, cond, ...)                                                                              \
    {                                                                                                                  \
        assert_type##_ASSERT_FMT(cond,                                                                                 \
                                 ([&](fmt::memory_buffer& buf, const char* const msgcb, auto&&... args) -> bool {      \
                                     fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[{}={}] "},                 \
                                                     fmt::make_format_args("rd", rdev_name()));                        \
                                     fmt::vformat_to(fmt::appender{buf}, fmt::string_view{msgcb},                      \
                                                     fmt::make_format_args(std::forward< decltype(args) >(args)...));  \
                                     return true;                                                                      \
                                 }),                                                                                   \
                                 ##__VA_ARGS__);                                                                       \
    }

#define RD_DBG_ASSERT(cond, ...) RD_ASSERT(DEBUG, cond, ##__VA_ARGS__)
#define RD_DBG_ASSERT_EQ(val1, val2, ...) RD_ASSERT_CMP(DEBUG, val1, ==, val2, ##__VA_ARGS__)
#define RD_DBG_ASSERT_NE(val1, val2, ...) RD_ASSERT_CMP(DEBUG, val1, !=, val2, ##__VA_ARGS__)
#define RD_DBG_ASSERT_LT(val1, val2, ...) RD_ASSERT_CMP(DEBUG, val1, <, val2, ##__VA_ARGS__)
#define RD_DBG_ASSERT_LE(val1, val2, ...) RD_ASSERT_CMP(DEBUG, val1, <=, val2, ##__VA_ARGS__)
#define RD_DBG_ASSERT_GT(val1, val2, ...) RD_ASSERT_CMP(DEBUG, val1, >, val2, ##__VA_ARGS__)
#define RD_DBG_ASSERT_GE(val1, val2, ...) RD_ASSERT_CMP(DEBUG, val1, >=, val2, ##__VA_ARGS__)

#define RD_REL_ASSERT(cond, ...) RD_ASSERT(RELEASE, cond, ##__VA_ARGS__)
#define RD_REL_ASSERT_EQ(val1, val2, ...) RD_ASSERT_CMP(RELEASE, val1, ==, val2, ##__VA_ARGS__)
#define RD_REL_ASSERT_NE(val1, val2, ...) RD_ASSERT_CMP(RELEASE, val1, !=, val2, ##__VA_ARGS__)
#define RD_REL_ASSERT_LT(val1, val2, ...) RD_ASSERT_CMP(RELEASE, val1, <, val2, ##__VA_ARGS__)
#define RD_REL_ASSERT_LE(val1, val2, ...) RD_ASSERT_CMP(RELEASE, val1, <=, val2, ##__VA_ARGS__)
#define RD_REL_ASSERT_GT(val1, val2, ...) RD_ASSERT_CMP(RELEASE, val1, >, val2, ##__VA_ARGS__)
#define RD_REL_ASSERT_GE(val1, val2, ...) RD_ASSERT_CMP(RELEASE, val1, >=, val2, ##__VA_ARGS__)

#define RD_LOGT(...) RD_LOG(TRACE, ##__VA_ARGS__)
#define RD_LOGD(...) RD_LOG(DEBUG, ##__VA_ARGS__)
#define RD_LOGI(...) RD_LOG(INFO, ##__VA_ARGS__)
#define RD_LOGW(...) RD_LOG(WARN, ##__VA_ARGS__)
#define RD_LOGE(...) RD_LOG(ERROR, ##__VA_ARGS__)
#define RD_LOGC(...) RD_LOG(CRITICAL, ##__VA_ARGS__)

// For the logic snapshot obj_id, we use the highest bit to indicate the type of the snapshot message.
// 0 is for HS, 1 is for Application.
static constexpr uint64_t snp_obj_id_type_app = 1ULL << 63;

using AsyncNotify = folly::SemiFuture< folly::Unit >;
using AsyncNotifier = folly::Promise< folly::Unit >;

class RaftReplDev;
class RaftStateMachine : public nuraft::state_machine {
private:
    folly::ConcurrentHashMap< int64_t /*lsn*/, repl_req_ptr_t > m_lsn_req_map;
    RaftReplDev& m_rd;
    nuraft::ptr< nuraft::buffer > m_success_ptr; // Preallocate the success return to raft
    // iomgr::timer_handle_t m_wait_blkid_write_timer_hdl{iomgr::null_timer_handle};
    bool m_resync_mode{false};

public:
    RaftStateMachine(RaftReplDev& rd);
    ~RaftStateMachine() override = default;
    RaftStateMachine(RaftStateMachine const&) = delete;
    RaftStateMachine& operator=(RaftStateMachine const&) = delete;

    /// NuRaft overrides
    uint64_t last_commit_index() override;
    raft_buf_ptr_t pre_commit_ext(const nuraft::state_machine::ext_op_params& params) override;
    raft_buf_ptr_t commit_ext(const nuraft::state_machine::ext_op_params& params) override;
    void commit_config(const ulong log_idx, raft_cluster_config_ptr_t& new_conf) override;
    void rollback_config(const ulong log_idx, raft_cluster_config_ptr_t& conf) override;
    void rollback_ext(const nuraft::state_machine::ext_op_params& params) override;
    void become_ready();

    void create_snapshot(nuraft::snapshot& s, nuraft::async_result< bool >::handler_type& when_done) override;
    int read_logical_snp_obj(nuraft::snapshot& s, void*& user_ctx, ulong obj_id, raft_buf_ptr_t& data_out,
                             bool& is_last_obj) override;
    void save_logical_snp_obj(nuraft::snapshot& s, ulong& obj_id, nuraft::buffer& data, bool is_first_obj,
                              bool is_last_obj) override;
    bool apply_snapshot(nuraft::snapshot& s) override;
    nuraft::ptr< nuraft::snapshot > last_snapshot() override;
    void free_user_snp_ctx(void*& user_snp_ctx) override;

    ////////// APIs outside of nuraft::state_machine requirements ////////////////////
    ReplServiceError propose_to_raft(repl_req_ptr_t rreq);
    repl_req_ptr_t localize_journal_entry_prepare(nuraft::log_entry& lentry);
    repl_req_ptr_t localize_journal_entry_finish(nuraft::log_entry& lentry);
    void link_lsn_to_req(repl_req_ptr_t rreq, int64_t lsn);
    void unlink_lsn_to_req(int64_t lsn, repl_req_ptr_t rreq);
    repl_req_ptr_t lsn_to_req(int64_t lsn);
    nuraft_mesg::repl_service_ctx* group_msg_service();

    void iterate_repl_reqs(std::function< void(int64_t, repl_req_ptr_t rreq) > const& cb);

    std::string rdev_name() const;

    static bool is_hs_snp_obj(uint64_t obj_id) { return (obj_id & snp_obj_id_type_app) == 0; }

private:
    void after_precommit_in_leader(const nuraft::raft_server::req_ext_cb_params& params);
};

} // namespace homestore
