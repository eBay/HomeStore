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

using AsyncNotify = folly::SemiFuture< folly::Unit >;
using AsyncNotifier = folly::Promise< folly::Unit >;

class RaftReplDev;
class RaftStateMachine : public nuraft::state_machine {
private:
    folly::ConcurrentHashMap< int64_t, repl_req_ptr_t > m_lsn_req_map;
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
    void rollback(uint64_t lsn, nuraft::buffer&) override { LOGCRITICAL("Unimplemented rollback on: [{}]", lsn); }

    bool apply_snapshot(nuraft::snapshot&) override { return false; }
    void create_snapshot(nuraft::snapshot& s, nuraft::async_result< bool >::handler_type& when_done) override;
    nuraft::ptr< nuraft::snapshot > last_snapshot() override { return nullptr; }

    ////////// APIs outside of nuraft::state_machine requirements ////////////////////
    ReplServiceError propose_to_raft(repl_req_ptr_t rreq);
    repl_req_ptr_t localize_journal_entry_prepare(nuraft::log_entry& lentry);
    repl_req_ptr_t localize_journal_entry_finish(nuraft::log_entry& lentry);
    void link_lsn_to_req(repl_req_ptr_t rreq, int64_t lsn);
    repl_req_ptr_t lsn_to_req(int64_t lsn);
    nuraft_mesg::repl_service_ctx* group_msg_service();

    std::string rdev_name() const;

private:
    void after_precommit_in_leader(const nuraft::raft_server::req_ext_cb_params& params);
};

} // namespace homestore
