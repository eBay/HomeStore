/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *    https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 *********************************************************************************/
#pragma once
#include <atomic>
#include <array>
#include <mutex>
#include <memory>
#include <functional>

#include <iomgr/iomgr.hpp>
#include <sisl/metrics/metrics.hpp>
#include <sisl/utility/enum.hpp>

#include <homestore/superblk_handler.hpp>
#include <homestore/checkpoint/cp.hpp>

namespace homestore {
static constexpr size_t MAX_CP_COUNT{2};

class CPMgrMetrics : public sisl::MetricsGroup {
public:
    explicit CPMgrMetrics() : sisl::MetricsGroup("CPMgr") {
        REGISTER_COUNTER(back_to_back_cps, "back to back cp");
        REGISTER_COUNTER(cp_cnt, "cp cnt");
        REGISTER_HISTOGRAM(cp_latency, "cp latency (in us)");
        register_me_to_farm();
    }

    CPMgrMetrics(const CPMgrMetrics&) = delete;
    CPMgrMetrics(CPMgrMetrics&&) noexcept = delete;
    CPMgrMetrics& operator=(const CPMgrMetrics&) = delete;
    CPMgrMetrics& operator=(const CPMgrMetrics&&) noexcept = delete;
    ~CPMgrMetrics() { deregister_me_from_farm(); }
};

class CPContext {
protected:
    CP* m_cp;
    folly::Promise< bool > m_flush_comp;

public:
    CPContext(CP* cp) : m_cp{cp} {}
    CP* cp() { return m_cp; }
    cp_id_t id() const;
    void complete(bool status) { m_flush_comp.setValue(status); }
#ifdef _PRERELEASE
    void abrupt() {
        m_cp->m_abrupt_cp.store(true);
        complete(true);
    }
    bool is_abrupt() {
        return m_cp->m_abrupt_cp.load();
    }
#endif
    folly::Future< bool > get_future() { return m_flush_comp.getFuture(); }

    virtual ~CPContext() = default;
};

class CPCallbacks {
public:
    virtual ~CPCallbacks() = default;

    /// @brief CPManager calls this method when a new CP is triggered and it is time to switchover the dirty buffer
    /// collection to the new CP and flush the existing CP.
    /// @param cur_cp Pointer to the current CP session which about to be switchedover
    /// @param new_cp Pointer to the new CP session which will be switched over to
    /// @return Returns the CPContext it has gathered so far as part of current cp session.
    virtual std::unique_ptr< CPContext > on_switchover_cp(CP* cur_cp, CP* new_cp) = 0;

    /// @brief After gathering CPContext from all consumers, CPManager calls this method to flush the dirty buffers
    /// accumulated in this CP. Once CP flush is completed, consumers are required to set the promise corresponding to
    /// returned future.
    /// @param cp CP pointer to which the dirty buffers have to be flushed
    /// @param done_cb Callback after cp is done
    virtual folly::Future< bool > cp_flush(CP* cp) = 0;

    /// @brief After all consumers flushed the CP, CPManager calls this method to clean up any CP related structures
    /// @param cp
    virtual void cp_cleanup(CP* cp) = 0;

    /// @brief While CP is progressing, CPManager calls this method frequently to check its flush progress.
    /// @return Returns the progress percentage of flush.
    virtual int cp_progress_percent() = 0;

    /// @brief In case CP is not progressing at all, CPManager calls this method to attempt the consumer to push harder
    /// to flush. Consumers are expected to increase any flow control to ensure flush goes faster.
    virtual void repair_slow_cp() {}
};

class CPWatchdog;

static constexpr uint64_t cp_sb_magic{0xc0c0c01a};
static constexpr uint32_t cp_sb_version{0x1};

#pragma pack(1)
struct cp_mgr_super_block {
    uint64_t magic{cp_sb_magic};
    uint32_t version{cp_sb_version};
    cp_id_t m_last_flushed_cp{-1};
};
#pragma pack()

class CPManager;
class CPGuard {
private:
    CP* m_cp{nullptr};
    bool m_pushed{false};

    // Why we need this thread_local variable and that too of type stack?
    // thread_local variable is needed because we wanted to make cp critical section re-entrant. So when a thread enters
    // into a critical section and crosses methods and other code within the stack needs to enter to critical section,
    // having this facility make sure that it uses already entered critical section within the stack.
    //
    // Why do we need a stack instead of only one CP* to track current critical section?
    // It is because CPGuard can be moved from one thread to other. The thread which it is moved to can be accessed
    // on a different cp critical section than one passed to. For example, if thread 1 gets into cp1 critical section
    // and passes the cp1 to thread2. However, before accessing cp1, thread2 already takes cp2 critical section and then
    // access cp1, then it needs to wind up with cp1 and once cp1 is done, has to go back to cp2. This nesting can
    // potentially happen recursively (although such pattern is not great, it can exist). That is why we use stack here
    static thread_local std::stack< CP* > t_cp_stack;

public:
    CPGuard(CPManager* mgr);
    ~CPGuard();

    CPGuard(const CPGuard& other);
    CPGuard operator=(const CPGuard& other);

    CPContext* context(cp_consumer_t consumer);
    CP& operator*();
    CP* operator->();
    CP* get();
};

/* It is responsible to trigger the checkpoints when all concurrent IOs are completed.
 * @ cp_type :- It is a consumer checkpoint with a base class of cp
 */
class CPManager {
    friend class CPGuard;

private:
    CP* m_cur_cp{nullptr}; // Current CP information
    std::atomic< bool > m_in_flush_phase{false};
    std::unique_ptr< CPMgrMetrics > m_metrics;
    std::mutex trigger_cp_mtx;
    Clock::time_point m_cp_start_time;
    std::array< std::unique_ptr< CPCallbacks >, (size_t)cp_consumer_t::SENTINEL > m_cp_cb_table;
    std::unique_ptr< CPWatchdog > m_wd_cp;
    superblk< cp_mgr_super_block > m_sb;
    std::vector< iomgr::io_fiber_t > m_cp_io_fibers;
    iomgr::timer_handle_t m_cp_timer_hdl;
    std::atomic< bool > m_cp_shutdown_initiated{false};

public:
    CPManager();
    virtual ~CPManager();

    /// @brief Start the CPManager, which creates a first cp session.
    /// @param first_time_boot
    void start(bool first_time_boot);

    /// @brief Start the cp timer so that periodic cps are started
    void start_timer();

    /// @brief Shutdown the checkpoint manager services. It will not trigger a flush, but cancels any existing
    /// checkpoint session abruptly. If caller needs clean shutdown, then they explicitly needs to trigger cp flush
    /// before calling shutdown.
    void shutdown();

    /// @brief Register a CP consumer to the checkpoint manager. CP consumer provides the callback they are interested
    /// in the checkpoint process. Each consumer gets a CPContext, which consumer can put its own dirty buffer info
    /// @param consumer_id : Pre-determined consumer id. Consumers are compile time defined. It doesn't support dynamic
    /// consumer registeration
    /// @param callbacks : Callbacks denoted by the consumers. Details are provided in CPCallbacks class
    void register_consumer(cp_consumer_t consumer_id, std::unique_ptr< CPCallbacks > callbacks);

    /// @brief Call this method before every IO that needs to be checkpointed. It marks the entrance of critical section
    /// of the returned CP and ensures that until it is exited, flush of the CP will not happen.
    ///
    /// @return Current CP that entered into critical section
    CP* cp_io_enter();

    /// @brief Counterpart to cp_io_enter. Once IO is done and critical section is completed, caller needs to call this.
    /// If CP flush is triggered for this CP, upon exiting the cp_io_exit and if there is no pending cp_io critical
    /// section will trigger the flush. NOTE: It is NOT required that cp_io_exit needs to be called from same thread as
    /// cp_io_enter.
    /// @param cp : Current CP that needs to exit from critical section
    void cp_io_exit(CP* cp);

    /// @brief RAII for cp_io_enter() and cp_io_exit(). This method returns a holder, which needs to be kept in context
    /// till the caller is in cp critical section. The CPHolder can be moved in that case, until it is accessed again,
    /// and releases, it will continue to be in critical section.
    /// @return CPHolder: Holder class of cp
    CPGuard cp_guard();

    /// @brief Get the current cp session.
    /// @return Returns the current CP
    CP* get_cur_cp();

    /// @brief Trigger a checkpoint flush on all subsystems registered. There is only 1 checkpoint per checkpoint
    /// manager. Checkpoint flush will wait for cp to exited all critical io sections.
    /// @param force : Do we need to force queue the checkpoint flush, in case previous checkpoint is being flushed
    folly::Future< bool > trigger_cp_flush(bool force = false);

    const std::array< std::unique_ptr< CPCallbacks >, (size_t)cp_consumer_t::SENTINEL >& consumer_list() const {
        return m_cp_cb_table;
    }

    iomgr::io_fiber_t pick_blocking_io_fiber() const;

private:
    void cp_ref(CP* cp);
    void create_first_cp();
    void cp_start_flush(CP* cp);
    void on_cp_flush_done(CP* cp);
    void cleanup_cp(CP* cp);
    void on_meta_blk_found(const sisl::byte_view& buf, void* meta_cookie);
    void start_cp_thread();
};
} // namespace homestore
