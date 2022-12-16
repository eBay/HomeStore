/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 * Author/Developer(s): Rishabh Mittal, Harihara Kadayam
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

namespace homestore {
static constexpr size_t MAX_CP_COUNT{2};
typedef int64_t cp_id_t;

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

VENUM(cp_consumer_t, uint8_t,
      HS_CLIENT = 0,       // Client of the homestore module
      INDEX_SVC = 1,       // Index service module
      BLK_DATA_SVC = 2,    // Block data service module
      REPLICATION_SVC = 3, // Replication service module
      SENTINEL = 4         // Should always be the last in this list
);

struct CP;
class CPContext {
private:
    cp_id_t m_cp_id;
    CP* m_cp;

public:
    CPContext(cp_id_t id) : m_cp_id{id} {}
    cp_id_t id() const { return m_cp_id; }
    CP* cp() { return m_cp; }

    virtual ~CPContext() = default;
};

typedef std::function< void(CP*) > cp_flush_done_cb_t;
typedef std::function< void(bool success) > cp_done_cb_t;

struct CPCallbacks {
    // Called by CPManager, when a new CP is triggered and it is time to switchover the dirty buffer collection to the
    // new CP and flush the existing CP
    std::function< std::unique_ptr< CPContext >(CP*, CP*) > on_switchover_cp{nullptr};

    // CPManager asks consumers to start flushing the CP dirty buffers. Once CP flush is completed, consumers are
    // required to call the flush_done callback.
    std::function< void(CP*, cp_flush_done_cb_t&&) > cp_flush{nullptr};

    // Cleanup any CP related structures allocated and truncate the journal.
    std::function< void(CP*) > cp_cleanup{nullptr};

    // Provide back the progress percentage on flush
    std::function< int(void) > cp_progress_percent{nullptr};

    // Will be called by CPManager, in case cp is not progressing at all. Consumers could repair this by
    // increasing any flow control on how fast flush is happening.
    std::function< void(void) > repair_slow_cp{nullptr};
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

/* It is responsible to trigger the checkpoints when all concurrent IOs are completed.
 * @ cp_type :- It is a consumer checkpoint with a base class of cp
 */
class CPManager {
private:
    CP* m_cur_cp{nullptr}; // Current CP information
    std::atomic< bool > m_in_flush_phase{false};
    std::unique_ptr< CPMgrMetrics > m_metrics;
    std::mutex trigger_cp_mtx;
    Clock::time_point m_cp_start_time;
    std::array< CPCallbacks, (size_t)cp_consumer_t::SENTINEL > m_cp_cb_table;
    sisl::atomic_counter< int32_t > m_cp_flush_waiters{0};
    std::unique_ptr< CPWatchdog > m_wd_cp;
    superblk< cp_mgr_super_block > m_sb;

public:
    CPManager(bool first_time_boot);
    virtual ~CPManager();

    /// @brief Shutdown the checkpoint manager services. It will not trigger a flush, but cancels any existing
    /// checkpoint session abruptly. If caller needs clean shutdown, then they explicitly needs to trigger cp flush
    /// before calling shutdown.
    void shutdown();

    /// @brief Register a CP consumer to the checkpoint manager. CP consumer provides the callback they are interested
    /// in the checkpoint process. Each consumer gets a CPContext, which consumer can put its own dirty buffer info
    /// @param consumer_id : Pre-determined consumer id. Consumers are compile time defined. It doesn't support dynamic
    /// consumer registeration
    /// @param callbacks : Callbacks denoted by the consumers. Details are provided in CPCallbacks class
    void register_consumer(cp_consumer_t consumer_id, CPCallbacks&& callbacks);

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

    /// @brief Get the current cp session.
    /// @return Returns the current CP
    CP* get_cur_cp();

    /// @brief Trigger a checkpoint flush on all subsystems registered. There is only 1 checkpoint per checkpoint
    /// manager. Checkpoint flush will wait for cp to exited all critical io sections.
    /// @param cb : Callback to be called upon completion of checkpoint flush
    /// @param force : Do we need to force queue the checkpoint flush, in case previous checkpoint is been flushed
    void trigger_cp_flush(cp_done_cb_t&& cb = nullptr, bool force = false);

    const std::array< CPCallbacks, (size_t)cp_consumer_t::SENTINEL >& consumer_list() const { return m_cp_cb_table; }

private:
    void create_first_cp();
    void cp_start_flush(CP* cp);
    void on_cp_flush_done(CP* cp);
    void cleanup_cp(CP* cp);
    void on_meta_blk_found(const sisl::byte_view& buf, void* meta_cookie);
};
} // namespace homestore