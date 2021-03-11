#pragma once
#include <fds/malloc_helper.hpp>
#include <urcu-call-rcu.h>
#include <urcu.h>
#include <utility/urcu_helper.hpp>
#include <atomic>
#include <utility/atomic_counter.hpp>
#include <cassert>
#include <memory>
#include <sds_logging/logging.h>
#include "engine/common/homestore_config.hpp"
#include "engine/common/homestore_header.hpp"
#include "engine/common/homestore_assert.hpp"
#include "engine/homestore_base.hpp"

/*
 * These are the design requirements of this class. If we don't follow these requirements then there can be serious
 * consequences in btree.
 * 1. It doesn't allow a cp to start if io is still in cp critical section. CP critical section is code between
 * cp_io_enter() and cp_io_exit().
 * 2. It doesn't allow two cps to start simultanously. second CP doesn't start until cp_done is not called in first cp.
 * 3. It call cp prepare. Purpose of this function is to create new cp and also to decide what operations we want to do
 * in that CP.
 * 4. New cp doesn't start until cp prepare is not called on a current cp.
 *
 * These are the stages of CP :-
 * CP prepare :- When cp is prepared to start flush
 * CP attach :- When new cp is created
 * Both these stages are combines in one API prepare_attach
 *
 * CP trigger :- It trigger current cp to flush
 * CP start :- It start the flush when all ios have called cp_io_exit on that cp
 * CP end :- when cp flush is completed. It frees the CP.
 */
typedef std::function< void(bool success) > cp_done_cb;
namespace homestore {
SDS_LOGGING_DECL(cp, replay)

#define CP_PERIODIC_LOG(level, cp_id, msg, ...)                                                                        \
    HS_PERIODIC_DETAILED_LOG(level, cp, "cp_id", cp_id, , , msg, ##__VA_ARGS__)
#define CP_LOG(level, cp_id, msg, ...) HS_SUBMOD_LOG(level, cp, , "cp_id", cp_id, msg, ##__VA_ARGS__)

ENUM(cp_status_t, uint8_t,
     cp_init,     // It is not inited yet.
     cp_io_ready, // IOs can start in a CP
     cp_trigger,  // cp is triggered
     cp_prepare,  // after attach prepare is called
     cp_start,    // Waiting for enter cnt to be zero.User can start flush data to disk
     cp_done      // Data flush is done.
);

/* It is a base class of consumer checkpoint. consumer checkpoint can use it to store
 * checkpoint related info related to checkpoint. It is allocated/freed by CPMgr class
 */

struct cp_base {
    std::atomic< cp_status_t > cp_status = cp_status_t::cp_init;
    std::atomic< int > enter_cnt;
    bool cp_trigger_waiting = false; // it is waiting for previous cp to complete
    std::mutex cb_list_mtx;
    /* callback when cp is done */
    std::vector< cp_done_cb > cb_list;

    cp_base() : enter_cnt(0), cb_list(0){};
    std::string to_string() {
        return fmt::format("[cp_status={}, enter_cnt={}]", enum_name(cp_status.load()), enter_cnt.load());
    }

    void push_cb(const cp_done_cb& cb) {
        std::unique_lock< std::mutex > lk(cb_list_mtx);
        HS_ASSERT_CMP(DEBUG, cp_status, !=, cp_status_t::cp_prepare);
        cb_list.push_back(std::move(cb));
    }
};

class CPMgrMetrics : public sisl::MetricsGroupWrapper {
    explicit CPMgrMetrics() : sisl::MetricsGroupWrapper("CPMgr") {
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

/* It is responsible to trigger the checkpoints when all concurrent IOs are completed.
 * @ cp_type :- It is a consumer checkpoint with a base class of cp
 */
template < typename cp_type = cp_base >
class CPMgr {
private:
    cp_type* m_cur_cp = nullptr;
    std::atomic< bool > in_cp_phase = false;
    std::mutex trigger_cp_mtx;
    std::atomic< bool > m_cp_suspend = true;
    CPMgrMetrics m_metrics;
    Clock::time_point m_cp_start_time;

public:
    CPMgr() {
        m_cur_cp = new cp_type();
        m_cur_cp->cp_status = cp_status_t::cp_io_ready;
    }

    virtual ~CPMgr() { HS_ASSERT(RELEASE, !m_cur_cp, "cur cp is not null"); }

    virtual void shutdown() {
        auto cp = get_cur_cp();
        delete (cp);
        rcu_xchg_pointer(&m_cur_cp, nullptr);
    }

    /* Get current CP */
    cp_type* get_cur_cp() {
        cp_type* p = rcu_dereference(m_cur_cp);
        return p;
    }

    /* It is called for each IO. It doesn't trigger a CP until cp_exit() is not called for this IO
     * and CP.
     * @ return :- return a current cp
     */
    cp_type* cp_io_enter() {
        rcu_read_lock();
        auto cp = get_cur_cp();

        if (!cp) {
            rcu_read_unlock();
            return nullptr;
        }
        auto cnt = cp->enter_cnt.fetch_add(1);
        HS_ASSERT(DEBUG,
                  (cp->cp_status == cp_status_t::cp_io_ready || cp->cp_status == cp_status_t::cp_trigger ||
                   cp->cp_status == cp_status_t::cp_prepare),
                  "cp status {}", cp->cp_status);

        rcu_read_unlock();

        return cp;
    }

    /* It exposes an API to increment the ref count on a cp. It assumes that caller is alrady in cp_io_enter
     * phase before calling cp_inc_ref.
     */
    void cp_inc_ref(cp_type* cp, int ref_cnt) {
        HS_ASSERT_CMP(DEBUG, cp->enter_cnt, >, 0);
        auto cnt = cp->enter_cnt.fetch_add(ref_cnt);
    }

    /* It is called for each IO when it is completed. It trigger a checkpoint if it is pending and there
     * are no outstanding IOs.
     * cp :- cp returned in cp_enter()
     */
    void cp_io_exit(cp_type* cp) {
        HS_ASSERT_CMP(DEBUG, cp->cp_status, !=, cp_status_t::cp_start);
        auto cnt = cp->enter_cnt.fetch_sub(1);
        if (cnt == 1 && cp->cp_status == cp_status_t::cp_prepare) {
            cp->cp_status = cp_status_t::cp_start;
            HS_PERIODIC_LOG(INFO, cp, "Outside of CP critical section, ref_count is 0, starting new CP");
            cp_start(cp);
        }
    }

    /* It should be called when all IOs are persisted in a checkpoint. It is assumed that it is called by only one
     * thread and only once.
     */
    void cp_end(cp_type* cp) {
        HS_ASSERT(DEBUG, in_cp_phase, "in_cp_phase");
        HS_ASSERT_CMP(DEBUG, cp->cp_status, ==, cp_status_t::cp_start);
        auto cb_list = cp->cb_list;
        HS_PERIODIC_LOG(DEBUG, cp, ">>>>>>>>>>>> cp ID completed {}, notified {} callbacks", cp->to_string(),
                        cb_list.size());
        HISTOGRAM_OBSERVE(m_metrics, cp_latency, get_elapsed_time_ns(m_cp_start_time));
        delete (cp);

        for (uint32_t i = 0; i < cb_list.size(); ++i) {
            cb_list[i](true);
        }
        in_cp_phase = false;

        /* Once a cp is done, try to check and release exccess memory if need be */
        size_t soft_sz =
            HS_DYNAMIC_CONFIG(generic.soft_mem_release_threshold) * HS_STATIC_CONFIG(input.app_mem_size) / 100;
        size_t agg_sz =
            HS_DYNAMIC_CONFIG(generic.aggressive_mem_release_threshold) * HS_STATIC_CONFIG(input.app_mem_size) / 100;
        sisl::release_mem_if_needed(soft_sz, agg_sz);

        auto cur_cp = cp_io_enter();
        if (!cur_cp) { return; }
        if (cur_cp->cp_trigger_waiting) {
            HS_PERIODIC_LOG(INFO, cp, "Triggering back to back CP");
            COUNTER_INCREMENT(m_metrics, back_to_back_cps, 1);
            trigger_cp();
        }
        cp_io_exit(cur_cp);
    }

    void attach_cb(cp_type* cp, const cp_done_cb& cb) { cp->push_cb(std::move(cb)); }

    /* Trigger a checkpoint if it is not in cp phase. It makes sure to attach a callback to a CP who hasn't called the
     * attach_prepare yet.
     */
    void trigger_cp(const cp_done_cb& cb = nullptr, bool force = false) {

        if (m_cp_suspend.load()) { return; }
        /* check the state of previous CP */
        bool expected = false;

        auto ret = in_cp_phase.compare_exchange_strong(expected, true);
        if (!ret) {
            if (cb || force) {
                std::unique_lock< std::mutex > lk(trigger_cp_mtx);
                auto cp = cp_io_enter();
                HS_ASSERT_CMP(DEBUG, cp->cp_status, !=, cp_status_t::cp_prepare);
                if (cb) { cp->push_cb(std::move(cb)); }
                cp->cp_trigger_waiting = true;
                cp_io_exit(cp);
            }
            return;
        }

        auto prev_cp = cp_io_enter();
        prev_cp->cp_status = cp_status_t::cp_trigger;
        HS_PERIODIC_LOG(INFO, cp, "<<<<<<<<<<< Triggering new CP {}", prev_cp->to_string());
        COUNTER_INCREMENT(m_metrics, cp_cnt, 1);
        m_cp_start_time = Clock::now();

        /* allocate a new cp */
        auto new_cp = new cp_type();
        {
            std::unique_lock< std::mutex > lk(trigger_cp_mtx);
            HS_PERIODIC_LOG(DEBUG, cp, "About to attach and prepare into the CP");
            cp_attach_prepare(prev_cp, new_cp);
            HS_PERIODIC_LOG(DEBUG, cp, "CP Attached completed, proceed to exit cp critical section");
            if (cb) { prev_cp->push_cb(std::move(cb)); }
            prev_cp->cp_status = cp_status_t::cp_prepare;
            new_cp->cp_status = cp_status_t::cp_io_ready;
            rcu_xchg_pointer(&m_cur_cp, new_cp);
            synchronize_rcu();
        }
        // At this point we are sure that there is no thread working on prev_cp without incrementing the cp_enter cnt

        HS_PERIODIC_LOG(DEBUG, cp, "CP critical section done, doing cp_io_exit");
        cp_io_exit(prev_cp);
    }

    void cp_suspend() { m_cp_suspend = true; }

    void cp_resume() { m_cp_suspend = false; }

    /* CP is divided into two stages :- CP prepare and CP start */

    /* It is called when cp is moving to prepare state. It is called under the lock and is called only once for a given
     * CP.
     */
    virtual void cp_attach_prepare(cp_type* prev_cp, cp_type* cur_cp) = 0;

    /* It should be defined by the derived class and is called when checkpoint is triggerd and all outstanding
     * IOs have called cp_io_exit.
     */
    virtual void cp_start(cp_type* cp) = 0;
};
} // namespace homestore
