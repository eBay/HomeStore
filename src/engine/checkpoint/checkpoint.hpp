#pragma once
#include <fds/malloc_helper.hpp>
#include "engine/device/blkbuffer.hpp"
#include "engine/blkstore/blkstore.hpp"
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
 * CP end :- when cp flush is completed. It frees the CP id.
 */
typedef std::function< void(bool success) > cp_done_cb;
namespace homestore {
SDS_LOGGING_DECL(cp)

ENUM(cp_status_t, uint8_t,
     cp_init,     // It is not inited yet.
     cp_io_ready, // IOs can start in a CP
     cp_trigger,  // cp is triggered
     cp_prepare,  // waiting for enter cnt to be zero
     cp_start,    // User can start flush data to disk
     cp_done      // Data flush is done.
);

/* It is a base class of consumer checkpoint ID. consumer checkpoint id can use it to store
 * checkpoint related info related to checkpoint. It is allocated/freed by CheckPoint class
 */

struct cp_id_base {
    std::atomic< cp_status_t > cp_status = cp_status_t::cp_init;
    std::atomic< int > enter_cnt;
    bool cp_trigger_waiting = false; // it is waiting for previous cp to complete

    cp_id_base() : enter_cnt(0){};
    std::string to_string() {
        return fmt::format("[cp_status={}, enter_cnt={}]", enum_name(cp_status.load()), enter_cnt.load());
    }

    /* callback when cp is done. This list is protected by trigger_cp_mtx */
    std::vector< cp_done_cb > cb_list;
};

/* It is responsible to trigger the checkpoints when all concurrent IOs are completed.
 * @ cp_id_type :- It is a consumer checkpoint ID with a base class of cp_id
 */
template < typename cp_id_type = cp_id_base >
class CheckPoint {
private:
    cp_id_type* m_cur_cp_id = nullptr;
    std::atomic< bool > in_cp_phase = false;
    std::mutex trigger_cp_mtx;

public:
    /* @timeo :- Timer in milliseconds to trigger a checkpoint. */
    CheckPoint(int timeo) {
        m_cur_cp_id = new cp_id_type();
        m_cur_cp_id->cp_status = cp_status_t::cp_io_ready;
        /* TODO :- integrate with io mgr to start a timer */
    }

    virtual ~CheckPoint() {
        auto cp_id = get_cur_cp_id();
        delete (cp_id);
    }

    /* Get current CP ID */
    cp_id_type* get_cur_cp_id() {
        cp_id_type* p = rcu_dereference(m_cur_cp_id);
        return p;
    }

    /* It is called for each IO. It doesn't trigger a CP until cp_exit() is not called for this IO
     * and CP id.
     * @ return :- return a current cp_id
     */
    cp_id_type* cp_io_enter() {

        rcu_read_lock();
        auto cp_id = get_cur_cp_id();
        cp_id->enter_cnt++;
        assert(cp_id->cp_status == cp_status_t::cp_io_ready || cp_id->cp_status == cp_status_t::cp_trigger);
        rcu_read_unlock();

        return cp_id;
    }

    /* It exposes an API to increment the ref count on a cp id. It assumes that caller is alrady in cp_io_enter
     * phase before calling cp_inc_ref.
     */
    void cp_inc_ref(cp_id_type* id, int ref_cnt) {
        assert(id->enter_cnt > 0);
        id->enter_cnt.fetch_add(ref_cnt);
    }

    /* It is called for each IO when it is completed. It trigger a checkpoint if it is pending and there
     * are no outstanding IOs.
     * id :- cp_id returned in cp_enter()
     */
    void cp_io_exit(cp_id_type* id) {
        assert(id->cp_status != cp_status_t::cp_start);
        auto cnt = id->enter_cnt.fetch_sub(1);
        if (cnt == 1 && id->cp_status == cp_status_t::cp_prepare) {
            id->cp_status = cp_status_t::cp_start;
            cp_start(id);
        }
    }

    /* It should be called when all IOs are persisted in a checkpoint. It is assumed that it is called by only one
     * thread and only once.
     */
    void cp_end(cp_id_type* id) {
        assert(in_cp_phase);
        HS_ASSERT_CMP(DEBUG, id->cp_status, ==, cp_status_t::cp_start);
        in_cp_phase = false;
        LOGDEBUGMOD(cp, "cp ID completed {}", id->to_string());
        for (uint32_t i = 0; i < id->cb_list.size(); ++i) {
            id->cb_list[i](true);
        }
        delete (id);

        /* Once a cp is done, try to check and release exccess memory if need be */
        size_t soft_sz =
            HS_DYNAMIC_CONFIG(generic.soft_mem_release_threshold) * HS_STATIC_CONFIG(input.app_mem_size) / 100;
        size_t agg_sz =
            HS_DYNAMIC_CONFIG(generic.aggressive_mem_release_threshold) * HS_STATIC_CONFIG(input.app_mem_size) / 100;
        sisl::release_mem_if_needed(soft_sz, agg_sz);

        auto cur_cp_id = cp_io_enter();
        if (cur_cp_id->cp_trigger_waiting) { trigger_cp(); }
        cp_io_exit(cur_cp_id);
    }

    void attach_cb(cp_id_type* cp_id, cp_done_cb cb) {
        std::unique_lock< std::mutex > lk(trigger_cp_mtx);
        assert(cp_id->cp_status != cp_status_t::cp_prepare);
        cp_id->cb_list.push_back(cb);
    }

    /* Trigger a checkpoint if it is not in cp phase. It makes sure to attach a callback to a CP who hasn't called the
     * attach_prepare yet.
     */
    void trigger_cp(cp_done_cb cb = nullptr) {

        /* check the state of previous CP */
        bool expected = false;

        auto ret = in_cp_phase.compare_exchange_strong(expected, true);
        if (!ret) {
            std::unique_lock< std::mutex > lk(trigger_cp_mtx);
            auto cp_id = cp_io_enter();
            assert(cp_id->cp_status != cp_status_t::cp_prepare);
            if (cb) { cp_id->cb_list.push_back(cb); }
            cp_id->cp_trigger_waiting = true;
            cp_io_exit(cp_id);
            return;
        }

        auto prev_cp_id = cp_io_enter();
        prev_cp_id->cp_status = cp_status_t::cp_trigger;
        LOGDEBUGMOD(cp, "cp ID state {}", prev_cp_id->to_string());

        /* allocate a new cp */
        auto new_cp_id = new cp_id_type();
        {
            std::unique_lock< std::mutex > lk(trigger_cp_mtx);
            cp_attach_prepare(prev_cp_id, new_cp_id);
            prev_cp_id->cp_status = cp_status_t::cp_prepare;
            new_cp_id->cp_status = cp_status_t::cp_io_ready;
            rcu_xchg_pointer(&m_cur_cp_id, new_cp_id);
            synchronize_rcu();
            prev_cp_id->cb_list.push_back(cb);
        }
        // At this point we are sure that there is no thread working on prev_cp_id without incrementing the cp_enter cnt

        cp_io_exit(prev_cp_id);
    }

    void trigger_cp(cp_id_type* id) {
        id->cp_trigger_waiting = true;
        assert(id->cp_status != cp_status_t::cp_start);
        trigger_cp();
    }

    /* CP is divided into two stages :- CP prepare and CP start */

    /* It is called when cp is moving to prepare state. It is called under the lock and is called only once for a given
     * CP.
     */
    virtual void cp_attach_prepare(cp_id_type* prev_id, cp_id_type* cur_id) = 0;

    /* It should be defined by the derived class and is called when checkpoint is triggerd and all outstanding
     * IOs have called cp_io_exit.
     */
    virtual void cp_start(cp_id_type* id) = 0;
};
} // namespace homestore
