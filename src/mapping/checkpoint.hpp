#pragma once
#include <device/blkbuffer.hpp>
#include <blkstore/blkstore.hpp>
#include <urcu-call-rcu.h>
#include <urcu.h>
#include <atomic>
#include <utility/atomic_counter.hpp>
#include <cassert>
#include <memory>
#include <sds_logging/logging.h>
#include <main/homestore_header.hpp>

namespace homestore {
SDS_LOGGING_DECL(cp)

typedef enum {
    cp_init = 1, // It is not inited yet.
    cp_io_ready, // IOs can start in a CP
    cp_trigger,  // cp is triggered
    cp_prepare,  // Preparing CP to commit the data on disk
    cp_start,    // User can start commiting data to disk
    cp_done      // Data commit on disk is done.
} cp_status_t;

/* It is a base class of consumer checkpoint ID. consumer checkpoint id can use it to store
 * checkpoint related info related to checkpoint. It is allocated/freed by CheckPoint class
 */

struct cp_id {
    std::atomic< cp_status_t > state = cp_status_t::cp_init;
    std::atomic< int > enter_cnt;

    cp_id() : enter_cnt(0){};
    std::string to_string() {
        std::string str = "state:" + std::to_string(state.load()) + "enter_cnt" + std::to_string(enter_cnt);
        return str;
    }
};

/* It is responsible to trigger the checkpoints when all concurrent IOs are completed.
 * @ cp_id_type :- It is a consumer checkpoint ID with a base class of cp_id
 */
template < typename cp_id_type = cp_id >
class CheckPoint {

private:
    cp_id_type* m_cur_cp_id = nullptr;
    std::mutex m_io_cv_lk;
    std::condition_variable m_io_cv;
    std::atomic< bool > in_cp_phase = false;

    void try_cp_prepare(cp_id_type* cp_id) {

        HS_ASSERT_CMP(DEBUG, cp_id->state, ==, cp_status_t::cp_trigger);
        HS_ASSERT_CMP(DEBUG, cp_id->enter_cnt, ==, 0);

        /* At this point we can be sure that there is no outstanding IO happening in that cp. We can
         * start IOs to a new cp id.
         */
        cp_id->state = cp_status_t::cp_prepare;
        auto cur_cp_id = get_cur_cp_id();
        cp_prepare(cp_id, cur_cp_id);

        {
            std::unique_lock< std::mutex > lk(m_io_cv_lk);
            cur_cp_id->state = cp_status_t::cp_io_ready;
            LOGDEBUGMOD(cp, "cp ID state {}", cur_cp_id->to_string());

            m_io_cv.notify_all();
        }
        cp_start(cp_id);
    }

public:
    /* @timeo :- Timer in milliseconds to trigger a checkpoint. */
    CheckPoint(int timeo) {
        m_cur_cp_id = new cp_id_type();
        m_cur_cp_id->state = cp_status_t::cp_io_ready;
        /* TODO :- integrate with io mgr to start a timer */
    }

    virtual ~CheckPoint() {
        auto cp_id = get_cur_cp_id();
        assert(cp_id->enter_cnt == 0);
        delete (cp_id);
    }

    /* Get current CP ID */
    cp_id_type* get_cur_cp_id() {
        cp_id_type* p = rcu_dereference(m_cur_cp_id);
        return p;
    }

    /* It is called for each IO. It doesn't trigger a CP until cp_exit() is not called for this IO
     * and CP id. There should be minimal operations between calling cp_io_enter() and cp_io_exit() because
     * other threads might be blocked if new CP is in cp init phase.
     * @ return :- return a current cp_id
     */
    cp_id_type* cp_io_enter() {

        rcu_read_lock();
        auto cp_id = get_cur_cp_id();
        cp_id->enter_cnt++;
        rcu_read_unlock();

        if (cp_id->state == cp_status_t::cp_init) {
            std::unique_lock< std::mutex > lk(m_io_cv_lk);
            if (cp_id->state != cp_status_t::cp_init) {
                LOGDEBUGMOD(cp, "suspending IO");
                m_io_cv.wait(lk);
                LOGDEBUGMOD(cp, "cp resuming IO");
            }
            HS_ASSERT_CMP(DEBUG, cp_id->state, ==, cp_status_t::cp_io_ready);
        }

        assert(cp_id->state == cp_status_t::cp_io_ready || cp_id->state == cp_status_t::cp_trigger);
        return cp_id;
    }

    /* It is called for each IO when it is completed. It trigger a checkpoint if it is pending and there
     * are no outstanding IOs.
     * id :- cp_id returned in cp_enter()
     */
    void cp_io_exit(cp_id_type* id) {
        auto cnt = id->enter_cnt.fetch_sub(1);
        if (cnt == 1 && id->state == cp_status_t::cp_trigger) { try_cp_prepare(id); }
    }

    /* It suspend the checkpoint. */
    void cp_suspend() {}

    /* It resume the checkpoint. */
    void cp_resume() {}

    /* It should be called when all IOs are persisted in a checkpoint. It is assumed that it is called by only one
     * thread and only once.
     */
    void cp_end(cp_id_type* id) {
        assert(in_cp_phase);
        HS_ASSERT_CMP(DEBUG, id->state, ==, cp_status_t::cp_start);
        in_cp_phase = false;
        LOGDEBUGMOD(cp, "cp ID completed {}", id->to_string());
        free(id);
    }

    /* Trigger a checkpoint.
     * @return
     *      true :- If CP trigger can happen
     *      false :- Failure. Need to try again.
     */
    bool cp_trigger() {

        /* check the state of previous CP */
        bool expected = false;

        auto ret = in_cp_phase.compare_exchange_strong(expected, true);
        if (!ret) { return false; }

        auto prev_cp_id = get_cur_cp_id();
        prev_cp_id->enter_cnt++;
        prev_cp_id->state = cp_status_t::cp_trigger;
        LOGDEBUGMOD(cp, "cp ID state {}", prev_cp_id->to_string());
        auto new_cp_id = new cp_id_type();
        rcu_xchg_pointer(&m_cur_cp_id, new_cp_id);
        synchronize_rcu();

        // At this point we are sure that there is no thread working on prev_cp_id without incrementing the cp_enter cnt

        auto cnt = prev_cp_id->enter_cnt.fetch_sub(1);
        if (cnt == 1) { try_cp_prepare(prev_cp_id); }
        return true;
    }

    /* CP is divided into two stages :- CP prepare and CP start */

    /* It is called when cp is moving to prepare state. It is called under the lock and is called only once for a given
     * CP. Work done in this function should be minimal because IOs are blocked until it is not completed.
     */
    virtual void cp_prepare(cp_id_type* prev_id, cp_id_type* cur_id) = 0;

    /* It should be defined by the derived class and is called when checkpoint is triggerd and all outstanding
     * IOs are completed.
     */
    virtual void cp_start(cp_id_type* id) = 0;
};
} // namespace homestore
