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
#include <memory>
#include <mutex>

#include <sisl/logging/logging.h>
#include <sisl/utility/atomic_counter.hpp>
#include <folly/futures/SharedPromise.h>

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
namespace homestore {
SISL_LOGGING_DECL(cp, replay)

#define CP_PERIODIC_LOG(level, cp_id, msg, ...)                                                                        \
    HS_PERIODIC_DETAILED_LOG(level, cp, "cp_id", cp_id, , , msg, ##__VA_ARGS__)
#define CP_LOG(level, cp_id, msg, ...) HS_SUBMOD_LOG(level, cp, , "cp_id", cp_id, msg, ##__VA_ARGS__)

typedef int64_t cp_id_t;
ENUM(cp_status_t, uint8_t,
     cp_unknown, // It is not inited yet.

     ////////////// IO Phase //////////////////
     cp_io_ready, // IOs can start in a CP
     cp_trigger,  // cp is triggered

     ////////////// Flush Phase ///////////////
     cp_flush_prepare, // after switchover flush is called
     cp_flushing,      // Waiting for enter cnt to be zero. User can start flush data to disk
     cp_flush_done,    // Data flush is done.

     ////////////// Cleanup Phase //////////////
     cp_cleaning);

class CPContext;
class CPManager;

VENUM(cp_consumer_t, uint8_t,
      HS_CLIENT = 0,       // Client of the homestore module
      INDEX_SVC = 1,       // Index service module
      BLK_DATA_SVC = 2,    // Block data service module
      REPLICATION_SVC = 3, // Replication service module
      SENTINEL = 4         // Should always be the last in this list
);

struct CP {
    std::atomic< cp_status_t > m_cp_status{cp_status_t::cp_unknown};
    sisl::atomic_counter< int64_t > m_enter_cnt;
    CPManager* m_cp_mgr;
    bool m_cp_waiting_to_trigger{false}; // it is waiting for previous cp to complete
    cp_id_t m_cp_id;
    std::array< std::unique_ptr< CPContext >, (size_t)cp_consumer_t::SENTINEL > m_contexts;
    folly::SharedPromise< bool > m_comp_promise;

public:
    CP(CPManager* mgr) : m_cp_mgr{mgr} {}

    cp_id_t id() const { return m_cp_id; }
    cp_status_t get_status() const { return m_cp_status.load(); }
    CPContext* context(cp_consumer_t consumer) const { return m_contexts[(size_t)consumer].get(); }
    void set_context(cp_consumer_t consumer, std::unique_ptr< CPContext > context) {
        m_contexts[(size_t)consumer] = std::move(context);
    }

    std::string to_string() const {
        return fmt::format("CP={}: status={}, enter_count={}", m_cp_id, enum_name(get_status()), m_enter_cnt.get());
    }
};
} // namespace homestore
