#pragma once
#include <memory>
#include <string>
#include <vector>
#include <functional>
#include <sisl/fds/buffer.hpp>
#include <home_replication/repl_decls.h>

namespace home_replication {

typedef std::function< void(std::error_condition) > io_completion_cb_t;
using repl_lsn_t = int64_t;

class StateMachineStore {
public:
    ////////////// Storage Writes of Data Blocks ///////////////////////
    virtual pba_list_t alloc_pbas(uint32_t size) = 0;
    virtual void async_write(const sisl::sg_list& sgs, const pba_list_t& in_pbas, const io_completion_cb_t& cb) = 0;
    virtual void async_read(pba_t pba, sisl::sg_list& sgs, uint32_t size, const io_completion_cb_t& cb) = 0;
    virtual void free_pba(pba_t pba) = 0;
    virtual uint32_t pba_to_size(pba_t pba) const = 0;

    //////////////////// Control operations ///////////////////////////////
    virtual void destroy() = 0;

    ////////////////// State machine and free pba persistence ///////////////////
    virtual void commit_lsn(repl_lsn_t lsn) = 0;
    virtual repl_lsn_t get_last_commit_lsn() const = 0;
    virtual void add_free_pba_record(repl_lsn_t lsn, const pba_list_t& pbas) = 0;
    virtual void get_free_pba_records(repl_lsn_t from_lsn, repl_lsn_t to_lsn,
                                      const std::function< void(repl_lsn_t lsn, const pba_list_t& pba) >& cb) = 0;
    virtual void remove_free_pba_records_upto(repl_lsn_t lsn) = 0;
    virtual void flush_free_pba_records() = 0;
};

} // namespace home_replication
