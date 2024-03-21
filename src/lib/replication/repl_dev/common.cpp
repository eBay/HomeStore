#include <boost/smart_ptr/intrusive_ref_counter.hpp>
#include <sisl/grpc/generic_service.hpp>
#include <sisl/grpc/rpc_call.hpp>
#include <homestore/replication/repl_dev.h>
#include "replication/repl_dev/common.h"
#include <libnuraft/nuraft.hxx>

namespace homestore {

void repl_req_ctx::alloc_journal_entry(uint32_t size, bool is_raft_buf) {
    if (is_raft_buf) {
        journal_buf = nuraft::buffer::alloc(size);
        journal_entry = new (raft_journal_buf()->data_begin()) repl_journal_entry();
    } else {
        journal_buf = std::unique_ptr< uint8_t[] >(new uint8_t[size]);
        journal_entry = new (raw_journal_buf()) repl_journal_entry();
    }
}

repl_req_ctx::~repl_req_ctx() {
    if (journal_entry) { journal_entry->~repl_journal_entry(); }
}

raft_buf_ptr_t& repl_req_ctx::raft_journal_buf() { return std::get< raft_buf_ptr_t >(journal_buf); }
uint8_t* repl_req_ctx::raw_journal_buf() { return std::get< std::unique_ptr< uint8_t[] > >(journal_buf).get(); }

static std::string req_state_name(uint32_t state) {
    if (state == (uint32_t)repl_req_state_t::INIT) { return "INIT"; }

    std::string ret;
    if (state & (uint32_t)repl_req_state_t::BLK_ALLOCATED) { ret += "BLK_ALLOCATED | "; }
    if (state & (uint32_t)repl_req_state_t::DATA_RECEIVED) { ret += "DATA_RECEIVED | "; }
    if (state & (uint32_t)repl_req_state_t::DATA_WRITTEN) { ret += "DATA_WRITTEN | "; }
    if (state & (uint32_t)repl_req_state_t::LOG_RECEIVED) { ret += "LOG_RECEIVED | "; }
    if (state & (uint32_t)repl_req_state_t::LOG_FLUSHED) { ret += "LOG_FLUSHED"; }
    return ret;
}

std::string repl_req_ctx::to_string() const {
    return fmt::format(
        "repl_key=[{}], lsn={} state=[{}] header_size={} key_size={} is_proposer={} local_blkid={} remote_blkid={}",
        rkey.to_string(), lsn, req_state_name(state.load()), header.size(), key.size(), is_proposer,
        local_blkid.to_string(), remote_blkid.blkid.to_string());
}

std::string repl_req_ctx::to_compact_string() const {
    return fmt::format("dsn={} term={} lsn={} local_blkid={} state=[{}]", rkey.dsn, rkey.term, lsn,
                       local_blkid.to_string(), req_state_name(state.load()));
}

} // namespace homestore