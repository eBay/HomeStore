#include <homestore/replication/repl_dev.h>
#include "replication/repl_dev/common.h"
#include <libnuraft/nuraft.hxx>

namespace homestore {

void repl_req_ctx::alloc_journal_entry(uint32_t size, bool is_raft_buf) {
    if (is_raft_buf) {
        journal_buf = nuraft::buffer::alloc(size);
        journal_entry = new (raft_journal_buf().get()) repl_journal_entry();
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

} // namespace homestore