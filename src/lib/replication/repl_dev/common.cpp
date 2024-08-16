#include <boost/smart_ptr/intrusive_ref_counter.hpp>
#include <sisl/grpc/generic_service.hpp>
#include <sisl/grpc/rpc_call.hpp>
#include <homestore/blkdata_service.hpp>
#include <homestore/replication/repl_dev.h>
#include <common/homestore_config.hpp>
#include "replication/repl_dev/common.h"
#include <libnuraft/nuraft.hxx>

namespace homestore {

void repl_req_ctx::init(repl_key rkey, journal_type_t op_code, bool is_proposer, sisl::blob const& user_header,
                        sisl::blob const& key, uint32_t data_size) {
    m_rkey = std::move(rkey);
#ifndef NDEBUG
    if (data_size > 0) {
        DEBUG_ASSERT_EQ(op_code, journal_type_t::HS_DATA_LINKED, "Calling wrong init method");
    } else {
        DEBUG_ASSERT_NE(op_code, journal_type_t::HS_DATA_LINKED, "Calling wrong init method");
    }
#endif
    m_op_code = op_code;
    m_is_proposer = is_proposer;
    m_header = user_header;
    m_key = key;
    m_is_jentry_localize_pending = (!is_proposer && (data_size > 0)); // Pending on the applier and with linked data
}

repl_req_ctx::~repl_req_ctx() {
    if (m_journal_entry) { m_journal_entry->~repl_journal_entry(); }
}

void repl_req_ctx::create_journal_entry(bool is_raft_buf, int32_t server_id) {
    uint32_t val_size = has_linked_data() ? m_local_blkid.serialized_size() : 0;
    uint32_t entry_size = sizeof(repl_journal_entry) + m_header.size() + m_key.size() + val_size;

    if (is_raft_buf) {
        m_journal_buf = nuraft::buffer::alloc(entry_size);
        m_journal_entry = new (raft_journal_buf()->data_begin()) repl_journal_entry();
    } else {
        m_journal_buf = std::unique_ptr< uint8_t[] >(new uint8_t[entry_size]);
        m_journal_entry = new (raw_journal_buf()) repl_journal_entry();
    }

    m_journal_entry->code = m_op_code;
    m_journal_entry->server_id = server_id;
    m_journal_entry->dsn = m_rkey.dsn;
    m_journal_entry->user_header_size = m_header.size();
    m_journal_entry->key_size = m_key.size();
    m_journal_entry->value_size = val_size;

    uint8_t* raw_ptr = uintptr_cast(m_journal_entry) + sizeof(repl_journal_entry);
    if (m_header.size()) {
        std::memcpy(raw_ptr, m_header.cbytes(), m_header.size());
        raw_ptr += m_header.size();
    }

    if (m_key.size()) {
        std::memcpy(raw_ptr, m_key.cbytes(), m_key.size());
        raw_ptr += m_key.size();
    }

    if (has_linked_data()) {
        auto const b = m_local_blkid.serialize();
        std::memcpy(raw_ptr, b.cbytes(), b.size());
    }
}

uint32_t repl_req_ctx::journal_entry_size() const {
    return sizeof(repl_journal_entry) + m_header.size() + m_key.size() +
        (has_linked_data() ? m_local_blkid.serialized_size() : 0);
}

void repl_req_ctx::change_raft_journal_buf(raft_buf_ptr_t new_buf, bool adjust_hdr_key) {
    m_journal_buf = std::move(new_buf);
    m_journal_entry = r_cast< repl_journal_entry* >(raft_journal_buf()->data_begin());

    if (adjust_hdr_key) {
        m_header =
            sisl::blob{uintptr_cast(m_journal_entry) + sizeof(repl_journal_entry), m_journal_entry->user_header_size};
        m_key =
            sisl::blob{uintptr_cast(m_journal_entry) + sizeof(repl_journal_entry) + m_journal_entry->user_header_size,
                       m_journal_entry->key_size};
    }
    m_is_jentry_localize_pending = false;
}

ReplServiceError repl_req_ctx::alloc_local_blks(cshared< ReplDevListener >& listener, uint32_t data_size) {
    DEBUG_ASSERT(has_linked_data(), "Trying to allocate a block for non-inlined block");

    auto const hints_result = listener->get_blk_alloc_hints(m_header, data_size);
    if (hints_result.hasError()) { return hints_result.error(); }

    auto status = data_service().alloc_blks(sisl::round_up(uint32_cast(data_size), data_service().get_blk_size()),
                                            hints_result.value(), m_local_blkid);
    if (status != BlkAllocStatus::SUCCESS) {
        DEBUG_ASSERT_EQ(status, BlkAllocStatus::SUCCESS, "Unable to allocate blks");
        return ReplServiceError::NO_SPACE_LEFT;
    }
    add_state(repl_req_state_t::BLK_ALLOCATED);
    return ReplServiceError::OK;
}

raft_buf_ptr_t& repl_req_ctx::raft_journal_buf() { return std::get< raft_buf_ptr_t >(m_journal_buf); }
uint8_t* repl_req_ctx::raw_journal_buf() { return std::get< std::unique_ptr< uint8_t[] > >(m_journal_buf).get(); }

void repl_req_ctx::set_lsn(int64_t lsn) {
    DEBUG_ASSERT((m_lsn == -1) || (m_lsn == lsn),
                 "Changing lsn for request={} on the fly can cause race condition, not expected", to_string());
    m_lsn = lsn;
    LOGTRACEMOD(replication, "Setting lsn={} for request={}", lsn, to_string());
}

bool repl_req_ctx::save_pushed_data(intrusive< sisl::GenericRpcData > const& pushed_data, uint8_t const* data,
                                    uint32_t data_size) {
    if (!add_state_if_not_already(repl_req_state_t::DATA_RECEIVED)) { return false; }

    if (((uintptr_t)data % data_service().get_align_size()) != 0) {
        // Unaligned buffer, create a new buffer and copy the entire buf
        m_buf_for_unaligned_data = std::move(sisl::io_blob_safe(data_size, data_service().get_align_size()));
        std::memcpy(m_buf_for_unaligned_data.bytes(), data, data_size);
        data = m_buf_for_unaligned_data.cbytes();
    }

    m_pushed_data = pushed_data;
    m_data = data;
    m_data_received_promise.setValue();
    return true;
}

bool repl_req_ctx::save_fetched_data(sisl::GenericClientResponse const& fetched_data, uint8_t const* data,
                                     uint32_t data_size) {
    if (!add_state_if_not_already(repl_req_state_t::DATA_RECEIVED)) { return false; }

    if (((uintptr_t)data % data_service().get_align_size()) != 0) {
        // Unaligned buffer, create a new buffer and copy the entire buf
        m_buf_for_unaligned_data = std::move(sisl::io_blob_safe(data_size, data_service().get_align_size()));
        std::memcpy(m_buf_for_unaligned_data.bytes(), data, data_size);
        data = m_buf_for_unaligned_data.cbytes();
    }

    m_fetched_data = fetched_data;
    m_data = data;
    m_data_received_promise.setValue();
    return true;
}

void repl_req_ctx::add_state(repl_req_state_t s) { m_state.fetch_or(uint32_cast(s)); }

bool repl_req_ctx::add_state_if_not_already(repl_req_state_t s) {
    bool changed{false};
    auto cur_v = m_state.load();
    while (!(cur_v & uint32_cast(s))) {
        if (m_state.compare_exchange_weak(cur_v, cur_v | uint32_cast(s))) {
            changed = true;
            break;
        }
    }

    return changed;
}

void repl_req_ctx::clear() {
    m_header = sisl::blob{};
    m_key = sisl::blob{};
    if (m_pushed_data) {
        m_pushed_data->send_response();
        m_pushed_data = nullptr;
    }
    m_fetched_data = sisl::GenericClientResponse{};
    m_pkts.clear();
}

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
    return fmt::format("repl_key=[{}], lsn={} state=[{}] m_headersize={} m_keysize={} is_proposer={} "
                       "local_blkid={} remote_blkid={}",
                       m_rkey.to_string(), m_lsn, req_state_name(uint32_cast(state())), m_header.size(), m_key.size(),
                       m_is_proposer, m_local_blkid.to_string(), m_remote_blkid.blkid.to_string());
}

std::string repl_req_ctx::to_compact_string() const {
    if (m_op_code == journal_type_t::HS_CTRL_DESTROY) {
        return fmt::format("term={} lsn={} op={}", m_rkey.term, m_lsn, enum_name(m_op_code));
    }
    return fmt::format("dsn={} term={} lsn={} op={} local_blkid={} state=[{}]", m_rkey.dsn, m_rkey.term, m_lsn,
                       enum_name(m_op_code), m_local_blkid.to_string(), req_state_name(uint32_cast(state())));
}

bool repl_req_ctx::is_expired() const {
    return get_elapsed_time_sec(m_start_time) > HS_DYNAMIC_CONFIG(consensus.repl_req_timeout_sec);
}

} // namespace homestore
