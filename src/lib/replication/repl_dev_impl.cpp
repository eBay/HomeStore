#include "repl_set_impl.h"

#include <sisl/fds/obj_allocator.hpp>
#include <sisl/fds/vector_pool.hpp>
#include <sisl/grpc/generic_service.hpp>
#include "state_machine/state_machine.h"
#include "log_store/repl_log_store.hpp"
#include "log_store/journal_entry.h"
#include "storage/storage_engine.h"
#include "rpc_data_channel_include.h"

#define RD_LOG(level, msg, ...)                                                                                        \
    LOG##level##MOD_FMT(home_replication, ([&](fmt::memory_buffer& buf, const char* msgcb, auto&&... args) -> bool {   \
                            fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[{}:{}] "},                          \
                                            fmt::make_format_args(file_name(__FILE__), __LINE__));                     \
                            fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[{}={}] "},                          \
                                            fmt::make_format_args("rd", m_group_id));                                  \
                            fmt::vformat_to(fmt::appender{buf}, fmt::string_view{msgcb},                               \
                                            fmt::make_format_args(std::forward< decltype(args) >(args)...));           \
                            return true;                                                                               \
                        }),                                                                                            \
                        msg, ##__VA_ARGS__);

namespace homestore {
ReplDevImpl::ReplDevImpl(superblk< repl_dev_superblk > const& rd_sb, bool load_existing) :
        m_group_id{rd_sb->gid}, m_sb{rd_sb} {
    if (load_existing) {
        // Open both data_journal and free_blks logstores
        logstore_service().open_log_store(LogStoreService::DATA_LOG_FAMILY_IDX, m_sb->data_journal_id, true,
                                          bind_this(ReplDevImpl::on_store_created, 1));

        logstore_service().open_log_store(LogStoreService::CTRL_LOG_FAMILY_IDX, m_sb->free_blks_journal_id, true,
                                          bind_this(ReplDevImpl::on_store_created, 1));
    } else {
        RD_LOG(DEBUG, "Creating new repl dev");

        // Logstore for data journal, which is raft compliant
        m_data_journal = std::make_shared< ReplLogStore >(
            logstore_service().create_new_log_store(LogStoreService::DATA_LOG_FAMILY_IDX, true));
        m_sb->data_journal_id - m_data_journal->logstore_id();

        // Create logstore to store the free blkid records
        m_free_blkid_journal = logstore_service().create_new_log_store(LogStoreService::CTRL_LOG_FAMILY_IDX, true);
        m_sb->free_blks_journal_id = m_free_blkid_journal->get_store_id();

        m_sb->commit_lsn = 0;
        m_sb->checkpoint_lsn = 0;
        m_sb.write();
        RD_LOG(DEBUG, "ReplDev created data_journal logstore={} free_blks logstore={}", m_sb->data_journal_id,
               m_sb->free_blks_journal_id);

        start_sb_flush_timer();
    }
    m_sb_in_mem = *m_sb;
}

void ReplDevImpl::destroy() {
    RD_LOG(DEBUG, "Data journal logstore={} is being physically removed", m_sb->data_journal_id);
    m_data_journal.reset();
    logstore_service().remove_log_store(LogStoreService::DATA_LOG_FAMILY_IDX, m_sb->data_journal_id);

    RD_LOG(DEBUG, "Free blks logstore={} is being physically removed", m_sb->free_blks_journal_id);
    m_free_blkid_journal.reset();
    logstore_service().remove_log_store(LogStoreService::CTRL_LOG_FAMILY_IDX, m_sb->free_blks_journal_id);

    m_sb.destroy();
    stop_sb_flush_timer();
}

void ReplDevImpl::async_alloc_write(sisl::blob const& header, sisl::blob const& key, sisl::sg_list const& value,
                                    blk_alloc_hints&& hints, void* user_ctx) {
    m_state_machine->propose(header, key, value, user_ctx);
}

void ReplDevImpl::async_free_blks(int64_t lsn, const blkid_list_t& blkids) {
    m_state_store->add_free_pba_record(lsn, pbas);
}

std::shared_ptr< nuraft::state_machine > ReplDevImpl::get_state_machine() {
    if (!m_state_machine) { m_state_machine = std::make_shared< ReplicaStateMachine >(this) };
    return std::dynamic_pointer_cast< nuraft::state_machine >(m_state_machine);
}

bool ReplDevImpl::is_leader() const { return m_repl_svc_ctx->is_raft_leader(); }

void ReplDevImpl::send_data_service_response(sisl::io_blob_list_t const& outgoing_buf,
                                             boost::intrusive_ptr< sisl::GenericRpcData >& rpc_data) {
    m_repl_svc_ctx->send_data_service_response(outgoing_buf, rpc_data);
}

bool ReplDevImpl::register_data_service_apis(std::shared_ptr< nuraft_mesg::consensus_component >& messaging) {
    if (auto resp = messaging->bind_data_service_request(
            SEND_DATA, m_group_id,
            [this](sisl::io_blob const& incoming_buf, boost::intrusive_ptr< sisl::GenericRpcData >& rpc_data) {
                m_state_machine->on_data_received(incoming_buf, rpc_data);
            });
        !resp) {
        // LOG ERROR
        return false;
    }

    if (auto resp = messaging->bind_data_service_request(
            FETCH_DATA, m_group_id,
            [this](sisl::io_blob const& incoming_buf, boost::intrusive_ptr< sisl::GenericRpcData >& rpc_data) {
                m_state_machine->on_fetch_data_request(incoming_buf, rpc_data);
            });
        !resp) {
        // LOG ERROR
        return false;
    }

    return true;
}

void ReplDevImpl::send_in_data_channel(BlkId const& blkid, sisl::blob const& header, sisl::sg_list const& value) {
    m_repl_svc_ctx->data_service_request(
        SEND_DATA, data_rpc::serialize(data_channel_rpc_hdr{m_group_id, 0 /*replace with replica id*/}, {blkid}, value),
        nullptr); // response callback is null as this is fire and forget
}

void ReplDevImpl::fetch_data_from_leader(const blkid_list_t& remote_blkids) {
    m_repl_svc_ctx->data_service_request(
        FETCH_DATA,
        data_rpc::serialize(data_channel_rpc_hdr{m_group_id, 0 /*replace with replica id*/}, remote_blkids,
                            sisl::sg_list{.size = 0, .iovs = {}}),
        [this](sisl::io_blob const& incoming_buf) { m_state_machine->on_data_received(incoming_buf, nullptr); });
}

void ReplDevImpl::commit_lsn(repl_lsn_t lsn) {
    folly::SharedMutexWritePriority::ReadHolder holder(m_sb_lock);
    m_sb_in_mem.commit_lsn = lsn;
}

repl_lsn_t ReplDevImpl::get_last_commit_lsn() const {
    folly::SharedMutexWritePriority::ReadHolder holder(m_sb_lock);
    return m_sb_in_mem.commit_lsn;
}

//////////////// Private Methods ////////////////////
void ReplDevImpl::on_store_created(shared< HomeLogStore > store) {
    if (store->get_store_id() == m_sb->data_journal_id) {
        m_data_journal = std::make_shared< ReplLogStore >(std::move(store));
        RD_LOG(DEBUG, "Successfully opened data journal logstore={}", m_sb->data_journal_id);
    } else if (store->get_store_id() == m_sb->free_blks_journal_id) {
        m_free_blkid_journal = std::move(store);
        // m_free_pba_store->register_log_found_cb(
        //     [this](int64_t lsn, homestore::log_buffer buf, [[maybe_unused]] void* ctx) { m_entry_found_cb(lsn, buf);
        //     });
        RD_LOG(DEBUG, "Successfully opened data journal logstore={}", m_sb->data_journal_id);
    } else {
        RELEASE_ASSERT(false, "Invalid store_id={} opened for ReplDev", store->get_store_id());
    }

    // Start flush timer once both the journals are opened.
    if (m_data_journal && m_free_blkid_journal) { start_sb_flush_timer(); }
}
} // namespace homestore
