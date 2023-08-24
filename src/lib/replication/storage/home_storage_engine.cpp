#include "home_storage_engine.h"
#include <sisl/fds/utils.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <homestore/blkdata_service.hpp>
#include <iomgr/iomgr_timer.hpp>
#include "service/repl_config.h"

#define SM_STORE_LOG(level, msg, ...)                                                                                  \
    LOG##level##MOD_FMT(home_replication, ([&](fmt::memory_buffer& buf, const char* msgcb, auto&&... args) -> bool {   \
                            fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[{}:{}] "},                          \
                                            fmt::make_format_args(file_name(__FILE__), __LINE__));                     \
                            fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[{}={}] "},                          \
                                            fmt::make_format_args("rs", boost::uuids::to_string(m_sb_in_mem.uuid)));   \
                            fmt::vformat_to(fmt::appender{buf}, fmt::string_view{msgcb},                               \
                                            fmt::make_format_args(std::forward< decltype(args) >(args)...));           \
                            return true;                                                                               \
                        }),                                                                                            \
                        msg, ##__VA_ARGS__);

SISL_LOGGING_DECL(home_replication)

namespace home_replication {
static constexpr store_lsn_t to_store_lsn(repl_lsn_t raft_lsn) { return raft_lsn - 1; }
static constexpr repl_lsn_t to_repl_lsn(store_lsn_t store_lsn) { return store_lsn + 1; }

///////////////////////////// HomeStateMachineStore Section ////////////////////////////
HomeStateMachineStore::HomeStateMachineStore(uuid_t rs_uuid) : m_sb{"replica_set"} {
    LOGDEBUGMOD(home_replication, "Creating new instance of replica state machine store for uuid={}", rs_uuid);

    // Create a superblk for the replica set.
    m_sb.create(sizeof(home_rs_superblk));
    m_sb->uuid = rs_uuid;

    // Create logstore to store the free pba records
    m_free_pba_store =
        homestore::logstore_service().create_new_log_store(homestore::LogStoreService::CTRL_LOG_FAMILY_IDX, true);
    if (!m_free_pba_store) { throw std::runtime_error("Failed to create log store"); }
    m_sb->free_pba_store_id = m_free_pba_store->get_store_id();
    m_sb.write();
    m_sb_in_mem = *m_sb;
    SM_STORE_LOG(DEBUG, "New free pba record logstore={} created", m_sb->free_pba_store_id);

    start_sb_flush_timer();
}

HomeStateMachineStore::HomeStateMachineStore(const homestore::superblk< home_rs_superblk >& rs_sb) :
        m_sb{"replica_set"} {
    LOGDEBUGMOD(home_replication, "Opening existing replica state machine store for uuid={}", rs_sb->uuid);
    m_sb = rs_sb;
    m_sb_in_mem = *m_sb;
    SM_STORE_LOG(DEBUG, "Opening free pba record logstore={}", m_sb->free_pba_store_id);
    homestore::logstore_service().open_log_store(homestore::LogStoreService::CTRL_LOG_FAMILY_IDX,
                                                 m_sb->free_pba_store_id, true,
                                                 bind_this(HomeStateMachineStore::on_store_created, 1));
}

HomeStateMachineStore::~HomeStateMachineStore() { stop_sb_flush_timer(); }

void HomeStateMachineStore::on_store_created(std::shared_ptr< homestore::HomeLogStore > free_pba_store) {
    assert(m_sb->free_pba_store_id == free_pba_store->get_store_id());
    m_free_pba_store = free_pba_store;
    // m_free_pba_store->register_log_found_cb(
    //     [this](int64_t lsn, homestore::log_buffer buf, [[maybe_unused]] void* ctx) { m_entry_found_cb(lsn, buf); });
    SM_STORE_LOG(DEBUG, "Successfully opened free pba record logstore={}", m_sb->free_pba_store_id);

    start_sb_flush_timer();
}

void HomeStateMachineStore::destroy() {
    SM_STORE_LOG(DEBUG, "Free pba record logstore={} is being physically removed", m_sb->free_pba_store_id);
    homestore::logstore_service().remove_log_store(homestore::LogStoreService::CTRL_LOG_FAMILY_IDX,
                                                   m_sb->free_pba_store_id);
    m_free_pba_store.reset();
    m_sb.destroy();
    stop_sb_flush_timer();
}

pba_list_t HomeStateMachineStore::alloc_pbas(uint32_t size) { return homestore::data_service().alloc_blks(size); }

void HomeStateMachineStore::async_write(const sisl::sg_list& sgs, const pba_list_t& in_pba_list,
                                        const io_completion_cb_t& cb) {
    homestore::blk_alloc_hints hints;
    static thread_local std::vector< homestore::BlkId > in_blkids;
    in_blkids.clear();

    for (const auto& pba : in_pba_list) {
        in_blkids.emplace_back(homestore::BlkId{pba});
    }

    // async write with input block ids;
    homestore::data_service().async_write(sgs, hints, in_blkids, cb);
}

void HomeStateMachineStore::async_read(pba_t pba, sisl::sg_list& sgs, uint32_t size, const io_completion_cb_t& cb) {
    homestore::data_service().async_read(homestore::BlkId{pba}, sgs, size, cb);
}

uint32_t HomeStateMachineStore::pba_to_size(pba_t pba) const {
    return homestore::BlkId{pba}.get_nblks() * homestore::data_service().get_page_size();
}

void HomeStateMachineStore::free_pba(pba_t pba) {
    homestore::data_service().async_free_blk(homestore::BlkId{pba},
                                             []([[maybe_unused]] std::error_condition err) { assert(!err); });
}

//////////////// StateMachine Superblock/commit update section /////////////////////////////
void HomeStateMachineStore::commit_lsn(repl_lsn_t lsn) {
    folly::SharedMutexWritePriority::ReadHolder holder(m_sb_lock);
    m_sb_in_mem.commit_lsn = lsn;
}

repl_lsn_t HomeStateMachineStore::get_last_commit_lsn() const {
    folly::SharedMutexWritePriority::ReadHolder holder(m_sb_lock);
    return m_sb_in_mem.commit_lsn;
}

void HomeStateMachineStore::start_sb_flush_timer() {
    iomanager.run_on(homestore::logstore_service().truncate_thread(), [this](iomgr::io_thread_addr_t) {
        m_sb_flush_timer_hdl =
            iomanager.schedule_thread_timer(HR_DYNAMIC_CONFIG(commit_lsn_flush_ms) * 1000 * 1000, true /* recurring */,
                                            nullptr, [this](void*) { flush_super_block(); });
    });
}

void HomeStateMachineStore::stop_sb_flush_timer() {
    if (m_sb_flush_timer_hdl != iomgr::null_timer_handle) {
        iomanager.run_on(
            homestore::logstore_service().truncate_thread(),
            [this](iomgr::io_thread_addr_t) {
                iomanager.cancel_timer(m_sb_flush_timer_hdl);
                m_sb_flush_timer_hdl = iomgr::null_timer_handle;
            },
            iomgr::wait_type_t::spin);
    }
}

void HomeStateMachineStore::flush_super_block() {
    bool do_flush{false};
    {
        folly::SharedMutexWritePriority::WriteHolder holder(m_sb_lock);
        if (m_sb_in_mem.commit_lsn > m_last_flushed_commit_lsn) {
            *m_sb = m_sb_in_mem;
            do_flush = true;
        }
    }

    if (do_flush) { m_sb.write(); }
}

//////////////// Free PBA Record section /////////////////////////////
void HomeStateMachineStore::add_free_pba_record(repl_lsn_t lsn, const pba_list_t& pbas) {
    // Serialize it as
    // # num pbas (N)       4 bytes
    // +---
    // | PBA                8 bytes
    // +--- repeat N
    uint32_t size_needed = sizeof(uint32_t) + (pbas.size() * sizeof(pba_t));
    sisl::io_blob b{size_needed, 0 /* unaligned */};
    *(r_cast< uint32_t* >(b.bytes)) = uint32_cast(pbas.size());

    pba_t* raw_ptr = r_cast< pba_t* >(b.bytes + sizeof(uint32_t));
    for (const auto pba : pbas) {
        *raw_ptr = pba;
        ++raw_ptr;
    }
    m_last_write_lsn.store(lsn);
    m_free_pba_store->write_async(to_store_lsn(lsn), b, nullptr,
                                  [](int64_t, sisl::io_blob& b, homestore::logdev_key, void*) { b.buf_free(); });
}

void HomeStateMachineStore::get_free_pba_records(repl_lsn_t start_lsn, repl_lsn_t end_lsn,
                                                 const std::function< void(repl_lsn_t, const pba_list_t&) >& cb) {
    m_free_pba_store->foreach (to_store_lsn(start_lsn),
                               [end_lsn, &cb](store_lsn_t lsn, const homestore::log_buffer& entry) -> bool {
                                   auto rlsn = to_repl_lsn(lsn);
                                   bool ret = (rlsn < end_lsn - 1);
                                   if (rlsn < end_lsn) {
                                       pba_list_t plist;
                                       uint32_t num_pbas = *(r_cast< uint32_t* >(entry.bytes()));
                                       pba_t* raw_ptr = r_cast< pba_t* >(entry.bytes() + sizeof(uint32_t));
                                       for (uint32_t i{0}; i < num_pbas; ++i) {
                                           plist.push_back(*raw_ptr);
                                           ++raw_ptr;
                                       }
                                       cb(rlsn, plist);
                                   }
                                   return ret;
                               });
}

void HomeStateMachineStore::remove_free_pba_records_upto(repl_lsn_t lsn) {
    m_free_pba_store->truncate(to_store_lsn(lsn));
    m_last_write_lsn.store(0);
}

void HomeStateMachineStore::flush_free_pba_records() {
    auto last_lsn = m_last_write_lsn.load();
    m_free_pba_store->flush_sync(last_lsn == 0 ? homestore::invalid_lsn() : to_store_lsn(last_lsn));
}

// TODO: PENDING CHECKPOINT AND FLUSH CODE
} // namespace home_replication
