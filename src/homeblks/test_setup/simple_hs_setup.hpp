#pragma once

#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <vector>

#include "api/vol_interface.hpp"
#include "fds/utils.hpp"
#include "folly/SharedMutex.h"
#include "iomgr/aio_drive_interface.hpp"
#include "iomgr/iomgr.hpp"
#include "sds_logging/logging.h"

namespace homestore {
#define vol_interface VolInterface::get_instance()

struct simple_store_cfg {
    uint32_t m_ndevices = 2;
    std::vector< std::string > m_devs;
    uint32_t m_nthreads = 4;
    uint32_t m_nvols = 1;
    uint64_t m_dev_size = 4 * 1024 * 1024 * 1024ul;
    uint64_t m_app_mem_size = 2 * 1024 * 1024 * 1024ul;
    uint64_t m_max_io_size = 1 * 1024 * 1024ul;
    bool is_shadow_vol = false;
    bool is_read_verify = false; // Should we verify the write followed by sync read
    uint64_t m_run_time_ms = 30 * 1000;
    uint32_t m_qdepth = 64;
    uint8_t m_read_pct = 50;
};

struct simple_store_req : public vol_interface_req {
    ssize_t size;
    off_t offset;
    uint64_t cur_vol;
    bool done = false;

    simple_store_req(uint8_t* const buffer, const uint64_t lba, const uint32_t nlbas) :
        vol_interface_req(buffer, lba, nlbas) {}
    virtual ~simple_store_req() override {
        if (buffer) free(buffer);
    }
    simple_store_req(const simple_store_req&) = delete;
    simple_store_req(simple_store_req&&) noexcept = delete;
    simple_store_req& operator=(const simple_store_req&) = delete;
    simple_store_req& operator=(simple_store_req&&) noexcept = delete;

    // void free_yourself() override { delete this; }
    // std::string to_string() override { return "simple_store_req"; }
};

struct vol_info {
    VolumePtr vol_obj;
    uint64_t max_vol_blks = 0;
    std::shared_ptr< sisl::Bitset > blk_bits;
    folly::SharedMutexWritePriority bitset_rwlock;

    explicit vol_info(const VolumePtr& obj) {
        vol_obj = obj;
        max_vol_blks =
            VolInterface::get_instance()->get_system_capacity().initial_total_size / vol_interface->get_page_size(obj);
        blk_bits = std::make_unique< sisl::Bitset >(max_vol_blks);
    }

    vol_info(const vol_info& other) {
        vol_obj = other.vol_obj;
        max_vol_blks = other.max_vol_blks;
        blk_bits = other.blk_bits;
    }

    void update_blk_bits(std::function< void(sisl::Bitset*) >&& cb) {
        folly::SharedMutexWritePriority::WriteHolder holder(bitset_rwlock);
        cb(blk_bits.get());
    }

    void read_blk_bits(std::function< void(sisl::Bitset*) >&& cb) {
        folly::SharedMutexWritePriority::ReadHolder holder(bitset_rwlock);
        cb(blk_bits.get());
    }
};

class SimpleTestStore {
private:
    // TestTarget m_tgt;
    simple_store_cfg m_cfg;
    init_params m_init_params;
    std::vector< dev_info > m_dev_infos;

    std::mutex m_mutex;
    std::condition_variable m_init_done_cv;
    std::condition_variable m_io_done_cv;

    std::vector< vol_info > m_vol_infos;
    std::atomic< size_t > m_outstanding_ios = 0;
    std::atomic< uint64_t > m_write_cnt = 0;
    std::atomic< uint64_t > m_read_cnt = 0;
    std::atomic< uint64_t > m_read_err_cnt = 0;

    uint64_t m_vol_size = 512 * 1024 * 1024;
    Clock::time_point m_start_time;

    static constexpr uint32_t vol_page_size = 4096;
    static constexpr const char* vol_prefix = "vol";

public:
    SimpleTestStore(const simple_store_cfg& cfg) {
        m_cfg = cfg;
        if (m_cfg.m_devs.size() == 0) {
            for (uint32_t i = 0; i < m_cfg.m_ndevices; i++) {
                m_cfg.m_devs.push_back(std::string("/tmp/file") + std::to_string(i));
            }
        } else {
            m_cfg.m_ndevices = m_cfg.m_devs.size();
        }

        for (auto& d : m_cfg.m_devs) {
            m_dev_infos.push_back(dev_info({d}));
        }
        m_vol_size = (m_cfg.m_dev_size * 80) / 100 / m_cfg.m_nvols;
    }

    virtual void setup_init_params() {
        m_init_params.open_flags = homestore::io_flag::DIRECT_IO;
        m_init_params.min_virtual_page_size = 4096;
        m_init_params.app_mem_size = m_cfg.m_app_mem_size;
        m_init_params.disk_init = true;
        m_init_params.devices = m_dev_infos;
        m_init_params.init_done_cb =
            std::bind(&SimpleTestStore::init_done_cb, this, std::placeholders::_1, std::placeholders::_2);
        m_init_params.vol_mounted_cb =
            std::bind(&SimpleTestStore::vol_mounted_cb, this, std::placeholders::_1, std::placeholders::_2);
        m_init_params.vol_state_change_cb =
            std::bind(&SimpleTestStore::vol_state_change_cb, this, std::placeholders::_1, std::placeholders::_2,
                      std::placeholders::_3);
        m_init_params.vol_found_cb = std::bind(&SimpleTestStore::vol_found_cb, this, std::placeholders::_1);
        // m_init_params.end_of_batch_cb = std::bind(&SimpleTestStore::multi_vol_done_cb, this,
        // std::placeholders::_1);
        boost::uuids::string_generator gen;
        m_init_params.system_uuid = gen("01970496-0262-11e9-8eb2-f2801f1b9fd1");
    }

    virtual void start_homestore(bool wait_to_start = true) {
        setup_init_params();

        /* Create devices as files */
        for (auto& di : m_dev_infos) {
            std::ofstream ofs(di.dev_names.c_str(), std::ios::binary | std::ios::out);
            ofs.seekp(m_cfg.m_dev_size - 1);
            ofs.write("", 1);
        }

        /* Start IOManager and a test target to enable doing IO */
        iomanager.start(m_cfg.m_nthreads);

        VolInterface::init(m_init_params);
        if (wait_to_start) { wait_homestore_init_done(); }
    }

    void wait_homestore_init_done() {
        std::unique_lock< std::mutex > lk(m_mutex);
        m_init_done_cv.wait(lk);
    }

    void kickstart_io() {
        iomanager.run_on(iomgr::thread_regex::all_io, [this](iomgr::io_thread_addr_t addr) { process_new_request(); });
    }

    void wait_for_io_done() {
        std::unique_lock< std::mutex > lk(m_mutex);
        m_io_done_cv.wait(lk);
    }

    void shutdown() {
        LOGINFO("shutting homestore");
        VolInterface::get_instance()->shutdown();

        LOGINFO("stopping iomgr");
        iomanager.stop();
    }

    virtual void init_done_cb(std::error_condition err, const out_params& params) {
        if (err) {
            m_init_done_cv.notify_all();
            m_io_done_cv.notify_all();
            return;
        }

        for (auto v = 0u; v < m_cfg.m_nvols; v++) {
            create_volume(v);
        }

        m_init_done_cv.notify_all(); /* notify who is waiting for init to be completed */
        m_start_time = Clock::now();
        return;
    }

    virtual void vol_mounted_cb(const VolumePtr& vol_obj, vol_state state) {
        VolInterface::get_instance()->attach_vol_completion_cb(
            vol_obj, std::bind(&SimpleTestStore::process_completions, this, std::placeholders::_1));
    }

    virtual void vol_state_change_cb(const VolumePtr& vol, vol_state old_state, vol_state new_state) {}
    virtual bool vol_found_cb(boost::uuids::uuid uuid) { return true; }

    virtual void create_volume(uint32_t vol_ordinal) {
        vol_params vparam;
        vparam.page_size = vol_page_size;
        vparam.size = m_vol_size;
        vparam.io_comp_cb = std::bind(&SimpleTestStore::process_completions, this, std::placeholders::_1);
        vparam.uuid = boost::uuids::random_generator()();
        std::string name = std::string(vol_prefix) + std::to_string(vol_ordinal);
        memcpy(vparam.vol_name, name.c_str(), (name.length() + 1));

        auto vol_obj = VolInterface::get_instance()->create_volume(vparam);
        if (vol_obj == nullptr) { LOGFATAL("volume creation failed"); }
        m_vol_infos.emplace_back(vol_obj);
    }

    virtual void process_new_request() {
        if (m_outstanding_ios.load(std::memory_order_acquire) >= m_cfg.m_qdepth) {
            // Can't take any more IOs
            return;
        }

        size_t cnt = 0;
        /* send 8 IOs in one schedule */
        while (cnt < 8 && (m_outstanding_ios.load(std::memory_order_acquire) < m_cfg.m_qdepth)) {
            (rand() % 100 < m_cfg.m_read_pct) ? read() : write();
            ++cnt;
        }
    }

    virtual void write(int vordinal = -1, uint64_t lba = -1U, uint32_t nlbas = -1U) {
        static int last_write_vol = -1;
        // Pick the volume, number of blks, lbas if not specified
        if (vordinal == -1) { vordinal = ++last_write_vol % m_cfg.m_nvols; }
        auto& vinfo = m_vol_infos[vordinal];

        if (nlbas == -1U) {
            auto max_blks = m_cfg.m_max_io_size / vol_interface->get_page_size(vinfo.vol_obj);
            nlbas = (rand() % max_blks);
            if (nlbas == 0) { nlbas = 1; }
        }
        if (lba == -1U) { lba = rand() % (vinfo.max_vol_blks - nlbas); }
        vinfo.update_blk_bits([&](auto* bset) { bset->set_bits(lba, nlbas); }); // Mark those blks as busy

        uint64_t size = nlbas * vol_interface->get_page_size(vinfo.vol_obj);
        uint8_t* buf = iomanager.iobuf_alloc(512, size);
        assert(buf != nullptr);

        boost::intrusive_ptr< simple_store_req > req(new simple_store_req(buf, lba, nlbas));
        req->size = size;
        req->offset = lba * vol_interface->get_page_size(vinfo.vol_obj);
        req->cur_vol = vordinal;
        m_outstanding_ios.fetch_add(1, std::memory_order_acq_rel);
        m_write_cnt.fetch_add(1, std::memory_order_relaxed);

        LOGDEBUG("Writing {} {} ", lba, nlbas);
        auto ret_io = vol_interface->write(vinfo.vol_obj, req);
        if (ret_io != no_error) {
            assert(0);
            iomanager.iobuf_free(buf);
            m_outstanding_ios.fetch_sub(1, std::memory_order_acq_rel);
            LOGINFO("write io failure");
            vinfo.update_blk_bits([&](auto* bset) { bset->reset_bits(lba, nlbas); });
        }
    }

    virtual void read(int vordinal = -1, uint64_t lba = -1, uint64_t nlbas = -1U) {
        static int last_read_vol = -1;

        // Pick the volume, number of blks, lbas if not specified
        if (vordinal == -1) { vordinal = ++last_read_vol % m_cfg.m_nvols; }
        auto& vinfo = m_vol_infos[vordinal];

        if (nlbas == -1U) {
            auto max_blks = m_cfg.m_max_io_size / vol_interface->get_page_size(vinfo.vol_obj);
            nlbas = (rand() % max_blks) + 1;
        }
        if (lba == -1U) { lba = rand() % (vinfo.max_vol_blks - nlbas); }

        // Get the nearest continous set bits
        auto b = vinfo.blk_bits->get_next_contiguous_n_reset_bits(lba, nlbas);
        if (b.nbits == 0) { return; }
        lba = b.start_bit;
        uint64_t size = nlbas * vol_interface->get_page_size(vinfo.vol_obj);

        boost::intrusive_ptr< simple_store_req > req(new simple_store_req(nullptr, lba, nlbas));
        req->size = size;
        req->offset = lba * vol_interface->get_page_size(vinfo.vol_obj);
        req->cur_vol = vordinal;
        m_outstanding_ios.fetch_add(1, std::memory_order_acq_rel);
        m_read_cnt.fetch_add(1, std::memory_order_relaxed);

        LOGDEBUG("Reading {} {} ", lba, nlbas);
        auto ret_io = vol_interface->read(vinfo.vol_obj, req);
        if (ret_io != no_error) {
            m_outstanding_ios.fetch_sub(1, std::memory_order_acq_rel);
            m_read_err_cnt.fetch_add(1, std::memory_order_relaxed);
            LOGINFO("read io failure");
        }
    }

    void process_completions(const vol_interface_req_ptr& vol_req) {
        boost::intrusive_ptr< simple_store_req > req = boost::static_pointer_cast< simple_store_req >(vol_req);
        static Clock::time_point last_print_time = Clock::now();
        static uint64_t print_time = 30 * 1000;

        /* it validates that we don't have two completions for the same requests */
        DEBUG_ASSERT_EQ(req->done, false);
        assert(req->err == no_error);
        req->done = true;

        auto& vinfo = m_vol_infos[req->cur_vol];
        if (get_elapsed_time_ms(last_print_time) > print_time) {
            LOGINFO("write ios cmpled {}", m_write_cnt.load(std::memory_order_relaxed));
            LOGINFO("read ios cmpled {}", m_read_cnt.load(std::memory_order_relaxed));
            last_print_time = Clock::now();
        }

        LOGTRACE("IO DONE, req_id={}, outstanding_ios={}", req->request_id,
                 m_outstanding_ios.load(std::memory_order_relaxed));
        if (req->is_write() && (req->err == no_error) && m_cfg.is_read_verify) {
            //(void)VolInterface::get_instance()->sync_read(vinfo.vol_obj, req->lba, req->nlbas, req);
            LOGTRACE("IO DONE, req_id={}, outstanding_ios={}", req->request_id,
                     m_outstanding_ios.load(std::memory_order_relaxed));
        }

        vinfo.update_blk_bits([&](auto* bset) { bset->reset_bits(req->lba, req->nlbas); });
        m_outstanding_ios.fetch_sub(1, std::memory_order_acq_rel);

        if (get_elapsed_time_ms(m_start_time) > m_cfg.m_run_time_ms) {
            m_io_done_cv.notify_all();
        } else {
            process_new_request();
        }
    }
};

#if 0
void TestTarget::on_new_io_request(int fd, void* cookie, int event) {
    uint64_t temp;
    [[maybe_unused]] auto rsize = read(m_ev_fd, &temp, sizeof(uint64_t));
    m_test_store->process_new_request();
}
#endif
} // namespace homestore
