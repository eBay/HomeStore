
//
// Created by Yaming Kuang 1/15/2020 
//

#include "meta_blks_mgr.hpp"
#include "homeblks/home_blks.hpp"
#include <sds_logging/logging.h>
#include <sds_options/options.h>
#include <gtest/gtest.h>
#include <iomgr/iomgr.hpp>
#include <iomgr/aio_drive_interface.hpp>
#include <fstream>
#include <cstdint>

using namespace homestore;

THREAD_BUFFER_INIT;
RCU_REGISTER_INIT;
SDS_LOGGING_INIT(HOMESTORE_LOG_MODS)

SDS_OPTIONS_ENABLE(logging, test_meta_blk_mgr)

SDS_LOGGING_DECL(test_meta_blk_mgr)

static void start_homestore(uint32_t ndevices, uint64_t dev_size, uint32_t nthreads) {
    std::vector< dev_info > device_info;
    std::mutex start_mutex;
    std::condition_variable cv;
    bool inited = false;

    LOGINFO("creating {} device files with each of size {} ", ndevices, dev_size);
    for (uint32_t i = 0; i < ndevices; i++) {
        std::string fpath = "/tmp/test_meta_blk_mgr_" + std::to_string(i + 1);
        std::ofstream ofs(fpath.c_str(), std::ios::binary | std::ios::out);
        ofs.seekp(dev_size - 1);
        ofs.write("", 1);
        ofs.close();
        device_info.push_back({fpath});
    }

    LOGINFO("Starting iomgr with {} threads", nthreads);
    iomanager.start(1 /* total interfaces */, nthreads);
    iomanager.add_drive_interface(
        std::dynamic_pointer_cast< iomgr::DriveInterface >(std::make_shared< iomgr::AioDriveInterface >()),
        true /* is_default */);

    uint64_t app_mem_size = ((ndevices * dev_size) * 15) / 100;
    LOGINFO("Initialize and start HomeBlks with app_mem_size = {}", app_mem_size);

    boost::uuids::string_generator gen;
    init_params params;
    params.open_flags = homestore::io_flag::DIRECT_IO;
    params.min_virtual_page_size = 4096;
    params.app_mem_size = app_mem_size;
    params.disk_init = true;
    params.devices = device_info;
    params.is_file = true;
    params.init_done_cb = [&](std::error_condition err, const out_params& params) {
        LOGINFO("HomeBlks Init completed");
        {
            std::unique_lock< std::mutex > lk(start_mutex);
            inited = true;
        }
        cv.notify_all();
    };
    params.vol_mounted_cb = [](const VolumePtr& vol_obj, vol_state state) {};
    params.vol_state_change_cb = [](const VolumePtr& vol, vol_state old_state, vol_state new_state) {};
    params.vol_found_cb = [](boost::uuids::uuid uuid) -> bool { return true; };
    params.system_uuid = gen("01970496-0262-11e9-8eb2-f2801f1b9fd1");
    VolInterface::init(params);

    std::unique_lock< std::mutex > lk(start_mutex);
    cv.wait(lk, [&] { return inited; });
}

struct Param {
    uint64_t num_io;
    uint64_t run_time;
    uint32_t per_write;
    uint32_t per_update;
    uint32_t per_remove;
    bool fixed_wrt_sz_enabled;
    uint32_t fixed_wrt_sz;
    uint32_t min_wrt_sz;
    uint32_t max_wrt_sz;
};

static Param gp;

struct sb_info_t {
    void* cookie;
    std::string str;
};

class VMetaBlkMgrTest : public ::testing::Test {

    enum class meta_op_type { write = 1, update = 2, remove = 3 };
    const std::string mtype = "TEST";

public:
    uint64_t get_elapsed_time(Clock::time_point start) {
        std::chrono::seconds sec = std::chrono::duration_cast< std::chrono::seconds >(Clock::now() - start);
        return sec.count();
    }

    bool keep_running() {
        HS_ASSERT(DEBUG, m_mbm->get_size() >= m_mbm->get_used_size(), "total size:{} less than used size: {}",
                  m_mbm->get_size(), m_mbm->get_used_size());
        auto free_size = m_mbm->get_size() - m_mbm->get_used_size();
        if (free_size < gp.max_wrt_sz) { return false; }
        if (get_elapsed_time(m_start_time) >= gp.run_time || io_cnt() >= gp.num_io) { return false; }
        return true;
    }

    uint64_t io_cnt() { return m_update_cnt + m_wrt_cnt + m_rm_cnt; }

    void gen_rand_buf(uint8_t* s, uint32_t len) {
        static const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        for (size_t i = 0u; i < len - 1; ++i) {
            s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
        }
        s[len - 1] = 0;
    }

    // size between 512 ~ 8192, 512 aligned;
    uint32_t rand_size(bool overflow) {
        if (overflow) {
            std::random_device rd;
            std::default_random_engine g(rd());
            std::uniform_int_distribution< long unsigned > dist(gp.min_wrt_sz, gp.max_wrt_sz);
            return sisl::round_up(dist(g), dma_boundary);
        } else {
            std::random_device rd;
            std::default_random_engine g(rd());
            std::uniform_int_distribution< long unsigned > dist(64, META_BLK_CONTEXT_SZ);
            return dist(g);
        }
    }

    uint64_t total_size_written(uint64_t context_sz) {
        if (context_sz <= META_BLK_CONTEXT_SZ) {
            return META_BLK_PAGE_SZ;
        } else {
            if ((context_sz - META_BLK_CONTEXT_SZ) % META_BLK_OVF_CONTEXT_SZ == 0) {
                return (1 + ((context_sz - META_BLK_CONTEXT_SZ) / META_BLK_OVF_CONTEXT_SZ)) * META_BLK_PAGE_SZ;
            } else {
                return (2 + ((context_sz - META_BLK_CONTEXT_SZ) / META_BLK_OVF_CONTEXT_SZ)) * META_BLK_PAGE_SZ;
            }
        }
    }

    void do_sb_write(bool overflow) {
        m_wrt_cnt++;
        auto sz_to_wrt = rand_size(overflow);

        uint8_t* buf = iomanager.iobuf_alloc(512, sz_to_wrt);
        gen_rand_buf(buf, sz_to_wrt);

        void* cookie = nullptr;
        m_mbm->add_sub_sb(mtype, buf, sz_to_wrt, cookie);
        assert(cookie != nullptr);

        meta_blk* mblk = (meta_blk*)cookie;
        if (overflow) {
            assert(sz_to_wrt >= META_BLK_PAGE_SZ);
            assert(mblk->hdr.h.ovf_blkid.to_integer() != BlkId::invalid_internal_id());
        } else {
            assert(sz_to_wrt <= META_BLK_CONTEXT_SZ);
            assert(mblk->hdr.h.ovf_blkid.to_integer() == BlkId::invalid_internal_id());
        }

        // verify context_sz
        HS_ASSERT(RELEASE, mblk->hdr.h.context_sz == sz_to_wrt, "context_sz mismatch: {}/{}",
                  (uint64_t)mblk->hdr.h.context_sz, sz_to_wrt);

        auto bid = mblk->hdr.h.blkid.to_integer();
        // save cookie;
        std::unique_lock< std::mutex > lg(m_mtx);
        HS_ASSERT(RELEASE, m_write_sbs.find(bid) == m_write_sbs.end(), "cookie already in the map.");

        // save to cache
        m_write_sbs[bid].cookie = cookie;
        m_write_sbs[bid].str = std::string((char*)buf, sz_to_wrt);

        m_total_wrt_sz += total_size_written(sz_to_wrt);
        // HS_ASSERT(RELEASE, m_total_wrt_sz == m_mbm->get_used_size(), "Used size mismatch: {}/{}", m_total_wrt_sz,
        //         m_mbm->get_used_size());

        free(buf);
    }

    void do_sb_remove() {
        m_rm_cnt++;
        auto sz = m_write_sbs.size();
        auto it = m_write_sbs.begin();
        std::advance(it, rand() % m_write_sbs.size());

        auto cookie = it->second.cookie;
        m_total_wrt_sz -= total_size_written(((meta_blk*)cookie)->hdr.h.context_sz);

        m_mbm->remove_sub_sb(cookie);
        m_write_sbs.erase(it);
        assert(sz == m_write_sbs.size() + 1);

        //    HS_ASSERT(RELEASE, m_total_wrt_sz == m_mbm->get_used_size(), "Used size mismatch: {}/{}", m_total_wrt_sz,
        //            m_mbm->get_used_size());
    }

    void do_sb_update() {
        m_update_cnt++;

        std::unique_lock< std::mutex > lg(m_mtx);
        auto it = m_write_sbs.begin();
        std::advance(it, rand() % m_write_sbs.size());

        bool overflow = rand() % 2;
        auto sz_to_wrt = rand_size(overflow);
        uint8_t* buf = iomanager.iobuf_alloc(512, sz_to_wrt);

        gen_rand_buf(buf, sz_to_wrt);

        void* cookie = it->second.cookie;
        m_write_sbs.erase(it);

        // update is in-place, the metablk is re-used, ovf-blk is freed then re-allocated;
        // so it is okay to decreaase at this point, then add it back after update completes;
        m_total_wrt_sz -= total_size_written(((meta_blk*)cookie)->hdr.h.context_sz);

        m_mbm->update_sub_sb(mtype, buf, sz_to_wrt, cookie);
        auto bid = ((meta_blk*)cookie)->hdr.h.blkid.to_integer();
        HS_ASSERT(RELEASE, m_write_sbs.find(bid) == m_write_sbs.end(), "cookie already in the map.");
        m_write_sbs[bid].cookie = cookie;
        m_write_sbs[bid].str = std::string((char*)buf, sz_to_wrt);

        // verify context_sz
        meta_blk* mblk = (meta_blk*)cookie;
        HS_ASSERT(RELEASE, mblk->hdr.h.context_sz == sz_to_wrt, "context_sz mismatch: {}/{}",
                  (uint64_t)mblk->hdr.h.context_sz, sz_to_wrt);

        // update total size, add size of metablk back;
        m_total_wrt_sz += total_size_written(sz_to_wrt);
        //        HS_ASSERT(RELEASE, m_total_wrt_sz == m_mbm->get_used_size(), "Used size mismatch: {}/{}",
        //        m_total_wrt_sz,
        //                m_mbm->get_used_size());

        free(buf);
    }

    // compare m_cb_blks with m_write_sbs;
    void verify_cb_blks() {
        std::unique_lock< std::mutex > lg(m_mtx);
        HS_ASSERT_CMP(DEBUG, m_cb_blks.size(), ==, m_write_sbs.size());

        for (auto it = m_write_sbs.cbegin(); it != m_write_sbs.end(); it++) {
            auto bid = it->first;
            auto it_cb = m_cb_blks.find(bid);

            HS_ASSERT(RELEASE, it_cb != m_cb_blks.end(), "Saved bid during write not found in recover callback.");

            // the saved buf should be equal to the buf received in the recover callback;
            int ret = it->second.str.compare(it_cb->second);
            HS_ASSERT(DEBUG, ret == 0, "Context data mismatch: Saved: {}, callback: {}.", it->second.str,
                      it_cb->second);
        }
    }

    void execute() {
        m_wrt_cnt = 0;
        m_rm_cnt = 0;
        m_update_cnt = 0;
        m_total_wrt_sz = 0;

        m_start_time = Clock::now();
        m_mbm = MetaBlkMgr::instance();

        // there is some overhead by MetaBlkMgr, such as meta ssb;
        m_total_wrt_sz = m_mbm->get_used_size();

        m_mbm->deregister_handler(mtype);
        m_mbm->register_handler(mtype,
                                [this](meta_blk* mblk, sisl::byte_view<> buf, size_t size) {
                                    if (mblk) {
                                        std::unique_lock< std::mutex > lg(m_mtx);
                                        m_cb_blks[mblk->hdr.h.blkid.to_integer()] =
                                            std::string((char*)(buf.bytes()), size);
                                    }
                                },
                                [this](bool success) { assert(success); });

        while (keep_running()) {
            switch (get_op()) {
            case meta_op_type::write:
                do_sb_write(rand() % 2);
                break;
            case meta_op_type::remove:
                do_sb_remove();
                break;
            case meta_op_type::update:
                do_sb_update();
                break;
            default:
                break;
            }
        }
    }

    void recover() {
        // do recover and callbacks will be triggered;
        m_mbm->recover(false);
    }

    void validate() {
        // verify received blks via callbaks are all good;
        verify_cb_blks();
    }

    void scan_blks() { m_mbm->scan_meta_blks(); }

    meta_op_type get_op() {
        if (do_write()) {
            return meta_op_type::write;
        } else if (do_update()) {
            return meta_op_type::update;
        } else {
            return meta_op_type::remove;
        }
    }

    uint32_t write_ratio() {
        if (m_wrt_cnt == 0) return 0;
        return (100 * m_wrt_cnt) / (m_update_cnt + m_wrt_cnt + m_rm_cnt);
    }

    uint32_t update_ratio() {
        if (m_update_cnt == 0) return 0;
        return (100 * m_update_cnt) / (m_update_cnt + m_wrt_cnt + m_rm_cnt);
    }

    bool do_update() {
        if (update_ratio() < gp.per_update) { return true; }
        return false;
    }

    bool do_write() {
        if (write_ratio() < gp.per_write) { return true; }
        return false;
    }

private:
    uint64_t m_wrt_cnt = 0;
    uint64_t m_update_cnt = 0;
    uint64_t m_rm_cnt = 0;
    uint64_t m_total_wrt_sz = 0;
    Clock::time_point m_start_time;
    MetaBlkMgr* m_mbm = nullptr;
    std::map< uint64_t, sb_info_t > m_write_sbs; // during write, save blkid to buf map;
    std::map< uint64_t, std::string > m_cb_blks; // during recover, save blkid to buf map;
    std::mutex m_mtx;
};

TEST_F(VMetaBlkMgrTest, VMetaBlkMgrTest) {
    this->execute();

    // simulate reboot case that MetaBlkMgr will scan the disk for all the metablks that were written;
    this->scan_blks();

    this->recover();

    this->validate();
}

SDS_OPTION_GROUP(
    test_meta_blk_mgr,
    (num_threads, "", "num_threads", "number of threads", ::cxxopts::value< uint32_t >()->default_value("2"), "number"),
    (num_devs, "", "num_devs", "number of devices to create", ::cxxopts::value< uint32_t >()->default_value("2"),
     "number"),
    (fixed_write_size_enabled, "", "fixed_write_size_enabled", "fixed write size enabled 0 or 1",
     ::cxxopts::value< uint32_t >()->default_value("0"), "flag"),
    (fixed_write_size, "", "fixed_write_size", "fixed write size", ::cxxopts::value< uint32_t >()->default_value("512"),
     "number"),
    (dev_size_mb, "", "dev_size_mb", "size of each device in MB", ::cxxopts::value< uint64_t >()->default_value("5120"),
     "number"),
    (run_time, "", "run_time", "running time in seconds", ::cxxopts::value< uint64_t >()->default_value("30"),
     "number"),
    (min_write_size, "", "min_write_size", "minimum write size", ::cxxopts::value< uint32_t >()->default_value("4096"),
     "number"),
    (max_write_size, "", "max_write_size", "maximum write size", ::cxxopts::value< uint32_t >()->default_value("65536"),
     "number"),
    (num_io, "", "num_io", "number of io", ::cxxopts::value< uint64_t >()->default_value("3000"), "number"),
    (per_update, "", "per_update", "update percentage", ::cxxopts::value< uint32_t >()->default_value("20"), "number"),
    (per_write, "", "per_write", "write percentage", ::cxxopts::value< uint32_t >()->default_value("60"), "number"),
    (per_remove, "", "per_remove", "remove percentage", ::cxxopts::value< uint32_t >()->default_value("20"), "number"),
    (hb_stats_port, "", "hb_stats_port", "Stats port for HTTP service",
     cxxopts::value< int32_t >()->default_value("5004"), "port"));

int main(int argc, char* argv[]) {
    SDS_OPTIONS_LOAD(argc, argv, logging, test_meta_blk_mgr);
    testing::InitGoogleTest(&argc, argv);
    sds_logging::SetLogger("test_meta_blk_mgr");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");

    start_homestore(SDS_OPTIONS["num_devs"].as< uint32_t >(), SDS_OPTIONS["dev_size_mb"].as< uint64_t >() * 1024 * 1024,
                    SDS_OPTIONS["num_threads"].as< uint32_t >());

    gp.num_io = SDS_OPTIONS["num_io"].as< uint64_t >();
    gp.run_time = SDS_OPTIONS["run_time"].as< uint64_t >();
    gp.per_update = SDS_OPTIONS["per_update"].as< uint32_t >();
    gp.per_write = SDS_OPTIONS["per_write"].as< uint32_t >();
    gp.fixed_wrt_sz_enabled = SDS_OPTIONS["fixed_write_size_enabled"].as< uint32_t >();
    gp.fixed_wrt_sz = SDS_OPTIONS["fixed_write_size"].as< uint32_t >();
    gp.min_wrt_sz = SDS_OPTIONS["min_write_size"].as< uint32_t >();
    gp.max_wrt_sz = SDS_OPTIONS["max_write_size"].as< uint32_t >();

    if (gp.per_update == 0 || gp.per_write == 0 || (gp.per_update + gp.per_write + gp.per_remove != 100)) {
        gp.per_update = 20;
        gp.per_write = 60;
        gp.per_remove = 20;
    }

    if (gp.max_wrt_sz < gp.min_wrt_sz || gp.min_wrt_sz < META_BLK_CONTEXT_SZ) {
        gp.min_wrt_sz = 4096;
        gp.max_wrt_sz = 65536;
        LOGINFO("Invalid input for min/max wrt sz: defaulting to {}/{}", gp.min_wrt_sz, gp.max_wrt_sz);
    }

    LOGINFO("Testing with run_time: {}, num_io: {}, write/update/remove percentage: {}/{}/{}, min/max io size: {}/{}",
            gp.run_time, gp.num_io, gp.per_write, gp.per_update, gp.per_remove, gp.min_wrt_sz, gp.max_wrt_sz);

    auto res = RUN_ALL_TESTS();
    VolInterface::get_instance()->shutdown();
    iomanager.stop();

    return res;
}
