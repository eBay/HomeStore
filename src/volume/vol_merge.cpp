#include <iomgr/iomgr.hpp>
#include <sds_logging/logging.h>
#include <sds_options/options.h>
#include <main/vol_interface.hpp>
//#include <volume/home_blks.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <fstream>
#include <iostream>
#include <string>
#include <homeds/bitmap/bitset.hpp>
#include <atomic>
#include <string>
#include <utility/thread_buffer.hpp>
#include <chrono>
#include <thread>

#include <mapping/mapping.hpp>

#define MAX_DEVICES 2
#define VOL_PREFIX "/var/tmp/vol/"

#if 0
struct dev_info {
    std::string dev_names;
};
#endif
THREAD_BUFFER_INIT;

std::array< std::string, 4 > names = {"/var/tmp/min1", "/var/tmp/min2", "/var/tmp/min3", "/var/tmp/min4"};
uint64_t                     max_vols = 2;
uint64_t                     max_num_writes;
uint64_t                     snap_after_writes = 4;
uint64_t                     run_time;
uint64_t                     num_threads = 1;
bool                         read_enable;
constexpr auto               Ki = 1024ull;
constexpr auto               Mi = Ki * Ki;
constexpr auto               Gi = Ki * Mi;
uint64_t                     max_io_size = 1 * Mi;
uint64_t                     max_outstanding_ios = 8u;
uint64_t                     max_disk_capacity = 10 * Gi;
uint64_t                     match_cnt = 0;
uint64_t                     max_capacity;
using log_level = spdlog::level::level_enum;
SDS_LOGGING_INIT(HOMESTORE_LOG_MODS)

// SDS_LOGGING_INIT(cache_vmod_evict, cache_vmod_write, iomgr, btree_structures, btree_nodes, btree_generics,
//                 varsize_blk_alloc, VMOD_VOL_MAPPING, httpserver_lmod, volume)

class test_ep : public iomgr::EndPoint {
public:
    test_ep(std::shared_ptr< iomgr::ioMgr > iomgr) : iomgr::EndPoint(iomgr) {}
    void shutdown_local() override {}
    void init_local() override {}
    void print_perf() override {}
};

/*** CLI options ***/
SDS_OPTION_GROUP(
    test_volume,
    (run_time, "", "run_time", "run time for io", ::cxxopts::value< uint32_t >()->default_value("30"), "seconds"),
    (num_threads, "", "num_threads", "num threads for io", ::cxxopts::value< uint32_t >()->default_value("1"),
     "number"),
    (read_enable, "", "read_enable", "read enable 0 or 1", ::cxxopts::value< uint32_t >()->default_value("1"), "flag"),
    (max_disk_capacity, "", "max_disk_capacity", "max disk capacity",
     ::cxxopts::value< uint64_t >()->default_value("5"), "GB"),
    (max_volume, "", "max_volume", "max volume", ::cxxopts::value< uint64_t >()->default_value("2"), "number"),
    (max_num_writes, "", "max_num_writes", "max num of writes", ::cxxopts::value< uint64_t >()->default_value("8"),
     "number"),
    (enable_crash_handler, "", "enable_crash_handler", "enable crash handler 0 or 1",
     ::cxxopts::value< uint32_t >()->default_value("1"), "flag"))

#define ENABLED_OPTIONS logging, home_blks, test_volume
SDS_OPTIONS_ENABLE(ENABLED_OPTIONS)
/*** ***/

#include <volume/volume.hpp>

uint64_t req_cnt = 0;
uint64_t req_free_cnt = 0;
class MinHS {
    std::vector< dev_info > device_info;

    bool init = true;
    struct vol_info_t {
        VolumePtr       vol;
        int             fd;
        int             staging_fd;
        std::mutex      vol_mutex;
        homeds::Bitset* m_vol_bm;
        uint64_t        max_vol_blks;
        uint64_t        cur_checkpoint;
        ~vol_info_t() { delete m_vol_bm; }
    };
    struct req : vol_interface_req {
        ssize_t  size;
        off_t    offset;
        uint64_t lba;
        uint32_t nblks;
        int      fd;
        uint8_t* buf;
        bool     is_read;
        uint64_t cur_vol;
        req() {
            buf = nullptr;
            req_cnt++;
        }
        virtual ~req() {
            free(buf);
            req_free_cnt++;
        }
    };

private:
    std::mutex                                   m_mutex;
    std::atomic< uint64_t >                      vol_indx;
    std::shared_ptr< iomgr::ioMgr >              iomgr_obj;
    uint64_t                                     max_vol_size;
    std::vector< std::shared_ptr< vol_info_t > > vol_info;
    std::vector< SnapshotPtr >                   snaps;
    std::atomic< uint64_t >                      vol_cnt;
    std::atomic< int >                           rdy_state;
    Clock::time_point                            startTime;
    std::condition_variable                      m_cv;

    test_ep*              ep;
    int                   ev_fd;
    void*                 init_buf;
    std::atomic< size_t > outstanding_ios;
    uint64_t              max_outstanding_ios = 8u;

    std::atomic< uint64_t > write_cnt = 0;
    std::atomic< uint64_t > read_cnt = 0;
    std::atomic< uint64_t > read_err_cnt = 0;

public:
    MinHS() : vol_indx(0) {}
    ~MinHS() {
        if (iomgr_obj) {
            iomgr_obj->stop();
            iomgr_obj.reset();
        }
    }

    void process_completions(const vol_interface_req_ptr& vol_req) {
        static bool snap = true;
        static bool first = true;
        //LOGINFO("Process Completions {} {}", write_cnt, outstanding_ios);

        --outstanding_ios;
        if (outstanding_ios.load() == 0) {

            LOGINFO("DIFF Values:");
            vol_info[0]->vol->get_mapping_handle()->diff(vol_info[1]->vol->get_mapping_handle());
            LOGINFO("Vol 0");
            vol_info[0]->vol->print_tree();
            LOGINFO("Vol 1");
            vol_info[1]->vol->print_tree();
            //vol_info[0]->vol->print_tree();

            notify_cmpl();
        }
    }

    void create_volume() {
        vol_params params;
        int        cnt = vol_indx.fetch_add(1, std::memory_order_acquire);

        params.page_size = 4096;
        params.size = max_vol_size;
        params.io_comp_cb = ([this](const vol_interface_req_ptr& vol_req) { process_completions(vol_req); });
        params.uuid = boost::uuids::random_generator()();
        std::string name = VOL_PREFIX + std::to_string(cnt);
        memcpy(params.vol_name, name.c_str(), (name.length() + 1));

        auto vol_obj = VolInterface::get_instance()->create_volume(params);
        if (vol_obj == nullptr) {
            LOGINFO("creation failed");
            return;
        }

        /* create file for verification */
        /*RMK: No need - done in init */

        /*RMK: No staging file */

        vol_init(vol_obj);
    }

    typedef std::shared_ptr< Volume > VolumePtr;
    void                              vol_init(const VolumePtr& vol_obj) {
        std::string                   file_name = std::string(VolInterface::get_instance()->get_name(vol_obj));
        std::shared_ptr< vol_info_t > info = std::make_shared< vol_info_t >();
        info->vol = vol_obj;
        info->fd = open(file_name.c_str(), O_RDWR | O_DIRECT);
        info->staging_fd = -1;
        info->max_vol_blks = VolInterface::get_instance()->get_vol_capacity(vol_obj).initial_total_size /
            VolInterface::get_instance()->get_page_size(vol_obj);
        info->m_vol_bm = new homeds::Bitset(info->max_vol_blks);
        info->cur_checkpoint = 0;

        assert(info->fd > 0);

        std::unique_lock< std::mutex > lk(m_mutex);
        vol_info.push_back(info);
    }

    void init_homestore(void) {
        for (int i = 0; i < MAX_DEVICES; i++) {
            dev_info temp_info;
            temp_info.dev_names = names[i];
            device_info.push_back(temp_info);
            if (init) {
                std::ofstream ofs(names[i].c_str(), std::ios::binary | std::ios::out);
                ofs.seekp(max_disk_capacity - 1);
                ofs.write("", 1);
                ofs.close();
            }
            max_capacity += max_disk_capacity;
        }

        max_vol_size = (60 * max_capacity) / (100 * max_vols);

        iomgr_obj = std::make_shared< iomgr::ioMgr >(1, num_threads);

        init_params params;

        params.flag = homestore::io_flag::DIRECT_IO;
        params.min_virtual_page_size = 4096;
        params.cache_size = 4 * 1024 * 1024 * 1024ul;
        params.disk_init = init;
        params.devices = device_info;
        params.is_file = true;
        params.iomgr = iomgr_obj;
        params.init_done_cb = std::bind(&MinHS::init_done_cb, this, std::placeholders::_1, std::placeholders::_2);
        params.vol_mounted_cb = std::bind(&MinHS::vol_mounted_cb, this, std::placeholders::_1, std::placeholders::_2);
        params.vol_state_change_cb = std::bind(&MinHS::vol_state_change_cb, this, std::placeholders::_1,
                                               std::placeholders::_2, std::placeholders::_3);
        params.vol_found_cb = std::bind(&MinHS::vol_found_cb, this, std::placeholders::_1);
        boost::uuids::string_generator gen;
        params.system_uuid = gen("01970496-0262-11e9-8eb2-f1082f1b9fd1");
        VolInterface::init(params);
    }

    void init_files(int cur) {
        for (off_t offset = 0; offset < (off_t)max_vol_size; offset = offset + max_io_size) {
            ssize_t write_size;
            if (offset + max_io_size > max_vol_size) {
                write_size = max_vol_size - offset;
            } else {
                write_size = max_io_size;
            }

            auto ret = pwrite(vol_info[cur]->fd, init_buf, write_size, (off_t)offset);
            assert(ret = write_size);
            if (ret != 0) {
                return;
            }
        }
    }

    void populate_buf(uint8_t* buf, uint64_t size, uint64_t lba, int cur) {
        LOGINFO("Populate: Lba {} Size {}", lba, size);
        for (uint64_t write_sz = 0; (write_sz + sizeof(uint64_t)) < size; write_sz = write_sz + sizeof(uint64_t)) {
            if (lba & 0x1) {
                *((uint64_t*)(buf + write_sz)) = 0xaaaaaaaaaaaaaaaa;
            } else {
                *((uint64_t*)(buf + write_sz)) = 0x5555555555555555;
            }

            ++lba;
        }
    }

    void read_vol(uint32_t cur, uint64_t lba, uint64_t nblks) {
        uint8_t* buf = nullptr;
        uint64_t size = nblks * VolInterface::get_instance()->get_page_size(vol_info[cur]->vol);
        auto     ret = posix_memalign((void**)&buf, 4096, size);
        if (ret) {
            assert(0);
        }
        assert(buf != nullptr);
        boost::intrusive_ptr< req > req(new struct req());
        req->lba = lba;
        req->nblks = nblks;
        req->fd = vol_info[cur]->fd;
        req->is_read = true;
        req->size = size;
        req->offset = lba * VolInterface::get_instance()->get_page_size(vol_info[cur]->vol);
        req->buf = buf;
        req->cur_vol = cur;
        outstanding_ios++;
        read_cnt++;
        auto ret_io = VolInterface::get_instance()->read(vol_info[cur]->vol, lba, nblks, req);
        if (ret_io != no_error) {
            outstanding_ios--;
            read_err_cnt++;
            std::unique_lock< std::mutex > lk(vol_info[cur]->vol_mutex);
            vol_info[cur]->m_vol_bm->reset_bits(lba, nblks);
        }
    }

    void write_vol(uint32_t cur, uint64_t lba, uint64_t nblks) {
        uint8_t* buf = nullptr;
        uint8_t* buf1 = nullptr;
        uint64_t size = nblks * VolInterface::get_instance()->get_page_size(vol_info[cur]->vol);
        auto     ret = posix_memalign((void**)&buf, 4096, size);
        if (ret) {
            assert(0);
        }
        ret = posix_memalign((void**)&buf1, 4096, size);
        assert(!ret);
        /* buf will be owned by homestore after sending the IO. so we need to allocate buf1 which will be used to
         * write to a file after ios are completed.
         */
        assert(buf != nullptr);
        assert(buf1 != nullptr);
        populate_buf(buf, size, lba, cur);

        memcpy(buf1, buf, size);

        boost::intrusive_ptr< req > req(new struct req());
        req->lba = lba;
        req->nblks = nblks;
        req->size = size;
        req->offset = lba * VolInterface::get_instance()->get_page_size(vol_info[cur]->vol);
        req->buf = buf1;
        req->fd = vol_info[cur]->fd;
        req->is_read = false;
        req->cur_vol = cur;
        ++outstanding_ios;
        ++write_cnt;
        ret = pwrite(vol_info[cur]->staging_fd, req->buf, req->size, req->offset);
        assert(ret == req->size);
        auto ret_io = VolInterface::get_instance()->write(vol_info[cur]->vol, lba, buf, nblks, req);
        if (ret_io != no_error) {
            assert(0);
            free(buf);
            outstanding_ios--;
            std::unique_lock< std::mutex > lk(vol_info[cur]->vol_mutex);
            vol_info[cur]->m_vol_bm->reset_bits(lba, nblks);
        }
        LOGINFO("Wrote {} {} ", lba, nblks);
    }

    void same_write(int cur) {
        static int widx = 0;
        struct lba_nblks_s {
            uint64_t lba;
            uint64_t nblks;
        } lba_nblks[10] = 
                //{{100, 16}, {132, 8}, {200, 8}, {220, 8}, {116, 8}, {130, 8}, {138, 8}, {142, 8}};
                /* 100-115, 116-123, 130-131, 132-137, 138-139, 140-141, 142-145, 146-149, 200-207, 220-227 */
                {{100, 16}, {132, 8}, {200, 8}, {220, 8}, {116, 8}, {120, 8}, {130, 8}, {270, 8}};
                /* 100-115, 116-119, 120-123, 124-127, 130-131, 132-137, 138-139, 200-207, 220-227, 270-277 */
                        

        write_vol(cur, lba_nblks[widx].lba, lba_nblks[widx].nblks);
        widx++;
    }

    void same_read() { read_vol(0, 5, 16); }

    void random_write(int cur) {
        // static uint64_t prev_lba = 0;
        uint64_t lba, nblks;
        uint64_t max_blks = max_io_size / VolInterface::get_instance()->get_page_size(vol_info[cur]->vol);
    start:
        lba = rand() % (vol_info[cur]->max_vol_blks - max_blks);
        nblks = rand() % max_blks;
        if (nblks == 0)
            nblks = 1;
        {
            std::unique_lock< std::mutex > lk(vol_info[cur]->vol_mutex);
            if (nblks && vol_info[cur]->m_vol_bm->is_bits_reset(lba, nblks)) {
                vol_info[cur]->m_vol_bm->set_bits(lba, nblks);
            } else {
                goto start;
            }
        }

        uint8_t *buf, *buf1;
        uint64_t size = nblks * VolInterface::get_instance()->get_page_size(vol_info[cur]->vol);

        buf = buf1 = nullptr;
        if (posix_memalign((void**)&buf, 4096, size)) {
            assert(0);
        }
        if (posix_memalign((void**)&buf1, 4096, size)) {
            assert(0);
        }

        assert(buf != nullptr && buf1 != nullptr);
        populate_buf(buf, size, lba, 0);
        memcpy(buf1, buf, size);

        boost::intrusive_ptr< req > req(new struct req());

        req->lba = lba;
        req->nblks = nblks;
        req->size = size;
        req->offset = lba * VolInterface::get_instance()->get_page_size(vol_info[cur]->vol);
        req->buf = buf1;
        req->fd = vol_info[cur]->fd;
        req->is_read = false;
        req->cur_vol = 0;

        ++outstanding_ios;
        ++write_cnt;

        auto ret_io = VolInterface::get_instance()->write(vol_info[cur]->vol, lba, buf, nblks, req);
        if (ret_io != no_error) {
            assert(0);
            free(buf);
            outstanding_ios--;
            std::unique_lock< std::mutex > lk(vol_info[cur]->vol_mutex);
            vol_info[cur]->m_vol_bm->reset_bits(lba, nblks);
        }
        LOGINFO("Wrote {} {} ", lba, nblks);
    }

    uint64_t get_elapsed_time(Clock::time_point startTime) {
        std::chrono::seconds sec = std::chrono::duration_cast< std::chrono::seconds >(Clock::now() - startTime);
        return sec.count();
    }

    void process_ev_common(int fd, void* cookie, int event) {
        uint64_t    temp;
        static bool first = true;

        auto rsize = read(ev_fd, &temp, sizeof(uint64_t));

        iomgr_obj->process_done(fd, event);

        LOGINFO("Write Cnt {} Max Num Writes {}", write_cnt, max_num_writes);
        if (write_cnt >= max_num_writes) {
            LOGINFO("Writes done.. waiting for completions {} {}", write_cnt, outstanding_ios);
            return;
        }
        if ((write_cnt < max_num_writes) ||
            (outstanding_ios.load() < max_outstanding_ios && get_elapsed_time(startTime) < run_time)) {
            /* raise an event */
            iomgr_obj->fd_reschedule(fd, event);
        }

        size_t cnt = 0;

        while (cnt < 4 && outstanding_ios < max_outstanding_ios) {
            LOGINFO("Calling SAME write");
            if (first) {
                same_write(0);
            } else {
                same_write(1);
            }
            ++cnt;
        }

        first = false;
    }

    void init_done_cb(std::error_condition err, const out_params& params) {
        rdy_state = 1;

        LOGINFO("Init DONE");
        if (init) {
            for (uint64_t i = 0; i < max_vols; i++) {
                create_volume();
                init_files(i);
            }
            // init_files();
            startTime = Clock::now();
        } else {
            assert(vol_cnt == max_vols);
        }
        max_io_size = params.max_io_size;
        auto ret = posix_memalign((void**)&init_buf, 4096, max_io_size);
        assert(!ret);
        bzero(init_buf, max_io_size);
        ev_fd = eventfd(0, EFD_NONBLOCK);

        iomgr_obj->add_fd(ev_fd, [this](auto fd, auto cookie, auto event) { process_ev_common(fd, cookie, event); },
                          EPOLLIN, 9, nullptr);
        ep = new test_ep(iomgr_obj);
        iomgr_obj->add_ep(ep);
        iomgr_obj->start();
        outstanding_ios = 0;
        uint64_t temp = 1;
        auto     wsize = write(ev_fd, &temp, sizeof(uint64_t));
        return;
    }

    void vol_mounted_cb(const VolumePtr& vol_obj, vol_state state) {
        assert(!init);
        int cnt = vol_cnt.fetch_add(1, std::memory_order_relaxed);
        vol_init(vol_obj);
        auto cb = [this](boost::intrusive_ptr< vol_interface_req > vol_req) { process_completions(vol_req); };
        VolInterface::get_instance()->attach_vol_completion_cb(vol_obj, cb);
    }

    void vol_state_change_cb(const VolumePtr& vol, vol_state old_state, vol_state new_state) { assert(0); }

    bool vol_found_cb(boost::uuids::uuid uuid) {
        assert(!init);
        return true;
    }

    void shutdown_callback(bool success) {
        VolInterface::del_instance();
        assert(success);
    }

    void shutdown() {
        std::unique_lock< std::mutex > lk(m_mutex);
        vol_info.clear();
        VolInterface::get_instance()->shutdown(std::bind(&MinHS::shutdown_callback, this, std::placeholders::_1));
    }

    void wait_cmpl() {
        std::unique_lock< std::mutex > lk(m_mutex);
        m_cv.wait(lk);
    }

    void notify_cmpl() { m_cv.notify_all(); }
};

int main(int argc, char* argv[]) {
    auto hs = new MinHS;

    srand(time(0));
    SDS_OPTIONS_LOAD(argc, argv, ENABLED_OPTIONS)
    sds_logging::SetLogger("test_volume");
    // sds_logging::install_crash_handler();
    spdlog::set_pattern("[%D %T.%f] [%^%L%$] [%t] %v");

    run_time = SDS_OPTIONS["run_time"].as< uint32_t >();
    num_threads = SDS_OPTIONS["num_threads"].as< uint32_t >();
    read_enable = SDS_OPTIONS["read_enable"].as< uint32_t >();
    max_disk_capacity = ((SDS_OPTIONS["max_disk_capacity"].as< uint64_t >()) * (1ul << 30));
    max_vols = SDS_OPTIONS["max_volume"].as< uint64_t >();
    max_num_writes = SDS_OPTIONS["max_num_writes"].as< uint64_t >();
    hs->init_homestore();
    hs->wait_cmpl();
    hs->shutdown();
    //    hs->remove_files();
    return 0;
}
