#include <sisl/logging/logging.h>
#include <sisl/options/options.h>
#include <main/vol_interface.hpp>
//#include <homeblks/home_blks.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <engine/homeds/bitmap/bitset.hpp>
#include <atomic>
#include <string>
#include <sisl/utility/thread_buffer.hpp>
#include <iomgr/io_environment.hpp>
#include <iomgr/aio_drive_interface.hpp>
#include <chrono>
#include <thread>

#include <mapping/mapping.hpp>

static constexpr size_t MAX_DEVICES{2};
static const std::string VOL_PREFIX{"/var/tmp/vol/"};

#if 0
struct dev_info {
    std::string dev_names;
};
#endif

std::array< std::string, 4 > names = {"/var/tmp/min1", "/var/tmp/min2", "/var/tmp/min3", "/var/tmp/min4"};
uint64_t max_vols = 2;
uint64_t max_num_writes;
uint64_t snap_after_writes = 4;
uint64_t run_time;
uint64_t num_threads = 1;
bool read_enable;
constexpr auto Ki = 1024ull;
constexpr auto Mi = Ki * Ki;
constexpr auto Gi = Ki * Mi;
uint64_t max_io_size = 1 * Mi;
uint64_t max_outstanding_ios = 8u;
uint64_t max_disk_capacity = 20 * Gi;
uint64_t match_cnt = 0;
uint64_t max_capacity;
using log_level = spdlog::level::level_enum;
SISL_LOGGING_INIT(HOMESTORE_LOG_MODS)

// SISL_LOGGING_INIT(cache_vmod_evict, cache_vmod_write, iomgr, btree_structures, btree_nodes, btree_generics,
//                 blkalloc, VMOD_VOL_MAPPING, httpserver_lmod, volume)

/*** CLI options ***/
SISL_OPTION_GROUP(
    test_volume,
    (run_time, "", "run_time", "run time for io", ::cxxopts::value< uint32_t >()->default_value("30"), "seconds"),
    (num_threads, "", "num_threads", "num threads for io", ::cxxopts::value< uint32_t >()->default_value("1"),
     "number"),
    (read_enable, "", "read_enable", "read enable 0 or 1", ::cxxopts::value< uint32_t >()->default_value("1"), "flag"),
    (max_disk_capacity, "", "max_disk_capacity", "max disk capacity",
     ::cxxopts::value< uint64_t >()->default_value("20"), "GB"),
    (max_volume, "", "max_volume", "max volume", ::cxxopts::value< uint64_t >()->default_value("2"), "number"),
    (max_num_writes, "", "max_num_writes", "max num of writes", ::cxxopts::value< uint64_t >()->default_value("8"),
     "number"),
    (enable_crash_handler, "", "enable_crash_handler", "enable crash handler 0 or 1",
     ::cxxopts::value< uint32_t >()->default_value("1"), "flag"))

#define ENABLED_OPTIONS logging, test_volume
SISL_OPTIONS_ENABLE(ENABLED_OPTIONS)
/*** ***/

#include <volume/volume.hpp>

uint64_t req_cnt = 0;
uint64_t req_free_cnt = 0;
class MinHS {
    std::vector< dev_info > device_info;

    bool init = true;
    struct vol_info_t {
        VolumePtr vol;
        int fd;
        int staging_fd;
        std::mutex vol_mutex;
        homeds::Bitset* m_vol_bm;
        uint64_t max_vol_blks;
        uint64_t cur_checkpoint;
        ~vol_info_t() { delete m_vol_bm; }
    };
    struct req {
        ssize_t size;
        off_t offset;
        uint64_t lba;
        uint32_t nlbas;
        int fd;
        uint8_t* buf;
        bool is_read;
        uint64_t cur_vol;
        req() {
            buf = nullptr;
            req_cnt++;
        }
        virtual ~req() {
            iomanager.iobuf_free(buf);
            req_free_cnt++;
        }
    };

private:
    std::mutex m_mutex;
    std::atomic< uint64_t > vol_indx;
    uint64_t max_vol_size;
    std::vector< std::shared_ptr< vol_info_t > > vol_info;
    std::vector< SnapshotPtr > snaps;
    std::atomic< uint64_t > vol_cnt;
    std::atomic< int > rdy_state;
    Clock::time_point startTime;
    std::condition_variable m_cv;

    int m_ev_fd;
    std::shared_ptr< iomgr::fd_info > m_ev_fdinfo;
    void* init_buf;
    std::atomic< size_t > outstanding_ios;
    uint64_t max_outstanding_ios = 8u;

    std::atomic< uint64_t > write_cnt = 0;
    std::atomic< uint64_t > read_cnt = 0;
    std::atomic< uint64_t > read_err_cnt = 0;

public:
    MinHS() : vol_indx(0) {}
    ~MinHS() { iomanager.stop(); }

    void process_completions(const vol_interface_req_ptr& vol_req) {
        static bool snap = true;
        static bool first = true;
        // LOGINFO("Process Completions {} {}", write_cnt, outstanding_ios);

        --outstanding_ios;
        if (outstanding_ios.load() == 0) {

            LOGINFO("DIFF Values:");
            vol_info[0]->vol->get_mapping_handle()->diff(vol_info[1]->vol->get_mapping_handle());
            LOGINFO("Vol 0");
            vol_info[0]->vol->print_tree();
            LOGINFO("Vol 1");
            vol_info[1]->vol->print_tree();
            // vol_info[0]->vol->print_tree();

            notify_cmpl();
        }
        req* request = (req*)vol_req->cookie;
        delete request; // no longer needed
    }

    void create_volume() {
        vol_params params;
        int cnt = vol_indx.fetch_add(1, std::memory_order_acquire);

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
    void vol_init(const VolumePtr& vol_obj) {
        std::string file_name = std::string(VolInterface::get_instance()->get_name(vol_obj));
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
        for (size_t i{0}; i < MAX_DEVICES; ++i) {
            const std::filesystem::path fpath{names[i]};
            if (init) {
                std::ofstream ofs{path.string(), std::ios::binary | std::ios::out};
                std::filesystem::resize_file(fpath, max_disk_capacity);
            }
            device_info.emplace_back(std::filesystem::canonical(fpath).string(), HSDevType::Data);
            max_capacity += max_disk_capacity;
        }

        ioenvironment.with_iomgr(num_threads);

        m_ev_fd = eventfd(0, EFD_NONBLOCK);
        m_ev_fdinfo = iomanager.add_fd(iomanager.default_drive_interface(), m_ev_fd,
                                       std::bind(&MinHS::process_ev_common, this, std::placeholders::_1,
                                                 std::placeholders::_2, std::placeholders::_3),
                                       EPOLLIN, 9, nullptr);

        max_vol_size = (60 * max_capacity) / (100 * max_vols);

        init_params params;

        params.open_flags = homestore::io_flag::DIRECT_IO;
        params.min_virtual_page_size = 4096;
        params.app_mem_size = 4 * 1024 * 1024 * 1024ul;
        params.devices = device_info;
        params.init_done_cb = std::bind(&MinHS::init_done_cb, this, std::placeholders::_1, std::placeholders::_2);
        params.vol_mounted_cb = std::bind(&MinHS::vol_mounted_cb, this, std::placeholders::_1, std::placeholders::_2);
        params.vol_state_change_cb = std::bind(&MinHS::vol_state_change_cb, this, std::placeholders::_1,
                                               std::placeholders::_2, std::placeholders::_3);
        params.vol_found_cb = std::bind(&MinHS::vol_found_cb, this, std::placeholders::_1);
        boost::uuids::string_generator gen;
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
            if (ret != 0) { return; }
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

    void read_vol(uint32_t cur, uint64_t lba, uint64_t nlbas) {
        uint64_t size = nlbas * VolInterface::get_instance()->get_page_size(vol_info[cur]->vol);
        uint8_t* buf = iomanager.iobuf_alloc(512, size);
        assert(buf != nullptr);

        req* req = new struct req();
        req->lba = lba;
        req->nlbas = nlbas;
        req->fd = vol_info[cur]->fd;
        req->is_read = true;
        req->size = size;
        req->offset = lba * VolInterface::get_instance()->get_page_size(vol_info[cur]->vol);
        req->buf = buf;
        req->cur_vol = cur;
        outstanding_ios++;
        read_cnt++;
        auto vreq = VolInterface::get_instance()->create_vol_interface_req();
        vreq->cookie = req;
        auto ret_io = VolInterface::get_instance()->read(vol_info[cur]->vol, lba, nlbas, vreq);
        if (ret_io != no_error) {
            outstanding_ios--;
            read_err_cnt++;
            std::unique_lock< std::mutex > lk(vol_info[cur]->vol_mutex);
            vol_info[cur]->m_vol_bm->reset_bits(lba, nlbas);
        }
    }

    void write_vol(uint32_t cur, uint64_t lba, uint64_t nlbas) {
        uint64_t size = nlbas * VolInterface::get_instance()->get_page_size(vol_info[cur]->vol);
        uint8_t* buf = iomanager.iobuf_alloc(512, size);
        uint8_t* buf1 = iomanager.iobuf_alloc(512, size);

        /* buf will be owned by homestore after sending the IO. so we need to allocate buf1 which will be used to
         * write to a file after ios are completed.
         */
        assert(buf != nullptr);
        assert(buf1 != nullptr);
        populate_buf(buf, size, lba, cur);

        memcpy(buf1, buf, size);

        req* req = new struct req();
        req->lba = lba;
        req->nlbas = nlbas;
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
        auto vreq = VolInterface::get_instance()->create_vol_interface_req();
        vreq->cookie = req;
        auto ret_io = VolInterface::get_instance()->write(vol_info[cur]->vol, lba, buf, nlbas, vreq);
        if (ret_io != no_error) {
            assert(false);
            iomanager.iobuf_free(buf);
            outstanding_ios--;
            std::unique_lock< std::mutex > lk(vol_info[cur]->vol_mutex);
            vol_info[cur]->m_vol_bm->reset_bits(lba, nlbas);
        }
        LOGINFO("Wrote {} {} ", lba, nlbas);
    }

    void same_write(int cur) {
        static int widx = 0;
        struct lba_nlbas_s {
            uint64_t lba;
            uint64_t nlbas;
        } lba_nlbas[10] =
            //{{100, 16}, {132, 8}, {200, 8}, {220, 8}, {116, 8}, {130, 8}, {138, 8}, {142, 8}};
            /* 100-115, 116-123, 130-131, 132-137, 138-139, 140-141, 142-145, 146-149, 200-207, 220-227 */
            {{100, 16}, {132, 8}, {200, 8}, {220, 8}, {116, 8}, {120, 8}, {130, 8}, {270, 8}};
        /* 100-115, 116-119, 120-123, 124-127, 130-131, 132-137, 138-139, 200-207, 220-227, 270-277 */

        write_vol(cur, lba_nlbas[widx].lba, lba_nlbas[widx].nlbas);
        widx++;
    }

    void same_read() { read_vol(0, 5, 16); }

    void random_write(int cur) {
        // static uint64_t prev_lba = 0;
        uint64_t lba, nlbas;
        uint64_t max_blks = max_io_size / VolInterface::get_instance()->get_page_size(vol_info[cur]->vol);
    start:
        lba = rand() % (vol_info[cur]->max_vol_blks - max_blks);
        nlbas = rand() % max_blks;
        if (nlbas == 0) nlbas = 1;
        {
            std::unique_lock< std::mutex > lk(vol_info[cur]->vol_mutex);
            if (nlbas && vol_info[cur]->m_vol_bm->is_bits_reset(lba, nlbas)) {
                vol_info[cur]->m_vol_bm->set_bits(lba, nlbas);
            } else {
                goto start;
            }
        }

        uint64_t size = nlbas * VolInterface::get_instance()->get_page_size(vol_info[cur]->vol);

        uint8_t* buf = iomanager.iobuf_alloc(512, size);
        uint8_t* buf1 = iomanager.iobuf_alloc(512, size);
        assert(buf != nullptr && buf1 != nullptr);
        populate_buf(buf, size, lba, 0);
        memcpy(buf1, buf, size);

        req* req = new struct req();

        req->lba = lba;
        req->nlbas = nlbas;
        req->size = size;
        req->offset = lba * VolInterface::get_instance()->get_page_size(vol_info[cur]->vol);
        req->buf = buf1;
        req->fd = vol_info[cur]->fd;
        req->is_read = false;
        req->cur_vol = 0;

        ++outstanding_ios;
        ++write_cnt;

        auto vreq = VolInterface::get_instance()->create_vol_interface_req();
        vreq->cookie = req;
        auto ret_io = VolInterface::get_instance()->write(vol_info[cur]->vol, lba, buf, nlbas, vreq);
        if (ret_io != no_error) {
            assert(false);
            iomanager.iobuf_free(buf);
            outstanding_ios--;
            std::unique_lock< std::mutex > lk(vol_info[cur]->vol_mutex);
            vol_info[cur]->m_vol_bm->reset_bits(lba, nlbas);
        }
        LOGINFO("Wrote {} {} ", lba, nlbas);
    }

    uint64_t get_elapsed_time(Clock::time_point startTime) {
        std::chrono::seconds sec = std::chrono::duration_cast< std::chrono::seconds >(Clock::now() - startTime);
        return sec.count();
    }

    void process_ev_common(int fd, void* cookie, int event) {
        static bool first = true;

        uint64_t temp;
        [[maybe_unused]] auto rsize = read(m_ev_fd, &temp, sizeof(uint64_t));

        LOGINFO("Write Cnt {} Max Num Writes {}", write_cnt, max_num_writes);
        if (write_cnt >= max_num_writes) {
            LOGINFO("Writes done.. waiting for completions {} {}", write_cnt, outstanding_ios);
            return;
        }
        if ((write_cnt < max_num_writes) ||
            (outstanding_ios.load() < max_outstanding_ios && get_elapsed_time(startTime) < run_time)) {
            /* raise an event */
            iomanager.fd_reschedule(fd, event);
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
        init_buf = iomanager.iobuf_alloc(512, max_io_size);
        bzero(init_buf, max_io_size);

        outstanding_ios = 0;
        uint64_t temp = 1;
        [[maybe_unused]] auto wsize = write(m_ev_fd, &temp, sizeof(uint64_t));

        return;
    }

    void vol_mounted_cb(const VolumePtr& vol_obj, vol_state state) {
        assert(!init);
        int cnt = vol_cnt.fetch_add(1, std::memory_order_relaxed);
        vol_init(vol_obj);
        auto cb = [this](boost::intrusive_ptr< vol_interface_req > vol_req) { process_completions(vol_req); };
        VolInterface::get_instance()->attach_vol_completion_cb(vol_obj, cb);
    }

    void vol_state_change_cb(const VolumePtr& vol, vol_state old_state, vol_state new_state) { assert(false); }

    bool vol_found_cb(boost::uuids::uuid uuid) {
        assert(!init);
        return true;
    }

    void shutdown() {
        std::unique_lock< std::mutex > lk(m_mutex);
        vol_info.clear();
        bool success = VolInterface::shutdown();
        assert(success);
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
    SISL_OPTIONS_LOAD(argc, argv, ENABLED_OPTIONS)
    sisl::logging::SetLogger("test_volume");
    // sisl::logging::install_crash_handler();
    spdlog::set_pattern("[%D %T.%f] [%^%L%$] [%t] %v");

    run_time = SISL_OPTIONS["run_time"].as< uint32_t >();
    num_threads = SISL_OPTIONS["num_threads"].as< uint32_t >();
    read_enable = SISL_OPTIONS["read_enable"].as< uint32_t >();
    max_disk_capacity = ((SISL_OPTIONS["max_disk_capacity"].as< uint64_t >()) * (1ul << 30));
    max_vols = SISL_OPTIONS["max_volume"].as< uint64_t >();
    max_num_writes = SISL_OPTIONS["max_num_writes"].as< uint64_t >();
    hs->init_homestore();
    hs->wait_cmpl();
    hs->shutdown();
    //    hs->remove_files();
    return 0;
}
