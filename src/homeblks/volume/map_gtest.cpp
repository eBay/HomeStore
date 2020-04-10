#include <gtest/gtest.h>
#include <fstream>
#include <iostream>
#include <thread>
#include <sds_logging/logging.h>
#include <sds_options/options.h>
#include "mapping.hpp"
#include <iomgr/iomgr.hpp>
#include <iomgr/aio_drive_interface.hpp>

extern "C" {
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/timeb.h>
}

SDS_LOGGING_INIT(HOMESTORE_LOG_MODS)
THREAD_BUFFER_INIT;

using namespace std;
using namespace homestore;

extern "C" __attribute__((no_sanitize_address)) const char* __asan_default_options() { return "detect_leaks=false"; }

#define MAX_LBA 1000000
#define MAX_NLBA 128
#define MAX_BLK 10000000
#define MAX_SIZE 7 * Gi
uint64_t num_ios;
uint64_t num_threads;

/* Simulating a test target - similar to SCST or NVMEoF target */
class MapTest;
class TestTarget {
public:
    TestTarget(MapTest* test) { m_test_store = test; }
    void init() {
        m_ev_fd = eventfd(0, EFD_NONBLOCK);
        m_ev_fdinfo = iomanager.add_fd(m_ev_fd,
                                       std::bind(&TestTarget::on_new_io_request, this, std::placeholders::_1,
                                                 std::placeholders::_2, std::placeholders::_3),
                                       EPOLLIN, 9, nullptr);
    }

    void shutdown() { iomanager.remove_fd(m_ev_fdinfo); }
    void kickstart_io() {
        uint64_t temp = 1;
        [[maybe_unused]] auto wsize = write(m_ev_fd, &temp, sizeof(uint64_t));
    }

    void on_new_io_request(int fd, void* cookie, int event);

    void io_request_done() {
        uint64_t temp = 1;
        [[maybe_unused]] auto wsize = write(m_ev_fd, &temp, sizeof(uint64_t));
    }

private:
    int m_ev_fd;
    std::shared_ptr< iomgr::fd_info > m_ev_fdinfo;
    MapTest* m_test_store;
};

struct MapTest : public testing::Test {
protected:
    std::condition_variable m_cv;
    std::mutex m_cv_mtx;
    std::mutex mutex;
    homeds::Bitset* m_lba_bm;
    homeds::Bitset* m_blk_bm;
    long long int m_blk_id_arr[MAX_LBA];
    mapping* m_map;

    uint64_t Ki = 1024ull;
    uint64_t Mi = Ki * Ki;
    uint64_t Gi = Ki * Mi;

    std::vector< dev_info > device_info;
    std::atomic< uint64_t > seq_Id;
    bool start = false;
    boost::uuids::uuid uuid;
    int fd;
    int ev_fd;
    std::atomic< size_t > outstanding_ios;
    uint64_t max_outstanding_ios = 64u;
    std::atomic< size_t > issued_ios;
    uint64_t max_issue_ios = 0u;
    std::atomic< size_t > unreturned_lbas;
    TestTarget m_tgt;

public:
    MapTest() : m_tgt(this) {
        m_lba_bm = new homeds::Bitset(MAX_LBA);
        m_blk_bm = new homeds::Bitset(MAX_BLK);
        for (auto i = 0u; i < MAX_LBA; i++)
            m_blk_id_arr[i] = -1;
        srand(time(0));
    }

    virtual ~MapTest() {}

    void process_free_blk_comp_callback() {
        // remove this assert if someone is actually calling this funciton
        assert(0);
    }

    void process_free_blk_callback(Free_Blk_Entry fbe) {
        // remove this assert if someone is actually calling this funciton
        assert(0);
    }

    void process_metadata_completions(const volume_req_ptr& req) {
        assert(!req->is_read);
        // verify old blks
        auto index = 0u;
        auto st = req->lba;
        auto et = st + req->nlbas - 1;
        while (st < req->lba + req->nlbas) {
            if (m_blk_id_arr[st] == -1) { // unused blkid
                st++;
                continue;
            }
            if (index == req->blkIds_to_free.size()) {
                m_map->print_tree();
                std::this_thread::sleep_for(std::chrono::seconds(5));
                assert(0); // less blks freed than expected
            }
            long long int bst = req->blkIds_to_free[index].m_blkId.get_id() + req->blkIds_to_free[index].m_blk_offset;
            long long int ben = bst + (int)(req->blkIds_to_free[index].m_nblks_to_free) - 1;
            while (bst <= ben) {
                if (st > et) assert(0);                 // more blks freeed than expected
                if (m_blk_id_arr[st] != bst) assert(0); // blks mistmach
                bst++;
                st++;
            }
            index++; // move to next free blk
        }
        assert(index == req->blkIds_to_free.size()); // check if more blks freed

        // update new blks
        for (auto st = req->lba, bst = req->blkId.get_id(); st < req->lba + req->nlbas; st++, bst++)
            m_blk_id_arr[st] = bst;

        // release lbas
        release_lba_range_lock(req->lba, req->nlbas);

        // release blkids
        for (auto& ptr : req->blkIds_to_free)
            release_blkId_lock(ptr.m_blkId, ptr.m_blk_offset, ptr.m_nblks_to_free);

        auto outstanding = outstanding_ios.fetch_sub(1);
        if (issued_ios.load() == max_issue_ios && outstanding == 1) {
            notify_cmpl();
        } else if (issued_ios.load() < max_issue_ios) {
            uint64_t temp = 1;
            [[maybe_unused]] auto rsize = read(ev_fd, &temp, sizeof(uint64_t));
            uint64_t size = write(ev_fd, &temp, sizeof(uint64_t));
        }
    }

    void process_completions(const vol_interface_req_ptr& hb_req) {}

    void start_homestore() {
        /* start homestore */
        /* create files */

        dev_info temp_info;
        temp_info.dev_names = "file101";
        device_info.push_back(temp_info);
        std::ofstream ofs(temp_info.dev_names.c_str(), std::ios::binary | std::ios::out);
        ofs.seekp(MAX_SIZE - 1);
        ofs.write("", 1);

        iomanager.start(1 /* total interfaces */, num_threads);
        iomanager.add_drive_interface(
            std::dynamic_pointer_cast< iomgr::DriveInterface >(std::make_shared< iomgr::AioDriveInterface >()),
            true /* is_default */);
        m_tgt.init();

        init_params params;
#ifndef NDEBUG
        params.open_flags = homestore::io_flag::BUFFERED_IO;
#else
        params.open_flags = homestore::io_flag::DIRECT_IO;
#endif
        params.min_virtual_page_size = 4096;
        params.cache_size = 4 * 1024 * 1024 * 1024ul;
        params.disk_init = true;
        params.devices = device_info;
        params.is_file = true;
        params.init_done_cb = std::bind(&MapTest::init_done_cb, this, std::placeholders::_1, std::placeholders::_2);
        params.vol_mounted_cb = std::bind(&MapTest::vol_mounted_cb, this, std::placeholders::_1, std::placeholders::_2);
        params.vol_state_change_cb = std::bind(&MapTest::vol_state_change_cb, this, std::placeholders::_1,
                                               std::placeholders::_2, std::placeholders::_3);
        params.vol_found_cb = std::bind(&MapTest::vol_found_cb, this, std::placeholders::_1);
        boost::uuids::string_generator gen;
        params.system_uuid = gen("01970496-0262-11e9-8eb2-f2801f1b9fd1");
        uuid = params.system_uuid;
        VolInterface::init(params);
    }

    bool vol_found_cb(boost::uuids::uuid uuid) { return true; }

    void vol_mounted_cb(const VolumePtr& vol_obj, vol_state state) {
        vol_init(vol_obj);
        auto cb = [this](const vol_interface_req_ptr& vol_req) { process_completions(vol_req); };
        VolInterface::get_instance()->attach_vol_completion_cb(vol_obj, cb);
    }

    void vol_init(const VolumePtr& vol_obj) { open(VolInterface::get_instance()->get_name(vol_obj), O_RDWR); }

    void vol_state_change_cb(const VolumePtr& vol, vol_state old_state, vol_state new_state) { assert(0); }

    void init_done_cb(std::error_condition err, const out_params& params1) {
        /* create volume */
        outstanding_ios = 0;
        max_issue_ios = num_ios;
        issued_ios = 0;
        unreturned_lbas = 0;
        vol_params params;
        params.page_size = 4096;
        params.size = MAX_SIZE;
        params.uuid = boost::uuids::random_generator()();
        std::string name = "vol1";
        memcpy(params.vol_name, name.c_str(), (name.length() + 1));
        m_map = new mapping(params.size, params.page_size, name,
                            std::bind(&MapTest::process_metadata_completions, this, std::placeholders::_1),
                            std::bind(&MapTest::process_free_blk_callback, this, std::placeholders::_1));

        start = true;
        m_tgt.kickstart_io();
    }

    void process_new_request() {
        if (issued_ios.load() == max_issue_ios) return;
        outstanding_ios++;
        issued_ios++;
        if (issued_ios % 10000 == 0) LOGINFO("Writes issued:{}", issued_ios.load());
        random_read();
        random_write();
    }

    void release_lba_range_lock(uint64_t& lba, uint64_t nlbas) {
        std::unique_lock< std::mutex > lk(mutex);
        assert(m_lba_bm->is_bits_set(lba, nlbas));
        assert(nlbas <= 128);
        unreturned_lbas.fetch_sub(nlbas);
        m_lba_bm->reset_bits(lba, nlbas);
    }

    void release_blkId_lock(BlkId& blkId, uint8_t offset, uint8_t nblks_to_free) {
        std::unique_lock< std::mutex > lk(mutex);
        assert(m_blk_bm->is_bits_set(blkId.get_id() + offset, nblks_to_free));
        m_blk_bm->reset_bits(blkId.get_id() + offset, nblks_to_free);
    }

    void generate_random_blkId(BlkId& blkId, uint64_t nblks) {
        uint64_t retry = 0;
    start:
        if (retry == MAX_BLK) assert(0); // cant allocated blk anymore

        /* we won't be writing more then 128 blocks in one io */
        uint64_t id = rand() % (MAX_BLK - MAX_NLBA);
        {
            std::unique_lock< std::mutex > lk(mutex);
            /* check if someone is already doing writes/reads */
            if (m_blk_bm->is_bits_reset(id, nblks))
                m_blk_bm->set_bits(id, nblks);
            else {
                retry++;
                goto start;
            }
        }
        blkId.set_id(id);
        blkId.set_nblks(nblks);
    }

    void generate_random_lba_nlbas(uint64_t& lba, uint64_t& nlbas) {
        int retry = 0;
    start:
        if (retry == 10000) {
            LOGINFO("Outstanding:{},issued:{}", outstanding_ios.load(), issued_ios.load());
            LOGINFO("unreturned_lbas:{}", unreturned_lbas.load());
            std::this_thread::sleep_for(std::chrono::seconds(5));
            assert(0); // cant allocated lba range anymore
        }

        lba = rand() % (MAX_LBA - MAX_NLBA);
        nlbas = (rand() % (MAX_NLBA - 1)) + 1;
        {
            assert(nlbas <= 128);
            std::unique_lock< std::mutex > lk(mutex);
            /* check if someone is already doing writes/reads */
            if (m_lba_bm->is_bits_reset(lba, nlbas)) {
                unreturned_lbas.fetch_add(nlbas);
                m_lba_bm->set_bits(lba, nlbas);
            } else {
                retry++;
                goto start;
            }
        }
    }

    void read_lba(uint64_t lba, uint64_t nlbas, std::vector< std::pair< MappingKey, MappingValue > >& kvs) {
        LOGDEBUG("Reading -> lba:{},nlbas:{}", lba, nlbas);
        auto volreq = std::make_unique< volume_req >();
        volreq->lba = lba;
        volreq->nlbas = nlbas;
        auto sid = seq_Id.fetch_add(1, memory_order_seq_cst);
        volreq->seqId = sid;
        volreq->lastCommited_seqId = sid; // read only latest value
        MappingKey key(lba, nlbas);

#ifndef NDEBUG
        volreq->vol_uuid = uuid;
#endif
        m_map->get(volreq.get(), kvs);
    }

    void verify_all() {
        // iterate read() 1k blks and call verify on kvs
        auto i = 0u;
        auto batch = 100u;
        while (i < MAX_LBA) {
            std::vector< std::pair< MappingKey, MappingValue > > kvs;
            read_lba(i, batch, kvs);
            verify(kvs);
            i += batch;
            if (i + batch > MAX_LBA) batch = MAX_LBA - i;
        }
    }

    void verify(std::vector< std::pair< MappingKey, MappingValue > >& kvs) {
        for (auto& kv : kvs) {
            auto st = kv.first.start();
            ValueEntry ve;
            long long int bst = 0;
            bool is_invalid = false;
            if (kv.second.is_valid()) {
                kv.second.get_array().get(0, ve, false);
                bst = ve.get_blkId().get_id() + ve.get_blk_offset();
            } else {
                is_invalid = true;
            }
            while (st <= kv.first.end() && m_blk_id_arr[st] != -1) {
                if (is_invalid || bst != m_blk_id_arr[st]) {
                    LOGINFO("lba st {}", st);
                    m_map->print_tree();
                    std::this_thread::sleep_for(std::chrono::seconds(5));
                    assert(0);
                }
                bst++;
                st++;
            }
        }
    }

    void random_read() {
        uint64_t lba = 0, nlbas = 0;
        generate_random_lba_nlbas(lba, nlbas);
        std::vector< std::pair< MappingKey, MappingValue > > kvs;
        read_lba(lba, nlbas, kvs);
        verify(kvs);
        release_lba_range_lock(lba, nlbas);
    }

    void write_lba(uint64_t lba, uint64_t nlbas, BlkId bid) {
        auto req = std::make_unique< volume_req >();

        auto sid = seq_Id.fetch_add(1, memory_order_seq_cst);

        req->seqId = sid;
        req->lastCommited_seqId = sid; // keeping only latest version always
        req->lba = lba;
        req->nlbas = nlbas;
        req->blkId = bid;
        MappingKey key(lba, nlbas);
        std::array< uint16_t, CS_ARRAY_STACK_SIZE > carr;

        for (auto i = 0ul, j = lba; j < lba + nlbas; i++, j++)
            carr[i] = j % 65000;
        ValueEntry ve(sid, bid, 0, nlbas, carr);
        MappingValue value(ve);
#ifndef NDEBUG
        req->vol_uuid = uuid;
#endif

        LOGDEBUG("Writing -> seqId:{} lba:{},nlbas:{},blk:{}", sid, lba, nlbas, bid.to_string());
        req->state = writeback_req_state::WB_REQ_COMPL;
        m_map->put(req.get(), key, value);
    }

    void random_write() {
        uint64_t lba = 0, nlbas = 0;
        BlkId bid;
        generate_random_lba_nlbas(lba, nlbas);
        generate_random_blkId(bid, nlbas);
        write_lba(lba, nlbas, bid);
    }

    void remove_files() { remove("file101"); }

    void notify_cmpl() { m_cv.notify_all(); }

    void wait_cmpl() {
        std::unique_lock< std::mutex > lk(m_cv_mtx);
        m_cv.wait(lk);
    }
};

void TestTarget::on_new_io_request(int fd, void* cookie, int event) {
    uint64_t temp;
    [[maybe_unused]] auto rsize = read(m_ev_fd, &temp, sizeof(uint64_t));
    m_test_store->process_new_request();
}

TEST_F(MapTest, RandomTest) {
    this->start_homestore();

    this->wait_cmpl();
    this->remove_files();
}

SDS_OPTION_GROUP(test_mapping,
                 (num_ios, "", "num_ios", "number of ios", ::cxxopts::value< uint64_t >()->default_value("30000"),
                  "number"),
                 (num_threads, "", "num_threads", "num threads for io",
                  ::cxxopts::value< uint64_t >()->default_value("8"), "number"))
SDS_OPTIONS_ENABLE(logging, test_mapping)

int main(int argc, char* argv[]) {
    SDS_OPTIONS_LOAD(argc, argv, logging, test_mapping)
    sds_logging::SetLogger("test_mapping");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");

    num_threads = SDS_OPTIONS["num_threads"].as< uint32_t >();
    num_ios = SDS_OPTIONS["num_ios"].as< uint64_t >();
    num_ios /= 2; // half read half write

    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
