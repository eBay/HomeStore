#include "mapping.hpp"
#include <gtest/gtest.h>
#include <fstream>
#include <iostream>
#include <thread>
#include <sds_logging/logging.h>

SDS_LOGGING_INIT(cache_vmod_evict, cache_vmod_write, iomgr, VMOD_BTREE_MERGE, VMOD_BTREE_SPLIT, varsize_blk_alloc,
                 VMOD_VOL_MAPPING, VMOD_BTREE, httpserver_lmod)
THREAD_BUFFER_INIT;

using namespace std;
using namespace homestore;

extern "C"
__attribute__((no_sanitize_address))
const char *__asan_default_options() {
    return "detect_leaks=false";
}

#define MAX_LBA            65535
#define MAX_NLBA             128
#define MAX_BLK       4294967295
#define MAX_SIZE          7 * Gi
uint64_t num_ios;
uint64_t num_threads;

struct MapTest : public testing::Test {
protected:
    std::mutex mutex;
    homeds::Bitset *m_lba_bm;
    homeds::Bitset *m_blk_bm;
    uint64_t m_blk_id_arr[MAX_LBA];
    mapping *m_map;

    uint64_t Ki = 1024ull;
    uint64_t Mi = Ki * Ki;
    uint64_t Gi = Ki * Mi;

    std::shared_ptr<iomgr::ioMgr> iomgr_obj;
    std::vector<dev_info> device_info;
    std::atomic<uint64_t> seq_Id;
    bool start = false;
    boost::uuids::uuid uuid;
public:
    MapTest() {
        m_lba_bm = new homeds::Bitset(MAX_LBA);
        m_blk_bm = new homeds::Bitset(MAX_BLK);
        for (auto i = 0u; i < MAX_LBA; i++) m_blk_id_arr[i] = 0;
        srand(time(0));
    }

    virtual ~MapTest() {
    }

    void process_metadata_completions(const volume_req_ptr& req) {
        for (auto &ptr : req->blkIds_to_free) {
            LOGINFO("Freeing Blk: {} {} {}", ptr.m_blkId.to_string(), ptr.m_blk_offset, ptr.m_nblks_to_free);
            release_blkId_lock(ptr.m_blkId, ptr.m_blk_offset, ptr.m_nblks_to_free);
        }
    }

    void process_completions(const vol_interface_req_ptr& hb_req) {
    }

    void start_homestore() {
        /* start homestore */
        /* create files */

        dev_info temp_info;
        temp_info.dev_names = "file101";
        device_info.push_back(temp_info);
        std::ofstream ofs(temp_info.dev_names.c_str(), std::ios::binary | std::ios::out);
        ofs.seekp(MAX_SIZE - 1);
        ofs.write("", 1);
        
        iomgr_obj = std::make_shared<iomgr::ioMgr>(2, num_threads);
        init_params params;
#ifndef NDEBUG
        params.flag = homestore::io_flag::BUFFERED_IO;
#else
        params.flag = homestore::io_flag::DIRECT_IO;
#endif
        params.min_virtual_page_size = 4096;
        params.cache_size = 4 * 1024 * 1024 * 1024ul;
        params.disk_init = true;
        params.devices = device_info;
        params.is_file = true;
        params.max_cap = MAX_SIZE;
        params.physical_page_size = 8192;
        params.disk_align_size = 4096;
        params.atomic_page_size = 8192;
        params.iomgr = iomgr_obj;
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

    bool vol_found_cb(boost::uuids::uuid uuid) {
        return true;
    }

    void vol_mounted_cb(const VolumePtr& vol_obj, vol_state state) {
        vol_init(vol_obj);
        auto cb = [this](const vol_interface_req_ptr& vol_req) { process_completions(vol_req); };
        VolInterface::get_instance()->attach_vol_completion_cb(vol_obj, cb);
    }

    void vol_init(const VolumePtr& vol_obj) {
        open(VolInterface::get_instance()->get_name(vol_obj), O_RDWR);
    }

    void vol_state_change_cb(const VolumePtr& vol, vol_state old_state, vol_state new_state) {
        assert(0);
    }


    void init_done_cb(std::error_condition err, const out_params& params1) {
        /* create volume */
        vol_params params;
        params.page_size = 4096;
        params.size = MAX_SIZE;
        params.uuid = boost::uuids::random_generator()();
        std::string name = "vol1";
        memcpy(params.vol_name, name.c_str(), (name.length() + 1));
        m_map = new mapping(params.size, params.page_size,
                            (std::bind(&MapTest::process_metadata_completions, this, std::placeholders::_1)));
        start = true;
    }

    void release_lba_range_lock(uint64_t &lba, uint64_t &nlbas) {
        std::unique_lock<std::mutex> lk(mutex);
        m_lba_bm->reset_bits(lba, nlbas);
    }

    void release_blkId_lock(BlkId &blkId, uint8_t offset, uint8_t nblks_to_free) {
        std::unique_lock<std::mutex> lk(mutex);
        m_blk_bm->reset_bits(blkId.get_id() + offset, nblks_to_free);
    }

    void generate_random_blkId(BlkId &blkId, uint64_t nblks) {
        uint64_t retry = 0;
        start:
        if (retry == MAX_BLK) assert(0);//cant allocated blk anymore

        /* we won't be writing more then 128 blocks in one io */
        uint64_t id = rand() % (MAX_BLK - MAX_NLBA);
        {
            std::unique_lock<std::mutex> lk(mutex);
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

    void generate_random_lba_nlbas(uint64_t &lba, uint64_t &nlbas) {
        int retry = 0;
        start:
        if (retry == MAX_LBA) assert(0);//cant allocated lba range anymore

        lba = rand() % (MAX_LBA - MAX_NLBA);
        nlbas = (rand() % (MAX_NLBA - 1)) + 1;
        {
            std::unique_lock<std::mutex> lk(mutex);
            /* check if someone is already doing writes/reads */
            if (m_lba_bm->is_bits_reset(lba, nlbas))
                m_lba_bm->set_bits(lba, nlbas);
            else {
                retry++;
                goto start;
            }
        }
    }

    void read(uint64_t lba, uint64_t nlbas, std::vector<std::pair<MappingKey, MappingValue>> &kvs) {
        LOGDEBUG("Reading -> lba:{},nlbas:{}", lba, nlbas);
        boost::intrusive_ptr<volume_req> volreq(new volume_req());
        volreq->lba = lba;
        volreq->nlbas = nlbas;
        auto sid = seq_Id.fetch_add(1, memory_order_seq_cst);
        volreq->seqId = sid;
        volreq->lastCommited_seqId = sid;//read only latest value
        MappingKey key(lba, nlbas);

#ifndef NDEBUG
        volreq->vol_uuid = uuid;
#endif
        m_map->get(volreq, key, kvs);
    }

    void verify_all() {
        //iterate read() 1k blks and call verify on kvs
        auto i = 0u;
        auto batch = 100u;
        while (i < MAX_LBA) {
            std::vector<std::pair<MappingKey, MappingValue>> kvs;
            read(i, batch, kvs);
            verify(kvs);
            i += batch;
            if (i + batch > MAX_LBA) batch = MAX_LBA - i;
        }
    }

    void verify(std::vector<std::pair<MappingKey, MappingValue>> &kvs) {
        for (auto &kv: kvs) {
            auto st = kv.first.start();
            ValueEntry ve;
            uint64_t bst = 0;
            bool is_invalid = false;
            if (kv.second.is_valid()) {
                kv.second.get_array().get(0, ve, false);
                bst = ve.get_blkId().get_id() + ve.get_blk_offset();
            } else
                is_invalid = true;
            while (st <= kv.first.end() && m_blk_id_arr[st] != 0) {
                if (is_invalid || bst != m_blk_id_arr[st]) {
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
        std::vector<std::pair<MappingKey, MappingValue>> kvs;
        read(lba, nlbas, kvs);
        verify(kvs);
        release_lba_range_lock(lba, nlbas);
    }

    void write(uint64_t lba, uint64_t nlbas, BlkId bid) {
        boost::intrusive_ptr<volume_req> req(new volume_req());

        auto sid = seq_Id.fetch_add(1, memory_order_seq_cst);

        req->seqId = sid;
        req->lastCommited_seqId = sid;//keeping only latest version always
        req->lba = lba;
        req->nlbas = nlbas;
        MappingKey key(lba, nlbas);
        std::array<uint16_t, CS_ARRAY_STACK_SIZE> carr;

        for (auto i = 0ul, j = lba; j < lba + nlbas; i++, j++) carr[i] = j % 65000;
        ValueEntry ve(sid, bid, 0, nlbas, carr);
        MappingValue value(ve);
#ifndef NDEBUG
        req->vol_uuid = uuid;
#endif

        LOGDEBUG("Writing -> seqId:{} lba:{},nlbas:{},blk:{}", sid, lba, nlbas, bid.to_string());
        m_map->put(req, key, value);

    }

    void random_write() {
        uint64_t lba = 0, nlbas = 0;
        BlkId bid;
        generate_random_lba_nlbas(lba, nlbas);


        generate_random_blkId(bid, nlbas);

        write(lba, nlbas, bid);

        for (auto st = lba, bst = bid.get_id(); st < lba + nlbas; st++, bst++)
            m_blk_id_arr[st] = bst;


        //do sync read
        std::vector<std::pair<MappingKey, MappingValue>> kvs;
        read(lba, nlbas, kvs);

        verify(kvs);
        release_lba_range_lock(lba, nlbas);
    }

    template<class Fn, class... Args>
    void run_in_parallel(int nthreads, Fn &&fn) {
        std::vector<std::thread *> thrs;
        for (auto i = 0; i < nthreads; i++) {
            thrs.push_back(new std::thread(fn, this));
        }
        for (auto t : thrs) {
            t->join();
            delete (t);
        }
        verify_all();
    }

    static void insert_and_get_thread(MapTest *test) {
        auto i = 0u;
        while (i++ < num_ios)test->random_write();

        i = 0u;
        while (i++ < num_ios)test->random_read();
    }
    void remove_files() {
        remove("file101");
    }
};

TEST_F(MapTest, RandomTest
) {
    this->start_homestore();

    while (!start)continue;
    run_in_parallel(num_threads, insert_and_get_thread);
    this->remove_files();
}

SDS_OPTION_GROUP(test_mapping,
                 (num_ios,
                         "", "num_ios", "number of ios", ::cxxopts::value<uint64_t>()->default_value(
                         "200"), "number"),
                 (num_threads, "", "num_threads", "num threads for io", ::cxxopts::value<uint64_t>()->default_value(
                         "8"), "number"))
SDS_OPTIONS_ENABLE(logging, test_mapping
)

int main(int argc, char *argv[]) {
    SDS_OPTIONS_LOAD(argc, argv, logging, test_mapping)
    sds_logging::SetLogger("test_mapping");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");

    testing::InitGoogleTest(&argc, argv);

    num_ios = SDS_OPTIONS["num_ios"].as<uint64_t>();
    num_threads = SDS_OPTIONS["num_threads"].as<uint64_t>();
    return RUN_ALL_TESTS();
}
