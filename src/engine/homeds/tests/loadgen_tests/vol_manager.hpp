#pragma once

#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <deque>
#include <fstream>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <random>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

#include <sisl/fds/bitset.hpp>

#include "engine/common/homestore_config.hpp"
#include "homelogstore/log_dev.hpp"
#include "vol_crc_persist_mgr.hpp"
#include "write_log_recorder.hpp"

#define MAX_DEVICES 2
#define VOL_PREFIX "vol_load_gen/vol"

//
// VolumeManager holds all the details about volume lifecyle:
// 1. init, create, delete, recovery, etc;
//
namespace homeds {
namespace loadgen {

constexpr uint64_t APP_MEM_SIZE = (5 * 1024 * 1024 * 1024ul);
constexpr uint32_t VOL_PAGE_SIZE = 4096;
constexpr uint32_t MAX_CRC_DEPTH = 3;
const uint64_t LOGDEV_BUF_SIZE = HS_STATIC_CONFIG(drive_attr.align_size) * 1024;

class VolReq {
public:
    ssize_t size;
    off_t offset;
    uint64_t lba;
    uint32_t nblks;
    uint8_t* buf; // read;
    bool is_read;
    bool verify; // only valid for read;
    uint64_t vol_id;
    std::vector< uint64_t > hash; // only valid for write

public:
    VolReq() { buf = nullptr; }

    virtual ~VolReq() {
        if (buf) { iomanager.iobuf_free(buf); }
    }
};

struct VolumeInfo {
    std::mutex m_mtx;   // lock
    sisl::Bitset* m_bm; // volume block write bitmap

    VolumeInfo(uint64_t vol_total_blks) { m_bm = new sisl::Bitset(vol_total_blks); }

    ~VolumeInfo() { delete m_bm; }
};

template < typename Executor >
class VolumeManager {
    typedef std::function< void(std::error_condition err) > init_done_callback;

public:
    VolumeManager() {
        // create vol loadgen folder
        mkdir(vol_loadgen_dir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    }

    ~VolumeManager() {
        for (auto& x : m_vol_info) {
            delete x;
        }

        m_verify_mgr.reset();
        m_write_recorder.reset();

        // remove the loadgen dir
        if (0 != rmdir(vol_loadgen_dir.c_str())) {
            LOGERROR("Deleting dir: {} failed, error no: {}, err msg: {}", vol_loadgen_dir, errno,
                     std::strerror(errno));
            assert(false);
        }
    }

    void start(bool enable_write_log, Executor& executor, init_done_callback init_done_cb) {
        m_enable_write_log = enable_write_log;
        m_max_cap = 0;
        m_max_vol_size = 0;
        m_max_disk_cap = 10 * Gi;

        struct stat st;
        m_file_names = {"vol_load_gen/file1", "vol_load_gen/file2", "vol_load_gen/file3", "vol_load_gen/file4"};
        m_done_cb = init_done_cb;

        if (m_enable_write_log) { m_write_recorder = std::make_shared< WriteLogRecorder< uint64_t > >(max_vols()); }

        start_homestore();

        m_verify_mgr = std::make_shared< VolVerifyMgr< uint64_t > >(max_vols(), max_vol_blks());
    }

    void stop() {
        LOGINFO("Shuting down... outstanding IO: {}", m_outstd_ios);

        Clock::time_point start = Clock::now();
        while (m_outstd_ios.load()) {
            if (get_elapsed_time(start) > 30) {
                LOGERROR("Wait outstanding io timeout ...");
                assert(false);
            }
            std::this_thread::sleep_for(std::chrono::seconds{2});
        }

        shutdown();

        start = Clock::now();

        while (!m_shutdown_cb_done.load()) {
            auto elapsed_time = get_elapsed_time(start);
            if (elapsed_time > 300) {
                LOGERROR("Wait shutdown callback timeout ...");
                assert(false);
            }
            std::this_thread::sleep_for(std::chrono::seconds{2});
        }

        remove_files();
    }

    void shutdown_callback(bool success) {
        assert(success);
        m_shutdown_cb_done = true;
    }

    void shutdown() {
        // release the ref_count to volumes;
        m_vols.clear();
        VolInterface::get_instance()->trigger_shutdown(
            std::bind(&VolumeManager::shutdown_callback, this, std::placeholders::_1));
    }

    uint64_t max_vols() const { return m_max_vols; }

    // get nblks based on volume size;
    uint64_t max_vol_blks() const { return m_max_vol_size / VOL_PAGE_SIZE; }

    // get nblks in max io size;
    uint64_t max_io_nblks() const { return m_max_io_size / VOL_PAGE_SIZE; }

    static void del_instance();

    static VolumeManager< Executor >* instance();

    bool check_and_set_bm(uint64_t vol_id, uint64_t lba, uint64_t nblks) {
        std::lock_guard< std::mutex > lk(m_vol_info[vol_id]->m_mtx);
        if (m_vol_info[vol_id]->m_bm->is_bits_reset(lba, nblks)) {
            // we don't allow write on same lba if there is already a read on it.
            m_vol_info[vol_id]->m_bm->set_bits(lba, nblks);
            return true;
        } else {
            // if there is already a write on same lba range, we allow this read, but skip verification
            return false;
        }
    }

    uint8_t* gen_value(const uint64_t nblks) const {
        const uint64_t size{get_size(nblks)};
        uint8_t* const bytes{iomanager.iobuf_alloc(512, size)};

        populate_buf(bytes, size);
        return bytes;
    }

#define MAX_GEN_KEY_TRY_CNT 100

    // genreate a key that no one is writing(not ACK yet) on same lba;
    void gen_key(uint64_t& vol_id, uint64_t& lba, uint64_t& nblks) {
        uint64_t try_cnt = 0;
        while (try_cnt++ < MAX_GEN_KEY_TRY_CNT) {

            uint64_t t_vol_id = get_rand_vol();
            uint64_t t_lba = get_rand_lba();
            uint64_t t_nblks = get_rand_nblks();

            {
                std::lock_guard< std::mutex > lk(m_vol_info[t_vol_id]->m_mtx);
                if (m_vol_info[t_vol_id]->m_bm->is_bits_reset(t_lba, t_nblks)) {
                    m_vol_info[t_vol_id]->m_bm->set_bits(t_lba, t_nblks);

                    vol_id = t_vol_id;
                    lba = t_lba;
                    nblks = t_nblks;

                    return;
                }
            }

            // key is same on write that is not ACK yet, keep finding other keys;
        }
        assert(false);
    }

    std::error_condition read(uint64_t vol_id, uint64_t lba, uint64_t nblks, bool verify) {
        uint64_t size = get_size(nblks);
        uint8_t* buf = iomanager.iobuf_alloc(512, size);

        VolReq* req = new VolReq();
        req->lba = lba;
        req->nblks = nblks;
        req->is_read = true;
        req->size = size;
        req->offset = size;
        req->buf = buf;
        req->vol_id = vol_id;
        req->verify = verify;
        m_rd_cnt++;
        m_outstd_ios++;

        if (verify == false) { m_read_verify_skip++; }

        auto vreq = VolInterface::get_instance()->create_vol_interface_req(nullptr, lba, nblks, false);
        vreq->cookie = req;
        auto ret_io = VolInterface::get_instance()->read(m_vols[vol_id], vreq);
        if (ret_io != no_error) {
            assert(false);
            m_outstd_ios--;
            m_rd_err_cnt++;
            iomanager.iobuf_free(buf);
            std::lock_guard< std::mutex > lk(m_vol_info[vol_id]->m_mtx);
            reset_bm_bits(vol_id, lba, nblks);
        }

        return ret_io;
    }

    std::error_condition write(uint64_t vol_id, uint64_t lba, uint8_t* buf, uint64_t nblks) {
        assert(buf);
        assert(lba < (max_vol_blks() - nblks));
        assert(vol_id < m_max_vols);

        auto size = get_size(nblks);
        VolReq* req = new VolReq();
        req->lba = lba;
        req->nblks = nblks;
        req->size = size;
        req->offset = size;
        req->buf = nullptr;
        req->is_read = false;
        req->vol_id = vol_id;
        m_outstd_ios++;
        m_wrt_cnt++;

        // Generate hash per block. The write complete routine will consume them;
        for (uint64_t i = 0; i < nblks; i++) {
            req->hash.push_back(get_hash((uint8_t*)((uint64_t)buf + get_size(i))));
        }

        auto vreq = VolInterface::get_instance()->create_vol_interface_req(buf, lba, nblks, false);
        vreq->cookie = req;
        auto ret_io = VolInterface::get_instance()->write(m_vols[vol_id], vreq);
        if (ret_io != no_error) {
            assert(false);
            m_outstd_ios--;
            m_wrt_err_cnt++;
            std::lock_guard< std::mutex > lk(m_vol_info[vol_id]->m_mtx);
            reset_bm_bits(vol_id, lba, nblks);
        }

        return ret_io;
    }

    void set_max_vols(uint64_t num_vols) { m_max_vols = num_vols; }

private:
#if 0
    void process_logdev_completions(const logdev_req_ptr& req) {
        LOGINFO("Logdev write callback received!");

        logdev_read_and_verify();
        m_logdev_done = true;
    }
    
    void logdev_read_and_verify() {
        // read verify: grab last written offset as input and compare the read data with stored data
        auto read_offset = m_logdev_offset.front();

        char* ptr = nullptr;
        int  ret = posix_memalign((void**)&ptr, HS_STATIC_CONFIG(drive_attr.align_size), LOGDEV_BUF_SIZE);
        if (ret != 0) {
            throw std::bad_alloc();
        }

        struct iovec* iov = nullptr;
        ret = posix_memalign((void**)&iov, HS_STATIC_CONFIG(drive_attr.align_size), sizeof(struct iovec));
        if (ret != 0) {
            throw std::bad_alloc();
        }

        iov[0].iov_base = (uint8_t*) ptr;
        iov[0].iov_len = LOGDEV_BUF_SIZE;

        LogDev::instance()->readv(read_offset, iov, 1);  
        
        ptr[m_logdev_data[read_offset].size()] = 0;

        if (m_logdev_data[read_offset].compare(ptr) != 0) {
            LOGERROR("Returned buf: {} is not same as stored buf: {}", ptr, m_logdev_data[read_offset]);
            assert(false);
        } 
         
        free(iov);   
        free(ptr);

        m_logdev_read_verified = true;
    }

    void logdev_write(uint64_t vol_id, uint64_t lba, uint64_t nblks, logdev_comp_callback cb) {
        std::string ss = std::to_string(vol_id) + " " + std::to_string(nblks);

        char* ptr = nullptr;
        int  ret = posix_memalign((void**)&ptr, HS_STATIC_CONFIG(drive_attr.align_size), LOGDEV_BUF_SIZE);

        if (ret != 0) {
            throw std::bad_alloc();
        }
        strncpy(ptr, ss.c_str(), ss.size());
        
        struct iovec* iov = nullptr;
        ret = posix_memalign((void**)&iov, HS_STATIC_CONFIG(drive_attr.align_size), sizeof(struct iovec));
        if (ret != 0) {
            throw std::bad_alloc();
        }

        iov[0].iov_base = (uint8_t*)ptr;
        iov[0].iov_len = LOGDEV_BUF_SIZE;
        
        uint64_t offset_1 = LogDev::instance()->reserve(LOGDEV_BUF_SIZE + sizeof (LogDevRecordHeader));
#if 1
        static bool two_reserve_test = true;
        uint64_t offset_2 = 0;

        // test two reserve followed by two writes;
        if (two_reserve_test) {
            offset_2 = LogDev::instance()->reserve(LOGDEV_BUF_SIZE + sizeof (LogDevRecordHeader));
            if (offset_2 != INVALID_OFFSET) {
                m_logdev_offset.push_front(offset_2);
                m_logdev_data[offset_2] = ss;

                m_logdev_read_verified = false;
                bool bret= LogDev::instance()->pwritev(iov, 1, offset_2, cb);
                
                if (bret) {
                    LOGINFO("offset: {}", offset_2);
                } else {
                    HS_ASSERT(DEBUG, 0, "Unexpected Failure! ");
                }

            } else {
                LOGERROR("Expected failure becuase of no space left. "); 
            }

            two_reserve_test = false;
        }  else {
            two_reserve_test = true;
        }

        // 
        // Wait for the 1st write(if there is any) to be read and verified before we start another write. 
        // This is just for the ease of testing code only, not a restriction for production code;
        //
        while (!m_logdev_read_verified) {
            std::this_thread::sleep_for(std::chrono::seconds{1});
        }
#endif
        if (offset_1 != INVALID_OFFSET) {
            m_logdev_data[offset_1] = ss;
            m_logdev_offset.push_front(offset_1);

            m_logdev_read_verified = false;
            bool bret= LogDev::instance()->pwritev(iov, 1, offset_1, cb);

            if (bret) {
                LOGINFO("offset: {}", offset_1);
            } else {
                HS_ASSERT(DEBUG, 0, "Unexpected Failure! ");
            }
        } else {
            LOGERROR("Expected failure becuase of no space left. "); 
        }

        free(iov);
        free(ptr);
    }

#endif
    uint64_t get_rand_vol() const {
        static thread_local std::random_device rd{};
        static thread_local std::default_random_engine generator{rd()};
        std::uniform_int_distribution< uint64_t > dist{0, m_max_vols - 1};
        return dist(generator);
    }

    uint64_t get_rand_lba() const {
        static thread_local std::random_device rd{};
        static thread_local std::default_random_engine generator{rd()};
        // make sure the the lba doesn't write accross max vol size;
        // MAX_KEYS is initiated as max vol size;
        // lba: [0, max_vol_blks - max_io_nblks)
        std::uniform_int_distribution< uint64_t > dist{0, KeySpec::MAX_KEYS - max_io_nblks() - 1};
        return dist(generator);
    }

    uint64_t get_rand_nblks() const {
        static thread_local std::random_device rd{};
        static thread_local std::default_random_engine generator{rd()};
        // nblks: [1, max_io_nblks]
        std::uniform_int_distribution< uint64_t > dist{1, max_io_nblks()};
        return dist(generator);
    }

    void populate_buf(uint8_t* const buf, const uint64_t size) const {
        assert(size > 0);
        assert(size % sizeof(uint64_t) == 0);

        static thread_local std::random_device rd{};
        static thread_local std::default_random_engine generator{rd()};
        std::uniform_int_distribution< uint64_t > dist{std::numeric_limits< unsigned long long >::min(),
                                                       std::numeric_limits< unsigned long long >::max()};

        for (uint64_t i{0}; i < size; i += sizeof(uint64_t)) {
            *reinterpret_cast< uint64_t* >(buf + i) = dist(generator);
        }
    }

    void reset_bm_bits(uint64_t vol_id, uint64_t lba, uint64_t nblks) {
        m_vol_info[vol_id]->m_bm->reset_bits(lba, nblks);
    }

    void remove_files() {
        for (auto& f : m_file_names) {
            remove(f.c_str());
        }
    }

    void start_homestore() {
        // create files
        for (uint32_t i = 0; i < MAX_DEVICES; i++) {
            dev_info temp_info;
            temp_info.dev_names = m_file_names[i];
            m_device_info.push_back(temp_info);

            std::ofstream ofs(m_file_names[i], std::ios::binary | std::ios::out);
            ofs.seekp(m_max_disk_cap - 1);
            ofs.write("", 1);
            ofs.close();
            m_max_cap += m_max_disk_cap;
        }

        /* Don't populate the whole disks. Only 80 % of it */
        m_max_vol_size = (80 * m_max_cap) / (100 * m_max_vols);

        init_params p;
        p.open_flags = homestore::io_flag::DIRECT_IO;
        p.min_virtual_page_size = VOL_PAGE_SIZE;
        p.app_mem_size = APP_MEM_SIZE;
        p.devices = m_device_info;

        p.init_done_cb = std::bind(&VolumeManager::init_done_cb, this, std::placeholders::_1, std::placeholders::_2);
        p.vol_mounted_cb =
            std::bind(&VolumeManager::vol_mounted_cb, this, std::placeholders::_1, std::placeholders::_2);
        p.vol_state_change_cb = std::bind(&VolumeManager::vol_state_change_cb, this, std::placeholders::_1,
                                          std::placeholders::_2, std::placeholders::_3);
        p.vol_found_cb = std::bind(&VolumeManager::vol_found_cb, this, std::placeholders::_1);

        VolInterface::init(p);
    }

    void init_done_cb(std::error_condition err, const out_params& params) {
        m_max_io_size = params.max_io_size;
        for (auto vol_cnt = 0ull; vol_cnt < m_max_vols; vol_cnt++) {
            create_volume(vol_cnt);
        }
        uint32_t vol_total_nblks = max_vol_blks();
        for (auto i = 0ull; i < m_max_vols; i++) {
            m_vol_info.push_back(new VolumeInfo(vol_total_nblks));
        }

        // IO will be triggered by loadgen
        // After creating volumes, notify loadgen with callback;
        std::error_condition no_err;
        m_done_cb(no_err);
    }

    void create_volume(int vol_index) {
        vol_params p;
        p.page_size = VOL_PAGE_SIZE;
        p.size = m_max_vol_size;
        p.io_comp_cb = ([this](const vol_interface_req_ptr& vol_req) { process_completions(vol_req); });
        p.uuid = boost::uuids::random_generator()();
        std::string name = VOL_PREFIX + std::to_string(vol_index);

        std::memcpy(p.vol_name, name.c_str(), (name.length() + 1));

        auto vol_obj = VolInterface::get_instance()->create_volume(p);

        assert(vol_obj != nullptr);

        assert(VolInterface::get_instance()->lookup_volume(p.uuid) == vol_obj);

        // leave verification to loadgen value spec for now;
        LOGINFO("Created volume of size: {}", m_max_vol_size);

        // open a corresponding file
        vol_init(vol_obj);
    }

    bool vol_found_cb(boost::uuids::uuid uuid) { return true; }

    void vol_mounted_cb(const VolumePtr& vol_obj, vol_state state) {
        vol_init(vol_obj);
        auto cb = [this](boost::intrusive_ptr< vol_interface_req > vol_req) { process_completions(vol_req); };
        VolInterface::get_instance()->attach_vol_completion_cb(vol_obj, cb);
    }

    void vol_init(const VolumePtr& vol_obj) {
        // we don't need to open fds since we don't handle verfication here for now.
        assert(VolInterface::get_instance()->get_size(vol_obj) == m_max_vol_size);
        m_vols.push_back(vol_obj);
    }

    void vol_state_change_cb(const VolumePtr& vol, vol_state old_state, vol_state new_state) { assert(false); }

    void print_io_counters() const {
        LOGINFO("write ios cmpled: {}", m_wrt_cnt);
        LOGINFO("read ios cmpled: {}", m_rd_cnt);
        LOGINFO("read/write err : {}/{}, read_verify_skip: {}, write_skip: {}", m_rd_err_cnt, m_wrt_err_cnt,
                m_read_verify_skip, m_writes_skip);
    }

    uint64_t get_elapsed_time(const Clock::time_point& start) const {
        const std::chrono::seconds sec{std::chrono::duration_cast< std::chrono::seconds >(Clock::now() - start)};
        return sec.count();
    }

    // For Read: do the verification.
    // For Write: update hash code;
    void process_completions(const vol_interface_req_ptr& vol_req) {
        VolReq* req = (VolReq*)vol_req->cookie;
        static uint64_t pt = 30;
        static Clock::time_point pt_start = Clock::now();

        auto elapsed_time = get_elapsed_time(pt_start);
        if (elapsed_time > pt) {
            print_io_counters();
            pt_start = Clock::now();
        }

        m_outstd_ios--;

        if (req->is_read) {
            verify(req, vol_req);
        } else {
            // write: update hash
            assert(req->hash.size() == req->nblks);
            for (uint64_t i = 0; i < req->nblks; i++) {
                m_verify_mgr->set_crc(req->vol_id, req->lba + i, req->hash[i]);
                LOGDEBUG("vol_id: {}, lba: {}, nblks: {}, map_hash: {}, hash: {}", req->vol_id, req->lba, req->nblks,
                         m_verify_mgr->get_crc(req->vol_id, req->lba + i), req->hash[i]);
            }

            // reset the bits so that key gen could pick up again
            std::lock_guard< std::mutex > lk(m_vol_info[req->vol_id]->m_mtx);
            reset_bm_bits(req->vol_id, req->lba, req->nblks);
        }
        delete req; // no longer needed
    }

    //
    // verify by compare the crc in the read buffer returned in req with crc saved with write;
    //
    void verify(VolReq* req, const vol_interface_req_ptr& vol_req) {
        // if req->verify is false, we still want to process the read_buf_list to verify
        // the nblks returned, just skip crc check;
        uint64_t nblks_in_buf_list = 0;

        // process returned read buf
        for (auto& info : vol_req->read_buf_list) {
            auto offset = info.offset;
            auto size = info.size;
            auto buf = info.buf;
            while (size != 0) {
                sisl::blob b = VolInterface::get_instance()->at_offset(buf, offset);
                auto hash = get_hash(b.bytes);
                auto stored_hash = m_verify_mgr->get_crc(req->vol_id, req->lba + nblks_in_buf_list);

                if (req->verify && hash != stored_hash) {
                    LOGERROR("Verify Failed: Hash Code Mismatch: vol_id: {}, lba: {}, nblks {}, hash: {} : {}",
                             req->vol_id, req->lba, req->nblks, hash, stored_hash);
                    assert(false);
                }

                offset += VOL_PAGE_SIZE;
                size -= VOL_PAGE_SIZE;
                nblks_in_buf_list++;
            }
        }

        assert(nblks_in_buf_list == req->nblks);

        if (req->verify) {
            std::lock_guard< std::mutex > lk(m_vol_info[req->vol_id]->m_mtx);
            reset_bm_bits(req->vol_id, req->lba, req->nblks);
        }
    }

    uint64_t get_size(const uint64_t n) const { return n * VOL_PAGE_SIZE; }

    uint64_t get_hash(const uint8_t* const bytes) const {
        return util::Hash64(reinterpret_cast< const char* >(bytes), static_cast< size_t >(VOL_PAGE_SIZE));
    }

private:
    std::vector< dev_info > m_device_info;
    init_done_callback m_done_cb;    // callback to loadgen test case;
    std::vector< VolumePtr > m_vols; // volume instances;
    std::vector< std::string > m_file_names;

    uint64_t m_max_vol_size;
    uint64_t m_max_cap;
    uint64_t m_max_disk_cap;
    uint64_t m_max_vols = 10;
    uint64_t m_max_io_size;
    // io count
    std::atomic< uint64_t > m_outstd_ios = 0;
    std::atomic< uint64_t > m_wrt_cnt = 0;
    std::atomic< uint64_t > m_rd_cnt = 0;
    std::atomic< uint64_t > m_rd_err_cnt = 0;
    std::atomic< uint64_t > m_wrt_err_cnt = 0;
    std::atomic< uint64_t > m_writes_skip = 0;
    std::atomic< uint64_t > m_read_verify_skip = 0;
    std::atomic< bool > m_shutdown_cb_done = false;

    static VolumeManager< Executor >* _instance;

    std::vector< VolumeInfo* > m_vol_info;
    std::shared_ptr< VolVerifyMgr< uint64_t > > m_verify_mgr; // crc type uint64_t

    bool m_enable_write_log;
    std::shared_ptr< WriteLogRecorder< uint64_t > > m_write_recorder;
    bool m_logdev_done = true;
    bool m_logdev_read_verified = false;
    std::map< uint64_t, std::string > m_logdev_data; // offset to string length
    std::deque< uint64_t > m_logdev_offset;
}; // VolumeManager

template < typename T >
VolumeManager< T >* VolumeManager< T >::_instance = nullptr;

template < typename T >
VolumeManager< T >* VolumeManager< T >::instance() {
    static std::once_flag f;
    std::call_once(f, []() { _instance = new VolumeManager< T >(); });
    return _instance;
}

template < typename T >
void VolumeManager< T >::del_instance() {
    delete _instance;
}

} // namespace loadgen
} // namespace homeds
