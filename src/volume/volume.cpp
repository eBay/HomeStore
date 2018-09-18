
//
// Created by Kadayam, Hari on 06/11/17.
//

#include "volume.hpp"
#include <mapping/mapping.cpp>
#include "perf_metrics.hpp"
#include <fstream>

using namespace std;

#define MAX_CACHE_SIZE     (100 * 1024ul * 1024ul) /* it has to be a multiple of 16k */
constexpr auto BLOCK_SIZE = (4 * 1024ul);

static std::map<std::string, std::shared_ptr<homestore::Volume>> volume_map;
static std::mutex map_lock;
std::atomic<int> vol_req_alloc;

#ifndef NDEBUG
/* only for testing */
bool vol_test_enable = false;
#endif
/* TODO: it will be more cleaner once statisitcs is integrated */
std::atomic<int> homestore::req_alloc(0);
std::atomic<int> homestore::req_dealloc(0);
int btree_buf_alloc;
int btree_buf_free;
int btree_buf_make_obj;

/* Names of metrics */
#define VOL_LABEL " for HomeStore Volume"

/* Metrics - Histograms */
enum e_vol_hist {
    READ_H = 0,
    WRITE_H,
    MAP_READ_H,
    IO_READ_H,
    IO_WRITE_H,
    BLK_ALLOC_H,
    MAX_VOL_HIST_CNT
};

static std::string vol_hist[] = {
    "Vol-Reads",
    "Vol-Writes",
    "Map-Reads",
    "IO-Reads",
    "IO-Writes",
    "Blk-Allocs"
};

using namespace homestore;

PerfMetrics* PerfMetrics::instance = 0;
PerfMetrics* PerfMetrics::getInstance() {
    if (!instance) {
        instance = new PerfMetrics();
    }
    return instance;
}

std::shared_ptr<Volume>
Volume::createVolume(std::string const &uuid,
                     DeviceManager *mgr,
                     uint64_t const size,
                     comp_callback comp_cb) {
    decltype(volume_map)::iterator it;
    // Try to add an entry for this volume
    {
        std::lock_guard<std::mutex> lg(map_lock);
        bool happened{false};
        std::tie(it, happened) = volume_map.emplace(std::make_pair(uuid, nullptr));
        if (!happened) {
            if (volume_map.end() != it) return it->second;
            throw std::runtime_error("Unknown bug");
        }
    }
    // Okay, this is a new volume so let's create it
    auto new_vol = new Volume(mgr, size, comp_cb);
    it->second.reset(new_vol);
    return it->second;
}

std::error_condition
Volume::removeVolume(std::string const &uuid) {
    std::shared_ptr<Volume> volume;
    // Locked Map
    {
        std::lock_guard<std::mutex> lg(map_lock);
        if (auto it = volume_map.find(uuid); volume_map.end() != it) {
            if (2 <= it->second.use_count()) {
                LOGERROR("Refusing to delete volume with outstanding references: {}", uuid);
                return std::make_error_condition(std::errc::device_or_resource_busy);
            }
            volume = std::move(it->second);
            volume_map.erase(it);
        }
    } // Unlock Map
    return (volume ? volume->destroy() : std::make_error_condition(std::errc::no_such_device_or_address));
}

std::shared_ptr<Volume>
Volume::lookupVolume(std::string const &uuid) {
    {
        std::lock_guard<std::mutex> lg(map_lock);
        auto it = volume_map.find(uuid);
        if (volume_map.end() != it) return it->second;
    }
    return nullptr;
}

Cache<BlkId> *Volume::glob_cache = NULL;

uint64_t
Volume::get_elapsed_time(Clock::time_point startTime) {
    std::chrono::nanoseconds ns = std::chrono::duration_cast
            <std::chrono::nanoseconds>(Clock::now() - startTime);
    return ns.count() / 1000;
}

AbstractVirtualDev *
Volume::new_vdev_found(DeviceManager *dev_mgr, vdev_info_block *vb) {
    LOGINFO("New virtual device found id = {} size = {}", vb->vdev_id, vb->size);

    /* TODO: enable it after testing */
#if 0
    Volume *volume = new Volume(dev_mgr, vb);
    return volume->blk_store->get_vdev();
#endif
    return NULL;
}

Volume::Volume(DeviceManager *dev_mgr, uint64_t size,
               comp_callback comp_cb) : comp_cb(comp_cb) {
    fLI::FLAGS_minloglevel = 3;
    if (Volume::glob_cache == NULL) {
        Volume::glob_cache = new Cache<BlkId>(MAX_CACHE_SIZE, BLOCK_SIZE);
        cout << "cache created\n";
    }

    /* TODO:create blkstore with 10% more space. This code will change later. */
    blk_store = new BlkStore<VdevVarSizeBlkAllocatorPolicy>
            (dev_mgr, Volume::glob_cache, size + (size * 40)/100,
             WRITEBACK_CACHE, 0,
             (std::bind(&Volume::process_data_completions,
                        this, std::placeholders::_1)));
    map = new mapping(size,
                      [this](homestore::BlkId bid) { free_blk(bid); },
                      (std::bind(&Volume::process_metadata_completions, this,
                                 std::placeholders::_1)), dev_mgr,
                      Volume::glob_cache);
    alloc_single_block_in_mem();
    init_perf_report();
}

Volume::Volume(DeviceManager *dev_mgr, vdev_info_block *vb) {
    size = vb->size;
    if (Volume::glob_cache == NULL) {
        Volume::glob_cache = new Cache<BlkId>(MAX_CACHE_SIZE, BLOCK_SIZE);
        cout << "cache created\n";
    }
    blk_store = new BlkStore<VdevVarSizeBlkAllocatorPolicy>
            (dev_mgr, Volume::glob_cache, vb,
             WRITEBACK_CACHE,
             (std::bind(&Volume::process_data_completions, this,
                        std::placeholders::_1)));
    map = new mapping(size,
                      [this](homestore::BlkId bid) { free_blk(bid); },
                      (std::bind(&Volume::process_metadata_completions, this,
                                 std::placeholders::_1)), dev_mgr,
                      Volume::glob_cache);
    alloc_single_block_in_mem();
    /* TODO: rishabh, We need a attach function to register completion callback if layers
     * are called from bottomup.
     */
    init_perf_report();
}

std::error_condition
Volume::destroy() {
    LOGWARN("UnImplemented volume destruction!");
    return std::error_condition();
}

void
homestore::Volume::process_metadata_completions(boost::intrusive_ptr<volume_req> req) {
    assert(!req->is_read);
    if (req->err == no_error) {
        PerfMetrics *perf = PerfMetrics::getInstance();
        assert(perf->updateHistogram(vol_hist[IO_WRITE_H], get_elapsed_time(req->startTime)));
    }
    for (std::shared_ptr<Free_Blk_Entry> ptr : req->blkids_to_free_due_to_overwrite) {
        LOGTRACE("Blocks to free {}", ptr.get()->to_string());
        blk_store->free_blk(ptr->blkId, ptr->blkId_offset, ptr->nblks_to_free);
    }
    comp_cb(req);
    outstanding_write_cnt.fetch_sub(1, memory_order_relaxed);
}

void
homestore::Volume::process_data_completions(boost::intrusive_ptr<blkstore_req<BlkBuffer>> bs_req) {
    boost::intrusive_ptr<volume_req> req = boost::static_pointer_cast<volume_req>(bs_req);

    if (!req->is_read) {
        return;
    }
    for (unsigned int i = 0; i < req->read_buf_list.size(); i++) {
        if (req->read_buf_list[i].buf == only_in_mem_buff) {
            continue;
        }
        blk_store->update_cache(req->read_buf_list[i].buf);
    }
    PerfMetrics *perf = PerfMetrics::getInstance();
    assert(perf->updateHistogram(vol_hist[IO_READ_H], get_elapsed_time(req->startTime)));
    comp_cb(req);
    outstanding_write_cnt.fetch_sub(1, memory_order_relaxed);
}

void
Volume::init_perf_report() {
    PerfMetrics *perf = PerfMetrics::getInstance();
    /* Register histogram (if not present) */
    for (auto i = 0U; i < MAX_VOL_HIST_CNT; i++) {
        perf->registerHistogram(vol_hist[i], vol_hist[i]+VOL_LABEL, "");
    }
    outstanding_write_cnt = 0;
}

void
Volume::print_perf_report() {
    PerfMetrics *perf = PerfMetrics::getInstance();
    std::ofstream ofs ("result.json", std::ofstream::out);
    ofs << perf->report() << std::endl;
    ofs.close();
}

void
homestore::Volume::free_blk(homestore::BlkId bid) {
    blk_store->free_blk(bid, boost::none, boost::none);
}

boost::intrusive_ptr<BlkBuffer>
Volume::write(uint64_t lba, uint8_t *buf, uint32_t nblks,
              boost::intrusive_ptr<volume_req> req) {
    BlkId bid;
    blk_alloc_hints hints;
    hints.desired_temp = 0;
    hints.dev_id_hint = -1;

    req->lba = lba;
    req->nblks = nblks;
    req->is_read = false;
    req->startTime = Clock::now();
    req->err = no_error;
    outstanding_write_cnt.fetch_add(1, memory_order_relaxed);

    {
        CURRENT_CLOCK(startTime)
        BlkAllocStatus status = blk_store->alloc_blk(nblks, hints, &bid);
        if (status != BLK_ALLOC_SUCCESS) {
            assert(0);
        }
        PerfMetrics *perf = PerfMetrics::getInstance();
        assert(perf->updateHistogram(vol_hist[BLK_ALLOC_H], get_elapsed_time(startTime)));
    }
    req->bid = bid;

    // LOG(INFO) << "Requested nblks: " << (uint32_t) nblks << " Allocation info: " << bid.to_string();

    homeds::blob b = {buf, (uint32_t) (BLOCK_SIZE * nblks)};

    Clock::time_point startTime = Clock::now();

    std::deque<boost::intrusive_ptr<writeback_req>> req_q;
    boost::intrusive_ptr<BlkBuffer> bbuf = blk_store->write(bid, b,
                                                            boost::static_pointer_cast<blkstore_req<BlkBuffer>>(req),
                                                            req_q);

    /* TODO: should check the write status */
    PerfMetrics *perf = PerfMetrics::getInstance();
    auto updated = perf->updateHistogram(vol_hist[WRITE_H], get_elapsed_time(startTime));
    assert(updated);
    //  LOG(INFO) << "Written on " << bid.to_string() << " for 8192 bytes";
    map->put(req, req->lba, req->nblks, req->bid);
    return bbuf;
}

void Volume::print_tree() {
    map->print_tree();
}

int
Volume::read(uint64_t lba, int nblks, boost::intrusive_ptr<volume_req> req) {

    std::vector<std::shared_ptr<Lba_Block>> mappingList;
    req->startTime = Clock::now();
    Clock::time_point startTime = Clock::now();

    std::error_condition ret = map->get(lba, nblks, mappingList);
    req->err = ret;
    req->is_read = true;

    outstanding_write_cnt.fetch_add(1, memory_order_relaxed);
    if (ret && ret == homestore_error::lba_not_exist) {
        process_data_completions(req);
        return 0;
    }

    PerfMetrics *perf = PerfMetrics::getInstance();
    assert(perf->updateHistogram(vol_hist[MAP_READ_H], get_elapsed_time(startTime)));

    req->lba = lba;
    req->nblks = nblks;

    req->blkstore_read_cnt = 1;

    startTime = Clock::now();
    for (std::shared_ptr<Lba_Block> bInfo: mappingList) {
        if (!bInfo->m_blkid_found) {
            uint8_t i = 0;
            while (i < bInfo->m_value.m_blkid.get_nblks()) {
                buf_info info;
                info.buf = only_in_mem_buff;
                info.size = BLOCK_SIZE;
                info.offset = 0;
                req->read_buf_list.push_back(info);
                i++;
            }
        } else {
            LOGTRACE("Volume - Sending read to blkbuffer - {},{},{}->{}", bInfo->m_value.m_blkid.m_id,
                    bInfo->m_interval_length, bInfo->m_value.m_blkid_offset, bInfo->m_value.m_blkid.to_string());

            boost::intrusive_ptr<BlkBuffer> bbuf = blk_store->read(bInfo->m_value.m_blkid,
                                                                   BLOCK_SIZE * bInfo->m_value.m_blkid_offset,
                                                                   BLOCK_SIZE * bInfo->m_interval_length,
                                                                   boost::static_pointer_cast<blkstore_req<BlkBuffer>>(
                                                                           req));
            buf_info info;
            info.buf = bbuf;
            info.size = BLOCK_SIZE * bInfo->m_interval_length ;
            info.offset = BLOCK_SIZE * bInfo->m_value.m_blkid_offset ;
            req->read_buf_list.push_back(info);

        }
    }

    int cnt = req->blkstore_read_cnt.fetch_sub(1, std::memory_order_acquire);
    if (cnt == 1) {
        process_data_completions(req);
    }

    assert(perf->updateHistogram(vol_hist[READ_H], get_elapsed_time(startTime)));
    return 0;
}

/* Just create single block in memory, not on physical device and not in cache */
void Volume::alloc_single_block_in_mem() {
    BlkId *out_blkid = new BlkId(0);
    // Create an object for the buffer
    only_in_mem_buff = BlkBuffer::make_object();
    only_in_mem_buff->set_key(*out_blkid);

    // Create a new block of memory for the blocks requested and set the memvec pointer to that
    uint8_t *ptr;
    uint32_t size = BLKSTORE_BLK_SIZE;
    int ret = posix_memalign((void **) &ptr, 4096, size); // TODO: Align based on hw needs instead of 4k
    if (ret != 0) {
        throw std::bad_alloc();
    }
    memset(ptr, 0, size);
    homeds::MemVector<BLKSTORE_BLK_SIZE> &mvec = only_in_mem_buff->get_memvec_mutable();
    mvec.set(ptr, size, 0);
}

