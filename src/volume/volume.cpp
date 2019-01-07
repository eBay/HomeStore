
//
// Created by Kadayam, Hari on 06/11/17.
//

#include "home_blks.hpp"
#include <mapping/mapping.cpp>
#include <fstream>
#include <atomic>

using namespace std;
using namespace homestore;

#define MAX_CACHE_SIZE     (100 * 1024ul * 1024ul) /* it has to be a multiple of 16k */
constexpr auto BLOCK_SIZE = (4 * 1024ul);

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

/* TODO: adding it here as there is no .c file in blkstore. we will create it later */
void homestore::intrusive_ptr_add_ref(BlkBuffer *buf) {
    intrusive_ptr_add_ref((WriteBackCacheBuffer<BlkId> *)buf);
}
    
void homestore::intrusive_ptr_release(BlkBuffer *buf) {
    intrusive_ptr_release((WriteBackCacheBuffer<BlkId> *)buf);
}

VolInterface *VolInterface::_instance = nullptr;
homestore::BlkStore<homestore::VdevVarSizeBlkAllocatorPolicy> *Volume::m_data_blkstore = nullptr;

uint64_t
Volume::get_elapsed_time(Clock::time_point startTime) {
    std::chrono::nanoseconds ns = std::chrono::duration_cast
            <std::chrono::nanoseconds>(Clock::now() - startTime);
    return ns.count() / 1000;
}

Volume::Volume(vol_params &params) : m_comp_cb(params.io_comp_cb) {
    m_state = vol_state::UNINITED;
    m_map = new mapping(params.size, params.page_size, (std::bind(&Volume::process_metadata_completions, this,
                                 std::placeholders::_1)));
    auto ret = posix_memalign((void **) &m_sb, HomeStoreConfig::align_size, VOL_SB_SIZE); 
    assert(m_sb != nullptr);
    m_sb->btree_sb = m_map->get_btree_sb();
    m_sb->state = vol_state::ONLINE;
    m_sb->page_size = params.page_size;
    m_sb->size = params.size;
    m_sb->uuid = params.uuid;
    memcpy(m_sb->vol_name, params.vol_name, VOL_NAME_SIZE);
    HomeBlks::instance()->vol_sb_init(m_sb);
    
    alloc_single_block_in_mem();
    init_perf_report();
    m_data_blkstore = HomeBlks::instance()->get_data_blkstore();
    m_state = vol_state::ONLINE;
    m_vol_ptr = std::shared_ptr<Volume>(this);
}

Volume::Volume(vol_sb *sb) : m_sb(sb) {
    m_state = vol_state::UNINITED;
    if (m_sb->state == vol_state::FAILED) {
        m_map = new mapping(m_sb->size, m_sb->page_size, (std::bind(&Volume::process_metadata_completions, this,
                                 std::placeholders::_1)));
        m_sb->btree_sb = m_map->get_btree_sb();
        m_state = vol_state::DEGRADED;
        m_sb->state = m_state;
        HomeBlks::instance()->vol_sb_write(m_sb);
    } else {
        m_map = new mapping(m_sb->size, m_sb->page_size, m_sb->btree_sb,
                      (std::bind(&Volume::process_metadata_completions, this,
                                 std::placeholders::_1)));
    }

    alloc_single_block_in_mem();
    init_perf_report();
    m_data_blkstore = HomeBlks::instance()->get_data_blkstore();
    m_state = m_sb->state;
    m_vol_ptr = std::shared_ptr<Volume>(this);
    vol_scan_alloc_blks();
}

char *
Volume::get_name() {
    return(get_sb()->vol_name);
}

uint64_t
Volume::get_page_size() {
    return(get_sb()->page_size);
}

uint64_t
Volume::get_size() {
    return(get_sb()->size);
}

void
Volume::attach_completion_cb(io_comp_callback &cb) {
    m_comp_cb = cb;
}

void 
Volume::vol_scan_alloc_blks() {
    /* TODO: need to add method to scan btree */
    /* This call is asynchronous */
    HomeBlks::instance()->vol_scan_cmpltd(m_vol_ptr, m_sb->state);
}

std::error_condition
Volume::destroy() {
    LOGWARN("UnImplemented volume destruction!");
    return std::error_condition();
}

void
homestore::Volume::process_metadata_completions(boost::intrusive_ptr<volume_req> req) {
    assert(!req->is_read);
    assert(!req->isSyncCall);
   
    for (std::shared_ptr<Free_Blk_Entry> ptr : req->blkids_to_free_due_to_overwrite) {
        LOGTRACE("Blocks to free {}", ptr.get()->to_string());
        m_data_blkstore->free_blk(ptr->blkId, BLOCK_SIZE * ptr->blkId_offset, 
                            BLOCK_SIZE * ptr->nblks_to_free);
    }
   
    req->done = true;
    auto parent_req = req->parent_req;
    assert(parent_req != nullptr);
    
    if (req->err != no_error) {
        parent_req->err = req->err;
    }

    if (parent_req->io_cnt.fetch_sub(1, memory_order_acquire) == 1) {
        if (req->err == no_error) {
            PerfMetrics::getInstance()->updateHist(VOL_IO_WRITE_H, get_elapsed_time(parent_req->startTime));
        }
        m_comp_cb(parent_req);
    }
}

void
Volume::process_vol_data_completions(boost::intrusive_ptr<blkstore_req<BlkBuffer>> bs_req) {
    boost::intrusive_ptr<volume_req> req = boost::static_pointer_cast<volume_req>(bs_req);
    req->vol_instance->process_data_completions(bs_req);
}

void
Volume::process_data_completions(boost::intrusive_ptr<blkstore_req<BlkBuffer>> bs_req) {
    boost::intrusive_ptr<volume_req> req = boost::static_pointer_cast<volume_req>(bs_req);

    assert(!req->isSyncCall);
    if (!req->is_read) {
        if (req->err == no_error) {
            m_map->put(req, req->lba, req->nblks, req->bid);
        } else {
            process_metadata_completions(req);
        }
        return;
    }
   
    auto parent_req = req->parent_req;
    assert(parent_req != nullptr);
    if (req->err != no_error) {
        parent_req->err = req->err;
    }

    if (parent_req->io_cnt.fetch_sub(1, memory_order_acquire) == 1) {
        PerfMetrics::getInstance()->updateHist(VOL_IO_READ_H, get_elapsed_time(parent_req->startTime));
        m_comp_cb(parent_req);
    }
}

void
Volume::init_perf_report() {
}

void
Volume::print_perf_report() {
    std::ofstream ofs ("result.json", std::ofstream::out);
    ofs << PerfMetrics::getInstance()->report() << std::endl;
    ofs.close();
}

std::error_condition
Volume::write(uint64_t lba, uint8_t *buf, uint32_t nblks,
        boost::intrusive_ptr<vol_interface_req> req) {
    try {
        assert(m_sb->state == vol_state::ONLINE);
        std::vector<BlkId> bid;
        blk_alloc_hints hints;
        hints.desired_temp = 0;
        hints.dev_id_hint = -1;
        assert(m_sb->page_size % HomeBlks::instance()->get_data_pagesz() == 0);
        hints.multiplier = (m_sb->page_size / HomeBlks::instance()->get_data_pagesz());

        req->startTime = Clock::now();

        assert((m_sb->page_size * nblks) <= VOL_MAX_IO_SIZE);
        {
            CURRENT_CLOCK(startTime)
                BlkAllocStatus status = m_data_blkstore->alloc_blk(nblks * m_sb->page_size, hints, bid);
            if (status != BLK_ALLOC_SUCCESS) {
                assert(0);
            }
            PerfMetrics::getInstance()->updateHist(VOL_BLK_ALLOC_H, get_elapsed_time(startTime));
        }

        Clock::time_point startTime = Clock::now();
        boost::intrusive_ptr<homeds::MemVector> mvec(new homeds::MemVector());
        mvec->set(buf, m_sb->page_size * nblks, 0);
        uint32_t offset = 0;
        uint32_t blks_snt = 0;
        uint32_t i = 0;

        req->io_cnt = 1;
        for (i = 0; i < bid.size(); ++i) {
            std::deque<boost::intrusive_ptr<writeback_req>> req_q;
            ++req->io_cnt;
            boost::intrusive_ptr<volume_req> child_req(new volume_req());

            child_req->parent_req = req;

            child_req->is_read = false;
            child_req->bid = bid[i];
            child_req->lba = lba + blks_snt;
            child_req->vol_instance = m_vol_ptr;
            assert((bid[i].data_size(HomeBlks::instance()->get_data_pagesz()) % m_sb->page_size) == 0);
            child_req->nblks =  bid[i].data_size(HomeBlks::instance()->get_data_pagesz()) / m_sb->page_size;
            boost::intrusive_ptr<BlkBuffer> bbuf = m_data_blkstore->write(bid[i], mvec, offset,
                                boost::static_pointer_cast<blkstore_req<BlkBuffer>>(child_req),
                                req_q);
            offset += bid[i].data_size(HomeBlks::instance()->get_data_pagesz());
            blks_snt += child_req->nblks;
        }

        assert(blks_snt == nblks);
        
        PerfMetrics::getInstance()->updateHist(VOL_WRITE_H, get_elapsed_time(startTime));
        if (req->io_cnt.fetch_sub(1, std::memory_order_acquire) == 1) {
            /* all completions are completed */
            PerfMetrics::getInstance()->updateHist(VOL_IO_WRITE_H, get_elapsed_time(req->startTime));
            m_comp_cb(req);
         }
    } catch (const std::exception &e) {
        assert(0);
        LOGERROR("{}", e.what());
        return std::make_error_condition(std::errc::device_or_resource_busy);
    }
    return no_error;
}

void Volume::print_tree() {
    m_map->print_tree();
}

#ifndef NDEBUG
void Volume::enable_split_merge_crash_simulation() {
    m_map->enable_split_merge_crash_simulation();
}
#endif

std::error_condition
Volume::read(uint64_t lba, int nblks, boost::intrusive_ptr<vol_interface_req> req, bool sync) {
    try {
        assert(m_sb->state == vol_state::ONLINE);
        std::vector<std::shared_ptr<Lba_Block>> mappingList;
        Clock::time_point startTime = Clock::now();

        std::error_condition ret = m_map->get(lba, nblks, mappingList);


        if (ret && ret == homestore_error::lba_not_exist) {
            return ret;
        }

        req->err = ret;
        req->io_cnt = 1;
        req->startTime = Clock::now();
        PerfMetrics::getInstance()->updateHist(VOL_MAP_READ_H, get_elapsed_time(startTime));
        startTime = Clock::now();

        for (std::shared_ptr<Lba_Block> bInfo: mappingList) {
            if (!bInfo->m_blkid_found) {
                uint8_t i = 0;
                while (i < bInfo->m_value.m_blkid.get_nblks()) {
                    buf_info info;
                    info.buf = m_only_in_mem_buff;
                    info.size = m_sb->page_size;
                    info.offset = 0;
                    req->read_buf_list.push_back(info);
                    i++;
                }
            } else {
                LOGTRACE("Volume - Sending read to blkbuffer - {},{},{}->{}", 
                        bInfo->m_value.m_blkid.m_id, bInfo->m_interval_length, 
                        bInfo->m_value.m_blkid_offset, 
                        bInfo->m_value.m_blkid.to_string());

                boost::intrusive_ptr<volume_req> child_req(new volume_req());
                req->io_cnt++;
                child_req->is_read = true;
                child_req->parent_req = req;
                child_req->vol_instance = m_vol_ptr;
                child_req->isSyncCall = sync;
                boost::intrusive_ptr<BlkBuffer> bbuf = 
                    m_data_blkstore->read(bInfo->m_value.m_blkid,
                            m_sb->page_size * bInfo->m_value.m_blkid_offset,
                            m_sb->page_size * bInfo->m_interval_length,
                            boost::static_pointer_cast<blkstore_req<BlkBuffer>>(
                                child_req));
                buf_info info;
                info.buf = bbuf;
                info.size = m_sb->page_size * bInfo->m_interval_length ;
                info.offset = m_sb->page_size * bInfo->m_value.m_blkid_offset ;
                req->read_buf_list.push_back(info);
            }
        }

        PerfMetrics::getInstance()->updateHist(VOL_READ_H, get_elapsed_time(startTime));
        if (req->io_cnt.fetch_sub(1, std::memory_order_acquire) == 1) {
            /* all completions are completed */
            PerfMetrics::getInstance()->updateHist(VOL_IO_READ_H, get_elapsed_time(req->startTime));
            if (!sync) {
                m_comp_cb(req);
            }
        }
    } catch (const std::exception &e) {
        assert(0);
        LOGERROR("{}", e.what());
        return std::make_error_condition(std::errc::device_or_resource_busy);
    }
    return no_error;
}

/* Just create single block in memory, not on physical device and not in cache */
void Volume::alloc_single_block_in_mem() {
    BlkId *out_blkid = new BlkId(0);
    // Create an object for the buffer
    m_only_in_mem_buff = BlkBuffer::make_object();
    m_only_in_mem_buff->set_key(*out_blkid);

    // Create a new block of memory for the blocks requested and set the memvec pointer to that
    uint8_t *ptr;
    uint32_t size = m_sb->page_size;
    ptr = (uint8_t *)malloc(size);
    if (ptr == nullptr) {
        throw std::bad_alloc();
    }
    memset(ptr, 0, size);
    boost::intrusive_ptr<homeds::MemVector> mvec(new homeds::MemVector());
    mvec->set(ptr, size, 0);
    m_only_in_mem_buff->set_memvec(mvec, 0, size);
}

