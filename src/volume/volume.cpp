
//
// Created by Kadayam, Hari on 06/11/17.
//

#include "home_blks.hpp"
#include <mapping/mapping.cpp>
#include <fstream>
#include <atomic>
#include "homeds/utility/useful_defs.hpp"

using namespace std;
using namespace homestore;

std::atomic< int > vol_req_alloc;

#ifndef NDEBUG
/* only for testing */
bool vol_test_enable = false;
#endif

/* TODO: it will be more cleaner once statisitcs is integrated */
std::atomic< int > homestore::req_alloc(0);
std::atomic< int > homestore::req_dealloc(0);
int                btree_buf_alloc;
int                btree_buf_free;
int                btree_buf_make_obj;

VolInterface*                                                    VolInterface::_instance = nullptr;
homestore::BlkStore< homestore::VdevVarSizeBlkAllocatorPolicy >* Volume::m_data_blkstore = nullptr;

Volume::Volume(const vol_params& params) : m_comp_cb(params.io_comp_cb), m_metrics(params.vol_name) {
    m_state = vol_state::UNINITED;
    m_map = new mapping(params.size, params.page_size,
                        (std::bind(&Volume::process_metadata_completions, this, std::placeholders::_1)));

    auto ret = posix_memalign((void**)&m_sb, HomeStoreConfig::align_size, VOL_SB_SIZE);
    assert(m_sb != nullptr);
    m_sb->btree_sb = m_map->get_btree_sb();
    m_sb->state = vol_state::ONLINE;
    m_sb->page_size = params.page_size;
    m_sb->size = params.size;
    m_sb->uuid = params.uuid;
    memcpy(m_sb->vol_name, params.vol_name, VOL_NAME_SIZE);
    HomeBlks::instance()->vol_sb_init(m_sb);

    alloc_single_block_in_mem();

    m_data_blkstore = HomeBlks::instance()->get_data_blkstore();
    m_state = vol_state::ONLINE;
}

Volume::Volume(vol_sb* sb) : m_sb(sb), m_metrics(sb->vol_name) {
    m_state = vol_state::UNINITED;
    if (m_sb->state == vol_state::FAILED) {
        m_map = new mapping(m_sb->size, m_sb->page_size,
                            (std::bind(&Volume::process_metadata_completions, this, std::placeholders::_1)));
        m_sb->btree_sb = m_map->get_btree_sb();
        m_state = vol_state::DEGRADED;
        m_sb->state = m_state;
        HomeBlks::instance()->vol_sb_write(m_sb);
    } else {
        m_map = new mapping(m_sb->size, m_sb->page_size, m_sb->btree_sb,
                            (std::bind(&Volume::process_metadata_completions, this, std::placeholders::_1)));
    }

    alloc_single_block_in_mem();

    m_data_blkstore = HomeBlks::instance()->get_data_blkstore();
    m_state = m_sb->state;
    vol_scan_alloc_blks();
}

void Volume::attach_completion_cb(io_comp_callback& cb) { m_comp_cb = cb; }

void Volume::vol_scan_alloc_blks() {
    /* TODO: need to add method to scan btree */
    /* This call is asynchronous */
    HomeBlks::instance()->vol_scan_cmpltd(shared_from_this(), m_sb->state);
}

std::error_condition Volume::destroy() {
    LOGWARN("UnImplemented volume destruction!");
    return std::error_condition();
}

void Volume::process_metadata_completions(boost::intrusive_ptr< volume_req > req) {
    assert(!req->is_read);
    assert(!req->isSyncCall);

    for (std::shared_ptr< Free_Blk_Entry > ptr : req->blkids_to_free_due_to_overwrite) {
        LOGTRACE("Blocks to free {}", ptr.get()->to_string());
        m_data_blkstore->free_blk(ptr->blkId, get_page_size() * ptr->blkId_offset,
                                  get_page_size() * ptr->nblks_to_free);
    }

    req->done = true;
    auto parent_req = req->parent_req;
    assert(parent_req != nullptr);

    if (req->err != no_error) {
        parent_req->err = req->err;
    }

    check_and_complete_io(parent_req);
}

void Volume::process_vol_data_completions(boost::intrusive_ptr< blkstore_req< BlkBuffer > > bs_req) {
    boost::intrusive_ptr< volume_req > req = boost::static_pointer_cast< volume_req >(bs_req);
    req->vol_instance->process_data_completions(bs_req);
}

void Volume::process_data_completions(boost::intrusive_ptr< blkstore_req< BlkBuffer > > bs_req) {
    boost::intrusive_ptr< volume_req > req = boost::static_pointer_cast< volume_req >(bs_req);
    assert(!req->isSyncCall);

    HISTOGRAM_OBSERVE_IF_ELSE(m_metrics, req->is_read, volume_data_read_latency, volume_data_write_latency,
                      get_elapsed_time_us(req->op_start_time));
    if (!req->is_read) {
        if (req->err == no_error) {
            req->op_start_time = Clock::now();
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

    check_and_complete_io(parent_req);
}

std::error_condition Volume::write(uint64_t lba, uint8_t* buf, uint32_t nblks,
                                   boost::intrusive_ptr< vol_interface_req > req) {
    try {
        assert(m_sb->state == vol_state::ONLINE);
        std::vector< BlkId > bid;
        blk_alloc_hints      hints;

        hints.desired_temp = 0;
        hints.dev_id_hint = -1;

        assert(m_sb->page_size % HomeBlks::instance()->get_data_pagesz() == 0);
        assert((m_sb->page_size * nblks) <= VOL_MAX_IO_SIZE);
        hints.multiplier = (m_sb->page_size / HomeBlks::instance()->get_data_pagesz());

        COUNTER_INCREMENT(m_metrics, volume_write_count, 1);

        req->io_start_time = Clock::now();
        BlkAllocStatus status = m_data_blkstore->alloc_blk(nblks * m_sb->page_size, hints, bid);
        assert(status == BLK_ALLOC_SUCCESS);
        HISTOGRAM_OBSERVE(m_metrics, volume_blkalloc_latency, get_elapsed_time_us(req->io_start_time));

        boost::intrusive_ptr< homeds::MemVector > mvec(new homeds::MemVector());
        mvec->set(buf, m_sb->page_size * nblks, 0);

        uint32_t offset = 0;
        uint32_t blks_snt = 0;
        uint32_t i = 0;

        Clock::time_point data_io_start_time = Clock::now();
        req->io_cnt.set(1);
        for (i = 0; i < bid.size(); ++i) {
            std::deque< boost::intrusive_ptr< writeback_req > > req_q;
            req->io_cnt.increment();

            boost::intrusive_ptr< volume_req > child_req(new volume_req());
            child_req->parent_req = req;
            child_req->is_read = false;
            child_req->bid = bid[i];
            child_req->lba = lba + blks_snt;
            child_req->vol_instance = shared_from_this();
            child_req->op_start_time = data_io_start_time;

            assert((bid[i].data_size(HomeBlks::instance()->get_data_pagesz()) % m_sb->page_size) == 0);
            child_req->nblks = bid[i].data_size(HomeBlks::instance()->get_data_pagesz()) / m_sb->page_size;

            boost::intrusive_ptr< BlkBuffer > bbuf = m_data_blkstore->write(
                bid[i], mvec, offset, boost::static_pointer_cast< blkstore_req< BlkBuffer > >(child_req), req_q);
            offset += bid[i].data_size(HomeBlks::instance()->get_data_pagesz());
            blks_snt += child_req->nblks;
        }

        HISTOGRAM_OBSERVE(m_metrics, volume_pieces_per_write, bid.size());
        assert(blks_snt == nblks);

        check_and_complete_io(req);
    } catch (const std::exception& e) {
        assert(0);
        LOGERROR("{}", e.what());
        return std::make_error_condition(std::errc::device_or_resource_busy);
    }
    return no_error;
}

void Volume::check_and_complete_io(boost::intrusive_ptr< vol_interface_req >& req, bool call_completion) {
    if (req->io_cnt.decrement_testz()) {
        HISTOGRAM_OBSERVE_IF_ELSE(m_metrics, req->is_read, volume_read_latency, volume_write_latency,
                          get_elapsed_time_us(req->io_start_time));
        if (req->err != no_error) {
            COUNTER_INCREMENT_IF_ELSE(m_metrics, req->is_read, volume_write_error_count, volume_read_error_count, 1);
        }
        if (call_completion) {
            m_comp_cb(req);
        }
    }
}

void Volume::print_tree() { m_map->print_tree(); }

#ifndef NDEBUG
void Volume::enable_split_merge_crash_simulation() { m_map->enable_split_merge_crash_simulation(); }
#endif

std::error_condition Volume::read(uint64_t lba, int nblks, boost::intrusive_ptr< vol_interface_req > req, bool sync) {
    try {
        assert(m_sb->state == vol_state::ONLINE);
        std::vector< std::shared_ptr< Lba_Block > > mapping_list;

        COUNTER_INCREMENT(m_metrics, volume_read_count, 1);
        req->io_start_time = Clock::now();

        // Read the mapping lba from mapping layer
        std::error_condition ret = m_map->get(lba, nblks, mapping_list);
        if (ret && ret == homestore_error::lba_not_exist) {
            COUNTER_INCREMENT(m_metrics, volume_read_error_count, 1);
            return ret;
        }
        HISTOGRAM_OBSERVE(m_metrics, volume_map_read_latency, get_elapsed_time_us(req->io_start_time));

        req->err = ret;
        req->io_cnt.set(1);
        req->read_buf_list.reserve(mapping_list.size());

        Clock::time_point data_io_start_time = Clock::now();
        for (std::shared_ptr< Lba_Block > bInfo : mapping_list) {
            if (!bInfo->m_blkid_found) {
                uint8_t i = 0;
                while (i < bInfo->m_value.m_blkid.get_nblks()) {
                    req->read_buf_list.emplace_back(m_sb->get_page_size(), 0, m_only_in_mem_buff);
                    i++;
                }
            } else {
                LOGTRACE("Volume - Sending read to blkbuffer - {},{},{}->{}", bInfo->m_value.m_blkid.m_id,
                         bInfo->m_interval_length, bInfo->m_value.m_blkid_offset, bInfo->m_value.m_blkid.to_string());

                boost::intrusive_ptr< volume_req > child_req(new volume_req());
                req->io_cnt.increment();
                child_req->is_read = true;
                child_req->parent_req = req;
                child_req->vol_instance = shared_from_this();
                child_req->isSyncCall = sync;
                child_req->op_start_time = data_io_start_time;

                boost::intrusive_ptr< BlkBuffer > bbuf =
                    m_data_blkstore->read(bInfo->m_value.m_blkid, m_sb->page_size * bInfo->m_value.m_blkid_offset,
                                          m_sb->page_size * bInfo->m_interval_length,
                                          boost::static_pointer_cast< blkstore_req< BlkBuffer > >(child_req));

                req->read_buf_list.emplace_back(m_sb->get_page_size() * bInfo->m_interval_length,      /* size */
                                                m_sb->get_page_size() * bInfo->m_value.m_blkid_offset, /* offset */
                                                bbuf /* Buffer */);
            }
        }

        check_and_complete_io(req, !sync);
    } catch (const std::exception& e) {
        assert(0);
        LOGERROR("{}", e.what());
        return std::make_error_condition(std::errc::device_or_resource_busy);
    }
    return no_error;
}

/* Just create single block in memory, not on physical device and not in cache */
void Volume::alloc_single_block_in_mem() {
    BlkId* out_blkid = new BlkId(0);
    // Create an object for the buffer
    m_only_in_mem_buff = BlkBuffer::make_object();
    m_only_in_mem_buff->set_key(*out_blkid);

    // Create a new block of memory for the blocks requested and set the memvec pointer to that
    uint8_t* ptr;
    uint32_t size = m_sb->page_size;
    ptr = (uint8_t*)malloc(size);
    if (ptr == nullptr) {
        throw std::bad_alloc();
    }
    memset(ptr, 0, size);
    boost::intrusive_ptr< homeds::MemVector > mvec(new homeds::MemVector());
    mvec->set(ptr, size, 0);
    m_only_in_mem_buff->set_memvec(mvec, 0, size);
}
