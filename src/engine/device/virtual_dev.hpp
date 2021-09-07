//
// Created by Kadayam, Hari on 08/11/17.
//
#pragma once

#include <array>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <functional>
#include <iterator>
#include <limits>
#include <memory>
#include <map>
#include <mutex>
#include <string>
#include <system_error>
#include <type_traits>
#include <vector>

#include <boost/range/irange.hpp>
#include <fds/buffer.hpp>
#include <metrics/metrics.hpp>
#include <sds_logging/logging.h>
#include <utility/atomic_counter.hpp>

#include "api/meta_interface.hpp"
#include "device.h"
#include "engine/blkalloc/blk_allocator.h"
#include "engine/blkalloc/varsize_blk_allocator.h"
#include "engine/common/error.h"
#include "engine/common/homestore_assert.hpp"
#include "engine/common/homestore_config.hpp"
#include "engine/common/homestore_header.hpp"
#include "engine/common/homestore_flip.hpp"
#include "engine/homestore_base.hpp"

SDS_LOGGING_DECL(device)

namespace homestore {

//#define VDEV_LABEL " for Homestore Virtual Device"
//#define PHYSICAL_HIST "physical"

class VdevFixedBlkAllocatorPolicy {
public:
    static std::shared_ptr< FixedBlkAllocator > create_allocator(const uint64_t size, const uint32_t vpage_size,
                                                                 const bool is_auto_recovery, const uint32_t unique_id,
                                                                 const bool init) {
        BlkAllocConfig cfg{vpage_size, size, std::string("fixed_chunk_") + std::to_string(unique_id)};
        cfg.set_auto_recovery(is_auto_recovery);
        return std::make_shared< FixedBlkAllocator >(cfg, init, unique_id);
    }
};

class VdevVarSizeBlkAllocatorPolicy {
public:
    static std::shared_ptr< VarsizeBlkAllocator > create_allocator(const uint64_t size, const uint32_t vpage_size,
                                                                   const bool is_auto_recovery,
                                                                   const uint32_t unique_id, const bool is_init) {
        VarsizeBlkAllocConfig cfg{vpage_size, size, std::string("varsize_chunk_") + std::to_string(unique_id)};
        HS_DEBUG_ASSERT_EQ((size % MIN_CHUNK_SIZE), 0);
        cfg.set_phys_page_size(HS_STATIC_CONFIG(drive_attr.phys_page_size));
        cfg.set_auto_recovery(is_auto_recovery);
        return std::make_shared< VarsizeBlkAllocator >(cfg, is_init, unique_id);
    }
};

struct pdev_chunk_map {
    PhysicalDev* pdev;
    std::vector< PhysicalDevChunk* > chunks_in_pdev;
};

struct virtualdev_req;

typedef std::function< void(const boost::intrusive_ptr< virtualdev_req >& req) > vdev_comp_cb_t;
typedef std::function< void(bool success) > vdev_format_cb_t;
typedef std::function< void(void) > vdev_high_watermark_cb_t;

struct virtualdev_req : public sisl::ObjLifeCounter< virtualdev_req > {
    uint64_t request_id{0};
    uint64_t version;
    vdev_comp_cb_t cb; // callback into vdev from static completion function. It is set for all the ops
    uint64_t size;
    std::error_condition err{no_error};
    bool is_read{false};
    bool isSyncCall{false};
    sisl::atomic_counter< int > refcount;
    PhysicalDevChunk* chunk;
    Clock::time_point io_start_time;
    bool part_of_batch{false};
    bool format{false};
    vdev_format_cb_t format_cb; // callback stored for format operation.

#ifndef NDEBUG
    uint64_t dev_offset;
    uint8_t* mem;
#endif

#ifdef _PRERELEASE
    bool delay_induced{false};
#endif
    bool outstanding_cbs{false};
    sisl::atomic_counter< uint8_t > outstanding_cb{0};

    void inc_ref() { intrusive_ptr_add_ref(this); }
    void dec_ref() { intrusive_ptr_release(this); }

    template < typename RequestType,
               typename = std::enable_if_t<
                   std::is_base_of_v< virtualdev_req, std::decay_t< typename RequestType::element_type > > > >
    static auto to_vdev_req(RequestType& req) {
        return boost::static_pointer_cast< virtualdev_req >(req);
    }

    // static boost::intrusive_ptr< virtualdev_req > make_request() {
    //    return boost::intrusive_ptr< virtualdev_req >(sisl::ObjectAllocator< virtualdev_req >::make_object());
    //}
    virtual void free_yourself() { sisl::ObjectAllocator< virtualdev_req >::deallocate(this); }
    friend void intrusive_ptr_add_ref(virtualdev_req* const req) { req->refcount.increment(1); }
    friend void intrusive_ptr_release(virtualdev_req* const req) {
        if (req->refcount.decrement_testz()) { req->free_yourself(); }
    }

    virtualdev_req(const virtualdev_req&) = delete;
    virtualdev_req(virtualdev_req&&) noexcept = delete;
    virtualdev_req& operator=(const virtualdev_req&) = delete;
    virtualdev_req& operator=(virtualdev_req&&) noexcept = delete;

    virtual ~virtualdev_req() { version = 0; }

protected:
    friend class sisl::ObjectAllocator< virtualdev_req >;
    virtualdev_req() : request_id{s_req_id.fetch_add(1, std::memory_order_relaxed)}, refcount{0} {}

private:
    static std::atomic< uint64_t > s_req_id;
};

[[maybe_unused]] static void virtual_dev_process_completions(const int64_t res, uint8_t* const cookie) {
    boost::intrusive_ptr< virtualdev_req > vd_req{reinterpret_cast< virtualdev_req* >(cookie), false};
    HS_ASSERT_CMP(DEBUG, vd_req->version, ==, 0xDEAD);

    if ((vd_req->err == no_error) && (res != 0)) {
        LOGERROR("seeing error on request id {} error {}", vd_req->request_id, res);
        /* TODO: it should have more specific errors */
        vd_req->err = std::make_error_condition(std::io_errc::stream);
    }

#ifdef _PRERELEASE
    if (homestore_flip->test_flip("io_write_comp_error_flip")) { vd_req->err = write_failed; }

    if (homestore_flip->test_flip("io_read_comp_error_flip")) { vd_req->err = read_failed; }
#endif

    if (!vd_req->format) {
        auto* const pdev{vd_req->chunk->get_physical_dev_mutable()};
        if (vd_req->err) {
            COUNTER_INCREMENT_IF_ELSE(pdev->get_metrics(), vd_req->is_read, drive_read_errors, drive_write_errors, 1);
            pdev->device_manager_mutable()->handle_error(pdev);
        } else {
            HISTOGRAM_OBSERVE_IF_ELSE(pdev->get_metrics(), vd_req->is_read, drive_read_latency, drive_write_latency,
                                      get_elapsed_time_us(vd_req->io_start_time));
        }
    }

    vd_req->cb(vd_req);
    // NOTE: Beyond this point vd_req could be freed by the callback. So once callback is made,
    // DO NOT ACCESS vd_req beyond this point.
}

class VirtualDevMetrics : public sisl::MetricsGroupWrapper {
public:
    explicit VirtualDevMetrics(const char* const inst_name) : sisl::MetricsGroupWrapper{"VirtualDev", inst_name} {
        REGISTER_COUNTER(vdev_read_count, "vdev total read cnt");
        REGISTER_COUNTER(vdev_write_count, "vdev total write cnt");
        REGISTER_COUNTER(vdev_truncate_count, "vdev total truncate cnt");
        REGISTER_COUNTER(vdev_high_watermark_count, "vdev total high watermark cnt");
        REGISTER_COUNTER(vdev_num_alloc_failure, "vdev blk alloc failure cnt");
        REGISTER_COUNTER(unalign_writes, "unalign write cnt");

        register_me_to_farm();
    }

    VirtualDevMetrics(const VirtualDevMetrics&) = delete;
    VirtualDevMetrics(VirtualDevMetrics&&) noexcept = delete;
    VirtualDevMetrics& operator=(const VirtualDevMetrics&) = delete;
    VirtualDevMetrics& operator=(VirtualDevMetrics&&) noexcept = delete;

    ~VirtualDevMetrics() { deregister_me_from_farm(); }
};

/*
 * VirtualDev: Virtual device implements a similar functionality of RAID striping, customized however. Virtual devices
 * can be created across multiple physical devices. Unlike RAID, its io is not always in a bigger strip sizes. It
 * support n-mirrored writes.
 *
 * Template parameters:
 * Allocator: The type of AllocatorPolicy to allocate blocks for writes.
 * DefaultDeviceSelector: Which device to select for allocation
 */
static constexpr uint32_t VIRDEV_BLKSIZE{512};
static constexpr uint64_t CHUNK_EOF{0xabcdabcd};
static constexpr off_t INVALID_OFFSET{std::numeric_limits< off_t >::max()};

static constexpr uint32_t vdev_high_watermark_per{80};

template < typename Allocator, typename DefaultDeviceSelector >
class VirtualDev : public AbstractVirtualDev {

    struct Chunk_EOF_t {
        uint64_t e;
    };

    // NOTE:  Usage of this needs to avoid punning which is now illegal in C++ 11 and up
    typedef union {
        struct Chunk_EOF_t eof;
        std::array < unsigned char, VIRDEV_BLKSIZE > padding;
    } Chunk_EOF;

    static_assert(sizeof(Chunk_EOF) == VIRDEV_BLKSIZE, "LogDevRecordHeader must be VIRDEV_SIZE bytes");

private:
    vdev_info_block* m_vb;   // This device block info
    DeviceManager* m_mgr;    // Device Manager back pointer
    std::string m_name;      // Name of the vdev
    uint64_t m_chunk_size;   // Chunk size that will be allocated in a physical device
    std::mutex m_mgmt_mutex; // Any mutex taken for management operations (like adding/removing chunks).

    // List of physical devices this virtual device uses and its corresponding chunks for the physdev
    std::vector< pdev_chunk_map > m_primary_pdev_chunks_list;

    // For each of the primary chunk we created, this is the list of mirrored chunks. The physical devices
    // for the mirrored chunk always follows the next device pattern.
    std::map< PhysicalDevChunk*, std::vector< PhysicalDevChunk* > > m_mirror_chunks;

    // Instance of device selector
    std::unique_ptr< DefaultDeviceSelector > m_selector;
    uint32_t m_num_chunks;
    vdev_comp_cb_t m_comp_cb;
    uint32_t m_pagesz;
    bool m_recovery_init;

    // data structure for append write
    uint64_t m_reserved_sz{0};                   // write size within chunk, used to check chunk boundary;
    off_t m_seek_cursor{0};                      // the seek cursor
    off_t m_data_start_offset{0};                // Start offset of where actual data begin for this vdev
    std::atomic< uint64_t > m_write_sz_in_total; // this size will be decreased by truncate and increased by append;
    bool m_auto_recovery;
    bool m_truncate_done{true};
    vdev_high_watermark_cb_t m_hwm_cb{nullptr};
    VirtualDevMetrics m_metrics;

public:
    static constexpr size_t context_data_size() { return MAX_CONTEXT_DATA_SZ; }

    void init(DeviceManager* const mgr, vdev_info_block* const vb, vdev_comp_cb_t cb, const uint32_t page_size, const bool auto_recovery,
              vdev_high_watermark_cb_t hwm_cb) {
        m_mgr = mgr;
        m_vb = vb;
        m_comp_cb = std::move(cb);
        m_chunk_size = 0;
        m_num_chunks = 0;
        m_pagesz = page_size;
        m_selector = std::make_unique< DefaultDeviceSelector >();
        m_recovery_init = false;
        m_reserved_sz = 0;
        m_auto_recovery = auto_recovery;
        m_write_sz_in_total.store(0, std::memory_order_relaxed);
        m_hwm_cb = std::move(hwm_cb);
    }

    /* Load the virtual dev from vdev_info_block and create a Virtual Dev. */
    VirtualDev(DeviceManager* const mgr, const char* const name, vdev_info_block* const vb, vdev_comp_cb_t cb, const bool recovery_init,
               const bool auto_recovery = false, vdev_high_watermark_cb_t hwm_cb = nullptr) :
            m_name{name}, m_metrics{name} {
        init(mgr, vb, std::move(cb), vb->page_size, auto_recovery, std::move(hwm_cb));

        m_recovery_init = recovery_init;
        m_mgr->add_chunks(vb->vdev_id, [this](PhysicalDevChunk* const chunk) { add_chunk(chunk); });

        HS_ASSERT_CMP(LOGMSG, vb->num_primary_chunks * (vb->num_mirrors + 1), ==,
                      m_num_chunks); // Mirrors should be at least one less than device list.
        HS_ASSERT_CMP(LOGMSG, vb->get_size(), ==, vb->num_primary_chunks * m_chunk_size);
    }

    /* Create a new virtual dev for these parameters */
    VirtualDev(DeviceManager* const mgr, const char* const name, const uint64_t context_size, const uint32_t nmirror, const bool is_stripe,
               const uint32_t page_size, const std::vector< PhysicalDev* >& pdev_list, vdev_comp_cb_t cb, char* const blob,
               const uint64_t size_in, const bool auto_recovery = false, vdev_high_watermark_cb_t hwm_cb = nullptr) :
            m_name{name}, m_metrics{name} {
        init(mgr, nullptr, std::move(cb), page_size, auto_recovery, std::move(hwm_cb));

        // Prepare primary chunks in a physical device for future inserts.
        const auto* const drive_interface{iomgr::IOManager::instance().default_drive_interface()};
        m_primary_pdev_chunks_list.reserve(pdev_list.size());

        const auto& pdev_device_name{pdev_list.empty() ? "" : pdev_list.front()->get_devname()};
        const auto pdev_drive_type{pdev_list.empty() ? iomgr::iomgr_drive_type::unknown
                                                     : drive_interface->get_drive_type(pdev_device_name)};
        for (const auto& pdev : pdev_list) {
            pdev_chunk_map mp;
            mp.pdev = pdev;
            mp.chunks_in_pdev.reserve(1);

            // ensure that all physical devices have same type
            bool add_device{true};
            const auto& new_pdev_device_name{pdev->get_devname()};
            if (pdev_device_name != new_pdev_device_name) {
                const auto new_pdev_drive_type{drive_interface->get_drive_type(new_pdev_device_name)};
                if (pdev_drive_type != new_pdev_drive_type) {
                    HS_LOG(ERROR, device, "Vdev={} - dev={} type={} does not match type dev={} type={}", m_name,
                           pdev_device_name, pdev_drive_type, new_pdev_device_name, new_pdev_drive_type);
                    add_device = false;
                }
            }

            if (add_device) { m_primary_pdev_chunks_list.push_back(std::move(mp)); }
        }
        // check that all pdevs valid and of same type
        HS_DEBUG_ASSERT_EQ(m_primary_pdev_chunks_list.size(), pdev_list.size());

        auto size{size_in};
        // Now its time to allocate chunks as needed
        HS_ASSERT_CMP(LOGMSG, nmirror, <,
                      m_primary_pdev_chunks_list.size()); // Mirrors should be at least one less than device list.

        if (is_stripe) {
            m_num_chunks = static_cast< uint32_t >(m_primary_pdev_chunks_list.size());
            uint32_t cnt{1};

            do {
                m_num_chunks = cnt * m_num_chunks;
                m_chunk_size = size / m_num_chunks;
                ++cnt;
            } while (m_chunk_size > MAX_CHUNK_SIZE);
        } else {
            m_chunk_size = size;
            m_num_chunks = 1;
        }

        if (m_chunk_size % MIN_CHUNK_SIZE > 0) {
            m_chunk_size = sisl::round_up(m_chunk_size, MIN_CHUNK_SIZE);
            HS_LOG(INFO, device, "size of a chunk is resized to {}", m_chunk_size);
        }

        LOGINFO("size of a chunk is {} is_stripe {} num chunks {}", m_chunk_size, is_stripe, m_num_chunks);
        if (m_chunk_size > MAX_CHUNK_SIZE) {
            throw homestore::homestore_exception("invalid chunk size in init", homestore_error::invalid_chunk_size);
        }

        /* make size multiple of chunk size */
        size = m_chunk_size * m_num_chunks;

        // Create a new vdev in persistent area and get the block of it
        m_vb = mgr->alloc_vdev(context_size, nmirror, page_size, m_num_chunks, blob, size);

        for (auto i : boost::irange< uint32_t >(0, m_num_chunks)) {
            const auto pdev_ind{i % m_primary_pdev_chunks_list.size()};

            // Create a chunk on selected physical device and add it to chunks in physdev list
            auto* const chunk{create_dev_chunk(pdev_ind, nullptr, INVALID_CHUNK_ID)};
            std::shared_ptr< BlkAllocator > ba{Allocator::create_allocator(
                m_chunk_size, get_page_size(), m_auto_recovery, chunk->get_chunk_id(), true /* init */)};
            // set initial value of "end of chunk offset";
            chunk->update_end_of_chunk(m_chunk_size);

            chunk->set_blk_allocator((nmirror > 0) ? ba : std::move(ba));
            m_primary_pdev_chunks_list[pdev_ind].chunks_in_pdev.push_back(chunk);

            // If we have mirror, create a map between chunk and its mirrored chunks
            if (nmirror > 0) {
                size_t next_ind{i};
                std::vector< PhysicalDevChunk* > vec;
                vec.reserve(nmirror);
                for (auto j : boost::irange< uint32_t >(0, nmirror)) {
                    if ((++next_ind) == m_primary_pdev_chunks_list.size()) { next_ind = 0; }
                    auto* const mchunk{create_dev_chunk(next_ind, ba, chunk->get_chunk_id())};
                    vec.push_back(mchunk);
                }
                m_mirror_chunks.emplace(std::make_pair(chunk, vec));
            }
        }

        for (const auto& pdev_chunk : m_primary_pdev_chunks_list) {
            m_selector->add_pdev(pdev_chunk.pdev);
        }
    }

    VirtualDev(const VirtualDev& other) = delete;
    VirtualDev& operator=(const VirtualDev& other) = delete;
    VirtualDev(VirtualDev&&) noexcept = delete;
    VirtualDev& operator=(VirtualDev&&) noexcept = delete;
    virtual ~VirtualDev() override = default;

    void reset_failed_state() {
        m_vb->set_failed(false);
        m_mgr->write_info_blocks();
    }

    void process_completions(const boost::intrusive_ptr< virtualdev_req >& req) {
#ifdef _PRERELEASE
        if (!req->delay_induced &&
            homestore_flip->delay_flip(
                "simulate_vdev_delay",
                [req, this]() {
                    HS_LOG(DEBUG, device, "[Vdev={},req={},is_read={}] - Calling delayed completion", m_name,
                           req->request_id, req->is_read);
                    process_completions(req);
                },
                m_name, req->is_read)) {
            req->delay_induced = true;
            HS_LOG(DEBUG, device, "[Vdev={},req={},is_read={}] - Delaying completion", m_name, req->request_id,
                   req->is_read);
            return;
        }
#endif
        if (!(req->outstanding_cbs)) {
            // call completion
            m_comp_cb(req);
        } else {
            if (req->outstanding_cb.decrement_testz(1)) {
                if (!(req->format)) {
                    // call completion
                    m_comp_cb(req);
                } else {
                    req->format_cb(req->err ? false : true);
                }
            }
        }

        /* XXX:we probably have to do something if a write/read is spread
         *
         * across the chunks from this layer.
         */
    }

    /* This method adds chunk to the vdev. It is expected that this will happen at startup time and hence it only
     * takes lock for writing and not reading
     */
    virtual void add_chunk(PhysicalDevChunk* const chunk) override {
        HS_LOG(INFO, device, "Adding chunk {} from vdev id {} from pdev id = {}", chunk->get_chunk_id(),
               chunk->get_vdev_id(), chunk->get_physical_dev()->get_dev_id());
        std::lock_guard< decltype(m_mgmt_mutex) > lock{m_mgmt_mutex};
        if (chunk->get_primary_chunk()) {
            add_mirror_chunk(chunk);
        } else {
            ++m_num_chunks;
            add_primary_chunk(chunk);
        }
    }

    /**
     * @brief : get the start logical offset where data starts;
     *
     * @return : the start logical offset where data starts;
     */
    off_t data_start_offset() const { return m_data_start_offset; }

    /**
     * @brief : persist start logical offset to vdev's super block
     * Supposed to be called when truncate happens;
     *
     * @param offset : the start logical offset to be persisted
     */
    void update_data_start_offset(const off_t offset) { m_data_start_offset = offset; }

    /**
     * @brief : get the logcial tail offset;
     *
     * @param reserve_space_include : include reserved space or not;
     *
     * @return : the logical tail offset;
     */
    off_t get_tail_offset(const bool reserve_space_include = true) const {
        off_t tail{static_cast<off_t>(data_start_offset() + m_write_sz_in_total.load(std::memory_order_relaxed))};
        if (reserve_space_include) { tail += m_reserved_sz; }
        if (static_cast<uint64_t>(tail) >= get_size()) { tail -= get_size(); }

        return tail;
    }

    /**
     * @brief : get the used space in vdev
     *
     * @return : the used space in vdev
     */
    uint64_t get_used_space() const { return m_write_sz_in_total.load(std::memory_order_relaxed) + m_reserved_sz; }

    /**
     * @brief : get the free space left in vdev
     *
     * @return : free space left in vdev
     */
    uint64_t get_free_space() const { return get_size() - get_used_space(); }

    /**
     * @brief : truncate vdev to the provided logcial offset
     *
     * @param offset: logical offset that vdev needs to truncate to.
     *
     * Concurrency:
     * 1. truncate and write can be received concurrently.
     * 2. multiple truncate calls can be received concurently.
     *
     * Following things should happen for truncate:
     * 1. update in-memory counter of total write size.
     * 2. update vdev superblock of the new start logical offset that is being truncate to;
     *
     */
    void truncate(const off_t offset) {
        const off_t ds_off{data_start_offset()};

        COUNTER_INCREMENT(m_metrics, vdev_truncate_count, 1);

        HS_PERIODIC_LOG(INFO, device, "truncating to logical offset: {}, start: {}, m_write_sz_in_total: {} ",
                        to_hex(offset), to_hex(ds_off), to_hex(m_write_sz_in_total.load()));

        uint64_t size_to_truncate{0};
        if (offset >= ds_off) {
            // the truncate offset is larger than current start offset
            size_to_truncate = offset - ds_off;
        } else {
            // the truncate offset is smaller than current start offset, meaning we are looping back to previous chunks;
            HS_PERIODIC_LOG(INFO, device,
                            "Loop-back truncating to logical offset: {} which is smaller than current data start "
                            "offset: {}, m_write_sz_in_total: {}",
                            to_hex(offset), to_hex(ds_off), to_hex(m_write_sz_in_total.load()));
            size_to_truncate = get_size() - (ds_off - offset);
            HS_ASSERT_CMP(RELEASE, m_write_sz_in_total.load(), >=, size_to_truncate, "invalid truncate offset");
            HS_ASSERT_CMP(RELEASE, get_tail_offset(), >=, offset);
        }

        // update in-memory total write size counter;
        m_write_sz_in_total.fetch_sub(size_to_truncate, std::memory_order_relaxed);

        // Update our start offset, to keep track of actual size
        update_data_start_offset(offset);

        HS_PERIODIC_LOG(INFO, device, "after truncate: m_write_sz_in_total: {}, start: {} ",
                        to_hex(m_write_sz_in_total.load()), to_hex(data_start_offset()));
        m_truncate_done = true;
    }

    /**
     * @brief : get the next chunk handle based on input dev_id and chunk_id
     *
     * @param dev_id : the current dev_id
     * @param chunk_id : the current chunk_id
     *
     * @return : the hundle to the next chunk, if current chunk is the last chunk, loop back to begining device/chunk;
     *
     * TODO: organize chunks in a vector so that we can get next chunk id easily;
     */
    PhysicalDevChunk* get_next_chunk(uint32_t dev_id, uint32_t chunk_id) {
        if ((chunk_id + 1) < m_primary_pdev_chunks_list[dev_id].chunks_in_pdev.size()) {
            // next chunk is within same dev;
            ++chunk_id;
        } else {
            // move next dev
            dev_id = ((dev_id + 1) % m_primary_pdev_chunks_list.size());
            chunk_id = 0;
        }
        return m_primary_pdev_chunks_list[dev_id].chunks_in_pdev[chunk_id];
    }

    /**
     * @brief : allocate space specified by input size.
     *
     * @param size : size to be allocated
     * @param chunk_overlap_ok : accepted chunk overlap while allocating spaces
     *
     * @return : the start unique offset of the allocated space
     *
     * Possible calling sequence:
     * offset_1 = reserve(size1);
     * offset_2 = reserve(size2);
     * write_at_offset(offset_2);
     * write_at_offset(offset_1);
     */
    off_t alloc_next_append_blk(const size_t size, const bool chunk_overlap_ok = false) {
        HS_ASSERT_CMP(DEBUG, chunk_overlap_ok, ==, false);

        if (get_used_space() + size > get_size()) {
            // not enough space left;
            HS_LOG(ERROR, device, "No space left! m_write_sz_in_total: {}, m_reserved_sz: {}",
                   m_write_sz_in_total.load(), m_reserved_sz);
            return INVALID_OFFSET;
        }

#ifdef _PRERELEASE
        HomeStoreFlip::test_and_abort("abort_before_update_eof_cur_chunk");
#endif

        const off_t ds_off{data_start_offset()};
        const off_t end_offset{get_tail_offset()};
        off_t offset_in_chunk{0};
        uint32_t dev_id{0}, chunk_id{0};

        const auto dev_in_offset{logical_to_dev_offset(end_offset, dev_id, chunk_id, offset_in_chunk)};

#ifndef NDEBUG
        if (end_offset < ds_off) {
            HS_ASSERT_CMP(DEBUG, get_size() - get_used_space(), ==, static_cast< uint64_t >(ds_off - end_offset));
        }
#endif
        // works for both "end_offset >= ds_off" and "end_offset < ds_off";
        if (offset_in_chunk + size <= m_chunk_size) {
            // not acrossing boundary, nothing to do;
        } else if ((get_used_space() + (m_chunk_size - offset_in_chunk) + size) <= get_size()) {
            // across chunk boundary, still enough space;

            // Update the overhead to total write size;
            m_write_sz_in_total.fetch_add(m_chunk_size - offset_in_chunk, std::memory_order_relaxed);

            // If across chunk boudary, update the chunk super-block of the chunk size
            auto* const chunk{m_primary_pdev_chunks_list[dev_id].chunks_in_pdev[chunk_id]};
            m_mgr->update_end_of_chunk(chunk, offset_in_chunk);

#ifdef _PRERELEASE
            HomeStoreFlip::test_and_abort("abort_after_update_eof_cur_chunk");
#endif
            // get next chunk handle
            auto* const next_chunk{get_next_chunk(dev_id, chunk_id)};
            if (next_chunk != chunk) {
                // Since we are re-using a new chunk, update this chunk's end as its original size;
                m_mgr->update_end_of_chunk(next_chunk, m_chunk_size);
            }
        } else {
            // across chunk boundary and no space left;
            HS_LOG(ERROR, device, "No space left! m_write_sz_in_total: {}, m_reserved_sz: {}",
                   m_write_sz_in_total.load(), m_reserved_sz);
            return INVALID_OFFSET;
            // m_reserved_sz stays sthe same;
        }

        // if we made a successful reserve, return the tail offset;
        const off_t offset{get_tail_offset()};

        // update reserved size;
        m_reserved_sz += size;

        high_watermark_check();

#ifdef _PRERELEASE
        HomeStoreFlip::test_and_abort("abort_after_update_eof_next_chunk");
#endif
        // assert that returnning logical offset is in good range;
        HS_ASSERT_CMP(DEBUG, static_cast< uint64_t >(offset), <=, get_size());
        return offset;
    }

    void format(const vdev_format_cb_t& cb) {
        boost::intrusive_ptr< virtualdev_req > req{sisl::ObjectAllocator< virtualdev_req >::make_object()};
        req->outstanding_cb.set(get_num_chunks() * (get_nmirrors() + 1));
        req->outstanding_cbs = true;
        req->format = true;
        req->format_cb = cb;
        req->version = 0xDEAD;
        req->cb = std::bind(&VirtualDev::process_completions, this, std::placeholders::_1);

        for (size_t dev_ind{0}; dev_ind < m_primary_pdev_chunks_list.size(); ++dev_ind) {
            for (auto* const pchunk : m_primary_pdev_chunks_list[dev_ind].chunks_in_pdev) {
                auto* const pdev{pchunk->get_physical_dev_mutable()};
                req->inc_ref();
                LOGINFO("writing zero for chunk: {}, size: {}, offset: {}", pchunk->get_chunk_id(), pchunk->get_size(),
                        pchunk->get_start_offset());
                pdev->write_zero(pchunk->get_size(), pchunk->get_start_offset(), reinterpret_cast< uint8_t* >(req.get()));
                auto mchunks_list = m_mirror_chunks[pchunk];
                for (auto& mchunk : mchunks_list) {
                    auto* const m_pdev{mchunk->get_physical_dev_mutable()};
                    req->inc_ref();
                    LOGINFO("writing zero for mirror chunk: {}, size: {}, offset: {}", mchunk->get_chunk_id(),
                            mchunk->get_size(), mchunk->get_start_offset());
                    m_pdev->write_zero(mchunk->get_size(), mchunk->get_start_offset(),
                                       reinterpret_cast< uint8_t* >(req.get()));
                }
            }
        }
    }

    /**
     * @brief : writes up to count bytes from the buffer starting at buf.
     * write advances seek cursor;
     *
     * @param buf : buffer to be written
     * @param count : size of buffer in bytes
     * @param req : async req;
     *
     * @return : On success, the number of bytes written is returned.  On error, -1 is returned.
     */
    ssize_t write(const void* const buf, const size_t count, boost::intrusive_ptr< virtualdev_req > req) {
        if (get_used_space() + count > get_size()) {
            // not enough space left;
            HS_LOG(ERROR, device, "No space left! m_write_sz_in_total: {}, m_reserved_sz: {}",
                   m_write_sz_in_total.load(), m_reserved_sz);
            return -1;
        }

        if (m_reserved_sz != 0) {
            HS_LOG(ERROR, device, "write can't be served when m_reserved_sz:{} is not comsumed by pwrite yet.",
                   m_reserved_sz);
            return -1;
        }

        const auto bytes_written{do_pwrite(buf, count, m_seek_cursor, req)};
        m_seek_cursor += bytes_written;

        return bytes_written;
    }

    ssize_t write(const void* const buf, const size_t count) { return write(buf, count, nullptr); }

    /**
     * @brief : writes up to count bytes from the buffer starting at buf at offset offset.
     * The cursor is not changed.
     * pwrite always use offset returned from alloc_next_append_blk to do the write;
     * pwrite should not across chunk boundaries because alloc_next_append_blk guarantees offset returned always doesn't
     * across chunk boundary;
     *
     * @param buf : buffer pointing to the data being written
     * @param count : size of buffer to be written
     * @param offset : offset to be written
     * @param req : async req
     *
     * @return : On success, the number of bytes read or written is returned, or -1 on error.
     */
    ssize_t pwrite(const void* const buf, const size_t count, const off_t offset, boost::intrusive_ptr< virtualdev_req > req = nullptr) {
        HS_ASSERT_CMP(RELEASE, count, <=, m_reserved_sz, "Write size:{} larger then reserved size: {} is not allowed!",
                      count, m_reserved_sz);

        // update reserved size
        m_reserved_sz -= count;

        // pwrite works with alloc_next_append_blk which already do watermark check;

        return do_pwrite(buf, count, offset, req);
    }

    /**
     * @brief : writes iovcnt buffers of data described by iov to the offset.
     * pwritev doesn't advance curosr;
     *
     * @param iov : the iovec that holds vector of data buffers
     * @param iovcnt : size of iov
     * @param offset : offset to be written
     * @param req : aync req.
     * if req is not nullptr, it will be an async call.
     * if req is nullptr, it will be a sync call.
     *
     * @return : On success, number of bytes written. On error, -1 is returned
     */
    ssize_t pwritev(const iovec* const iov, const int iovcnt, const off_t offset,
                    boost::intrusive_ptr< virtualdev_req > req = nullptr) {
        uint32_t dev_id{0}, chunk_id{0};
        const auto len{get_len(iov, iovcnt)};

        // if len is smaller than reserved size, it means write will never be overlapping start offset;
        // it is guaranteed by alloc_next_append_blk api;
        HS_ASSERT_CMP(RELEASE, len, <=, m_reserved_sz, "Write size:{} larger then reserved size: {} is not allowed!",
                      len, m_reserved_sz);

        m_reserved_sz -= len;

        const auto offset_in_dev{process_pwrite_offset(len, offset, dev_id, chunk_id, req)};

        ssize_t bytes_written{0};
        try {
            PhysicalDevChunk* const chunk{m_primary_pdev_chunks_list[dev_id].chunks_in_pdev[chunk_id]};
            auto* const pdev{m_primary_pdev_chunks_list[dev_id].pdev};

            LOGDEBUG("Writing in device: {}, offset: {}, m_write_sz_in_total: {}, start off: {}", to_hex(dev_id),
                     to_hex(offset_in_dev), to_hex(m_write_sz_in_total.load()), to_hex(data_start_offset()));

            bytes_written = do_pwritev_internal(pdev, chunk, iov, iovcnt, len, offset_in_dev, req);

            // bytes written should always equal to requested write size, since alloc_next_append_blk handles offset
            // which will never across chunk boundary;
            HS_ASSERT_CMP(DEBUG, (uint64_t)bytes_written, ==, len, "Bytes written not equal to input len!");

        } catch (const std::exception& e) { HS_ASSERT(DEBUG, 0, "{}", e.what()); }

        return bytes_written;
    }

    /**
     * @brief : read up to count bytes into the buffer starting at buf.
     * Only read the size before end of chunk and update m_seek_cursor to next chunk;
     *
     * @param buf : the buffer that points to read out data
     * @param count : the size of buffer;
     *
     * @return : On success, the number of bytes read is returned (zero indicates end of file), and the cursor is
     * advanced by this number. it is not an error if this number is smaller than the number requested, because it can
     * be end of chunk, since read won't across chunk.
     */
    ssize_t read(void* const buf, const size_t count_in) {
        size_t count{count_in};
        uint32_t dev_id{0}, chunk_id{0};
        off_t offset_in_chunk{0};

        logical_to_dev_offset(m_seek_cursor, dev_id, chunk_id, offset_in_chunk);

        auto* const chunk{m_primary_pdev_chunks_list[dev_id].chunks_in_pdev[chunk_id]};
        const auto end_of_chunk{chunk->get_end_of_chunk()};
        const auto chunk_size{std::min<uint64_t>(end_of_chunk, m_chunk_size)};

        bool across_chunk{false};

        HS_ASSERT_CMP(RELEASE, (uint64_t)end_of_chunk, <=, m_chunk_size,
                      "Invalid end of chunk: {} detected on chunk num: {}", end_of_chunk, chunk->get_chunk_id());
        HS_ASSERT_CMP(RELEASE, (uint64_t)offset_in_chunk, <=, chunk_size,
                      "Invalid m_seek_cursor: {} which falls in beyond end of chunk: {}!", m_seek_cursor, end_of_chunk);

        // if read size is larger then what's left in this chunk
        if (count >= (chunk_size - offset_in_chunk)) {
            // truncate size to what is left;
            count = chunk_size - offset_in_chunk;
            across_chunk = true;
        }

        const auto bytes_read{pread(buf, count, m_seek_cursor)};

        if (bytes_read != -1) {
            // Update seek cursor after read;
            HS_ASSERT_CMP(RELEASE, (size_t)bytes_read, ==, count,
                          "bytes_read returned: {} must be equal to requested size: {}!", bytes_read, count);
            m_seek_cursor += bytes_read;
            if (across_chunk) { m_seek_cursor += (m_chunk_size - end_of_chunk); }
            m_seek_cursor = m_seek_cursor % get_size();
        }

        return bytes_read;
    }

    /**
     * @brief : reads up to count bytes at offset into the buffer starting at buf.
     * The curosr is not updated.
     *
     * @param buf : the buffer that points to the read out data.
     * @param count : size of buffer
     * @param offset : the start offset to do read
     *
     * @return : On success, returns the number of bytes. On error, -1 is returned.
     */
    ssize_t pread(void* const buf, const size_t count_in, const off_t offset) {
        size_t count{count_in};
        uint32_t dev_id{0}, chunk_id{0};
        off_t offset_in_chunk{0};

        const uint64_t offset_in_dev{logical_to_dev_offset(offset, dev_id, chunk_id, offset_in_chunk)};

        // if the read count is acrossing chunk, only return what's left in this chunk
        if (m_chunk_size - offset_in_chunk < count) {
            // truncate requsted rean length to end of chunk;
            count = m_chunk_size - offset_in_chunk;
        }

        auto* const pdev{m_primary_pdev_chunks_list[dev_id].pdev};
        auto* const pchunk{m_primary_pdev_chunks_list[dev_id].chunks_in_pdev[chunk_id]};

        return do_read_internal(pdev, pchunk, offset_in_dev, reinterpret_cast< char* >(buf), count);
    }

    std::shared_ptr< blkalloc_cp > attach_prepare_cp(std::shared_ptr< blkalloc_cp >& cur_ba_cp) {
        return (PhysicalDevChunk::attach_prepare_cp(cur_ba_cp));
    }

    /**
     * @brief : read at offset and save output to iov.
     * We don't have a use case for external caller of preadv now, meaning iov will always have only 1 element;
     * if the len is acrossing chunk boundary,
     * we only do read on one chunk and return the num of bytes read on this chunk;
     *
     * @param iov : the iovect to store the read out data
     * @param iovcnt : size of iovev
     * @param offset : the start offset to read
     *
     * @return : return the number of bytes read; On error, -1 is returned.
     */
    ssize_t preadv(const iovec* const iov, const int iovcnt, const off_t offset,
                   boost::intrusive_ptr< virtualdev_req > req = nullptr) {
        if (req) {
            HS_ASSERT(DEBUG, false, "Not implemented yet");
            return 0;
        }

        uint32_t dev_id{0}, chunk_id{0};
        off_t offset_in_chunk{0};
        const uint64_t len{get_len(iov, iovcnt)};

        const uint64_t offset_in_dev{logical_to_dev_offset(offset, dev_id, chunk_id, offset_in_chunk)};

        if (m_chunk_size - offset_in_chunk < len) {
            HS_ASSERT_CMP(
                DEBUG, iovcnt, ==, 1,
                "iovector more than 1 element is not supported when requested read len is acrossing chunk boundary. ");
            if (iovcnt > 1) { return -1; }

            // truncate requsted rean length to end of chunk;
            len = m_chunk_size - offset_in_chunk;

            iov[0].iov_len = len; // is this needed?
        }

        auto* const pdev{m_primary_pdev_chunks_list[dev_id].pdev};
        auto* const chunk{m_primary_pdev_chunks_list[dev_id].chunks_in_pdev[chunk_id]};

        return do_preadv_internal(pdev, chunk, offset_in_dev, iov, iovcnt, len, req);
    }

    /**
     * @brief : repositions the cusor of the device to the argument offset
     * according to the directive whence as follows:
     * SEEK_SET
     *     The curosr is set to offset bytes.
     * SEEK_CUR
     *     The cursor is set to its current location plus offset bytes.
     * SEEK_END
     *     Not supported yet. No use case for now.
     *
     * @param offset : the logical offset
     * @param whence : see above
     *
     * @return :  Upon successful completion, lseek() returns the resulting offset
     * location as measured in bytes from the beginning of the file.  On
     * error, the value (off_t) -1 is returned
     */
    off_t lseek(const off_t offset, const int whence = SEEK_SET) {
        switch (whence) {
        case SEEK_SET:
            m_seek_cursor = offset;
            break;
        case SEEK_CUR:
            m_seek_cursor += offset;
            break;
        case SEEK_END:
        default:
            HS_ASSERT(DEBUG, false, "Not supported seek type: {}", whence);
            break;
        }

        return m_seek_cursor;
    }

    /**
     * @brief :- it returns the vdev offset after nbytes from start offset
     */
    off_t get_dev_offset(const off_t nbytes) const {
        off_t vdev_offset{data_start_offset()};
        uint32_t dev_id{0}, chunk_id{0};
        off_t offset_in_chunk{0};
        off_t cur_read_cur{0};

        while (cur_read_cur != nbytes) {
            logical_to_dev_offset(vdev_offset, dev_id, chunk_id, offset_in_chunk);

            auto* const chunk{m_primary_pdev_chunks_list[dev_id].chunks_in_pdev[chunk_id]};
            const auto end_of_chunk{chunk->get_end_of_chunk()};
            const auto chunk_size{std::min< uint64_t >(end_of_chunk, m_chunk_size)};
            const auto remaining{nbytes - cur_read_cur};
            if (remaining >= (static_cast< off_t >(chunk_size) - offset_in_chunk)) {
                cur_read_cur += (chunk_size - offset_in_chunk);
                vdev_offset += (m_chunk_size - offset_in_chunk);
                vdev_offset = vdev_offset % get_size();
            } else {
                vdev_offset += remaining;
                cur_read_cur = nbytes;
            }
        }
        return vdev_offset;
    }

    /**
     * @brief : this API can be replaced by lseek(0, SEEK_CUR);
     *
     * @return : current curosr offset
     */
    off_t seeked_pos() const { return m_seek_cursor; }

    /**
     * @brief : update the tail to vdev, this API will be called during reboot and
     * upper layer(logdev) has completed scanning all the valid records in vdev and then
     * update the tail in vdev.
     *
     * @param tail : logical tail offset
     */
    void update_tail_offset(const off_t tail) {
        const off_t start{data_start_offset()};
        HS_LOG(INFO, device, "total_size: {}, tail is being updated to: {}, start: {}", to_hex(get_size()),
               to_hex(tail), to_hex(start));

        if (tail >= start) {
            m_write_sz_in_total.store(tail - start, std::memory_order_relaxed);
        } else {
            m_write_sz_in_total.store(get_size() - start + tail, std::memory_order_relaxed);
        }
        lseek(tail);

        HS_LOG(INFO, device, "m_write_sz_in_total updated to: {}", to_hex(m_write_sz_in_total.load()));

        HS_ASSERT(RELEASE, get_tail_offset() == tail, "tail offset mismatch after calculation {} : {}",
                  get_tail_offset(), tail);
    }

    bool is_blk_alloced(const BlkId& blkid) const {
        const PhysicalDevChunk* const primary_chunk{m_mgr->get_chunk(blkid.get_chunk_num())};
        return (primary_chunk->get_blk_allocator()->is_blk_alloced(blkid));
    }

    BlkAllocStatus reserve_blk(const BlkId& blkid) {
        PhysicalDevChunk* const primary_chunk{m_mgr->get_chunk_mutable(blkid.get_chunk_num())};
        HS_LOG(DEBUG, device, "alloc_on_disk: bid {}", blkid.to_string());
        return primary_chunk->get_blk_allocator_mutable()->alloc_on_disk(blkid);
    }

    BlkAllocStatus alloc_contiguous_blk(const blk_count_t nblks, const blk_alloc_hints& hints, BlkId* const out_blkid) {
        BlkAllocStatus ret;
        try {
            static thread_local std::vector< BlkId > blkid{};
            blkid.clear();
            HS_ASSERT_CMP(DEBUG, hints.is_contiguous, ==, true);
            ret = alloc_blk(nblks, hints, blkid);
            if (ret == BlkAllocStatus::SUCCESS) {
                HS_RELEASE_ASSERT_EQ(blkid.size(), 1, "out blkid more than 1 entries({}) will lead to blk leak!",
                                     blkid.size());
                *out_blkid = std::move(blkid.front());
            } else {
                HS_ASSERT_CMP(DEBUG, blkid.size(), ==, 0);
            }
        } catch (const std::exception& e) {
            ret = BlkAllocStatus::FAILED;
            HS_ASSERT(DEBUG, 0, "{}", e.what());
        }
        return ret;
    }

    BlkAllocStatus alloc_blk(const blk_count_t nblks, const blk_alloc_hints& hints, std::vector< BlkId >& out_blkid) {
        try {
            uint32_t dev_ind{0};
            uint32_t chunk_num, start_chunk_num;
            BlkAllocStatus status{BlkAllocStatus::FAILED};

            // First select a device to allocate from
            dev_ind = (hints.dev_id_hint == -1) ? m_selector->select(hints) : static_cast<uint32_t>(hints.dev_id_hint);

            // Pick a physical chunk based on physDevId.
            // TODO: Right now there is only one primary chunk per device in a virtualdev. Need to support multiple
            // chunks. In that case just using physDevId as chunk number is not right strategy.
            uint32_t start_dev_ind{dev_ind};
            do {
                for (auto& chunk : m_primary_pdev_chunks_list[dev_ind].chunks_in_pdev) {
#ifdef _PRERELEASE
                    if (const auto fake_status{homestore_flip->get_test_flip< uint32_t >("blk_allocation_flip", nblks,
                                                                                         chunk->get_vdev_id())}) {
                        return static_cast< BlkAllocStatus >(fake_status.get());
                    }
#endif
                    static thread_local std::vector< BlkId > chunk_blkid{};
                    chunk_blkid.clear();
                    status = chunk->get_blk_allocator_mutable()->alloc(nblks, hints, chunk_blkid);
                    if (status == BlkAllocStatus::PARTIAL) {
                        // free partial result
                        chunk->get_blk_allocator_mutable()->free(chunk_blkid);
                        status = BlkAllocStatus::FAILED;
                    } else if (status == BlkAllocStatus::SUCCESS) {
                        // append chunk blocks to out blocks
                        out_blkid.insert(std::end(out_blkid), std::make_move_iterator(std::begin(chunk_blkid)),
                                         std::make_move_iterator(std::end(chunk_blkid)));
                        break;
                    }
                }

                if ((status == BlkAllocStatus::SUCCESS) || !hints.can_look_for_other_dev) { break; }
                dev_ind = static_cast< uint32_t >((dev_ind + 1) % m_primary_pdev_chunks_list.size());
            } while (dev_ind != start_dev_ind);

            if (status != BlkAllocStatus::SUCCESS) {
                LOGERROR("nblks={} failed to alloc after trying to allo on every chunks {} and devices {}.", nblks);
                COUNTER_INCREMENT(m_metrics, vdev_num_alloc_failure, 1);
            }

            return status;
        } catch (const std::exception& e) {
            LOGERROR("exception happened {}", e.what());
            assert(false);
            return BlkAllocStatus::FAILED;
        }
    }

    bool free_on_realtime(const BlkId& b) {
        PhysicalDevChunk* const chunk{m_mgr->get_chunk_mutable(b.get_chunk_num())};
        return chunk->get_blk_allocator_mutable()->free_on_realtime(b);
    }

    void free_blk(const BlkId& b) {
        PhysicalDevChunk* const chunk{m_mgr->get_chunk_mutable(b.get_chunk_num())};
        chunk->get_blk_allocator_mutable()->free(b);
    }

    void recovery_done() {
        for (auto& pcm : m_primary_pdev_chunks_list) {
            for (auto& pchunk : pcm.chunks_in_pdev) {
                pchunk->get_blk_allocator_mutable()->inited();
                auto mchunks_list = m_mirror_chunks[pchunk];
                for (auto& mchunk : mchunks_list) {
                    mchunk->get_blk_allocator_mutable()->inited();
                }
            }
        }
    }

    void write(const BlkId& bid, const iovec* const iov, const int iovcnt, boost::intrusive_ptr< virtualdev_req > req = nullptr) {
        PhysicalDevChunk* chunk;
        const auto size{get_len(iov, iovcnt)};
        const uint64_t dev_offset{to_dev_offset(bid, &chunk)};
        if (req) {
            req->version = 0xDEAD;
            req->cb = std::bind(&VirtualDev::process_completions, this, std::placeholders::_1);
            req->size = size;
            req->chunk = chunk;
        }

        auto* const pdev{chunk->get_physical_dev_mutable()};

        HS_LOG(TRACE, device, "Writing in device: {}, offset = {}", pdev->get_dev_id(), dev_offset);

        // return bytes written already verified to be equal to size by lower level;
        do_pwritev_internal(pdev, chunk, iov, iovcnt, size, dev_offset, req);
    }

    void write(const BlkId& bid, const homeds::MemVector& buf, boost::intrusive_ptr< virtualdev_req > req,
               const uint32_t data_offset_in = 0) {
        BlkOpStatus ret_status{BlkOpStatus::SUCCESS};
        uint32_t data_offset{data_offset_in};
        const uint32_t size{bid.get_nblks() * get_page_size()};
        std::array < iovec, BlkId::max_blks_in_op() > iov;
        int iovcnt{0};

        const uint32_t end_offset{data_offset + bid.data_size(m_pagesz)};
        while (data_offset != end_offset) {
            sisl::blob b;
            buf.get(&b, data_offset);
            iov[iovcnt].iov_base = b.bytes;
            if (data_offset + b.size > end_offset) {
                iov[iovcnt].iov_len = end_offset - data_offset;
            } else {
                iov[iovcnt].iov_len = b.size;
            }
            data_offset += iov[iovcnt].iov_len;
            ++iovcnt;
        }

        HS_ASSERT_CMP(DEBUG, data_offset, ==, end_offset);

        write(bid, iov.data(), iovcnt, req);
    }

    void write_nmirror(const char* const buf, const uint32_t size, PhysicalDevChunk* const chunk, const uint64_t dev_offset_in) {
        uint64_t dev_offset { dev_offset_in };
        const uint64_t primary_chunk_offset{dev_offset - chunk->get_start_offset()};

        // Write to the mirror as well
        for (auto i : boost::irange< uint32_t >(0, get_nmirrors())) {
            for (auto* const mchunk : m_mirror_chunks.find(chunk)->second) {
                dev_offset = mchunk->get_start_offset() + primary_chunk_offset;

                // We do not support async mirrored writes yet.
                auto* const pdev{mchunk->get_physical_dev_mutable()};

                COUNTER_INCREMENT(pdev->get_metrics(), drive_sync_write_count, 1);
                const auto start_time{Clock::now()};
                pdev->sync_write(buf, size, dev_offset);
                HISTOGRAM_OBSERVE(pdev->get_metrics(), drive_write_latency, get_elapsed_time_us(start_time));
            }
        }
    }

    void writev_nmirror(const iovec* const iov, const int iovcnt, const uint32_t size, PhysicalDevChunk* const chunk, const uint64_t dev_offset_in) {
        uint64_t dev_offset{dev_offset_in};
        const uint64_t primary_chunk_offset{dev_offset - chunk->get_start_offset()};

        // Write to the mirror as well
        for (auto i : boost::irange< uint32_t >(0, get_nmirrors())) {
            for (auto* const mchunk : m_mirror_chunks.find(chunk)->second) {
                dev_offset = mchunk->get_start_offset() + primary_chunk_offset;

                // We do not support async mirrored writes yet.
                auto* const pdev{mchunk->get_physical_dev_mutable()};

                COUNTER_INCREMENT(pdev->get_metrics(), drive_sync_write_count, 1);
                const auto start_time{Clock::now()};
                pdev->sync_writev(iov, iovcnt, size, dev_offset);
                HISTOGRAM_OBSERVE(pdev->get_metrics(), drive_write_latency, get_elapsed_time_us(start_time));
            }
        }
    }

    void read_nmirror(const BlkId& bid, std::vector< boost::intrusive_ptr< homeds::MemVector > > mp, const uint64_t size,
                      const uint32_t nmirror) {
        HS_ASSERT_CMP(DEBUG, nmirror, <=, get_nmirrors());
        uint32_t cnt{0};
        PhysicalDevChunk* primary_chunk;
        const uint64_t primary_dev_offset{to_dev_offset(bid, &primary_chunk)};
        const uint64_t primary_chunk_offset{primary_dev_offset - primary_chunk->get_start_offset()};

        sisl::blob b;
        mp[cnt]->get(&b, 0);
        HS_ASSERT_CMP(DEBUG, b.size, ==, bid.data_size(m_pagesz));
        primary_chunk->get_physical_dev_mutable()->sync_read(reinterpret_cast< char* >(b.bytes), b.size, primary_dev_offset);
        if (cnt == nmirror) { return; }
        ++cnt;
        for (auto* const mchunk : m_mirror_chunks.find(primary_chunk)->second) {
            const uint64_t dev_offset{mchunk->get_start_offset() + primary_chunk_offset};

            mp[cnt]->get(&b, 0);
            HS_ASSERT_CMP(DEBUG, b.size, ==, bid.data_size(m_pagesz));
            mchunk->get_physical_dev_mutable()->sync_read(reinterpret_cast< char* >(b.bytes), b.size, dev_offset);

            ++cnt;
            if (cnt == nmirror + 1) { break; }
        }
    }

    /* Read the data for a given BlkId. With this method signature, virtual dev can read only in block boundary
     * and nothing in-between offsets (say if blk size is 8K it cannot read 4K only, rather as full 8K. It does not
     * have offset as one of the parameter. Reason for that is its actually ok and make the interface and also
     * buf (caller buf) simple and there is no use case. However, we need to keep the blk size to be small as possible
     * to avoid read overhead */
    void read(const BlkId& bid, const homeds::MemPiece& mp, boost::intrusive_ptr< virtualdev_req > req) {
        PhysicalDevChunk* primary_chunk;

        const uint64_t primary_dev_offset{to_dev_offset(bid, &primary_chunk)};

        do_read_internal(primary_chunk->get_physical_dev_mutable(), primary_chunk, primary_dev_offset, reinterpret_cast< char* >(mp.ptr()),
                         mp.size(), req);
    }

    void read(const BlkId& bid, std::vector< iovec >& iovecs, const uint64_t size,
              boost::intrusive_ptr< virtualdev_req > req) {
        PhysicalDevChunk* primary_chunk;

        const uint64_t primary_dev_offset{to_dev_offset(bid, &primary_chunk)};
        do_preadv_internal(primary_chunk->get_physical_dev_mutable(), primary_chunk, primary_dev_offset, iovecs.data(),
                           iovecs.size(), size, req);
    }

    void readv(const BlkId& bid, const homeds::MemVector& buf, boost::intrusive_ptr< virtualdev_req > req) {
        // Convert the input memory to iovector
        std::array < iovec, BlkId::max_blks_in_op()> iov;
        int iovcnt{0};
        const uint32_t size{buf.size()};

        HS_ASSERT_CMP(DEBUG, buf.size(), ==,
                      bid.get_nblks() * get_page_size()); // Expected to be less than allocated blk originally.
        for (auto i : boost::irange< uint32_t >(0, buf.npieces())) {
            sisl::blob b;
            buf.get(&b, i);

            iov[iovcnt].iov_base = b.bytes;
            iov[iovcnt].iov_len = b.size;
            iovcnt++;
        }

        PhysicalDevChunk* const primary_chunk;
        const uint64_t primary_dev_offset{to_dev_offset(bid, &primary_chunk)};

        auto* const pdev{primary_chunk->get_physical_dev_mutable()};

        do_preadv_internal(pdev, primary_chunk, primary_dev_offset, iov.data(), iovcnt, size, req);
    }

    void get_vb_context(const sisl::blob& ctx_data) const { m_mgr->get_vb_context(m_vb->vdev_id, ctx_data); }

    void update_vb_context(const sisl::blob& ctx_data) { m_mgr->update_vb_context(m_vb->vdev_id, ctx_data); }
    uint64_t get_size() const { return m_vb->size; }

    uint64_t get_available_blks() const {
        uint64_t avl_blks{0};
        for (size_t i{0}; i < m_primary_pdev_chunks_list.size(); ++i) {
            for (uint32_t chunk_indx = 0; chunk_indx < m_primary_pdev_chunks_list[i].chunks_in_pdev.size();
                 ++chunk_indx) {
                const auto* const chunk{m_primary_pdev_chunks_list[i].chunks_in_pdev[chunk_indx]};
                avl_blks += chunk->get_blk_allocator()->get_available_blks();
            }
        }
        return avl_blks;
    }

    uint64_t get_used_size() const {
        uint64_t alloc_cnt{0};
        for (size_t i{0}; i < m_primary_pdev_chunks_list.size(); ++i) {
            for (uint32_t chunk_indx = 0; chunk_indx < m_primary_pdev_chunks_list[i].chunks_in_pdev.size();
                 ++chunk_indx) {
                const auto* const chunk{m_primary_pdev_chunks_list[i].chunks_in_pdev[chunk_indx]};
                alloc_cnt += chunk->get_blk_allocator()->get_used_blks();
            }
        }
        return (alloc_cnt * get_page_size());
    }

    void expand(const uint32_t addln_size) {}

    // Remove this virtualdev altogether
    void rm_device() {
        for (auto& pcm : m_primary_pdev_chunks_list) {
            for (auto& c : pcm.chunks_in_pdev) {
                m_mgr->free_chunk(c);
            }
        }

        for (auto& v : m_mirror_chunks) {
            for (auto& c : v.second) {
                m_mgr->free_chunk(c);
            }
        }

        m_mgr->free_vdev(m_vb);
    }

    std::string to_string() const { return std::string{}; }

    uint64_t get_num_chunks() const { return m_num_chunks; }
    uint64_t get_chunk_size() const { return m_chunk_size; }

    void blkalloc_cp_start(std::shared_ptr< blkalloc_cp >& ba_cp) {
        for (size_t i{0}; i < m_primary_pdev_chunks_list.size(); ++i) {
            for (size_t chunk_indx{0}; chunk_indx < m_primary_pdev_chunks_list[i].chunks_in_pdev.size();
                 ++chunk_indx) {
                auto* const chunk{m_primary_pdev_chunks_list[i].chunks_in_pdev[chunk_indx]};
                chunk->cp_start(ba_cp);
            }
        }
    }

private:
    /**
     * @brief : convert logical offset to physical offset for pwrite/pwritev;
     *
     * @param len : len of data that is going to be written
     * @param offset : logical offset to be written
     * @param dev_id : the return value of device id
     * @param chunk_id : the return value of chunk id
     * @param req : async req
     *
     * @return : the unique offset
     */
    off_t process_pwrite_offset(const size_t len, const off_t offset, uint32_t& dev_id, uint32_t& chunk_id,
                                const boost::intrusive_ptr< virtualdev_req >& req = nullptr) {
        off_t offset_in_chunk{0};

        if (req) { 
            req->outstanding_cb.set(1); 
            req->outstanding_cbs = true;
        }

        // convert logical offset to dev offset
        const uint64_t offset_in_dev{logical_to_dev_offset(offset, dev_id, chunk_id, offset_in_chunk)};

        // this assert only valid for pwrite/pwritev, which calls alloc_next_append_blk to get the offset to do the
        // write, which guarantees write will with the returned offset will not accross chunk boundary.
        HS_ASSERT_CMP(RELEASE, m_chunk_size - offset_in_chunk, >=, len,
                      "Writing size: {} crossing chunk is not allowed!", len);

        m_write_sz_in_total.fetch_add(len, std::memory_order_relaxed);

        PhysicalDevChunk* const chunk{m_primary_pdev_chunks_list[dev_id].chunks_in_pdev[chunk_id]};
        if (req) {
            req->version = 0xDEAD;
            req->cb = std::bind(&VirtualDev::process_completions, this, std::placeholders::_1);
            req->size = len;
            req->chunk = chunk;
        }

        return offset_in_dev;
    }

    /* Create debug bitmap for all chunks */
    BlkAllocStatus create_debug_bm() {
        try {
            for (auto& pdev_chunks : m_primary_pdev_chunks_list) {
                auto chunk_list{pdev_chunks.chunks_in_pdev};
                for (auto& chunk : chunk_list) {
                    chunk->get_blk_allocator_mutable()->create_debug_bm();
                }
            }
            return BlkAllocStatus::SUCCESS;

        } catch (const std::exception& e) {
            LOGERROR("exception happened {}", e.what());
            return BlkAllocStatus::FAILED;
        }
    }

    /* Update debug bitmap for a given BlkId */
    BlkAllocStatus update_debug_bm(const BlkId& bid) {
        try {
            PhysicalDevChunk* chunk{nullptr};
            const uint64_t dev_offset{to_dev_offset(bid, &chunk)};
            chunk->get_blk_allocator_mutable()->update_debug_bm(bid);
            return BlkAllocStatus::SUCCESS;

        } catch (const std::exception& e) {
            LOGERROR("Update debug bitmap hit exception {}", e.what());
            return BlkAllocStatus::FAILED;
        }
    }

    /* Verify debug bitmap for all chunks */
    BlkAllocStatus verify_debug_bm(const bool free_debug_bm = true) {
        try {
            for (auto& pdev_chunks : m_primary_pdev_chunks_list) {
                auto chunk_list{pdev_chunks.chunks_in_pdev};
                for (auto& chunk : chunk_list) {
                    if (chunk->get_blk_allocator_mutable()->verify_debug_bm(free_debug_bm) == false) {
                        LOGERROR("Verify bitmap failure for chunk {}", static_cast< void* >(chunk));
                        return BlkAllocStatus::FAILED;
                    } else {
                        LOGDEBUG("Verify bitmap success for chunk {}", static_cast< void* >(chunk));
                    }
                }
            }
            return BlkAllocStatus::SUCCESS;
        } catch (const std::exception& e) {
            LOGERROR("exception happened {}", e.what());
            return BlkAllocStatus::FAILED;
        }
    }

    /* Get status for all chunks */
    nlohmann::json get_status(const int log_level) const {
        nlohmann::json j;
        try {
            for (const auto& pdev_chunks : m_primary_pdev_chunks_list) {
                const auto chunk_list{pdev_chunks.chunks_in_pdev};
                for (const auto& chunk : chunk_list) {
                    j.update(chunk->get_blk_allocator()->get_status(log_level));
                }
            }
        } catch (const std::exception& e) { LOGERROR("exception happened {}", e.what()); }
        return j;
    }

    //
    // split do_write from pwrite so that write could re-use this sub-routine
    //
    ssize_t do_pwrite(const void* const buf, const size_t count, const off_t offset, const boost::intrusive_ptr< virtualdev_req >& req = nullptr) {
        uint32_t dev_id{0}, chunk_id{0};

        const auto offset_in_dev{process_pwrite_offset(count, offset, dev_id, chunk_id, req)};

        ssize_t bytes_written{0};
        try {
            PhysicalDevChunk* const chunk{m_primary_pdev_chunks_list[dev_id].chunks_in_pdev[chunk_id]};

            auto* const pdev{m_primary_pdev_chunks_list[dev_id].pdev};

            HS_LOG(TRACE, device, "Writing in device: {}, offset: {}", dev_id, offset_in_dev);

            bytes_written = do_pwrite_internal(pdev, chunk, reinterpret_cast< const char* >(buf), count, offset_in_dev, req);

            // bytes written should always equal to requested write size, since alloc_next_append_blk handles offset
            // which will never across chunk boundary;
            HS_ASSERT_CMP(DEBUG, static_cast< size_t >(bytes_written), ==, count, "Bytes written not equal to input len!");

        } catch (const std::exception& e) { HS_ASSERT(DEBUG, 0, "{}", e.what()); }

        return bytes_written;
    }

    /**
     * @brief
     */
    void high_watermark_check() {
        const uint32_t used_per{static_cast<uint32_t>(100 * get_used_space() / get_size())};
        ResourceMgr::check_journal_size_and_trigger_cp(get_used_space(), get_size());
        if (used_per >= ResourceMgr::get_journal_size_limit()) {
            COUNTER_INCREMENT(m_metrics, vdev_high_watermark_count, 1);
            HS_LOG_EVERY_N(WARN, device, 50, "high watermark hit, used percentage: {}, high watermark percentage: {}",
                           used_per, vdev_high_watermark_per);
            if (m_hwm_cb && m_truncate_done) {
                // don't send high watermark callback repeated until at least one truncate has been received;
                HS_LOG(INFO, device, "Callback to client for high watermark warning.");
                m_hwm_cb();
                m_truncate_done = false;
            }
        }
    }

    /**
     * @brief : convert logical offset in chunk to the physical device offset
     *
     * @param dev_id : the device id
     * @param chunk_id : the chunk id;
     * @param offset_in_chunk : the logical offset in chunk;
     *
     * @return : the physical device offset;
     */
    uint64_t get_offset_in_dev(const uint32_t dev_id, const uint32_t chunk_id, const uint64_t offset_in_chunk) const {
        return get_chunk_start_offset(dev_id, chunk_id) + offset_in_chunk;
    }

    /**
     * @brief : get the physical start offset of the chunk;
     *
     * @param dev_id : the deivce id;
     * @param chunk_id : the chunk id;
     *
     * @return : the physical start offset of the chunk;
     */
    uint64_t get_chunk_start_offset(const uint32_t dev_id, const uint32_t chunk_id) const {
        return m_primary_pdev_chunks_list[dev_id].chunks_in_pdev[chunk_id]->get_start_offset();
    }

    /**
     * @brief : get total length of the iov
     *
     * @param iov : iovector
     * @param iovcnt : the count of vectors in iov
     *
     * @return : the total size of buffer in iov
     */
    uint64_t get_len(const iovec* const iov, const int iovcnt) {
        uint64_t len{0};
        for (int i{0}; i < iovcnt; ++i) {
            len += iov[i].iov_len;
        }
        return len;
    }

    /**
     * @brief : internal implementation of pwritev, so that it can be called by differnet callers;
     *
     * @param pdev : pointer to device
     * @param pchunk : pointer to chunk
     * @param iov : io vector
     * @param iovcnt : the count of vectors in iov
     * @param len : total size of buffer length in iov
     * @param offset_in_dev : physical offset in device
     * @param req : if req is nullptr, it is a sync call, if not, it will be an async call;
     *
     * @return : size that has been written;
     */
    ssize_t do_pwritev_internal(PhysicalDev* const pdev, PhysicalDevChunk* const pchunk, const iovec* const iov, const int iovcnt,
                                const uint64_t len, const uint64_t offset_in_dev,
                                const boost::intrusive_ptr< virtualdev_req >& req = nullptr) {
        COUNTER_INCREMENT(pdev->get_metrics(), drive_write_vector_count, 1);

        ssize_t bytes_written{0};
        auto align_sz = HS_STATIC_CONFIG(drive_attr.phys_page_size);
        COUNTER_INCREMENT(m_metrics, vdev_write_count, 1);
        if (sisl_unlikely(!hs_utils::mod_aligned_sz(offset_in_dev, align_sz))) {
            COUNTER_INCREMENT(m_metrics, unalign_writes, 1);
        }

        if (!req || req->isSyncCall) {
            const auto start_time{Clock::now()};
            COUNTER_INCREMENT(pdev->get_metrics(), drive_sync_write_count, 1);
            bytes_written = pdev->sync_writev(iov, iovcnt, len, offset_in_dev);
            HISTOGRAM_OBSERVE(pdev->get_metrics(), drive_write_latency, get_elapsed_time_us(start_time));
        } else {
            COUNTER_INCREMENT(pdev->get_metrics(), drive_async_write_count, 1);
            req->inc_ref();
            req->io_start_time = Clock::now();
            pdev->writev(iov, iovcnt, len, offset_in_dev, reinterpret_cast< uint8_t* >(req.get()), req->part_of_batch);
            // we are going to get error in callback if the size being writen in aysc is not equal to the size that was
            // requested.
            bytes_written = len;
        }

        if (get_nmirrors()) {
            // We do not support async mirrored writes yet.
            HS_ASSERT(DEBUG, ((req == nullptr) || req->isSyncCall), "Expected null req or a sync call");
            writev_nmirror(iov, iovcnt, len, pchunk, offset_in_dev);
        }

        return bytes_written;
    }

    /**
     * @brief : the internal implementation of pwrite
     *
     * @param pdev : pointer to devic3
     * @param pchunk : pointer to chunk
     * @param buf : buffer to be written
     * @param len : length of buffer
     * @param offset_in_dev : physical offset in device to be written
     * @param req : if req is null, it will be sync call, if not, it will be async call;
     *
     * @return : bytes written;
     */
    ssize_t do_pwrite_internal(PhysicalDev* const pdev, PhysicalDevChunk* const pchunk, const char* const buf, const uint32_t len,
                               const uint64_t offset_in_dev, const boost::intrusive_ptr< virtualdev_req >& req = nullptr) {
        COUNTER_INCREMENT(pdev->get_metrics(), drive_write_vector_count, 1);

        const auto align_sz{HS_STATIC_CONFIG(drive_attr.phys_page_size)};
        COUNTER_INCREMENT(m_metrics, vdev_write_count, 1);
        if (sisl_unlikely(!hs_utils::mod_aligned_sz(offset_in_dev, align_sz))) {
            COUNTER_INCREMENT(m_metrics, unalign_writes, 1);
        }

        ssize_t bytes_written{0};

        if (!req || req->isSyncCall) {
            const auto start_time{Clock::now()};
            COUNTER_INCREMENT(pdev->get_metrics(), drive_sync_write_count, 1);
            bytes_written = pdev->sync_write(buf, len, offset_in_dev);
            HISTOGRAM_OBSERVE(pdev->get_metrics(), drive_write_latency, get_elapsed_time_us(start_time));
        } else {
            COUNTER_INCREMENT(pdev->get_metrics(), drive_async_write_count, 1);
            req->inc_ref();
            req->io_start_time = Clock::now();
            pdev->write(buf, len, offset_in_dev, reinterpret_cast< uint8_t* >(req.get()), req->part_of_batch);
            // we are going to get error in callback if the size being writen in aysc is not equal to the size that was
            // requested.
            bytes_written = len;
        }

        if (get_nmirrors()) {
            // We do not support async mirrored writes yet.
            HS_ASSERT(DEBUG, ((req == nullptr) || req->isSyncCall), "Expected null req or a sync call");
            write_nmirror(buf, len, pchunk, offset_in_dev);
        }

        return bytes_written;
    }

    ssize_t do_read_internal(PhysicalDev* const pdev, PhysicalDevChunk* const primary_chunk, const uint64_t primary_dev_offset,
                             char* const ptr, const uint64_t size, const boost::intrusive_ptr< virtualdev_req >& req = nullptr) {
        COUNTER_INCREMENT(pdev->get_metrics(), drive_read_vector_count, 1);
        COUNTER_INCREMENT(m_metrics, vdev_read_count, 1);
        ssize_t bytes_read{0};

        if (!req || req->isSyncCall) {
            // if req is null (sync), or it is a sync call;
            const auto start{Clock::now()};
            COUNTER_INCREMENT(pdev->get_metrics(), drive_sync_read_count, 1);
            bytes_read = pdev->sync_read(ptr, size, primary_dev_offset);
            HISTOGRAM_OBSERVE(pdev->get_metrics(), drive_read_latency, get_elapsed_time_us(start));
        } else {
            COUNTER_INCREMENT(pdev->get_metrics(), drive_async_read_count, 1);
            // aysnc read
            req->version = 0xDEAD;
            req->cb = std::bind(&VirtualDev::process_completions, this, std::placeholders::_1);
            req->size = size;
            req->chunk = primary_chunk;
            req->io_start_time = Clock::now();
            req->inc_ref();

            pdev->read(ptr, size, primary_dev_offset, reinterpret_cast< uint8_t* >(req.get()), req->part_of_batch);
            bytes_read = size;
        }

        if (sisl_unlikely(get_nmirrors())) {
            // If failed and we have mirrors, we can read from any one of the mirrors as well

            const uint64_t primary_chunk_offset{primary_dev_offset - primary_chunk->get_start_offset()};
            for (auto* const mchunk : m_mirror_chunks.find(primary_chunk)->second) {
                const uint64_t dev_offset{mchunk->get_start_offset() + primary_chunk_offset};
                auto* const pdev{mchunk->get_physical_dev_mutable()};
                HS_ASSERT(DEBUG, ((req == nullptr) || req->isSyncCall), "Expecting null req or sync call");

                COUNTER_INCREMENT(pdev->get_metrics(), drive_sync_read_count, 1);
                const auto start_time{Clock::now()};
                pdev->sync_read(ptr, size, dev_offset);
                HISTOGRAM_OBSERVE(pdev->get_metrics(), drive_read_latency, get_elapsed_time_us(start_time));
            }
        }

        return bytes_read;
    }

    /**
     * @brief : internal implementation for preadv, so that it call be reused by different callers;
     *
     * @param pdev : pointer to device
     * @param pchunk : pointer to chunk
     * @param dev_offset : physical offset in device
     * @param iov : io vector
     * @param iovcnt : the count of vectors in iov
     * @param size : size of buffers in iov
     * @param req : async req, if req is nullptr, it is a sync call, if not, it is an async call;
     *
     * @return : size being read.
     */
    ssize_t do_preadv_internal(PhysicalDev* const pdev, PhysicalDevChunk* const pchunk, const uint64_t dev_offset,
                               iovec* const iov, const int iovcnt, const uint64_t size,
                               const boost::intrusive_ptr< virtualdev_req >& req = nullptr) {
        COUNTER_INCREMENT(pdev->get_metrics(), drive_read_vector_count, iovcnt);
        COUNTER_INCREMENT(m_metrics, vdev_read_count, 1);
        ssize_t bytes_read{0};
        if (!req || req->isSyncCall) {
            const auto start{Clock::now()};
            COUNTER_INCREMENT(pdev->get_metrics(), drive_sync_read_count, 1);
            bytes_read = pdev->sync_readv(iov, iovcnt, size, dev_offset);
            HISTOGRAM_OBSERVE(pdev->get_metrics(), drive_read_latency, get_elapsed_time_us(start));
        } else {
            COUNTER_INCREMENT(pdev->get_metrics(), drive_async_read_count, 1);
            req->version = 0xDEAD;
            req->cb = std::bind(&VirtualDev::process_completions, this, std::placeholders::_1);
            req->size = size;
            req->inc_ref();
            req->chunk = pchunk;
            req->io_start_time = Clock::now();

            pdev->readv(iov, iovcnt, size, dev_offset, reinterpret_cast< uint8_t* >(req.get()), req->part_of_batch);
            bytes_read = size; // no one consumes return value for async read;
        }

        if (sisl_unlikely(get_nmirrors())) {
            // If failed and we have mirrors, we can read from any one of the mirrors as well
            const uint64_t primary_chunk_offset{dev_offset - pchunk->get_start_offset()};
            for (auto mchunk : m_mirror_chunks.find(pchunk)->second) {
                const uint64_t dev_offset_m{mchunk->get_start_offset() + primary_chunk_offset};
                req->inc_ref();
                mchunk->get_physical_dev_mutable()->readv(iov, iovcnt, size, dev_offset_m, reinterpret_cast< uint8_t* >(req.get()),
                                                          req->part_of_batch);
            }
        }

        return bytes_read;
    }

    /**
     * @brief : Convert from logical offset to device offset.
     * It handles device overloop, e.g. reach to end of the device then start from the beginning device
     *
     * @param log_offset : the logical offset
     * @param dev_id     : the device id after convertion
     * @param chunk_id   : the chunk id after convertion
     * @param offset_in_chunk : the relative offset in chunk
     *
     * @return : the unique offset after converion;
     */
    uint64_t logical_to_dev_offset(const off_t log_offset, uint32_t& dev_id, uint32_t& chunk_id,
                                   off_t& offset_in_chunk) const {
        dev_id = 0;
        chunk_id = 0;
        offset_in_chunk = 0;

        uint64_t off_l{static_cast<uint64_t>(log_offset)};
        for (size_t d{0}; d < m_primary_pdev_chunks_list.size(); ++d) {
            for (size_t c{0}; c < m_primary_pdev_chunks_list[d].chunks_in_pdev.size(); ++c) {
                if (off_l >= m_chunk_size) {
                    off_l -= m_chunk_size;
                } else {
                    dev_id = d;
                    chunk_id = c;
                    offset_in_chunk = off_l;

                    return get_offset_in_dev(dev_id, chunk_id, offset_in_chunk);
                }
            }
        }

        HS_ASSERT(DEBUG, false, "Input log_offset is invalid: {}, should be between 0 ~ {}", log_offset,
                  m_chunk_size * m_num_chunks);
        return 0;
    }

    /* Adds a primary chunk to the chunk list in pdev */
    void add_primary_chunk(PhysicalDevChunk* const chunk) {
        const auto pdev_id{chunk->get_physical_dev()->get_dev_id()};

        if (m_chunk_size == 0) {
            m_chunk_size = chunk->get_size();
        } else {
            HS_ASSERT_CMP(DEBUG, m_chunk_size, ==, chunk->get_size());
        }

        pdev_chunk_map* found_pcm{nullptr};
        for (auto& pcm : m_primary_pdev_chunks_list) {
            if (pcm.pdev->get_dev_id() == pdev_id) {
                found_pcm = &pcm;
                break;
            }
        }

        if (found_pcm) {
            found_pcm->chunks_in_pdev.push_back(chunk);
        } else {
            // Have not seen the pdev before, so add the chunk and also add it to device selector
            pdev_chunk_map pcm;
            pcm.pdev = m_mgr->get_pdev(pdev_id);
            pcm.chunks_in_pdev.push_back(chunk);

            m_primary_pdev_chunks_list.push_back(pcm);
            m_selector->add_pdev(pcm.pdev);
        }
        HS_ASSERT_CMP(DEBUG, m_chunk_size, <=, MAX_CHUNK_SIZE);
        std::shared_ptr< BlkAllocator > ba{Allocator::create_allocator(m_chunk_size, get_page_size(), m_auto_recovery,
                                                                       chunk->get_chunk_id(), m_recovery_init)};
        chunk->set_blk_allocator(ba);
        if (!m_recovery_init) { chunk->recover(); }
        /* set the same blk allocator to other mirror chunks */
        const auto itr_pair{m_mirror_chunks.emplace(chunk, std::vector< PhysicalDevChunk* >{})};
        if (itr_pair.second) {
            // Not found, just created a new entry
        } else {
            for (auto* const chunk : itr_pair.first->second) {
                chunk->set_blk_allocator(ba);
            }
        }
    }

    void add_mirror_chunk(PhysicalDevChunk* const chunk) {
        const auto pdev_id{chunk->get_physical_dev()->get_dev_id()};
        auto* const pchunk{chunk->get_primary_chunk_mutable()};

        if (m_chunk_size == 0) {
            m_chunk_size = chunk->get_size();
        } else {
            HS_ASSERT_CMP(DEBUG, m_chunk_size, ==, chunk->get_size());
        }

        // Try to find the parent chunk in the map
        const auto itr_pair{m_mirror_chunks.emplace(chunk, std::vector< PhysicalDevChunk* >{})};
        itr_pair.first->second.emplace_back(chunk);
        if (itr_pair.second) {
            // Not found, just created a new entry
        } else {
            // set block allocator
            itr_pair.first->second.back()->set_blk_allocator(pchunk->get_blk_allocator_mutable());
        }
    }

#if 0
    std::shared_ptr< BlkAllocator > create_allocator(const uint64_t size, const uint32_t unique_id, const bool init) {
        std::shared_ptr< BlkAllocator > allocator{
            std::make_shared< typename Allocator::AllocatorType >(
        Allocator::get_config(size, get_page_size(), m_auto_recovery)};

        typename Allocator::AllocatorConfig cfg(std::string{"chunk_"} + std::to_string(unique_id));
        Allocator::get_config(size, get_page_size(), &cfg);
        cfg.set_auto_recovery(m_auto_recovery);

        std::shared_ptr< BlkAllocator > allocator{
            std::make_shared< typename Allocator::AllocatorType >(cfg, init, unique_id)};
        return allocator;
    }
#endif

    PhysicalDevChunk* create_dev_chunk(const uint32_t pdev_ind, const std::shared_ptr< BlkAllocator >& ba, const uint32_t primary_id) {
        auto* const pdev{m_primary_pdev_chunks_list[pdev_ind].pdev};
        PhysicalDevChunk* const chunk{m_mgr->alloc_chunk(pdev, m_vb->vdev_id, m_chunk_size, primary_id)};
        HS_LOG(DEBUG, device, "Allocating new chunk for vdev_id = {} pdev_id = {} chunk: {}", m_vb->get_vdev_id(),
               pdev->get_dev_id(), chunk->to_string());
        chunk->set_blk_allocator(ba);

        return chunk;
    }

    uint64_t to_dev_offset(const BlkId& glob_uniq_id, PhysicalDevChunk** const chunk) const {
        *chunk = m_mgr->get_chunk_mutable(glob_uniq_id.get_chunk_num());

        const uint64_t dev_offset{static_cast< uint64_t >(glob_uniq_id.get_blk_num()) * get_page_size() +
                                  static_cast< uint64_t >((*chunk)->get_start_offset())};
        return dev_offset;
    }

    uint32_t get_blks_per_chunk() const { return get_chunk_size() / get_page_size(); }
    uint32_t get_page_size() const { return m_vb->page_size; }
    uint32_t get_nmirrors() const { return m_vb->num_mirrors; }
};

} // namespace homestore
