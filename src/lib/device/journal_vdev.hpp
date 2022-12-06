#pragma once

#include <array>
#include <atomic>
#include <functional>
#include <memory>

#include "device.h"
#include "virtual_dev.hpp"

namespace homestore {
typedef std::function< void(const off_t ret_off) > alloc_next_blk_cb_t;

class JournalVirtualDev : public VirtualDev {
    struct Chunk_EOF_t {
        uint64_t e;
    };

    // NOTE:  Usage of this needs to avoid punning which is now illegal in C++ 11 and up
    typedef union {
        struct Chunk_EOF_t eof;
        std::array< unsigned char, VIRDEV_BLKSIZE > padding;
    } Chunk_EOF;

    static_assert(sizeof(Chunk_EOF) == VIRDEV_BLKSIZE, "LogDevRecordHeader must be VIRDEV_SIZE bytes");

private:
    off_t m_seek_cursor{0};                         // the seek cursor
    off_t m_data_start_offset{0};                   // Start offset of where actual data begin for this vdev
    std::atomic< uint64_t > m_write_sz_in_total{0}; // this size will be decreased by truncate and increased by append;
    bool m_truncate_done{true};
    vdev_high_watermark_cb_t m_hwm_cb{nullptr};
    uint64_t m_reserved_sz{0}; // write size within chunk, used to check chunk boundary;

public:
    /* Create a new virtual dev for these parameters */
    JournalVirtualDev(DeviceManager* mgr, const char* name, PhysicalDevGroup pdev_group, uint64_t size_in,
                      uint32_t nmirror, bool is_stripe, uint32_t blk_size, char* context, uint64_t context_size,
                      bool auto_recovery = false, vdev_high_watermark_cb_t hwm_cb = nullptr) :
            VirtualDev{mgr,     name,         pdev_group,    blk_allocator_type_t::none,
                       size_in, nmirror,      is_stripe,     blk_size,
                       context, context_size, auto_recovery, hwm_cb} {}

    /* Load the virtual dev from vdev_info_block and create a Virtual Dev. */
    JournalVirtualDev(DeviceManager* mgr, const char* name, vdev_info_block* vb, PhysicalDevGroup pdev_group,
                      bool recovery_init, bool auto_recovery = false, vdev_high_watermark_cb_t hwm_cb = nullptr) :
            VirtualDev(mgr, name, vb, pdev_group, blk_allocator_type_t::none, recovery_init, auto_recovery, hwm_cb) {}

    JournalVirtualDev(const JournalVirtualDev& other) = delete;
    JournalVirtualDev& operator=(const JournalVirtualDev& other) = delete;
    JournalVirtualDev(JournalVirtualDev&&) noexcept = delete;
    JournalVirtualDev& operator=(JournalVirtualDev&&) noexcept = delete;
    virtual ~JournalVirtualDev() override = default;

    /**
     * @brief : allocate space specified by input size.
     *
     * @param size : size to be allocated
     *
     * @return : the start unique offset of the allocated space
     *
     * Possible calling sequence:
     * offset_1 = reserve(size1);
     * offset_2 = reserve(size2);
     * write_at_offset(offset_2);
     * write_at_offset(offset_1);
     */
    off_t alloc_next_append_blk(const size_t size);

    /**
     * @brief : writes up to count bytes from the buffer starting at buf. append advances seek cursor;
     *
     * @param buf : buffer to be written
     * @param count : size of buffer in bytes
     * @param req : async req;
     *
     * @return : On success, the number of bytes written is returned.  On error, -1 is returned.
     */
    void async_append(const uint8_t* buf, size_t count, vdev_io_comp_cb_t cb);

    /**
     * @brief : writes up to count bytes from the buffer starting at buf at offset offset.
     * The cursor is not changed.
     * pwrite always use offset returned from alloc_next_append_blk to do the write;
     * pwrite should not across chunk boundaries because alloc_next_append_blk guarantees offset returned always doesn't
     * across chunk boundary;
     *
     * @param buf : buffer pointing to the data being written
     * @param size : size of buffer to be written
     * @param offset : offset to be written
     * @param req : async req
     *
     * @return : On success, the number of bytes read or written is returned, or -1 on error.
     */
    void async_pwrite(const uint8_t* buf, size_t size, off_t offset, vdev_io_comp_cb_t cb);

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
    void async_pwritev(const iovec* iov, int iovcnt, off_t offset, vdev_io_comp_cb_t cb);

    /// @brief writes up to count bytes from the buffer starting at buf at offset offset. The cursor is not
    /// changed. pwrite always use offset returned from alloc_next_append_blk to do the write;pwrite should not across
    /// chunk boundaries because alloc_next_append_blk guarantees offset returned always doesn't across chunk boundary;
    ///
    /// @param buf : buffer pointing to the data being written
    /// @param size : size of buffer to be written
    /// @param offset : offset to be written
    /// @return : On success, the number of bytes written is returned, or -1 on error.
    ssize_t sync_pwrite(const uint8_t* buf, size_t size, off_t offset);

    ssize_t sync_pwritev(const iovec* iov, int iovcnt, off_t offset);

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
    ssize_t sync_next_read(uint8_t* buf, size_t count_in);

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
    ssize_t sync_pread(uint8_t* buf, const size_t count_in, const off_t offset);

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
    ssize_t sync_preadv(iovec* iov, const int iovcnt, const off_t offset);

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
    off_t lseek(off_t offset, int whence = SEEK_SET);

    /**
     * @brief : this API can be replaced by lseek(0, SEEK_CUR);
     *
     * @return : current curosr offset
     */
    off_t seeked_pos() const { return m_seek_cursor; }

    /**
     * @brief :- it returns the vdev offset after nbytes from start offset
     */
    off_t dev_offset(off_t nbytes) const;

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
    void update_data_start_offset(off_t offset) { m_data_start_offset = offset; }

    /**
     * @brief : get the logical tail offset;
     *
     * @param reserve_space_include : include reserved space or not;
     *
     * @return : the logical tail offset;
     */
    off_t tail_offset(bool reserve_space_include = true) const;

    /**
     * @brief : update the tail to vdev, this API will be called during reboot and
     * upper layer(logdev) has completed scanning all the valid records in vdev and then
     * update the tail in vdev.
     *
     * @param tail : logical tail offset
     */
    void update_tail_offset(off_t tail);

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
    void truncate(off_t offset);

    /**
     * @brief : get the used size in vdev
     *
     * @return : the used space in vdev
     */
    uint64_t used_size() const override { return m_write_sz_in_total.load(std::memory_order_relaxed) + m_reserved_sz; }

    /**
     * @brief : get the free space left in vdev
     *
     * @return : free space left in vdev
     */
    uint64_t available_size() const { return size() - used_size(); }

    /**
     * @brief : get the free blks available in vdev, assuming page_size as a measure of blks
     *
     * @return : free number of pages/blks available.
     */
    uint64_t available_blks() const override { return available_size() / block_size(); }

    /**
     * @brief Get the status of the journal vdev and its internal structures
     * @param log_level: Log level to do verbosity.
     * @return Json containing internal details
     */
    nlohmann::json get_status(int log_level) const override;

    /////////////////////////////////////////////////////////////////////////
    // All methods which are invalid for journal vdev are put here.
    // TODO: Do an assert after it is verified to be ok or better split current vdev into vdevbase and vdev.
    bool is_blk_alloced(const BlkId& blkid) const override {
        HS_DBG_ASSERT(false, "Unsupported API for journalvdev");
        return false;
    }

    BlkAllocStatus commit_blk(const BlkId& blkid) override {
        HS_DBG_ASSERT(false, "Unsupported API for journalvdev");
        return BlkAllocStatus::BLK_ALLOC_NONE;
    }

    BlkAllocStatus alloc_blk(uint32_t nblks, const blk_alloc_hints& hints, std::vector< BlkId >& out_blkid) override {
        HS_DBG_ASSERT(false, "Unsupported API for journalvdev");
        return BlkAllocStatus::BLK_ALLOC_NONE;
    }

    bool free_on_realtime(const BlkId& b) override {
        HS_DBG_ASSERT(false, "Unsupported API for journalvdev");
        return false;
    }

    void free_blk(const BlkId& b) override { HS_DBG_ASSERT(false, "Unsupported API for journalvdev"); }

    void recovery_done() override { HS_DBG_ASSERT(false, "Unsupported API for journalvdev"); }

    BlkAllocStatus create_debug_bm() override {
        HS_DBG_ASSERT(false, "Unsupported API for journalvdev");
        return BlkAllocStatus::BLK_ALLOC_NONE;
    }

    BlkAllocStatus update_debug_bm(const BlkId& bid) override {
        HS_DBG_ASSERT(false, "Unsupported API for journalvdev");
        return BlkAllocStatus::BLK_ALLOC_NONE;
    }

    BlkAllocStatus verify_debug_bm(const bool free_debug_bm) override {
        HS_DBG_ASSERT(false, "Unsupported API for journalvdev");
        return BlkAllocStatus::BLK_ALLOC_NONE;
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
    auto process_pwrite_offset(size_t len, off_t offset);
    void do_pwrite(const uint8_t* buf, size_t count, off_t offset, vdev_io_comp_cb_t cb);

    /**
     * @brief : convert logical offset in chunk to the physical device offset
     *
     * @param dev_id : the device id
     * @param chunk_id : the chunk id;
     * @param offset_in_chunk : the logical offset in chunk;
     *
     * @return : the physical device offset;
     */
    uint64_t get_offset_in_dev(uint32_t dev_id, uint32_t chunk_id, uint64_t offset_in_chunk) const;

    /**
     * @brief : get the physical start offset of the chunk;
     *
     * @param dev_id : the deivce id;
     * @param chunk_id : the chunk id;
     *
     * @return : the physical start offset of the chunk;
     */
    uint64_t get_chunk_start_offset(uint32_t dev_id, uint32_t chunk_id) const;

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
    uint64_t logical_to_dev_offset(off_t log_offset, uint32_t& dev_id, uint32_t& chunk_id,
                                   off_t& offset_in_chunk) const;

    bool validate_append_size(size_t count) const;

    void high_watermark_check();

    off_t alloc_next_append_blk_internal(size_t size);

    bool is_alloc_accross_chunk(size_t size);

    auto get_dev_details(size_t len, off_t offset);
};

} // namespace homestore
