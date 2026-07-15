/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *    https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 *********************************************************************************/
#pragma once
#include <sys/uio.h>
#include <cstdint>

#include <boost/container/small_vector.hpp>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wuninitialized"
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#include <iomgr/io_op.hpp>     // iomgr::io_result (the data-surface error type)
#include <sisl/async/task.hpp> // sisl::async::task
#pragma GCC diagnostic pop
#include <sisl/fds/buffer.hpp>
#include <sisl/utility/atomic_counter.hpp>

#include <homestore/homestore_decl.hpp>
#include <homestore/blk.hpp>
#include <homestore/error.hpp> // homestore::result / homestore::status

namespace homestore {
// callback type for caller to provide
typedef std::function< void(std::error_condition) > io_completion_cb_t;

class VirtualDev;
struct vdev_info;
struct stream_info_t;
class BlkReadTracker;
struct blk_alloc_hints;
class ChunkSelector;
class blk_data_service;

// A [[nodiscard]] RAII batch scope. Hand `&batch` to an async IO op and it is accumulated rather than submitted
// immediately; the destructor submits the accumulated batch, so a batch can never be left unsubmitted (this
// replaces the old `bool part_of_batch=true` + a separate, easy-to-forget submit_io_batch()). Reactor-local:
// issue the batched IOs and let the token drop on the same reactor.
class io_batch {
public:
    io_batch(io_batch&& o) noexcept : m_svc{o.m_svc} { o.m_svc = nullptr; }
    io_batch& operator=(io_batch&& o) noexcept;
    io_batch(io_batch const&) = delete;
    io_batch& operator=(io_batch const&) = delete;
    ~io_batch();

private:
    friend class blk_data_service;
    explicit io_batch(blk_data_service* svc) noexcept : m_svc{svc} {}
    blk_data_service* m_svc{nullptr};
};

class blk_data_service {
public:
    /**
     * @brief Constructs a new blk_data_service object with the given custom chunk selector.
     *
     * @param custom_chunk_selector A shared pointer to a ChunkSelector object that will be used to select chunks for
     * this service.
     */
    blk_data_service(shared< ChunkSelector > custom_chunk_selector);

    /**
     * @brief Destructor for the blk_data_service class.
     *
     * This destructor is responsible for cleaning up any resources
     * allocated by the blk_data_service instance.
     */
    ~blk_data_service();

    /**
     * @brief Creates a new virtual device with the specified size and block size, using the specified
     * block allocator and chunk selector types. The virtual device will be composed of a number of chunks.
     * Either `num_chunks` or `chunk_size` must be specified.
     * Prioritize `num_chunks` over `chunk_size` if both are provided.
     *
     * @param size The size of the virtual device, in bytes.
     * @param blk_size The size of each block in the virtual device, in bytes.
     * @param alloc_type The type of block allocator to use for the virtual device.
     * @param chunk_sel_type The type of chunk selector to use for the virtual device.
     * @param num_chunks The number of chunks to use for the virtual device.
     * @param chunk_size The size of chunks to use for the virtual device, in bytes.
     */
    void create_vdev(uint64_t size, HSDevType devType, uint32_t blk_size, blk_allocator_type_t alloc_type,
                     chunk_selector_type_t chunk_sel_type, uint32_t num_chunks, uint32_t chunk_size);

    /**
     * @brief Opens a virtual device with the specified virtual device information.
     *
     * @param vinfo The virtual device information.
     * @param load_existing Whether to load an existing virtual device or create a new one.
     * @return A shared pointer to the opened virtual device.
     */
    shared< VirtualDev > open_vdev(vdev_info const& vinfo, bool load_existing);

    /**
     * @brief Asynchronously allocates and writes data to a block device using the provided scatter-gather list.
     *
     * @param sgs The scatter-gather list containing the data to write.
     * @param hints Hints for allocating the block(s) to write to.
     * @param out_blkids The ID(s) of the block(s) that were allocated and written to.
     * @param batch Optional batch token from begin_batch(); pass `&batch` to accumulate this op into that batch.
     * @return A Future that will contain an error code indicating the success or failure of the operation.
     */
    sisl::async::task< iomgr::io_result > async_alloc_write(sisl::sg_list const& sgs, blk_alloc_hints const& hints,
                                                            multi_blk_id& out_blkids, io_batch* batch = nullptr);

    /**
     * @brief Asynchronously writes the given buffer to the specified block ID.
     *
     * @param buf The buffer to write.
     * @param size The size of the buffer in bytes.
     * @param bid The ID of the block to write to.
     * @param batch Optional batch token from begin_batch(); pass `&batch` to accumulate this op into that batch.
     * @return A Future that will resolve to an error code indicating the result of the write operation.
     */
    sisl::async::task< iomgr::io_result > async_write(const char* buf, uint32_t size, multi_blk_id const& bid,
                                                      io_batch* batch = nullptr);
    /**
     * @brief : asynchronous write with input block ids;
     *
     * @param sgs : the data buffer that needs to be written
     * @param hints : blk alloc hints
     * @param in_blkids : input block ids that this write should be written to;
     * @param cb : callback that will be triggered after write completes
     * @param batch : optional batch token from begin_batch(); pass `&batch` to accumulate this op into that batch;
     */
    sisl::async::task< iomgr::io_result > async_write(sisl::sg_list const& sgs, multi_blk_id const& in_blkids,
                                                      io_batch* batch = nullptr);

    /**
     * @brief : asynchronous write with input block ids;
     *
     * @param sgs : the data buffer that needs to be written
     * @param hints : blk alloc hints
     * @param in_blkids : input block ids that this write should be written to;
     * @param cb : callback that will be triggered after write completes
     * @param batch : optional batch token from begin_batch(); pass `&batch` to accumulate this op into that batch;
     */
    sisl::async::task< iomgr::io_result >
    async_write(sisl::sg_list const& sgs, std::vector< multi_blk_id > const& in_blkids, io_batch* batch = nullptr);

    /**
     * @brief Asynchronously reads data from the specified block ID into the provided buffer.
     *
     * @param bid The ID of the block to read from.
     * @param buf The buffer to read data into.
     * @param size The number of bytes to read.
     * @param batch Optional batch token from begin_batch(); pass `&batch` to accumulate this op into that batch.
     * @return A Future that will resolve to an error code indicating the result of the operation.
     */
    sisl::async::task< iomgr::io_result > async_read(multi_blk_id const& bid, uint8_t* buf, uint32_t size,
                                                     io_batch* batch = nullptr);

    /**
     * @brief Asynchronously reads data from the specified block ID.
     *
     * @param bid The block ID to read from.
     * @param sgs The scatter-gather list to store the read data.
     * @param size The size of the data to read.
     * @param batch Optional batch token from begin_batch(); pass `&batch` to accumulate this op into that batch.
     *
     * @return A task that completes with the iomgr::io_result of the read operation.
     */
    sisl::async::task< iomgr::io_result > async_read(multi_blk_id const& bid, sisl::sg_list& sgs, uint32_t size,
                                                     io_batch* batch = nullptr);

    /**
     * @brief Begin a batch of IO operations. Hand `&batch` to the async read/write/alloc_write calls below to
     * accumulate them; the returned [[nodiscard]] token submits the batch when it is destroyed (so it can never be
     * forgotten). Issue the batched IOs and let the token drop on the same reactor.
     */
    [[nodiscard]] io_batch begin_batch() { return io_batch{this}; }

    /**
     * @brief Commits the block with the given multi_blk_id.
     *
     * @param bid The multi_blk_id of the block to commit.
     * @param recommit If true, skip the allocation check and commit the blk unconditionally.
     *        Use this when re-committing a blk that is known to be live but whose allocator state
     *        may have been lost (e.g. after a crash where the blk exists in the index but the
     *        allocator watermarks were not yet persisted). Safe to pass when the allocator already
     *        tracks the blk, as the underlying operations are monotonically advancing.
     * @return success, or the error_condition describing the failure.
     */
    status commit_blk(multi_blk_id const& bid, bool recommit = false);

    /**
     * @brief Allocates a contiguous block of disk space of the given size. Use this when the consumer expects the blks
     * to be allocated on the same chunk (one multi_blk_id).
     *
     * @param size The size of the block to allocate, in bytes.
     * @param hints Hints for how to allocate the block.
     * @return The allocated multi_blk_id, or the error_condition describing the failure.
     */
    result< multi_blk_id > alloc_blks(uint32_t size, blk_alloc_hints const& hints);

    /**
     * @brief Allocates blocks of disk space of the given size, where allocation may span multiple chunks (an arbitrary
     * list of BlkIds, which can hold more pieces than a single multi_blk_id).
     *
     * @param size The size of the block to allocate, in bytes.
     * @param hints Hints for how to allocate the block.
     * @return The list of allocated BlkIds, or the error_condition describing the failure.
     */
    result< std::vector< blk_id > > alloc_blk_list(uint32_t size, blk_alloc_hints const& hints);

    /**
     * @brief Asynchronously frees the specified block IDs.
     * It is asynchronous because it might need to wait for pending read to complete if same block is being read and not
     * completed yet;
     *
     * @param bid The block IDs to free.
     * @return A Future that will resolve to an error code indicating the result of the operation.
     */
    sisl::async::task< iomgr::io_result > async_free_blk(multi_blk_id const& bid);

    /**
     * @brief Frees the specified block IDs immediately. Used during log replay on commit only.
     *
     * @param bid The block ID to free.
     * @return success, or the error_condition describing the failure.
     */
    status free_blk_now(multi_blk_id const& bid);

    /**
     * @brief Check if the blk id is free or not.
     *
     * @param bid The block ID to check.
     * @return Return whether blkid is alloced or not.
     */
    bool is_blk_alloced(blk_id const& blkid) const;

    /**
     * @brief : get the blk size of this data service;
     *
     * @return : blk size
     */
    uint32_t get_blk_size() const { return m_blk_size; }

    /**
     * @brief : get the blk size of this data service;
     *
     * @return : blk size
     */
    uint32_t get_align_size() const;

    /**
     * @brief : get the read block tracker handle;
     *
     * @return : the read block tracker pointer;
     */
    BlkReadTracker* read_blk_tracker() { return m_blk_read_tracker.get(); }

    /**
     * @brief Starts the block data service.
     *
     * This function starts the block data service, which is responsible for managing
     * the storage and retrieval of block data. Once started, the service will listen
     * for incoming requests and respond accordingly.
     */
    void start();

    /**
     * @brief Gets the total capacity of the block data service.
     *
     * This function returns the total capacity of the block data service, in bytes.
     *
     * @return The total capacity of the block data service, in bytes.
     */
    uint64_t get_total_capacity() const;

    /**
     * @brief Gets the used capacity of the block data service.
     *
     * This function returns the used capacity of the block data service, in bytes.
     *
     * @return The used capacity of the block data service, in bytes.
     */
    uint64_t get_used_capacity() const;

    /**
     * @brief Gets the drive type of the data service.
     *
     * Data Service doesn't support mixed drive types.
     *
     * @return The drive type of the data service, HDD or NVME.
     */
    HSDevType get_dev_type() const;

    void stop();

private:
    friend class io_batch;
    // Submit the accumulated batch to the underlying vdev. Only io_batch (on destruction) calls this; batch
    // accumulation is never exposed on the public surface.
    void submit_io_batch();

    /**
     * @brief Initializes the block data service.
     *
     * This function initializes the block data service by performing any necessary setup
     * and configuration. It should be called before any other functions in the service are used.
     */
    void init();

    /**
     * @brief Callback function for processing data completion.
     *
     * This function is called when data processing is complete. It takes an error condition and a cookie as arguments.
     *
     * @param ec The error condition.
     * @param cookie A pointer to the cookie associated with the data processing.
     */
    static void process_data_completion(std::error_condition ec, void* cookie);

    // Read one piece while bracketing it in the read tracker. Member coroutines (not capturing lambdas) so `this`
    // and the args are copied into the self-owning frame -- a capturing coroutine lambda would dangle once the
    // enclosing call returns the (lazy) task.
    sisl::async::task< iomgr::io_result > do_read_blk(blk_id bid, uint8_t* buf, uint32_t size, bool part_of_batch);
    sisl::async::task< iomgr::io_result > do_readv_blk(blk_id bid, sisl::sg_iovs_t iovs, uint32_t size,
                                                       bool part_of_batch);

private:
    std::shared_ptr< VirtualDev > m_vdev;
    std::unique_ptr< BlkReadTracker > m_blk_read_tracker;
    std::shared_ptr< ChunkSelector > m_custom_chunk_selector;
    uint32_t m_blk_size;

private:
    // graceful shutdown related
    std::atomic_bool m_stopping{false};
    mutable std::atomic_uint64_t pending_request_num{0};

    bool is_stopping() const { return m_stopping.load(); }
    void start_stopping() { m_stopping = true; }

    uint64_t get_pending_request_num() const { return pending_request_num.load(); }

    void incr_pending_request_num() const { pending_request_num++; }
    void decr_pending_request_num() const { pending_request_num--; }
};

extern blk_data_service& data_service();
} // namespace homestore
