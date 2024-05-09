/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
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

#include <cassert>
#include <cstdint>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <sisl/fds/bitset.hpp>
#include <folly/MPMCQueue.h>
#include <sisl/utility/enum.hpp>
#include <sisl/utility/urcu_helper.hpp>
#include <sisl/fds/thread_vector.hpp>

#include <homestore/homestore_decl.hpp>
#include <homestore/blk.h>
#include "common/homestore_config.hpp"
#include "common/homestore_assert.hpp"

#include "blk_allocator.h"

namespace homestore {

class BlkAllocPortion {
private:
    mutable std::mutex m_blk_lock;
    blk_num_t m_portion_num;
    blk_temp_t m_temperature;

public:
    BlkAllocPortion(blk_temp_t temp = default_temperature()) : m_temperature(temp) {}
    ~BlkAllocPortion() = default;
    BlkAllocPortion(BlkAllocPortion const&) = delete;
    BlkAllocPortion(BlkAllocPortion&&) noexcept = delete;
    BlkAllocPortion& operator=(BlkAllocPortion const&) = delete;
    BlkAllocPortion& operator=(BlkAllocPortion&&) noexcept = delete;

    auto portion_auto_lock() const { return std::scoped_lock< std::mutex >(m_blk_lock); }
    blk_num_t get_portion_num() const { return m_portion_num; }
    blk_temp_t temperature() const { return m_temperature; }

    void set_portion_num(blk_num_t portion_num) { m_portion_num = portion_num; }
    void set_temperature(const blk_temp_t temp) { m_temperature = temp; }
    static constexpr blk_temp_t default_temperature() { return 1; }
};

class CP;
class BitmapBlkAllocator : public BlkAllocator {
public:
    BitmapBlkAllocator(BlkAllocConfig const& cfg, bool is_fresh, chunk_num_t id = 0);
    BitmapBlkAllocator(BlkAllocator const&) = delete;
    BitmapBlkAllocator(BitmapBlkAllocator&&) noexcept = delete;
    BitmapBlkAllocator& operator=(BitmapBlkAllocator const&) = delete;
    BitmapBlkAllocator& operator=(BitmapBlkAllocator&&) noexcept = delete;
    virtual ~BitmapBlkAllocator() = default;

    virtual void load() = 0;
    BlkAllocStatus reserve_on_disk(BlkId const& in_bid) override;
    void free_on_disk(BlkId const& b) override;
    bool is_blk_alloced_on_disk(BlkId const& b, bool use_lock = false) const override;
    void cp_flush(CP* cp) override;

    blk_num_t get_num_portions() const { return (m_num_blks - 1) / m_blks_per_portion + 1; }
    blk_num_t get_blks_per_portion() const { return m_blks_per_portion; }

    BlkAllocPortion& get_blk_portion(blk_num_t portion_num) {
        HS_DBG_ASSERT_LT(portion_num, get_num_portions(), "Portion num is not in range");
        return m_blk_portions[portion_num];
    }

    blk_num_t blknum_to_portion_num(const blk_num_t blknum) const { return blknum / m_blks_per_portion; }
    BlkAllocPortion& blknum_to_portion(blk_num_t blknum) { return m_blk_portions[blknum_to_portion_num(blknum)]; }
    BlkAllocPortion const& blknum_to_portion_const(blk_num_t blknum) const {
        return m_blk_portions[blknum_to_portion_num(blknum)];
    }

    sisl::Bitset const* get_disk_bitmap() const { return is_persistent() ? m_disk_bm.get() : nullptr; }

    /* Get status */
    nlohmann::json get_status(int log_level) const override;

    void incr_alloced_blk_count(blk_count_t nblks) { m_alloced_blk_count.fetch_add(nblks, std::memory_order_relaxed); }
    void decr_alloced_blk_count(blk_count_t nblks) { m_alloced_blk_count.fetch_sub(nblks, std::memory_order_relaxed); }
    int64_t get_alloced_blk_count() const { return m_alloced_blk_count.load(std::memory_order_acquire); }

private:
    void do_init();
    sisl::ThreadVector< MultiBlkId >* get_alloc_blk_list();
    void on_meta_blk_found(void* mblk_cookie, sisl::byte_view const& buf, size_t size);

    // Acquire the underlying bitmap buffer and while the caller has acquired, all the new allocations
    // will be captured in a separate list and then pushes into buffer once released.
    // NOTE: THIS IS NON-THREAD SAFE METHOD. Caller is expected to ensure synchronization between multiple
    // acquires/releases
    sisl::byte_array acquire_underlying_buffer();
    void release_underlying_buffer();

protected:
    blk_num_t m_blks_per_portion;

private:
    sisl::ThreadVector< MultiBlkId >* m_alloc_blkid_list{nullptr};
    std::unique_ptr< BlkAllocPortion[] > m_blk_portions;
    std::unique_ptr< sisl::Bitset > m_disk_bm{nullptr};
    std::atomic< bool > m_is_disk_bm_dirty{true}; // initially disk_bm treated as dirty
    void* m_meta_blk_cookie{nullptr};
    std::atomic< int64_t > m_alloced_blk_count{0};
};
} // namespace homestore
