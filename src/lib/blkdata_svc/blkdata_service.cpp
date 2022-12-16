/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 * Author/Developer(s): Harihara Kadayam, Yaming Kuang
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
#include "../api/blkdata_service.hpp"
#include "../device/virtual_dev.hpp"
#include "../homestore.hpp"

namespace homestore {
BlkDataService::BlkDataService(uint64_t size, uint32_t page_size, blk_allocator_type_t blkalloc_type,
                               bool cache = false) {
    HS_REL_ASSERT_EQ(cache, false, "We don't support cached blkdata service yet");

    struct blkstore_blob hdr {};
    hdr.type = blkstore_type::DATA_STORE;

    m_vdev = std::make_unique< VirtualDev >(hs()->device_manager(), "DataVDev", PhysicalDevGroup::DATA, blkalloc_type,
                                            sizeof(blkstore_blob), 0, true /* is_stripe */, page_size,
                                            bind_this(BlkDataService::vdev_io_completion, 1), hdr, size,
                                            true /* auto_recovery */);
    m_page_size = page_size;
}

BlkDataService::BlkDataService(vdev_info_block* vb, blk_allocator_type_t blkalloc_type, bool cache = false) {
    HS_REL_ASSERT_EQ(cache, false, "We don't support cached blkdata service yet");

    m_vdev = std::make_unique< VirtualDev >(hs()->device_manager(), "DataVDev", vb, PhysicalDevGroup::DATA,
                                            blkalloc_type, bind_this(BlkDataService::vdev_io_completion, 1), true,
                                            true /* auto_recovery */);
    m_page_size = vb->page_size;
}

struct sg_iterator {
    sg_iterator(const std::vector< iovec >& v) : m_input_iovs{v} {
        HS_DBG_ASSERT_GT(v.size(), 0, "Iterating over empty iov list");
    }

    std::vector< iovec > next_iovs(uint32_t size) {
        std::vector< iovec > ret_iovs;
        int64_t remain_size = size;

        while ((remain_size > 0) && (m_cur_index < m_input_iovs.size()) {
            const auto& inp_iov = m_input_iovs[m_cur_index];
            iovec this_iov;
            this_iov.iov_base = static_cast< uint8_t* >(inp_iov.iov_base) + m_cur_offset;
            if (remain_size < inp_iov.iov_len - m_cur_offset) {
                this_iov.iov_len = remain_size;
                m_cur_offset += remain_size;
            } else {
                this_iov.iov_len = inp_iov.iov_len - m_cur_offset;
                ++m_cur_index;
                m_cur_offset = 0;
            }

            ret_iovs.push_back(this_iov);
            remain_size -= iov.iov_len
        }
        return ret_iovs;
    }

    const std::vector< iovec >& m_input_iovs;
    uint64_t m_cur_offset{0};
    size_t m_cur_index{0};
};

void BlkDataService::async_write(const sg_list& sgs, const blk_alloc_hints& hints, std::vector< BlkId >& out_blkids,
                                 const io_completion_cb_t& cb) {
    out_blkids.clear();
    const auto status = alloc_blks(sgs.size, hints, out_blkids);
    if (status != BlkAllocStatus::success) {
        cb(-ENOMEM, nullptr);
        return;
    }

    if (out_blkids.size() == 1) {
        // Shortcut to most common case
        m_vdev.write(bid, sgs.iovs.data(), sgs.iovs.size(), req);
    } else {
        sg_iterator sg_it{sgs.iovs};
        for (const auto& bid : out_blkids) {
            const auto iovs = sg_it.next_iovs(bid.get_nblks() * m_page_size);
            m_vdev.write(bid, iovs.data(), iovs.size(), req);
        }
    }
}

BlkAllocStatus BlkDataService::alloc_blks(uint32_t size, blk_alloc_hints& hints, std::vector< BlkId >& out_blkids) {
    HS_DBG_ASSERT_EQ(size % m_page_size, 0, "Non aligned size requested");
    blk_count_t nblks = static_cast< blk_count_t >(size / m_pagesz);

    if (nblks <= BlkId::max_blks_in_op()) {
        return (m_vdev.alloc_blk(nblks, hints, out_blkid));
    } else {
        while (nblks != 0) {
            static thread_local std::vector< BlkId > result_blkid{};
            result_blkid.clear();

            const blk_count_t nblks_op = std::min(static_cast< blk_count_t >(BlkId::max_blks_in_op()), nblks);
            const auto ret = m_vdev.alloc_blk(nblks_op, hints, result_blkid);
            if (ret != BlkAllocStatus::SUCCESS) { return ret; }

            out_blkid.insert(std::end(out_blkid), std::make_move_iterator(std::begin(result_blkid)),
                             std::make_move_iterator(std::end(result_blkid)));
            nblks -= nblks_op;
        }
        return BlkAllocStatus::SUCCESS;
    }
}
} // namespace homestore