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
#include "homestore_utils.hpp"
#include "homestore_assert.hpp"
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>

namespace homestore {
uint8_t* hs_utils::iobuf_alloc(const size_t size, const sisl::buftag tag, const size_t alignment) {
    if (tag == sisl::buftag::btree_node) {
        HS_DBG_ASSERT_EQ(size, m_btree_mempool_size);
        auto buf = iomanager.iobuf_pool_alloc(alignment, size, tag);
        HS_REL_ASSERT_NOTNULL(buf, "io buf is null. probably going out of memory");
        return buf;
    }
    auto buf = iomanager.iobuf_alloc(alignment, size, tag);
    HS_REL_ASSERT_NOTNULL(buf, "io buf is null. probably going out of memory");
    return buf;
}

hs_uuid_t hs_utils::gen_system_uuid() { return std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()); }

void hs_utils::iobuf_free(uint8_t* const ptr, const sisl::buftag tag) {
    if (tag == sisl::buftag::btree_node) {
        iomanager.iobuf_pool_free(ptr, m_btree_mempool_size, tag);
    } else {
        iomanager.iobuf_free(ptr, tag);
    }
}

void hs_utils::set_btree_mempool_size(const size_t size) { m_btree_mempool_size = size; }

uint64_t hs_utils::aligned_size(const size_t size, const size_t alignment) { return sisl::round_up(size, alignment); }

bool hs_utils::mod_aligned_sz(size_t size_to_check, size_t align_sz) {
    HS_DBG_ASSERT_EQ((align_sz & (align_sz - 1)), 0);
    return !(size_to_check & static_cast< size_t >(align_sz - 1)); // return true if it is aligned.
}

sisl::byte_view hs_utils::create_byte_view(const uint64_t size, const bool is_aligned_needed, const sisl::buftag tag,
                                           const size_t alignment) {
    return (is_aligned_needed) ? sisl::byte_view{static_cast< uint32_t >(aligned_size(size, alignment)),
                                                 static_cast< uint32_t >(alignment), tag}
                               : sisl::byte_view{static_cast< uint32_t >(size), 0, tag};
}

sisl::io_blob hs_utils::create_io_blob(const uint64_t size, const bool is_aligned_needed, const sisl::buftag tag,
                                       const size_t alignment) {
    return (is_aligned_needed) ? sisl::io_blob{size, static_cast< uint32_t >(alignment), tag}
                               : sisl::io_blob{size, 0, tag};
}

sisl::byte_array hs_utils::make_byte_array(const uint64_t size, const bool is_aligned_needed, const sisl::buftag tag,
                                           const size_t alignment) {
    return (is_aligned_needed)
        ? sisl::make_byte_array(static_cast< uint32_t >(aligned_size(size, alignment)), alignment, tag)
        : sisl::make_byte_array(static_cast< uint32_t >(size), 0, tag);
}

sisl::byte_array hs_utils::extract_byte_array(const sisl::byte_view& b, const bool is_aligned_needed,
                                              const size_t alignment) {
    return (is_aligned_needed) ? b.extract(alignment) : b.extract(0);
};

std::string hs_utils::encodeBase64(const uint8_t* first, std::size_t size) {
    using Base64FromBinary = boost::archive::iterators::base64_from_binary<
        boost::archive::iterators::transform_width< const char*, // sequence of chars
                                                    6,           // get view of 6 bit
                                                    8            // from sequence of 8 bit
                                                    > >;
    std::vector< unsigned char > bytes{first, first + size};
    std::size_t bytes_to_pad = (3 - size % 3) % 3;
    if (bytes_to_pad > 0) { bytes.resize(bytes.size() + bytes_to_pad, 0); }
    std::string encoded{Base64FromBinary{bytes.data()}, Base64FromBinary{bytes.data() + (bytes.size() - bytes_to_pad)}};

    return encoded.append(bytes_to_pad, '=');
}

std::string hs_utils::encodeBase64(const sisl::byte_view& b){
    return encodeBase64(b.bytes(), b.size());
}

template <typename T>
void hs_utils::decodeBase64(const std::string &encoded_data, T out)
{
    using BinaryFromBase64 = boost::archive::iterators::transform_width<
        boost::archive::iterators::binary_from_base64<std::string::const_iterator>,
        8, // get a view of 8 bit
        6  // from a sequence of 6 bit
        >;
    auto unpadded_data = encoded_data;
    const auto bytes_to_pad = std::count(begin(encoded_data), end(encoded_data), '=');
    std::replace(begin(unpadded_data), end(unpadded_data), '=', 'A'); // A_64 == \0

    std::string decoded_data{BinaryFromBase64{begin(unpadded_data)},
                        BinaryFromBase64{begin(unpadded_data) + unpadded_data.length()}};

    decoded_data.erase(end(decoded_data) - bytes_to_pad, end(decoded_data));
    std::copy(begin(decoded_data), end(decoded_data), out);
}

std::string hs_utils::decodeBase64(const std::string &encoded_data)
{
    std::string rv;
    decodeBase64(encoded_data, std::back_inserter(rv));
    return rv;
}

size_t hs_utils::m_btree_mempool_size;
} // namespace homestore
