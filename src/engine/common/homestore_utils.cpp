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
#include <isa-l/crc.h>

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

constexpr unsigned long long operator"" _KB(unsigned long long x) { return x * 1024; }

constexpr std::array< size_t, 7 > predefined_sizes = {4_KB, 8_KB, 16_KB, 32_KB, 64_KB, 128_KB, 256_KB};

// Function to initialize the CRC map with predefined sizes
void initialize_crc_map(std::map< size_t, uint16_t >& crc_map) {
    std::vector< uint8_t > zero_buf;
    for (auto s : predefined_sizes) {
        zero_buf.resize(s, 0); // Resize buffer to the required size, filling with zeros
        crc_map[s] = crc16_t10dif(init_crc_16, zero_buf.data(), s);
    }
}

uint16_t hs_utils::crc_zero(const size_t size) {
    static std::map< size_t, uint16_t > crc_map;
    static std::once_flag init_flag;

    // Thread-safe initialization of the CRC map
    std::call_once(init_flag, initialize_crc_map, std::ref(crc_map));

    // Check if the size is already in the map
    if (auto it = crc_map.find(size); it != crc_map.end()) { return it->second; }

    std::vector< uint8_t > zero_buf(size, 0);
    return crc16_t10dif(init_crc_16, zero_buf.data(), size);
}

bool hs_utils::is_buf_zero(const uint8_t* buf, size_t size) {
    // TODO: subsample the buffer to detect zero request instead of working on the whole buffer to achieve constant
    //  processing time for large buffer size requests. Needs to investigate the performance impact of this change
    //  in end2end testing.
    auto zero_crc = crc_zero(size);
    const auto crc = crc16_t10dif(init_crc_16, buf, size);
    return (crc == zero_crc) ? (buf[0] == 0 && !std::memcmp(buf, buf + 1, size - 1)) : false;
}

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

std::string hs_utils::encodeBase64(const sisl::byte_view& b) { return encodeBase64(b.bytes(), b.size()); }

template < typename T >
void hs_utils::decodeBase64(const std::string& encoded_data, T out) {
    using BinaryFromBase64 = boost::archive::iterators::transform_width<
        boost::archive::iterators::binary_from_base64< std::string::const_iterator >,
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

std::string hs_utils::decodeBase64(const std::string& encoded_data) {
    std::string rv;
    decodeBase64(encoded_data, std::back_inserter(rv));
    return rv;
}

size_t hs_utils::m_btree_mempool_size;
} // namespace homestore
