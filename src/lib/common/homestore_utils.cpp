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
#include <boost/uuid/random_generator.hpp>
#include "homestore_utils.hpp"
#include "homestore_assert.hpp"

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

uuid_t hs_utils::gen_random_uuid() { return boost::uuids::random_generator()(); }

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

bool hs_utils::topological_sort(std::unordered_map< std::string, std::vector< std::string > >& DAG,
                                std::vector< std::string >& ordered_entries) {
    std::unordered_map< std::string, int > in_degree;
    std::queue< std::string > q;

    // Calculate in-degree of each vertex
    for (const auto& [vertex, edges] : DAG) {
        // we should make sure all the vertex in in_degree map;
        // if vertex is not in the map, 0 will be assigned.
        in_degree[vertex];
        for (const auto& edge : edges) {
            in_degree[edge]++;
        }
    }

    // Add vertices with in-degree 0 to the queue
    for (const auto& [vertex, degree] : in_degree) {
        if (degree == 0) q.push(vertex);
    }

    // Process vertices in the queue
    while (!q.empty()) {
        const auto vertex = q.front();
        q.pop();
        ordered_entries.push_back(vertex);

        for (const auto& edge : DAG[vertex]) {
            in_degree[edge]--;
            if (in_degree[edge] == 0) { q.push(edge); }
        }
    }

    // Check for cycle
    return ordered_entries.size() != DAG.size();
}

size_t hs_utils::m_btree_mempool_size;
} // namespace homestore
