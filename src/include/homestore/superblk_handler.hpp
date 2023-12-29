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
#include <atomic>
#include <string>

#include <nlohmann/json.hpp>
#include <sisl/fds/buffer.hpp>
#include <homestore/meta_service.hpp>

namespace homestore {

template < typename T >
class superblk {
public:
    static uint64_t next_count() {
        static std::atomic< uint64_t > s_count{0};
        return ++s_count;
    }

    superblk(const std::string& meta_name = "") { set_name(meta_name); }

    superblk(const superblk&) = delete;
    superblk& operator=(const superblk&) = delete;

    superblk(superblk&& rhs) noexcept
         : m_meta_mgr_cookie(rhs.m_meta_mgr_cookie)
           , m_raw_buf(std::move(rhs.m_raw_buf))
           , m_sb(rhs.m_sb)
           , m_metablk_name(std::move(rhs.m_metablk_name)) {
	rhs.m_meta_mgr_cookie = nullptr;
	rhs.m_sb = nullptr;
    }

    superblk& operator=(superblk&& rhs) noexcept {
        if (this != &rhs) {
            m_meta_mgr_cookie = rhs.m_meta_mgr_cookie;
            m_raw_buf = std::move(rhs.m_raw_buf);
            m_sb = rhs.m_sb;
            m_metablk_name = std::move(rhs.m_metablk_name);
            rhs.m_meta_mgr_cookie = nullptr;
            rhs.m_sb = nullptr;
	}
	return *this;
    }

    void set_name(const std::string& meta_name) {
        if (meta_name.empty()) {
            m_metablk_name = "meta_blk_" + std::to_string(next_count());
        } else {
            m_metablk_name = meta_name;
        }
    }

    T* load(const sisl::byte_view& buf, void* meta_cookie) {
        m_meta_mgr_cookie = voidptr_cast(meta_cookie);
        m_raw_buf = meta_service().is_aligned_buf_needed(buf.size()) ? buf.extract(meta_service().align_size())
                                                                     : buf.extract(0);
        m_sb = r_cast< T* >(m_raw_buf->bytes());
        return m_sb;
    }

    T* create(uint32_t size = sizeof(T)) {
        if (meta_service().is_aligned_buf_needed(size)) {
            auto al_sz = meta_service().align_size();
            m_raw_buf = sisl::make_byte_array(uint32_cast(sisl::round_up(size, al_sz)), al_sz, sisl::buftag::metablk);
        } else {
            m_raw_buf = sisl::make_byte_array(uint32_cast(size), 0, sisl::buftag::metablk);
        }
        m_sb = new (m_raw_buf->bytes()) T();
        return m_sb;
    }

    void destroy() {
        if (m_meta_mgr_cookie) {
            meta_service().remove_sub_sb(m_meta_mgr_cookie);
            m_meta_mgr_cookie = nullptr;
        }
        m_raw_buf.reset();
        m_sb = nullptr;
    }

    uint32_t size() const { return m_raw_buf->size(); }
    sisl::byte_array raw_buf() { return m_raw_buf; }

    void write() {
        if (m_meta_mgr_cookie) {
            meta_service().update_sub_sb(m_raw_buf->cbytes(), m_raw_buf->size(), m_meta_mgr_cookie);
        } else {
            meta_service().add_sub_sb(m_metablk_name, m_raw_buf->cbytes(), m_raw_buf->size(), m_meta_mgr_cookie);
        }
    }

    bool is_empty() const { return (m_sb == nullptr); }
    T* get() { return m_sb; }
    T* operator->() { return m_sb; }
    const T* operator->() const { return m_sb; }
    T& operator*() { return *m_sb; }

private:
    void* m_meta_mgr_cookie{nullptr};
    sisl::byte_array m_raw_buf;
    T* m_sb{nullptr};
    std::string m_metablk_name;
};

class json_superblk {
private:
    void* m_meta_mgr_cookie{nullptr};
    nlohmann::json m_json_sb;
    std::string m_metablk_name;

public:
    static uint64_t next_count() {
        static std::atomic< uint64_t > s_count{0};
        return ++s_count;
    }

    json_superblk(const std::string& meta_name = "") { set_name(meta_name); }

    void set_name(const std::string& meta_name) {
        if (meta_name.empty()) {
            m_metablk_name = "meta_blk_" + std::to_string(next_count());
        } else {
            m_metablk_name = meta_name;
        }
    }

    nlohmann::json& load(const sisl::byte_view& buf, void* meta_cookie) {
        m_meta_mgr_cookie = voidptr_cast(meta_cookie);
        std::string_view const b{c_charptr_cast(buf.bytes()), buf.size()};

        try {
            m_json_sb = nlohmann::json::from_msgpack(b);
        } catch (nlohmann::json::exception const& e) {
            DEBUG_ASSERT(false, "Failed to load superblk for meta_blk={}", m_metablk_name);
            return m_json_sb;
        }
        return m_json_sb;
    }

    nlohmann::json& create() { return m_json_sb; }

    void destroy() {
        if (m_meta_mgr_cookie) {
            meta_service().remove_sub_sb(m_meta_mgr_cookie);
            m_meta_mgr_cookie = nullptr;
        }
        m_json_sb = nlohmann::json{};
    }

    uint32_t size() const { return m_json_sb.size(); }

    void write() {
        auto do_write = [this](sisl::blob const& b) {
            if (m_meta_mgr_cookie) {
                meta_service().update_sub_sb(b.cbytes(), b.size(), m_meta_mgr_cookie);
            } else {
                meta_service().add_sub_sb(m_metablk_name, b.cbytes(), b.size(), m_meta_mgr_cookie);
            }
        };

        auto const packed_data = nlohmann::json::to_msgpack(m_json_sb);
        auto const size = packed_data.size();
        if (meta_service().is_aligned_buf_needed(size)) {
            sisl::io_blob_safe buffer(size, meta_service().align_size());
            std::memcpy(buffer.bytes(), packed_data.data(), size);
            do_write(buffer);
        } else {
            do_write(sisl::blob{r_cast< uint8_t const* >(packed_data.data()), uint32_cast(size)});
        }
    }

    nlohmann::json& operator*() { return m_json_sb; }
};

} // namespace homestore
