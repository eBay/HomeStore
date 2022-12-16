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
#ifndef HOMESTORE_FILE_STORE_SPEC_HPP
#define HOMESTORE_FILE_STORE_SPEC_HPP

#include <array>
#include <cassert>
#include <cstdint>
#include <functional>

#ifdef __linux__
#include <fcntl.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "homeds/loadgen/spec/store_spec.hpp"
#include "homeds/tests/loadgen_tests/keyspecs/map_key_spec.hpp"
#include "homeds/tests/loadgen_tests/valuespecs/blk_value_spec.hpp"

using namespace homeds::btree;

namespace homeds {
namespace loadgen {

class FileStoreSpec : public StoreSpec< MapKey, BlkValue > {
public:
    static constexpr uint64_t MAX_SEGMENT_BLKS{64};
    static constexpr uint64_t MAX_SEGMENT_SIZE{MAX_SEGMENT_BLKS * BlkValue::BLK_SIZE};

private:
    typedef std::function< void(generator_op_error, const key_info< MapKey, BlkValue >*, void*, const std::string&) >
        store_error_cb_t;
    std::vector< int > m_fd_list;
    std::vector< ssize_t > device_size;
    ssize_t m_total_size{0};
    uint32_t m_max_seg{0};

public:
    FileStoreSpec() = default;
    FileStoreSpec(const FileStoreSpec&) = delete;
    FileStoreSpec& operator=(const FileStoreSpec&) = delete;
    FileStoreSpec(FileStoreSpec&&) noexcept = delete;
    FileStoreSpec& operator=(FileStoreSpec&&) noexcept = delete;
    virtual ~FileStoreSpec() override = default;

    virtual bool insert(MapKey& k, std::shared_ptr< BlkValue > v) override { return update(k, v); }

    virtual bool upsert(MapKey& k, std::shared_ptr< BlkValue > v) override { return update(k, v); }

    virtual void init_store(const homeds::loadgen::Param& parameters) override {
        for (size_t i{0}; i < parameters.file_names.size(); ++i) {
            const auto fd{::open(parameters.file_names[i].c_str(), O_RDWR | O_DIRECT)};
            m_fd_list.push_back(fd);
            struct stat buf;
            uint64_t devsize{0};
            if (::fstat(fd, &buf) >= 0) {
                devsize = buf.st_size;
            } else {
                ::ioctl(fd, BLKGETSIZE64, &devsize);
            }
            assert(devsize > 0);
            devsize = devsize - (devsize % MAX_SEGMENT_SIZE);
            device_size.push_back(devsize);
            if (i > 0) { assert(device_size[i - 1] == device_size[i]); }
            m_total_size += devsize;
        }
        m_max_seg = m_total_size / MAX_SEGMENT_SIZE;
    }

    /*Map put always appends if exists, no feature to force udpate/insert and return error*/
    virtual bool update(MapKey& k, std::shared_ptr< BlkValue > v) override {
        std::vector< std::shared_ptr< BlkValue > > result(0);
        result.push_back(v);
        auto end_key{MapKey::gen_key(KeyPattern::SEQUENTIAL, &k)};
        return (range_update(k, true, end_key, false, result));
    }

    virtual bool get(const MapKey& k, BlkValue* const out_v) const override {
        std::vector< std::pair< MapKey, BlkValue > > result;
        const auto end_key{MapKey::gen_key(KeyPattern::SEQUENTIAL, &k)};
        if (query(k, true, end_key, false, result)) {
            *out_v = std::move(result.back().second);
            return true;
        }
        return false;
    }

    virtual bool remove(const MapKey& k, BlkValue* const removed_v = nullptr) override {
        assert(false);
        return false; // map does not have remove impl
    }

    virtual bool remove_any(const MapKey& start_key, const bool start_incl, const MapKey& end_key, const bool end_incl,
                            MapKey* const out_key, BlkValue* const out_val) override {
        assert(false);
        return false; // map does not have remove impl
    }

    virtual uint32_t query(const MapKey& start_key, const bool start_incl, const MapKey& end_key, const bool end_incl,
                           std::vector< std::pair< MapKey, BlkValue > >& result) const override {
        auto start_offset{start_key.start()};
        const auto end_offset{end_key.start()};
        uint64_t num_blks{0};
        if (end_incl) {
            num_blks = end_offset - start_offset + 1;
        } else {
            num_blks = end_offset - start_offset;
        }

        const size_t size{num_blks * BlkValue::BLK_SIZE};
        void* const buf{iomanager.iobuf_alloc(512, size)};

        std::vector< int > fd_list;
        std::vector< uint64_t > offset;
        std::vector< uint64_t > size_blks;
        get_fd_and_offset(start_offset, num_blks, fd_list, offset, size_blks);

        for (size_t fd{0}; fd < fd_list.size(); ++fd) {
            const uint64_t temp_size{size_blks[fd] * BlkValue::BLK_SIZE};
            const uint64_t temp_offset{offset[fd] * BlkValue::BLK_SIZE};
            const auto ret{::pread(fd_list[fd], buf, temp_size, temp_offset)};
            if (ret != static_cast< ssize_t >(temp_size)) {
                LOGINFO("read failed error no {}", errno);
                iomanager.iobuf_free(static_cast< uint8_t* >(buf));
                return false;
            }
            for (uint64_t i{0}; i < size_blks[fd]; ++i) {
                BlkValue v{util::Hash64(reinterpret_cast< const char* >(reinterpret_cast< const uint64_t* >(buf) +
                                                                        (i * BlkValue::BLK_SIZE)),
                                        BlkValue::BLK_SIZE)};
                result.push_back(std::make_pair(
                    MapKey{start_offset, 1},
                    BlkValue{util::Hash64(reinterpret_cast< const char* >(reinterpret_cast< const uint64_t* >(buf) +
                                                                          (i * BlkValue::BLK_SIZE)),
                                          BlkValue::BLK_SIZE)}));
                ++start_offset;
            }
        }
        iomanager.iobuf_free(static_cast< uint8_t* >(buf));
        return true;
    }

    virtual bool range_update(MapKey& start_key, const bool start_incl, MapKey& end_key, const bool end_incl,
                              std::vector< std::shared_ptr< BlkValue > >& result) override {
        static int cnt{0};
        const auto start_offset{start_key.start()};
        const auto end_offset{end_key.start()};
        auto num_blks{end_offset - start_offset + 1};
        if (!end_incl) { --num_blks; }
        std::vector< int > fd_list;
        std::vector< uint64_t > offset;
        std::vector< uint64_t > size;
        get_fd_and_offset(start_offset, num_blks, fd_list, offset, size);
        std::array< iovec, MAX_SEGMENT_BLKS > iov;

        assert(num_blks == result.size());
        if (num_blks > 1) { LOGINFO("numblks {}", num_blks); }

        int start_blks{0};
        for (size_t fd{0}; fd < fd_list.size(); ++fd) {
            for (uint64_t i{0}; i < size[fd]; ++i) {
                iov[i].iov_base = result[start_blks]->get();
                iov[i].iov_len = BlkValue::BLK_SIZE;
                ++start_blks;
            }
            const uint64_t temp_size{size[fd] * BlkValue::BLK_SIZE};
            const uint64_t temp_offset{offset[fd] * BlkValue::BLK_SIZE};
            const auto ret{::pwritev(fd_list[fd], iov.data(), size[fd], temp_offset)};
            if (ret != static_cast< ssize_t >(size[fd] * BlkValue::BLK_SIZE)) {
                LOGINFO("write fail error no {}", errno);
                return false;
            }
        }
        return true;
    }

    void get_fd_and_offset(const uint64_t offset_in, const uint32_t nblks_in, std::vector< int >& fd_list,
                           std::vector< uint64_t >& fd_offset, std::vector< uint64_t >& size) const {
        uint64_t offset{offset_in};
        uint32_t nblks{nblks_in};
        while (nblks != 0) {
            const size_t seg_num{offset / MAX_SEGMENT_BLKS};
            assert(seg_num <= m_max_seg);
            const uint64_t seg_offset{offset - (seg_num * MAX_SEGMENT_BLKS)};
            uint64_t io_size{MAX_SEGMENT_BLKS - seg_offset};

            if (nblks > io_size) {
                nblks = nblks - io_size;
                offset = offset + io_size;
            } else {
                io_size = nblks;
                nblks = 0;
            }

            fd_list.push_back(m_fd_list[seg_num % m_fd_list.size()]);
            fd_offset.push_back(((seg_num / m_fd_list.size()) * MAX_SEGMENT_BLKS) + seg_offset);
            size.push_back(io_size);
        }
    }

private:
};

} // namespace loadgen
} // namespace homeds

#endif // HOMESTORE_MAP_STORE_SPEC_HPP
