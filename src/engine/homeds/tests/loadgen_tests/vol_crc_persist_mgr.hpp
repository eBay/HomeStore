/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 * Author/Developer(s): Yaming Kuang
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
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#ifdef __linux__
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include "write_log_recorder.hpp"

namespace homeds {
namespace loadgen {

const std::string vol_crc_dir{vol_loadgen_dir + "crc/"};
const std::string vol_crc_file_prefix{vol_crc_dir + "vol_crc_"};

// crc persistence
//
template < typename crc_t >
class VolVerifyMgr {
    struct VolCRCMMap {
        int m_fd;
        uint64_t m_vol_id;
        uint8_t* m_map_handle;
        uint64_t m_nblks;
        mutable std::mutex m_mtx;

    public:
        VolCRCMMap(const uint64_t vol_id, const uint64_t nblks) : m_vol_id{vol_id}, m_nblks{nblks} {
            const auto fd{create_crc_file(vol_id, get_file_size())};
            assert(fd != -1);

            const auto map{static_cast< uint8_t* >(
                ::mmap(0, static_cast< size_t >(get_file_size()), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0))};
            if (map == MAP_FAILED) {
                ::close(fd);
                LOGERROR("Error mmapping the file");
                assert(false);
            }
            m_fd = fd;
            m_map_handle = map;
        }

        VolCRCMMap(const VolCRCMMap&) = delete;
        VolCRCMMap& operator=(const VolCRCMMap&) = delete;
        VolCRCMMap(VolCRCMMap&&) noexcept = delete;
        VolCRCMMap& operator=(VolCRCMMap&&) noexcept = delete;

        ~VolCRCMMap() {
            if (::munmap(m_map_handle, static_cast< size_t >(get_file_size())) == -1) {
                LOGERROR("Error un-mmapping the file");
                assert(false);
            }
            // Un-mmaping doesn't close the file, so we still need to do that.
            ::close(m_fd);

            // remove crc file
            std::filesystem::remove(get_file_name());
        }

    private:
        uint64_t get_file_size() const { return m_nblks * sizeof(crc_t); }

        std::string get_file_name() const {
            std::string f{vol_crc_file_prefix + std::to_string(m_vol_id)};
            return f;
        }

        int create_crc_file(const uint64_t vol_id, const uint64_t file_size) {
            const auto fd{open(get_file_name().c_str(), O_RDWR | O_CREAT | O_TRUNC, static_cast< mode_t >(0600))};

            if (fd == -1) {
                LOGERROR("Error opening file for writing");
                assert(false);
                return -1;
            }

            std::fstream fs{get_file_name(), std::ios::binary};
            std::error_code ec;
            std::filesystem::resize_file(get_file_name(), static_cast< uintmax_t >(file_size),
                                         ec); // set the file size
            if (ec) {
                ::close(fd);
                LOGERROR("Failed to resize file");
                assert(false);
                return -1;
            }

            return fd;
        }

    }; // VolCRCMMap

public:
    VolVerifyMgr(const uint64_t num_vols, const uint64_t nblks) {
        // create vol log folder
        std::error_code ec;
        std::filesystem::create_directory(vol_crc_dir, ec);
        if (ec) {
            LOGERROR("Create folder: {} failed.", vol_crc_dir);
            assert(false);
        }
        std::filesystem::permissions(vol_crc_dir,
                                     std::filesystem::perms::owner_all | std::filesystem::perms::group_all |
                                         std::filesystem::perms::others_read | std::filesystem::perms::others_exec,
                                     ec);
        if (ec) {
            LOGERROR("Create folder: {} failed.", vol_crc_dir);
            assert(false);
        }

        assert((num_vols > 0) && (nblks > 0));
        for (size_t vol_id{0}; vol_id < num_vols; ++vol_id) {
            m_vol_mmap.push_back(std::make_shared< VolCRCMMap >(vol_id, nblks));
        }
    }

    VolVerifyMgr(const VolVerifyMgr&) = delete;
    VolVerifyMgr& operator=(const VolVerifyMgr&) = delete;
    VolVerifyMgr(VolVerifyMgr&&) noexcept = delete;
    VolVerifyMgr& operator=(VolVerifyMgr&&) noexcept = delete;

    ~VolVerifyMgr() {
        m_vol_mmap.clear();

        std::error_code ec;
        std::filesystem::remove_all(vol_crc_dir, ec);
        if (ec) {
            LOGERROR("Deleting dir: {} failed, error no: {}, err msg: {}", vol_crc_dir, errno, ec.message());
            assert(false);
        }
    }

    void set_crc(const uint64_t vol_id, const uint64_t lba, const uint64_t crc) {
        std::lock_guard< std::mutex > lk{m_vol_mmap[vol_id]->m_mtx};
        *(reinterpret_cast< uint64_t* >(m_vol_mmap[vol_id]->m_map_handle) + lba) = crc;
    }

    uint64_t get_crc(const uint64_t vol_id, const uint64_t lba) const {
        std::lock_guard< std::mutex > lk{m_vol_mmap[vol_id]->m_mtx};
        return *(reinterpret_cast< const uint64_t* >(m_vol_mmap[vol_id]->m_map_handle) + lba);
    }

private:
    //
    // create dirs with input with dir tree, such as /tmp/a/b/c
    //
    bool create_dir_tree(const std::string& dir_path) {
        bool create{false};
        size_t p{0};
        for (;;) {
            p = dir_path.find_first_of("/", p);
            if (p != std::string::npos) {
                auto s{dir_path.substr(0, ++p)};
                if (create || !std::filesystem::exists(s)) {
                    // we don't need to test dir existence anymore;
                    create = true;

                    std::error_code ec;
                    std::filesystem::create_directory(s, ec);
                    if (ec) {
                        LOGERROR("Create dir: {} failed.", s);
                        return false;
                    }
                    std::filesystem::permissions(s,
                                                 std::filesystem::perms::owner_all | std::filesystem::perms::group_all |
                                                     std::filesystem::perms::others_read |
                                                     std::filesystem::perms::others_exec,
                                                 ec);
                    if (ec) {
                        LOGERROR("Create dir permissions set: {} failed.", s);
                        return false;
                    }
                }

                // if dir exists, move on to check sub dir path
            } else {
                // nothing to be processed.
                break;
            }
        }
        return true;
    }

private:
    std::vector< std::shared_ptr< VolCRCMMap > > m_vol_mmap;
};
} // namespace loadgen
} // namespace homeds
