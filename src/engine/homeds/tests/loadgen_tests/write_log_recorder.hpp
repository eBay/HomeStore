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

#include <cassert>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <string>
#include <system_error>
#include <vector>

#ifdef __linux__
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace homeds {
namespace loadgen {

constexpr uint64_t LOG_FILE_SIZE{static_cast< uint64_t >(1) * 1024 * 1024 * 1024};
const std::string vol_loadgen_dir{"vol_load_gen/"};
const std::string vol_log_dir{vol_loadgen_dir + "log/"};
const std::string vol_log_prefix{vol_log_dir + "vol_log_"};

//
// Step-1: memory-only
// Step-2: persist to disk
//
template < typename crc_t >
class WriteLogRecorder {
    //
    // in-memory log data structure
    //
    struct LogEntry {
        uint64_t m_start_lba;
        uint64_t m_nblks;
        std::vector< crc_t > m_crc_entries;

        LogEntry(const uint64_t start_lba, const uint64_t nblks, std::vector< crc_t >& crc) :
                m_start_lba{start_lba}, m_nblks{nblks} {
            for (auto& c : crc) {
                m_crc_entries.emplace_back(c);
            }
        }
        LogEntry(const LogEntry&) = delete;
        LogEntry& operator=(const LogEntry&) = delete;
        LogEntry(LogEntry&&) noexcept = delete;
        LogEntry& operator=(LogEntry&&) noexcept = delete;

        ~LogEntry() { m_crc_entries.clear(); }
    };

    //
    // TODO: Combine CRC persistent manager as one common persistence class;
    //
    struct VolLogTracker {
        int m_fd;                       // memory map fd;
        uint8_t* m_map_handle{nullptr}; // handle for memory mapped region
        uint64_t m_cursor{0};           // cursor to mapped region

        uint64_t m_vol_id;
        uint64_t m_write_id{0};
        mutable std::mutex m_mtx;
        // std::vector<std::shared_ptr<LogEntry>>      m_log_entries;

        VolLogTracker(const uint64_t vol_id) : m_vol_id{vol_id} {
            // create map handle
            m_fd = create_file(get_file_size());
            assert(m_fd != -1);

            m_map_handle = static_cast< uint8_t* >(
                ::mmap(0, static_cast< size_t >(get_file_size()), PROT_READ | PROT_WRITE, MAP_SHARED, m_fd, 0));
            if (m_map_handle == MAP_FAILED) {
                ::close(m_fd);
                LOGERROR("Error mmapping the file");
                assert(false);
            }
        }
        VolLogTracker(const VolLogTracker&) = delete;
        VolLogTracker& operator=(const VolLogTracker&) = delete;
        VolLogTracker(VolLogTracker&&) noexcept = delete;
        VolLogTracker& operator=(VolLogTracker&&) noexcept = delete;

        ~VolLogTracker() {
            // m_log_entries.clear();

            if (::munmap(m_map_handle, static_cast< size_t >(get_file_size())) == -1) {
                LOGERROR("Error un-mmapping the file");
                assert(false);
            }

            // Un-mmaping doesn't close the file, so we still need to do that.
            ::close(m_fd);
            std::filesystem::remove(get_file_name());
        }

        //
        // serilize write log to mapped region
        //
        // Mapped Memory Layout:
        // ------------------------------------------------------------------------------------------------------------
        // |write_id | lba | nblks | crc_1 | crc_2 | ... | crc_n | ... | write_id | lba | nblks | crc_1 | ... | crc_n |
        // ------------------------------------------------------------------------------------------------------------
        //                                 |
        //                              m_cursor
        //
        void append(const uint64_t lba, const uint64_t nblks, std::vector< crc_t >& crc) {
            std::lock_guard< std::mutex > lk{m_mtx};
            // m_log_entries.push_back(std::make_shared<LogEntry>(lba, nblks, crc));

            // reset cursor if this append would exeed the file size;
            if (m_cursor + 3 * sizeof(uint64_t) + nblks * sizeof(crc_t) > get_file_size()) {
                // TODO: instead of overwrite on same log file,
                //       create new file for mapping and
                //       move current file a write.log.1;
                LOGINFO("WARNING: Log cursor will exceed max mapped file size, resetting cursor to 0. Old log buffer "
                        "will be lost. ");
                m_cursor = 0;
            }

            // bump up write_id to this volume;
            ++m_write_id;

            *reinterpret_cast< uint64_t* >(m_map_handle + m_cursor) = m_write_id;
            m_cursor += sizeof(uint64_t);

            *reinterpret_cast< uint64_t* >(m_map_handle + m_cursor) = lba;
            m_cursor += sizeof(uint64_t);

            *reinterpret_cast< uint64_t* >(m_map_handle + m_cursor) = nblks;
            m_cursor += sizeof(uint64_t);

            for (size_t i{0}; i < crc.size(); ++i) {
                *reinterpret_cast< crc_t* >(m_map_handle + m_cursor) = crc[i];
                m_cursor += sizeof(crc_t);
            }
        }

        //
        // deserilize from mapped region
        //
        void dump_history(const uint64_t lba) const {
            std::lock_guard< std::mutex > lk{m_mtx};
            for (uint64_t cursor{0}; cursor < m_cursor;) {
                const uint64_t write_id{*reinterpret_cast< const uint64_t* >(m_map_handle + cursor)};
                cursor += sizeof(uint64_t);

                const uint64_t start_lba{*reinterpret_cast< const uint64_t* >(m_map_handle + cursor)};
                cursor += sizeof(uint64_t);

                const uint64_t nblks{*reinterpret_cast< const uint64_t* >(m_map_handle + cursor)};
                cursor += sizeof(uint64_t);

                if ((lba >= start_lba) && (lba <= start_lba + nblks)) {
                    // got one matched lba, dump it;
                    LOGINFO("vol_id: {},  write_id: {}, lba: {}, crc: {}", m_vol_id, write_id, lba,
                            *reinterpret_cast< const uint64_t* >(m_map_handle + cursor +
                                                                 (lba - start_lba) * sizeof(crc_t)));
                }

                // move cursor to next log;
                cursor += (sizeof(crc_t) * nblks);
            }
        }

    private:
        uint64_t get_file_size() const { return LOG_FILE_SIZE; }

        std::string get_file_name() const {
            std::string f{vol_log_prefix + std::to_string(m_vol_id)};
            return f;
        }

        int create_file(const uint64_t file_size) {
            const auto fd{::open(get_file_name().c_str(), O_RDWR | O_CREAT | O_TRUNC, (mode_t)0600)};
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
    };

public:
    WriteLogRecorder(const uint64_t num_vols) {
        // create vol log folder
        std::error_code ec;
        std::filesystem::create_directory(vol_log_dir, ec);
        if (ec) {
            LOGERROR("Create folder: {} failed.", vol_log_dir);
            assert(false);
        }
        std::filesystem::permissions(vol_log_dir,
                                     std::filesystem::perms::owner_all | std::filesystem::perms::group_all |
                                         std::filesystem::perms::others_read | std::filesystem::perms::others_exec,
                                     ec);
        if (ec) {
            LOGERROR("Create folder set permissions: {} failed.", vol_log_dir);
            assert(false);
        }

        for (size_t vol_id{0}; vol_id < num_vols; ++vol_id) {
            m_vols.push_back(std::make_shared< VolLogTracker >(vol_id));
        }
    }
    WriteLogRecorder(const WriteLogRecorder&) = delete;
    WriteLogRecorder& operator=(const WriteLogRecorder&) = delete;
    WriteLogRecorder(WriteLogRecorder&&) noexcept = delete;
    WriteLogRecorder& operator=(WriteLogRecorder&&) noexcept = delete;

    ~WriteLogRecorder() {
        m_vols.clear();

        std::error_code ec;
        std::filesystem::remove_all(vol_log_dir, ec);
        if (ec) {
            LOGERROR("Deleting dir: {} failed, error no: {}, err msg: {}", vol_log_dir, errno, ec.message());
            assert(false);
        }
    }

    void append(const uint64_t vol_id, const uint64_t lba, const uint64_t nblks, std::vector< crc_t >& crc) {
        m_vols[vol_id]->append(lba, nblks, crc);
    }

    void dump_history(const uint64_t vol_id, const uint64_t lba) const { m_vols[vol_id]->dump_history(lba); }

private:
    std::vector< std::shared_ptr< VolLogTracker > > m_vols;
};

} // namespace loadgen
} // namespace homeds
