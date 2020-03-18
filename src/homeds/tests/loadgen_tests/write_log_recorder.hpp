#pragma once

namespace homeds {
namespace loadgen {

constexpr uint64_t LOG_FILE_SIZE = 1 * 1024 * 1024 * 1024ull;
std::string vol_loadgen_dir = "vol_load_gen/";
std::string vol_log_dir = vol_loadgen_dir + "log/";
std::string vol_log_prefix = vol_log_dir + "vol_log_";

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

        LogEntry(uint64_t start_lba, uint64_t nblks, std::vector< crc_t >& crc) :
                m_start_lba(start_lba),
                m_nblks(nblks) {
            for (auto& c : crc) {
                m_crc_entries.emplace_back(c);
            }
        }

        ~LogEntry() { m_crc_entries.clear(); }
    };

    //
    // TODO: Combine CRC persistent manager as one common persistence class;
    //
    struct VolLogTracker {
        int m_fd;                     // memory map fd;
        char* m_map_handle = nullptr; // handle for memory mapped region
        uint64_t m_cursor = 0;        // cursor to mapped region

        uint64_t m_vol_id;
        uint64_t m_write_id = 0;
        std::mutex m_mtx;
        // std::vector<std::shared_ptr<LogEntry>>      m_log_entries;

        VolLogTracker(uint64_t vol_id) : m_vol_id(vol_id) {
            // create map handle
            m_fd = create_file(get_file_size());
            assert(m_fd != -1);

            m_map_handle = (char*)mmap(0, get_file_size(), PROT_READ | PROT_WRITE, MAP_SHARED, m_fd, 0);
            if (m_map_handle == MAP_FAILED) {
                close(m_fd);
                LOGERROR("Error mmapping the file");
                assert(0);
            }
        }

        ~VolLogTracker() {
            // m_log_entries.clear();

            if (munmap(m_map_handle, get_file_size()) == -1) {
                LOGERROR("Error un-mmapping the file");
                assert(0);
            }

            // Un-mmaping doesn't close the file, so we still need to do that.
            close(m_fd);
            remove(get_file_name().c_str());
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
        void append(uint64_t lba, uint64_t nblks, std::vector< crc_t >& crc) {
            std::lock_guard< std::mutex > lk(m_mtx);
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
            m_write_id++;

            *(uint64_t*)(m_map_handle + m_cursor) = m_write_id;
            m_cursor += sizeof(uint64_t);

            *(uint64_t*)(m_map_handle + m_cursor) = lba;
            m_cursor += sizeof(uint64_t);

            *(uint64_t*)(m_map_handle + m_cursor) = nblks;
            m_cursor += sizeof(uint64_t);

            for (size_t i = 0; i < crc.size(); i++) {
                *(crc_t*)(m_map_handle + m_cursor) = crc[i];
                m_cursor += sizeof(crc_t);
            }
        }

        //
        // deserilize from mapped region
        //
        void dump_history(uint64_t lba) {
            std::lock_guard< std::mutex > lk(m_mtx);
            for (uint64_t cursor = 0; cursor < m_cursor;) {
                uint64_t write_id = *(uint64_t*)(m_map_handle + cursor);
                cursor += sizeof(uint64_t);

                uint64_t start_lba = *(uint64_t*)(m_map_handle + cursor);
                cursor += sizeof(uint64_t);

                uint64_t nblks = *(uint64_t*)(m_map_handle + cursor);
                cursor += sizeof(uint64_t);

                if (lba >= start_lba && lba <= start_lba + nblks) {
                    // got one matched lba, dump it;
                    LOGINFO("vol_id: {},  write_id: {}, lba: {}, crc: {}", m_vol_id, write_id, lba,
                            *(uint64_t*)(m_map_handle + cursor + (lba - start_lba) * sizeof(crc_t)));
                }

                // move cursor to next log;
                cursor += (sizeof(crc_t) * nblks);
            }
        }

    private:
        uint64_t get_file_size() { return LOG_FILE_SIZE; }

        std::string get_file_name() {
            std::string f(vol_log_prefix + std::to_string(m_vol_id));
            return f;
        }

        int create_file(uint64_t file_size) {
            auto fd = open(get_file_name().c_str(), O_RDWR | O_CREAT | O_TRUNC, (mode_t)0600);
            if (fd == -1) {
                LOGERROR("Error opening file for writing");
                assert(0);
                return -1;
            }

            auto result = lseek(fd, file_size - 1, SEEK_SET);
            if (result == -1) {
                close(fd);
                LOGERROR("Error calling lseek() to 'stretch' the file");
                assert(0);
                return -1;
            }

            result = write(fd, "", 1);
            if (result != 1) {
                close(fd);
                LOGERROR("Error writing last byte of the file");
                assert(0);
                return -1;
            }

            return fd;
        }
    };

public:
    WriteLogRecorder(uint64_t num_vols) {
        // create vol log folder
        auto ret = mkdir(vol_log_dir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
        if (ret != 0) {
            LOGERROR("Create folder: {} failed.", vol_log_dir);
            assert(0);
        }

        for (size_t vol_id = 0; vol_id < num_vols; vol_id++) {
            m_vols.push_back(std::make_shared< VolLogTracker >(vol_id));
        }
    }

    ~WriteLogRecorder() {
        m_vols.clear();

        // remove log dir;
        if (0 != rmdir(vol_log_dir.c_str())) {
            LOGERROR("Deleting dir: {} failed, error no: {}, err msg: {}", vol_log_dir, errno, std::strerror(errno));
            assert(0);
        }
    }

    void append(uint64_t vol_id, uint64_t lba, uint64_t nblks, std::vector< crc_t >& crc) {
        m_vols[vol_id]->append(lba, nblks, crc);
    }

    void dump_history(uint64_t vol_id, uint64_t lba) { m_vols[vol_id]->dump_history(lba); }

private:
    std::vector< std::shared_ptr< VolLogTracker > > m_vols;
};

} // namespace loadgen
} // namespace homeds
