#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <dirent.h>
#include <vector>

namespace homeds {
namespace loadgen {

std::string vol_crc_dir = vol_loadgen_dir + "crc/";
std::string vol_crc_file_prefix = vol_crc_dir + "vol_crc_";

// crc persistence
//
template < typename crc_t >
class VolVerifyMgr {
    struct VolCRCMMap {
        int m_fd;
        uint64_t m_vol_id;
        char* m_map_handle;
        uint64_t m_nblks;
        std::mutex m_mtx;

    public:
        VolCRCMMap(uint64_t vol_id, uint64_t nblks) : m_vol_id(vol_id), m_nblks(nblks) {
            auto fd = create_crc_file(vol_id, get_file_size());
            assert(fd != -1);

            auto map = (char*)mmap(0, get_file_size(), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
            if (map == MAP_FAILED) {
                close(fd);
                LOGERROR("Error mmapping the file");
                assert(0);
            }
            m_fd = fd;
            m_map_handle = map;
        }

        ~VolCRCMMap() {
            if (munmap(m_map_handle, get_file_size()) == -1) {
                LOGERROR("Error un-mmapping the file");
                assert(0);
            }
            // Un-mmaping doesn't close the file, so we still need to do that.
            close(m_fd);

            // remove crc file
            remove(get_file_name().c_str());
        }

    private:
        uint64_t get_file_size() { return m_nblks * sizeof(crc_t); }

        std::string get_file_name() {
            std::string f(vol_crc_file_prefix + std::to_string(m_vol_id));
            return f;
        }

        int create_crc_file(uint64_t vol_id, uint64_t file_size) {
            auto fd = open(get_file_name().c_str(), O_RDWR | O_CREAT | O_TRUNC, (mode_t)0600);

            if (fd == -1) {
                LOGERROR("Error opening file for writing");
                assert(0);
                return -1;
            }

            // Stretch the file size to the size of the (mmapped) array of ints
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

    }; // VolCRCMMap

public:
    VolVerifyMgr(uint64_t num_vols, uint64_t nblks) {
        // create a folder containing all the crc file;
        auto ret = mkdir(vol_crc_dir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
        if ((ret != 0) && (errno != EEXIST)) {
            LOGERROR("Create folder: {} failed.", vol_crc_dir);
            assert(0);
        }

        assert(num_vols > 0 && nblks > 0);
        for (size_t vol_id = 0; vol_id < num_vols; vol_id++) {
            m_vol_mmap.push_back(std::make_shared< VolCRCMMap >(vol_id, nblks));
        }
    }

    ~VolVerifyMgr() {
        m_vol_mmap.clear();

        // remove crc folder
        if (0 != rmdir(vol_crc_dir.c_str())) {
            LOGERROR("Deleting dir: {} failed, error no: {}, err msg: {}", vol_crc_dir, errno, std::strerror(errno));
            assert(0);
        }
    }

    void set_crc(uint64_t vol_id, uint64_t lba, uint64_t crc) {
        std::lock_guard< std::mutex > lk(m_vol_mmap[vol_id]->m_mtx);
        *((uint64_t*)(m_vol_mmap[vol_id]->m_map_handle) + lba) = crc;
    }

    uint64_t get_crc(uint64_t vol_id, uint64_t lba) {
        std::lock_guard< std::mutex > lk(m_vol_mmap[vol_id]->m_mtx);
        return *((uint64_t*)(m_vol_mmap[vol_id]->m_map_handle) + lba);
    }

private:
    //
    // create dirs with input with dir tree, such as /tmp/a/b/c
    //
    bool create_dir_tree(std::string dir_path) {
        bool create = false;
        size_t p = 0;
        while (1) {
            p = dir_path.find_first_of("/", p);
            if (p != std::string::npos) {
                auto s = dir_path.substr(0, ++p);
                if (create || !opendir(s.c_str())) {
                    // we don't need to test dir existence anymore;
                    create = true;
                    auto ret = mkdir(s.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
                    if (ret) {
                        LOGERROR("Creating dir: {} failed. ", s);
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
