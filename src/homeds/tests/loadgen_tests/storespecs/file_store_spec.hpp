// Modified by Amit Desai
//

#ifndef HOMESTORE_FILE_STORE_SPEC_HPP
#define HOMESTORE_FILE_STORE_SPEC_HPP

#include "homeds/loadgen/spec/store_spec.hpp"
#include "homeds/tests/loadgen_tests/keyspecs/map_key_spec.hpp"
#include "homeds/tests/loadgen_tests/valuespecs/blk_value_spec.hpp"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <linux/fs.h>
#include <sys/ioctl.h>

using namespace homeds::btree;
#define MAX_SEGMENT_BLKS 64
#define MAX_SEGMENT_SIZE (MAX_SEGMENT_BLKS * BLK_SIZE)

namespace homeds {
namespace loadgen {
#define INVALID_SEQ_ID UINT64_MAX

class FileStoreSpec : public StoreSpec< MapKey, BlkValue > {
    typedef std::function< void(generator_op_error, const key_info< MapKey, BlkValue >*, void*, const std::string&) >
        store_error_cb_t;
    std::vector< int > m_fd_list;
    std::vector< ssize_t > device_size;
    ssize_t m_total_size = 0;
    uint32_t m_max_seg = 0;

public:
    FileStoreSpec() {}

    virtual bool insert(MapKey& k, std::shared_ptr< BlkValue > v) override { return update(k, v); }

    virtual bool upsert(MapKey& k, std::shared_ptr< BlkValue > v) override { return update(k, v); }

    virtual void init_store(homeds::loadgen::Param& parameters) override {
        for (uint32_t i = 0; i < parameters.file_names.size(); ++i) {
            auto fd = open(parameters.file_names[i].c_str(), O_RDWR | O_DIRECT);
            m_fd_list.push_back(fd);
            struct stat buf;
            uint64_t devsize = 0;
            if (fstat(fd, &buf) >= 0) {
                devsize = buf.st_size;
            } else {
                ioctl(fd, BLKGETSIZE64, &devsize);
            }
            assert(devsize > 0);
            devsize = devsize - (devsize % MAX_SEGMENT_SIZE);
            device_size.push_back(devsize);
            if (i > 0) {
                assert(device_size[i - 1] == device_size[i]);
            }
            m_total_size += devsize;
        }
        m_max_seg = m_total_size / MAX_SEGMENT_SIZE;
    }

    /*Map put always appends if exists, no feature to force udpate/insert and return error*/
    virtual bool update(MapKey& k, std::shared_ptr< BlkValue > v) override {
        std::vector< std::shared_ptr< BlkValue > > result(0);
        result.push_back(v);
        auto end_key = (MapKey::gen_key(KeyPattern::SEQUENTIAL, &k));
        return (range_update(k, true, end_key, false, result));
    }

    virtual bool get(MapKey& k, BlkValue* out_v) override {
        std::vector< std::pair< MapKey, BlkValue > > result;
        auto end_key = (MapKey::gen_key(KeyPattern::SEQUENTIAL, &k));
        if (query(k, true, end_key, false, result)) {
            *out_v = std::move(result.back().second);
            return true;
        }
        return false;
    }

    virtual bool remove(MapKey& k, BlkValue* removed_v = nullptr) override {
        assert(0);
        return true; // map does not have remove impl
    }

    virtual bool remove_any(MapKey& start_key, bool start_incl, MapKey& end_key, bool end_incl, MapKey* out_key,
                            BlkValue* out_val) override {
        assert(0);
        return true; // map does not have remove impl
    }

    virtual uint32_t query(MapKey& start_key, bool start_incl, MapKey& end_key, bool end_incl,
                           std::vector< std::pair< MapKey, BlkValue > >& result) override {
        auto start_offset = start_key.start();
        auto end_offset = end_key.start();
        uint64_t num_blks = 0;
        if (end_incl) {
            num_blks = end_offset - start_offset + 1;
        } else {
            num_blks = end_offset - start_offset;
        }

        void* buf = nullptr;
        ssize_t size = num_blks * BLK_SIZE;
        auto ret = posix_memalign((void**)&buf, 4096, size);
        assert(ret == 0);

        std::vector< int > fd_list;
        std::vector< uint64_t > offset;
        std::vector< uint64_t > size_blks;
        get_fd_and_offset(start_offset, num_blks, fd_list, offset, size_blks);

        for (uint32_t fd = 0; fd < fd_list.size(); ++fd) {
            uint64_t temp_size = size_blks[fd] * BLK_SIZE;
            uint64_t temp_offset = offset[fd] * BLK_SIZE;
            ret = pread(fd_list[fd], buf, temp_size, temp_offset);
            if (ret != (int)temp_size) {
                LOGINFO("read failed error no {}", errno);
                free(buf);
                return false;
            }
            for (uint64_t i = 0; i < size_blks[fd]; ++i) {
                BlkValue v(util::Hash64((const char*)((uint64_t)buf + (i * BLK_SIZE)), BLK_SIZE));
                result.push_back(
                    std::make_pair(MapKey(start_offset, 1),
                                   BlkValue(util::Hash64((const char*)((uint64_t)buf + (i * BLK_SIZE)), BLK_SIZE))));
                ++start_offset;
            }
        }
        free(buf);
        return true;
    }

    virtual bool range_update(MapKey& start_key, bool start_incl, MapKey& end_key, bool end_incl,
                              std::vector< std::shared_ptr< BlkValue > >& result) {
        static int cnt = 0;
        auto start_offset = start_key.start();
        auto end_offset = end_key.start();
        auto num_blks = end_offset - start_offset + 1;
        if (!end_incl) {
            --num_blks;
        }
        std::vector< int > fd_list;
        std::vector< uint64_t > offset;
        std::vector< uint64_t > size;
        get_fd_and_offset(start_offset, num_blks, fd_list, offset, size);
        struct iovec iov[MAX_SEGMENT_BLKS];

        assert(num_blks == result.size());
        if (num_blks > 1) {
            LOGINFO("numblks {}", num_blks);
        }

        int start_blks = 0;
        for (uint32_t fd = 0; fd < fd_list.size(); ++fd) {
            for (uint32_t i = 0; i < size[fd]; ++i) {
                iov[i].iov_base = result[start_blks]->get();
                iov[i].iov_len = BLK_SIZE;
                ++start_blks;
            }
            uint64_t temp_size = size[fd] * BLK_SIZE;
            uint64_t temp_offset = offset[fd] * BLK_SIZE;
            auto ret = pwritev(fd_list[fd], iov, size[fd], temp_offset);
            if (ret != (int)(size[fd] * BLK_SIZE)) {
                LOGINFO("write fail error no {}", errno);
                return false;
            }
        }
        return true;
    }

    void get_fd_and_offset(uint64_t offset, uint32_t nblks, std::vector< int >& fd_list,
                           std::vector< uint64_t >& fd_offset, std::vector< uint64_t >& size) {
        while (nblks != 0) {
            uint32_t seg_num = offset / MAX_SEGMENT_BLKS;
            assert(seg_num <= m_max_seg);
            int seg_offset = offset - (seg_num * MAX_SEGMENT_BLKS);
            uint64_t io_size = MAX_SEGMENT_BLKS - seg_offset;

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
