#ifndef HOMESTORE_VOL_CONFIG_HPP
#define HOMESTORE_VOL_CONFIG_HPP

/* NOTE: This file exports interface required to access homeblocks. we should try to avoid including any
 * homestore/homeblocks related hpp file.
 */
#include "homestore_header.hpp"
#include <functional>
#include <vector>
#include <memory>
#include <error/error.h>
#include <iomgr/iomgr.hpp>
#include <boost/intrusive_ptr.hpp>
#include <cassert>
#include <sds_logging/logging.h>
#include <mutex>
#include <utility/atomic_counter.hpp>
#include "homeds/utility/useful_defs.hpp"

namespace homestore {
class Volume;
class BlkBuffer;
void intrusive_ptr_add_ref(BlkBuffer* buf);
void intrusive_ptr_release(BlkBuffer* buf);

class VolInterface;
struct init_params;
VolInterface* vol_homestore_init(init_params& cfg);

struct buf_info {
    uint64_t                          size;
    int                               offset;
    boost::intrusive_ptr< BlkBuffer > buf;

    buf_info(uint64_t sz, int off, boost::intrusive_ptr< BlkBuffer >& bbuf) : size(sz), offset(off), buf(bbuf) {}
};

struct vol_interface_req {
    std::vector< buf_info >     read_buf_list;
    std::error_condition        err;
    sisl::atomic_counter< int > io_cnt;
    sisl::atomic_counter< int > refcount;
    Clock::time_point           io_start_time;

    friend void intrusive_ptr_add_ref(vol_interface_req* req) { req->refcount.increment(1); }

    friend void intrusive_ptr_release(vol_interface_req* req) {
        if (req->refcount.decrement_testz()) {
            delete (req);
        }
    }

    vol_interface_req() : err(no_error), io_cnt(0), refcount(0){};
    virtual ~vol_interface_req(){};
};

enum vol_state {
    ONLINE = 0,
    FAILED = 1,
    OFFLINE = 2,
    DEGRADED = 3,
    MOUNTING = 4,
    UNINITED = 5,
};

typedef std::function< void(boost::intrusive_ptr< vol_interface_req > req) > io_comp_callback;
struct vol_params {
    uint64_t           page_size;
    uint64_t           size;
    boost::uuids::uuid uuid;
    io_comp_callback   io_comp_cb;
#define VOL_NAME_SIZE 100
    char vol_name[VOL_NAME_SIZE];
};

struct out_params {
    uint64_t max_io_size; // currently it is 1 MB based on 4k minimum page size
};

struct init_params {
    typedef std::function< void(std::error_condition err, struct out_params params) > init_done_callback;
    typedef std::function< bool(boost::uuids::uuid uuid) >                            vol_found_callback;
    typedef std::function< void(std::shared_ptr< Volume > vol, vol_state state) >     vol_mounted_callback;
    typedef std::function< void(std::shared_ptr< Volume > vol, vol_state old_state, vol_state new_state) >
        vol_state_change_callback;

    uint32_t                min_virtual_page_size; // minimum page size supported. Ideally it should be 4k.
    uint64_t                cache_size;            // memory available for cache. We should give 80 % of the whole
    bool                    disk_init;             // true if disk has to be initialized.
    std::vector< dev_info > devices;               // name of the devices.
    bool                    is_file;
    uint64_t                max_cap;                  // max capacity of this system.
    uint32_t                physical_page_size;       /* page size of ssds. It should be same for all
                                                       * the disks. It shouldn't be less then 8k
                                                       */
    uint32_t disk_align_size;                         /* size alignment supported by disks. It should be
                                                       * same for all the disks.
                                                       */
    uint32_t                        atomic_page_size; /* atomic page size of the disk */
    std::shared_ptr< iomgr::ioMgr > iomgr;

    /* completions callback */
    init_done_callback        init_done_cb;
    vol_found_callback        vol_found_cb;
    vol_mounted_callback      vol_mounted_cb;
    vol_state_change_callback vol_state_change_cb;
    boost::uuids::uuid        system_uuid;
    io_flag                   flag;
    init_params() : flag(DIRECT_IO){};
};

class VolInterface {
    static VolInterface* _instance;

public:
    static bool init(init_params& cfg) {
        static std::once_flag flag1;
        try {
            std::call_once(flag1, [&cfg]() { _instance = vol_homestore_init(cfg); });
            return true;
        } catch (const std::exception& e) {
            LOGERROR("{}", e.what());
            assert(0);
            return false;
        }
    }

    static VolInterface* get_instance() { return _instance; }

    virtual std::error_condition      write(std::shared_ptr< Volume > vol, uint64_t lba, uint8_t* buf, uint32_t nblks,
                                            boost::intrusive_ptr< vol_interface_req > req) = 0;
    virtual std::error_condition      read(std::shared_ptr< Volume > vol, uint64_t lba, int nblks,
                                           boost::intrusive_ptr< vol_interface_req > req) = 0;
    virtual std::error_condition      sync_read(std::shared_ptr< Volume > vol, uint64_t lba, int nblks,
                                                boost::intrusive_ptr< vol_interface_req > req) = 0;
    virtual const char*               get_name(std::shared_ptr< Volume > vol) = 0;
    virtual uint64_t                  get_page_size(std::shared_ptr< Volume > vol) = 0;
    virtual uint64_t                  get_size(std::shared_ptr< Volume > vol) = 0;
    virtual homeds::blob              at_offset(boost::intrusive_ptr< BlkBuffer > buf, uint32_t offset) = 0;
    virtual std::shared_ptr< Volume > createVolume(const vol_params& params) = 0;
    virtual std::error_condition      removeVolume(boost::uuids::uuid const& uuid) = 0;
    virtual std::shared_ptr< Volume > lookupVolume(boost::uuids::uuid const& uuid) = 0;

    /* AM should call it in case of recovery or reboot when homestore try to mount the existing volume */
    virtual void attach_vol_completion_cb(std::shared_ptr< Volume > vol, io_comp_callback cb) = 0;

#ifndef NDEBUG
    virtual void print_tree(std::shared_ptr< Volume > vol) = 0;
#endif
    virtual void attach_vol_completion_cb(std::shared_ptr< Volume > vol, io_comp_callback cb) = 0;
};
} // namespace homestore

#endif
