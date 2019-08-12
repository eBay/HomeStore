#pragma once

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
#include <utility/obj_life_counter.hpp>
#include <atomic>
#include <boost/optional.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <sstream>
#include <string>
#include <iostream>

namespace homestore {
class Volume;
class BlkBuffer;
void intrusive_ptr_add_ref(BlkBuffer* buf);
void intrusive_ptr_release(BlkBuffer* buf);

class VolInterface;
struct init_params;
VolInterface* vol_homestore_init(const init_params& cfg);

struct cap_attrs {
    uint64_t used_data_size;
    uint64_t used_metadata_size;
    uint64_t used_total_size;
    uint64_t initial_total_size;
    std::string to_string() {
        std::stringstream ss;
        ss << "used_data_size = " << used_data_size << ", used_metadata_size = " << used_metadata_size 
            << ", used_total_size = " << used_total_size << ", initial_total_size = " << initial_total_size;
        return ss.str();
    }
};

struct buf_info {
    uint64_t                          size;
    int                               offset;
    boost::intrusive_ptr< BlkBuffer > buf;

    buf_info(uint64_t sz, int off, boost::intrusive_ptr< BlkBuffer >& bbuf) : size(sz), offset(off), buf(bbuf) {}
};

struct _counter_generator {
    static _counter_generator& instance() {
        static _counter_generator inst;
        return inst;
    }

    _counter_generator() : request_id_counter(0) {}
    uint64_t next_request_id() { return request_id_counter.fetch_add(1, std::memory_order_relaxed); }
    std::atomic< uint64_t > request_id_counter;
};
#define counter_generator _counter_generator::instance()

struct vol_interface_req : public sisl::ObjLifeCounter< vol_interface_req > {
    std::vector< buf_info >     read_buf_list;
    sisl::atomic_counter< int > outstanding_io_cnt;
    sisl::atomic_counter< int > refcount;
    Clock::time_point           io_start_time;
    std::error_condition        err;
    std::atomic< bool >         is_fail_completed;
    bool                        is_read;
    uint64_t                    request_id;

    friend void intrusive_ptr_add_ref(vol_interface_req* req) { req->refcount.increment(1); }

    friend void intrusive_ptr_release(vol_interface_req* req) {
        if (req->refcount.decrement_testz()) {
            delete(req);
        }
    }

    /* Set the error with error code,
     * Returns
     * true: if it is able to set the error
     * false: if request is already completed
     */
    bool set_error(const std::error_condition& ec) {
        bool expected_val = false;
        if (is_fail_completed.compare_exchange_strong(expected_val, true, std::memory_order_acq_rel)) {
            err = ec;
            return true;
        } else {
            return false;
        }
    }

    std::error_condition get_status() const { return err; }

    std::string to_string() {
        std::stringstream ss;
        ss << "vol_interface_req: request_id=" << request_id << " dir=" << (is_read ? "R" : "W")
           << " outstanding_io_cnt=" << outstanding_io_cnt.get();
        return ss.str();
    }

public:
    vol_interface_req() : outstanding_io_cnt(0), refcount(0), is_fail_completed(false)
    {}
    virtual ~vol_interface_req() = default;

    void init() {
        outstanding_io_cnt.set(0);
        is_fail_completed.store(false);
        request_id = counter_generator.next_request_id();
        err = no_error;
    }
};
typedef boost::intrusive_ptr< vol_interface_req > vol_interface_req_ptr;

enum vol_state {
    ONLINE = 0,
    FAILED = 1, // It moved to offline only when it find vdev in failed state during boot
    OFFLINE = 2, // Either AM can move it to offline or internally HS can move it offline if there are error on a disk
    DEGRADED = 3, // If a data of a volume in a failed state is deleted. We delete the data if we found any volume in a 
                  // failed state during boot.
    MOUNTING = 4,
    DESTROYING = 5,
    UNINITED = 6,
};

typedef std::function< void(const vol_interface_req_ptr& req) > io_comp_callback;
typedef std::function< void(bool success) > shutdown_comp_callback;

struct vol_params {
    uint64_t           page_size;
    uint64_t           size;
    boost::uuids::uuid uuid;
    io_comp_callback   io_comp_cb;
#define VOL_NAME_SIZE 100
    char vol_name[VOL_NAME_SIZE];

    std::string to_string() const {
        std::stringstream ss;
        ss  << "page_size=" << page_size << ",size=" << size
            << ",vol_name=" << vol_name  << ",uuid="
            << boost::lexical_cast<std::string>(uuid);
        return ss.str();
    }
};

struct out_params {
    uint64_t max_io_size; // currently it is 1 MB based on 4k minimum page size
};

typedef std::shared_ptr< Volume > VolumePtr;

/* This is the optional parameteres which should be given by its consumers only when there is no
 * system command to get these parameteres directly from disks. Or Consumer want to override
 * the default values.
 */
struct disk_attributes {
    uint32_t                physical_page_size;    // page size of ssds. It should be same for all the disks.
                                                   // It shouldn't be less then 8k
    uint32_t                disk_align_size;       // size alignment supported by disks. It should be
                                                   // same for all the disks.
    uint32_t                atomic_page_size;      // atomic page size of the disk
};

struct init_params {
public:
    typedef std::function< void(std::error_condition err, const out_params& params) > init_done_callback;
    typedef std::function< bool(boost::uuids::uuid uuid) >                            vol_found_callback;
    typedef std::function< void(const VolumePtr& vol, vol_state state) >              vol_mounted_callback;
    typedef std::function< void(const VolumePtr& vol, vol_state old_state, vol_state new_state) >
        vol_state_change_callback;

    /* system parameters */
    uint32_t                min_virtual_page_size; // minimum page size supported. Ideally it should be 4k.
    uint64_t                cache_size;            // memory available for cache. We should give 80 % of the whole
    bool                    disk_init;             // true if disk has to be initialized.
    std::vector< dev_info > devices;               // name of the devices.
    bool                    is_file;
    std::shared_ptr< iomgr::ioMgr > iomgr;
    boost::uuids::uuid      system_uuid;
    io_flag                 flag = io_flag::DIRECT_IO;

    /* optional parameters */
    boost::optional< disk_attributes > disk_attr;
    boost::optional< bool > is_read_only;

    /* completions callback */
    init_done_callback        init_done_cb;
    vol_found_callback        vol_found_cb;
    vol_mounted_callback      vol_mounted_cb;
    vol_state_change_callback vol_state_change_cb;

public:
    std::string to_string() {
        std::stringstream ss;
        ss << "min_virtual_page_size=" << min_virtual_page_size << ",cache_size=" << cache_size <<",disk_init=" << disk_init 
            << ",is_file=" << is_file << ",flag =" << flag 
            << ",number of devices =" << devices.size();
        ss << "device names = ";
        for (uint32_t i = 0; i < devices.size(); ++i) {
            ss << devices[i].dev_names;
            ss << ", ";
        }
        return ss.str();
    }
    init_params() = default;
};

class VolInterface {
    static VolInterface* _instance;

public:
    virtual ~VolInterface() {}
    static bool init(const init_params& cfg) {
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
    static void del_instance() { delete _instance;}

    virtual std::error_condition write(const VolumePtr& vol, uint64_t lba, uint8_t* buf, uint32_t nblks,
                                       const vol_interface_req_ptr& req) = 0;
    virtual std::error_condition read(const VolumePtr& vol, uint64_t lba, int nblks,
                                      const vol_interface_req_ptr& req) = 0;
    virtual std::error_condition sync_read(const VolumePtr& vol, uint64_t lba, int nblks,
                                           const vol_interface_req_ptr& req) = 0;
    virtual const char*          get_name(const VolumePtr& vol) = 0;
    virtual uint64_t             get_page_size(const VolumePtr& vol) = 0;
    virtual boost::uuids::uuid   get_uuid(std::shared_ptr<Volume> vol) = 0;
    virtual homeds::blob         at_offset(const boost::intrusive_ptr< BlkBuffer >& buf, uint32_t offset) = 0;
    virtual VolumePtr            create_volume(const vol_params& params) = 0;
    virtual std::error_condition remove_volume(const boost::uuids::uuid& uuid) = 0;
    virtual VolumePtr            lookup_volume(const boost::uuids::uuid& uuid) = 0;

    /* AM should call it in case of recovery or reboot when homestore try to mount the existing volume */
    virtual void attach_vol_completion_cb(const VolumePtr& vol, io_comp_callback cb) = 0;

    virtual std::error_condition shutdown(shutdown_comp_callback shutdown_comp_cb, bool force = false) = 0;
    virtual cap_attrs get_system_capacity() = 0;
    virtual cap_attrs get_vol_capacity(const VolumePtr& vol) = 0;
    virtual bool vol_state_change(const VolumePtr& vol, vol_state new_state) = 0;

    virtual void print_tree(const VolumePtr& vol, bool chksum = true) = 0;
    virtual void print_node(const VolumePtr& vol, uint64_t id,
            uint8_t nblks, uint16_t chunk_num, bool chksum = true) = 0;
#ifndef NDEBUG
    virtual void verify_pending_blks(const VolumePtr& vol) = 0;
#endif
};
} // namespace homestore
