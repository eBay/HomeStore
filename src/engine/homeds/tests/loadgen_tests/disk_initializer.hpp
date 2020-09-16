namespace homeds {
namespace loadgen {
using namespace std;
#define MAX_SIZE 7 * Gi
typedef std::function< void(std::error_condition err, const out_params& params) > init_done_callback;

template < typename Executor >
class DiskInitializer {
    std::vector< dev_info > device_info;
    boost::uuids::uuid uuid;

public:
    ~DiskInitializer() {
        auto success = VolInterface::get_instance()->shutdown();
        assert(success);
    }
    void cleanup() { remove("file_load_gen"); }
    void init(Executor& executor, init_done_callback init_done_cb, size_t atomic_phys_page_size = 2048) {
        start_homestore(init_done_cb, atomic_phys_page_size);
    }

    void start_homestore(init_done_callback init_done_cb, size_t atomic_phys_page_size) {
        /* start homestore */
        /* create files */

        dev_info temp_info;
        temp_info.dev_names = "file_load_gen";
        device_info.push_back(temp_info);
        std::ofstream ofs(temp_info.dev_names.c_str(), std::ios::binary | std::ios::out);
        ofs.seekp(MAX_SIZE - 1);
        ofs.write("", 1);

        //                iomgr_obj = std::make_shared<iomgr::ioMgr>(2, num_threads);
        init_params params;
#ifndef NDEBUG
        params.open_flags = homestore::io_flag::BUFFERED_IO;
#else
        params.open_flags = homestore::io_flag::DIRECT_IO;
#endif
        params.min_virtual_page_size = 4096;
        params.app_mem_size = 5 * 1024 * 1024 * 1024ul;
        params.disk_init = true;
        params.devices = device_info;
        params.init_done_cb = init_done_cb;
        params.drive_attr = iomgr::drive_attributes();
        params.drive_attr->phys_page_size = 4096;
        params.drive_attr->align_size = 512;
        params.drive_attr->atomic_phys_page_size = atomic_phys_page_size;
        params.vol_mounted_cb =
            std::bind(&DiskInitializer::vol_mounted_cb, this, std::placeholders::_1, std::placeholders::_2);
        params.vol_state_change_cb = std::bind(&DiskInitializer::vol_state_change_cb, this, std::placeholders::_1,
                                               std::placeholders::_2, std::placeholders::_3);
        params.vol_found_cb = std::bind(&DiskInitializer::vol_found_cb, this, std::placeholders::_1);
        boost::uuids::string_generator gen;
        params.system_uuid = gen("01970496-0262-11e9-8eb2-f2801f1b9fd1");
        uuid = params.system_uuid;
        VolInterface::init(params);
    }

    bool vol_found_cb(boost::uuids::uuid uuid) { return true; }

    void process_completions(const vol_interface_req_ptr& hb_req) {}

    void vol_mounted_cb(const VolumePtr& vol_obj, vol_state state) {
        vol_init(vol_obj);
        auto cb = [this](const vol_interface_req_ptr& vol_req) { process_completions(vol_req); };
        VolInterface::get_instance()->attach_vol_completion_cb(vol_obj, cb);
    }

    void vol_init(const VolumePtr& vol_obj) { open(VolInterface::get_instance()->get_name(vol_obj), O_RDWR); }

    void vol_state_change_cb(const VolumePtr& vol, vol_state old_state, vol_state new_state) { assert(0); }
};
} // namespace loadgen
} // namespace homeds
