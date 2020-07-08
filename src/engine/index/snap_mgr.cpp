#include "snap_mgr.hpp"

SnapMgr::SnapMgr(boost::uuids::uuid uuid, std::string name, io_done_cb io_cb, create_indx_tbl func,
                 bool is_snap_enabled) :
        IndxMgr(uuid, name, io_cb, func, is_snap_enabled) {}

SnapMgr::SnapMgr(boost::uuids::uuid uuid, std::string name, io_done_cb io_cb, create_indx_tbl create_func,
                 recover_indx_tbl recover_func, indx_mgr_static_sb sb) :
        IndxMgr(uuid, name, io_cb, create_func, recover_func, sb) {}

uint64_t SnapMgr::snap_create(indx_tbl* diff_tbl) {
    snap_sb sb;
    void* meta_blk;
    sb->btree_sb = diff_tbl->get_btree_sb();
    sb->indx_mgr_uuid = m_uuid;
    sb->snap_id = ++snap_id;
    snap_sb->add_sub_sb("SNAP_MGR_SB", &sb, sizeof(sb), meta_blk);
    snap_map[sb->snap_id] = meta_blk;
    return sb->snap_id;
}

indx_tbl* SnapMgr::snap_get_diff_tbl() {}

uint64_t SnapMgr::snap_get_diff_id() {}

void SnapMgr::snap_created(uint64_t snap_id, int64_t max_psn, int64_t contiguous_psn) {}
