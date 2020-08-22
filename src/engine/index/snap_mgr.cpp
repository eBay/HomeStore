#include "snap_mgr.hpp"

using namespace homestore;
SnapMgr::SnapMgr(boost::uuids::uuid uuid, std::string name, io_done_cb io_cb, const read_indx_comp_cb_t& read_cb, create_indx_tbl func,
                 bool is_snap_enabled) :
        IndxMgr(uuid, name, io_cb, read_cb, func, is_snap_enabled) {}

SnapMgr::SnapMgr(boost::uuids::uuid uuid, std::string name, io_done_cb io_cb, const read_indx_comp_cb_t& read_cb,
                 create_indx_tbl create_func, recover_indx_tbl recover_func, indx_mgr_sb sb) :
        IndxMgr(uuid, name, io_cb, read_cb, create_func, recover_func, sb) {}

int64_t SnapMgr::snap_create(indx_tbl* diff_tbl, int64_t cp_cnt) {
#if 0
    snap_sb sb;
    void* meta_blk;
    sb->btree_sb = diff_tbl->get_btree_sb();
    sb->indx_mgr_uuid = m_uuid;
    sb->snap_id = ++snap_id;
    snap_sb->add_sub_sb("SNAP_MGR_SB", &sb, sizeof(sb), meta_blk);
    snap_map[sb->snap_id] = meta_blk;
#endif
    return -1;
}

int64_t SnapMgr::snap_get_diff_id() { return -1; }
void SnapMgr::snap_create_done(uint64_t snap_id, int64_t max_psn, int64_t contiguous_psn, int64_t end_cp_cnt) {}
homeds::btree::btree_super_block SnapMgr::snap_get_diff_tbl_sb() {
    homeds::btree::btree_super_block sb;
    return sb;
}
