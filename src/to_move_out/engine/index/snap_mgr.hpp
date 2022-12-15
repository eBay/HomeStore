#pragma once
#include "indx_mgr.hpp"

namespace homestore {
struct snap_sb {
    boost::uuids::uuid indx_mgr_uuid;
    uint64_t snap_id;
    homeds::btree::btree_super_block btree_sb;
    bool is_diff = true; // we set it to false when snapshot is created successfully
    uint64_t indx_tbl_size; // it is used to calculate the size used in reboot.
    int64_t cp_cnt; // start cp_cnt of this snapshot. It means contain all the ios starting from this cp_cnt till the
                    // cp_cnt of next snapshot.
} __attribute__((__packed__));

class SnapMgr : public IndxMgr {
public:
    /* static public members */
    template < typename... Args >
    static std::shared_ptr< SnapMgr > make_SnapMgr(Args&&... args) {
        auto snap_ptr = std::make_shared< SnapMgr >(std::forward< Args >(args)...);
        return snap_ptr;
    }

public:
    /* public members */

    /* It is called in first time create.
     * @params io_cb :- it is used to send callback with io is completed
     * @params recovery_mode :- true :- it is recovery
     *                          false :- it is first time create
     * @params func :- function to create indx table
     */
    SnapMgr(boost::uuids::uuid uuid, std::string name, io_done_cb io_cb, const read_indx_comp_cb_t& read_cb, create_indx_tbl func, bool is_snap_enabled);

    /* constructor for recovery */
    SnapMgr(boost::uuids::uuid uuid, std::string name, io_done_cb io_cb, const read_indx_comp_cb_t& read_cb,
            create_indx_tbl create_func, recover_indx_tbl recover_func, indx_mgr_sb sb);

protected:
    virtual int64_t snap_create(indx_tbl* m_diff_tbl, int64_t cp_cnt) override;
    virtual int64_t snap_get_diff_id() override;
    virtual void snap_create_done(uint64_t snap_id, int64_t max_psn, int64_t contiguous_psn,
                                  int64_t end_cp_cnt) override;
    virtual homeds::btree::btree_super_block snap_get_diff_tbl_sb() override;

private:
    /* static private members */
    //    static std::atomic< uint64_t > snap_id = 0;
    //   static std::map< boost::uuids::uuid, std::pair< meta_blk* > > hs_snap_map; // It is used only in recovery

private:
    /* private members */
    // std::map< uint64_t, meta_blk* > snap_map;
};
} // namespace homestore
