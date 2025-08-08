#include <string_view>
#include <string>
#include <homestore/btree/btree_base.hpp>
#include <homestore/btree/btree_store.h>
#include <homestore/btree/detail/btree_node.hpp>
#include "common/homestore_assert.hpp"

namespace homestore {
BtreeBase::BtreeBase(BtreeConfig const& cfg, uuid_t uuid, uuid_t parent_uuid, uint32_t user_sb_size) :
        Index::Index{cfg.store_type() == IndexStore::Type::MEM_BTREE},
        m_bt_cfg{cfg},
        m_metrics{m_bt_cfg.name().c_str()} {
    m_sb.create(sizeof(IndexSuperBlock));
    m_sb->uuid = uuid;
    m_sb->parent_uuid = parent_uuid;
    m_sb->user_sb_size = user_sb_size;
    m_sb->index_store_type = cfg.store_type();
    m_sb->ordinal = hs()->index_service().reserve_ordinal();

    auto bt_sb = new (m_sb.get()->underlying_index_sb.data()) BtreeSuperBlock();
    m_store =
        std::static_pointer_cast< BtreeStore >(hs()->index_service().lookup_or_create_store(cfg.store_type(), {}));

    if (m_bt_cfg.m_btree_name.empty()) { m_bt_cfg.m_btree_name = "btree" + std::to_string(m_sb->ordinal); }

    // Determine the correct node size
    auto const max_node_size = m_store->max_node_size();
    if ((m_bt_cfg.m_node_size == 0) || (m_bt_cfg.m_node_size > max_node_size)) { m_bt_cfg.m_node_size = max_node_size; }
    m_bt_cfg.finalize(sizeof(BtreeNode::PersistentHeader));

    // Create the underlying btree instance
    m_bt_private = std::move(m_store->create_underlying_btree(*this, false /* load_existing */));

    bt_sb->node_size = m_bt_cfg.m_node_size;
    m_sb.write();
}

BtreeBase::BtreeBase(BtreeConfig const& cfg, superblk< IndexSuperBlock >&& sb) :
        Index::Index{cfg.store_type() == IndexStore::Type::MEM_BTREE},
        m_bt_cfg{cfg},
        m_metrics{m_bt_cfg.name().c_str()} {
    HS_REL_ASSERT_EQ(cfg.store_type(), sb->index_store_type,
                     "Config requirement and super block differs in store_type");
    m_sb = std::move(sb);
    m_store =
        std::static_pointer_cast< BtreeStore >(hs()->index_service().lookup_or_create_store(cfg.store_type(), {}));

    if (m_bt_cfg.m_btree_name.empty()) { m_bt_cfg.m_btree_name = "btree" + std::to_string(m_sb->ordinal); }

    // Retrieve the correct node_size
    auto bt_sb = r_cast< BtreeSuperBlock* >(m_sb.get()->underlying_index_sb.data());
    m_bt_cfg.m_node_size = bt_sb->node_size;
    HS_DBG_ASSERT_NE(bt_sb->node_size, 0, "Invalid node_size in the btree super block");
    HS_DBG_ASSERT_LE(bt_sb->node_size, m_store->max_node_size(),
                     "Node size in btree super block, exceeds store max node size");
    m_bt_cfg.finalize(sizeof(BtreeNode::PersistentHeader));

    m_bt_private = std::move(m_store->create_underlying_btree(*this, true /* load_existing*/));
    m_root_node_info = m_bt_private->load_root_node_id();
}

BtreeBase::~BtreeBase() = default;
uint32_t BtreeBase::node_size() const { return m_bt_cfg.node_size(); }

uint64_t BtreeBase::space_occupied() const { return m_bt_private->space_occupied(); }

uint32_t BtreeBase::ordinal() const { return m_sb->ordinal; }

std::string BtreeBase::name() const { return m_bt_cfg.name(); }

BtreeRouteTracer& BtreeBase::route_tracer() { return m_route_tracer; }

#define lock_node(a, b, c) _lock_node(a, b, c, __FILE__, __LINE__)

btree_status_t BtreeBase::create_root_node() {
    auto cpg = bt_cp_guard();
    auto cp_context = cpg.context(cp_consumer_t::INDEX_SVC);

    // Assign one node as root node and also create a child leaf node and set it as edge
    BtreeNodePtr root = create_leaf_node(cp_context);
    if (root == nullptr) { return btree_status_t::space_not_avail; }

    root->set_level(0u);
    auto ret = write_node(root, cp_context);
    if (ret != btree_status_t::success) {
        remove_node(root, locktype_t::NONE, cp_context);
        return btree_status_t::space_not_avail;
    }

    m_root_node_info = BtreeLinkInfo{root->node_id(), root->link_version()};
    ret = m_bt_private->on_root_changed(root, cp_context);
    if (ret != btree_status_t::success) {
        remove_node(root, locktype_t::NONE, cp_context);
        m_root_node_info = BtreeLinkInfo{};
    }
    return ret;
}

btree_status_t BtreeBase::read_and_lock_node(bnodeid_t id, BtreeNodePtr& node_ptr, locktype_t int_lock_type,
                                             locktype_t leaf_lock_type, CPContext* context) const {
    auto ret = m_bt_private->read_node(id, node_ptr);
    if (node_ptr == nullptr) {
        BT_LOG(ERROR, "read failed, reason: {}", ret);
        return ret;
    }

    auto acq_lock = (node_ptr->is_leaf()) ? leaf_lock_type : int_lock_type;
    ret = lock_node(node_ptr, acq_lock, context);
    if (ret != btree_status_t::success) { BT_LOG(ERROR, "Node lock and refresh failed"); }

    return ret;
}

btree_status_t BtreeBase::get_child_and_lock_node(const BtreeNodePtr& node, uint32_t index, BtreeLinkInfo& child_info,
                                                  BtreeNodePtr& child_node, locktype_t int_lock_type,
                                                  locktype_t leaf_lock_type, CPContext* context) const {
    if (index == node->total_entries()) {
        if (!node->has_valid_edge()) {
            BT_NODE_LOG_ASSERT(false, node, "Child index {} does not have valid bnode_id", index);
            return btree_status_t::not_found;
        }
        child_info = node->get_edge_value();
    } else {
        BT_NODE_LOG_ASSERT_LT(index, node->total_entries(), node);
        node->get_nth_value(index, &child_info, false /* copy */);
    }

    return (read_and_lock_node(child_info.bnode_id(), child_node, int_lock_type, leaf_lock_type, context));
}

btree_status_t BtreeBase::write_node(const BtreeNodePtr& node, CPContext* context) {
    COUNTER_INCREMENT_IF_ELSE(m_metrics, node->is_leaf(), btree_leaf_node_writes, btree_int_node_writes, 1);
    HISTOGRAM_OBSERVE_IF_ELSE(m_metrics, node->is_leaf(), btree_leaf_node_occupancy, btree_int_node_occupancy,
                              ((node_size() - node->available_size()) * 100) / node_size());

    return (m_bt_private->write_node(node, context));
}

/* Caller of this api doesn't expect read to fail in any circumstance */
void BtreeBase::read_node_or_fail(bnodeid_t id, BtreeNodePtr& node) const {
    BT_NODE_REL_ASSERT_EQ(m_bt_private->read_node(id, node), btree_status_t::success, node);
}

/*
 * This function upgrades the parent node and child node locks from read lock to write lock and take required steps if
 * things have changed during the upgrade.
 *
 * Inputs:
 * parent_node - Parent Node to upgrade
 * child_node - Child Node to upgrade
 * child_cur_lock - Current child node which is held
 * context - Context to pass down
 *
 * Returns - If successfully able to upgrade both the nodes, return success, else return status of upgrade_node.
 * In case of not success, all nodes locks are released.
 *
 * NOTE: This function expects both the parent_node and child_node to be already locked. Parent node is
 * expected to be read locked and child node could be either read or write locked.
 */
btree_status_t BtreeBase::upgrade_node_locks(const BtreeNodePtr& parent_node, const BtreeNodePtr& child_node,
                                             locktype_t& parent_cur_lock, locktype_t& child_cur_lock,
                                             CPContext* context) {
    btree_status_t ret = btree_status_t::success;

    auto const parent_prev_gen = parent_node->node_gen();
    auto const child_prev_gen = child_node->node_gen();

    unlock_node(child_node, child_cur_lock);
    unlock_node(parent_node, parent_cur_lock);

    ret = lock_node(parent_node, locktype_t::WRITE, context);
    if (ret != btree_status_t::success) {
        parent_cur_lock = child_cur_lock = locktype_t::NONE;
        return ret;
    }

    ret = lock_node(child_node, locktype_t::WRITE, context);
    if (ret != btree_status_t::success) {
        unlock_node(parent_node, locktype_t::WRITE);
        parent_cur_lock = child_cur_lock = locktype_t::NONE;
        return ret;
    }

    // If the node things have been changed between unlock and lock example, it has been made invalid (probably by merge
    // nodes) ask caller to start over again.
    if (parent_node->is_node_deleted() || (parent_prev_gen != parent_node->node_gen()) ||
        child_node->is_node_deleted() || (child_prev_gen != child_node->node_gen())) {
        unlock_node(child_node, locktype_t::WRITE);
        unlock_node(parent_node, locktype_t::WRITE);
        parent_cur_lock = child_cur_lock = locktype_t::NONE;
        return btree_status_t::retry;
    }

    parent_cur_lock = child_cur_lock = locktype_t::WRITE;
#if 0
#ifdef _PRERELEASE
    {
        auto time = iomgr_flip::instance()->get_test_flip< uint64_t >("btree_upgrade_delay");
        if (time) { std::this_thread::sleep_for(std::chrono::microseconds{time.get()}); }
    }
#endif
#endif

#if 0
#ifdef _PRERELEASE
    {
        int is_leaf = 0;

        if (child_node && child_node->is_leaf()) { is_leaf = 1; }
        if (iomgr_flip::instance()->test_flip("btree_upgrade_node_fail", is_leaf)) {
            unlock_node(my_node, cur_lock);
            cur_lock = locktype_t::NONE;
            if (child_node) {
                unlock_node(child_node, child_cur_lock);
                child_cur_lock = locktype_t::NONE;
            }
            ret = btree_status_t::retry;
        }
    }
#endif
#endif

    return ret;
}

btree_status_t BtreeBase::upgrade_node_lock(const BtreeNodePtr& node, locktype_t& cur_lock, CPContext* context) {
    auto const prev_gen = node->node_gen();

    unlock_node(node, cur_lock);
    cur_lock = locktype_t::NONE;

    auto ret = lock_node(node, locktype_t::WRITE, context);
    if (ret != btree_status_t::success) { return ret; }

    if (node->is_node_deleted() || (prev_gen != node->node_gen())) {
        unlock_node(node, locktype_t::WRITE);
        return btree_status_t::retry;
    }
    cur_lock = locktype_t::WRITE;
    return ret;
}

btree_status_t BtreeBase::_lock_node(const BtreeNodePtr& node, locktype_t type, CPContext* context, const char* fname,
                                     int line) const {
#ifdef _DEBUG
    _start_of_lock(node, type, fname, line);
#endif
    node->lock(type);

    auto ret = m_bt_private->refresh_node(node, (type == locktype_t::WRITE), context);
    if (ret != btree_status_t::success) {
        node->unlock(type);
#ifdef _DEBUG
        end_of_lock(node, type);
#endif
        return ret;
    }

    return btree_status_t::success;
}

void BtreeBase::unlock_node(const BtreeNodePtr& node, locktype_t type) const {
    node->unlock(type);
#ifdef _DEBUG
    auto time_spent = end_of_lock(node, type);
    observe_lock_time(node, type, time_spent);
#endif
}

BtreeNodePtr BtreeBase::create_leaf_node(CPContext* context) {
    BtreeNodePtr n = m_bt_private->create_node(true /* is_leaf */, context);
    if (n) {
        COUNTER_INCREMENT(m_metrics, btree_leaf_node_count, 1);
        ++m_total_nodes;
    }
    return n;
}

BtreeNodePtr BtreeBase::create_interior_node(CPContext* context) {
    BtreeNodePtr n = m_bt_private->create_node(false /* is_leaf */, context);
    if (n) {
        COUNTER_INCREMENT(m_metrics, btree_int_node_count, 1);
        ++m_total_nodes;
    }
    return n;
}

BtreeNodePtr BtreeBase::clone_temp_node(const BtreeNode& node) {
    BtreeNodePtr tmp_node = new_node(node.node_id(), node.is_leaf(), BtreeNode::Allocator::default_token);
    tmp_node->overwrite(node);
    return tmp_node;
}

[[nodiscard]] CPGuard BtreeBase::bt_cp_guard() { return CPGuard{is_ephemeral() ? nullptr : &(cp_mgr())}; }

/* Note:- This function assumes that access of this node is thread safe. */

void BtreeBase::remove_node(const BtreeNodePtr& node, locktype_t cur_lock, CPContext* context) {
    BT_NODE_LOG(TRACE, node, "Removing node");

    COUNTER_DECREMENT_IF_ELSE(m_metrics, node->is_leaf(), btree_leaf_node_count, btree_int_node_count, 1);
    if (cur_lock != locktype_t::NONE) {
        BT_NODE_DBG_ASSERT_NE(cur_lock, locktype_t::READ, node, "We can't remove a node with read lock type right?");
        node->set_node_deleted();
        unlock_node(node, cur_lock);
    }
    --m_total_nodes;

    m_bt_private->remove_node(node, context);
    // intrusive_ptr_release(node.get());
}

#ifdef _DEBUG
void BtreeBase::observe_lock_time(const BtreeNodePtr& node, locktype_t type, uint64_t time_spent) const {
    if (time_spent == 0) { return; }

    if (type == locktype_t::READ) {
        HISTOGRAM_OBSERVE_IF_ELSE(m_metrics, node->is_leaf(), btree_inclusive_time_in_leaf_node,
                                  btree_inclusive_time_in_int_node, time_spent);
    } else {
        HISTOGRAM_OBSERVE_IF_ELSE(m_metrics, node->is_leaf(), btree_exclusive_time_in_leaf_node,
                                  btree_exclusive_time_in_int_node, time_spent);
    }
}

void BtreeBase::_start_of_lock(const BtreeNodePtr& node, locktype_t ltype, const char* fname, int line) {
    NodeLockInfo info;

    info.fname = fname;
    info.line = line;

    info.start_time = Clock::now();
    info.node = node.get();
    if (ltype == locktype_t::WRITE) {
        thread_vars()->wr_locked_nodes.push_back(info);
        LOGTRACEMOD(btree, "ADDING node {} to write locked nodes list, its size={}", (void*)info.node,
                    thread_vars()->wr_locked_nodes.size());
    } else if (ltype == locktype_t::READ) {
        thread_vars()->rd_locked_nodes.push_back(info);
        LOGTRACEMOD(btree, "ADDING node {} to read locked nodes list, its size={}", (void*)info.node,
                    thread_vars()->rd_locked_nodes.size());
    } else {
        DEBUG_ASSERT(false, "Invalid locktype_t {}", ltype);
    }
}

bool BtreeBase::remove_locked_node(const BtreeNodePtr& node, locktype_t ltype, NodeLockInfo* out_info) {
    auto pnode_infos = (ltype == locktype_t::WRITE) ? &thread_vars()->wr_locked_nodes : &thread_vars()->rd_locked_nodes;

    if (!pnode_infos->empty()) {
        auto info = pnode_infos->back();
        if (info.node == node.get()) {
            *out_info = info;
            pnode_infos->pop_back();
            LOGTRACEMOD(btree, "REMOVING node {} from {} locked nodes list, its size = {}", (void*)info.node,
                        (ltype == locktype_t::WRITE) ? "write" : "read", pnode_infos->size());
            return true;
        } else if (pnode_infos->size() > 1) {
            info = pnode_infos->at(pnode_infos->size() - 2);
            if (info.node == node.get()) {
                *out_info = info;
                pnode_infos->at(pnode_infos->size() - 2) = pnode_infos->back();
                pnode_infos->pop_back();
                LOGTRACEMOD(btree, "REMOVING node {} from {} locked nodes list, its size = {}", (void*)info.node,
                            (ltype == locktype_t::WRITE) ? "write" : "read", pnode_infos->size());
                return true;
            }
        }
    }

    if (pnode_infos->empty()) {
        LOGERRORMOD(btree, "locked_node_list: node = {} not found, locked node list empty", (void*)node.get());
    } else if (pnode_infos->size() == 1) {
        LOGERRORMOD(btree, "locked_node_list: node = {} not found, total list count = 1, Expecting node = {}",
                    (void*)node.get(), (void*)pnode_infos->back().node);
    } else {
        LOGERRORMOD(btree, "locked_node_list: node = {} not found, total list count = {}, Expecting nodes = {} or {}",
                    (void*)node.get(), pnode_infos->size(), (void*)pnode_infos->back().node,
                    (void*)pnode_infos->at(pnode_infos->size() - 2).node);
    }
    return false;
}

uint64_t BtreeBase::end_of_lock(const BtreeNodePtr& node, locktype_t ltype) {
    NodeLockInfo info;
    if (!remove_locked_node(node, ltype, &info)) {
        DEBUG_ASSERT(false, "Expected node = {} is not there in locked_node_list", (void*)node.get());
        return 0;
    }
    // DEBUG_ASSERT_EQ(node.get(), info.node);
    return get_elapsed_time_ns(info.start_time);
}

void BtreeBase::check_lock_debug() {
    // both wr_locked_nodes and rd_locked_nodes are thread_local;
    // nothing will be dumpped if there is no assert failure;
    for (const auto& x : thread_vars()->wr_locked_nodes) {
        x.dump();
    }
    for (const auto& x : thread_vars()->rd_locked_nodes) {
        x.dump();
    }
    DEBUG_ASSERT_EQ(thread_vars()->wr_locked_nodes.size(), 0);
    DEBUG_ASSERT_EQ(thread_vars()->rd_locked_nodes.size(), 0);
}
#endif

BtreeRouteTracer::BtreeRouteTracer(uint32_t buf_size_per_op, bool log_if_rolled) :
        m_max_buf_size_per_op{buf_size_per_op}, m_log_if_rolled{log_if_rolled} {
    m_enabled_ops.reserve(enum_count< BtreeRouteTracer::Op >());
    m_ops_routes.reserve(enum_count< BtreeRouteTracer::Op >());

    for (uint32_t i{0}; i < enum_count< BtreeRouteTracer::Op >(); ++i) {
        m_enabled_ops.push_back(false);
    }
}

void BtreeRouteTracer::append_to(Op op, std::string const& route_str) {
    std::string& cur_buf = m_ops_routes[uint32_cast(op)];
    if (!m_enabled_ops[uint32_cast(op)]) { return; }

    std::unique_lock< iomgr::FiberManagerLib::shared_mutex > lock{m_append_mtx};
    while (cur_buf.size() + route_str.size() > m_max_buf_size_per_op) {
        size_t head_pos = cur_buf.find("Route size=");
        size_t next_pos = cur_buf.find("Route size=", head_pos + 1);
        if (m_log_if_rolled) {
            // TODO: We need to change this to btree specific log.
            LOGINFOMOD(btree, "Btree Route Trace: {}", std::string_view(cur_buf).substr(head_pos, next_pos));
        }

        if (next_pos == std::string::npos) {
            cur_buf.clear();
            break;
        } else {
            cur_buf.erase(0, next_pos);
        }
    }
    cur_buf.append(route_str);
}

std::string BtreeRouteTracer::get(Op op) const {
    m_append_mtx.lock_shared();
    std::shared_lock< iomgr::FiberManagerLib::shared_mutex > lock{m_append_mtx};
    auto const ret = m_ops_routes[uint32_cast(op)];
    m_append_mtx.unlock_shared();
    return ret;
}

std::vector< std::string > BtreeRouteTracer::get_all() const {
    m_append_mtx.lock_shared();
    auto const ret = m_ops_routes;
    m_append_mtx.unlock_shared();
    return ret;
}
} // namespace homestore