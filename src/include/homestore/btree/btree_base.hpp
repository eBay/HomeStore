#pragma once

#include <array>
#include <homestore/index_service.hpp>
#include <homestore/btree/detail/btree_internal.hpp>
#include <homestore/checkpoint/cp_mgr.hpp>
#include <homestore/btree/detail/btree_node.hpp>

namespace homestore {
class UnderlyingBtree {
public:
    virtual ~UnderlyingBtree() = default;

    virtual BtreeNodePtr create_node(bool is_leaf, CPContext* context) = 0;
    virtual btree_status_t write_node(BtreeNodePtr const& node, CPContext* context) = 0;
    virtual btree_status_t read_node(bnodeid_t id, BtreeNodePtr& node) const = 0;
    virtual btree_status_t refresh_node(BtreeNodePtr const& node, bool for_read_modify_write, CPContext* context) = 0;
    virtual void remove_node(BtreeNodePtr const& node, CPContext* context) = 0;
    virtual btree_status_t transact_nodes(const BtreeNodeList& new_nodes, const BtreeNodeList& removed_nodes,
                                          const BtreeNodePtr& left_child_node, const BtreeNodePtr& parent_node,
                                          CPContext* context) = 0;
    virtual BtreeLinkInfo load_root_node_id() = 0;
    virtual btree_status_t on_root_changed(BtreeNodePtr const& root, CPContext* context) = 0;
    virtual uint64_t space_occupied() const = 0;
};

// Btree based implementations superblock area
struct BtreeSuperBlock {
    static constexpr size_t underlying_btree_sb_size =
        IndexSuperBlock::index_impl_sb_size - sizeof(bnodeid_t) - sizeof(uint64_t) - sizeof(uint32_t);

    bnodeid_t root_node_id{empty_bnodeid}; // Btree Root Node ID
    uint64_t root_link_version{0};
    uint32_t node_size{0};              // Node size used for this btree
    std::array< uint8_t, underlying_btree_sb_size > underlying_btree_sb;
};

class BtreeBase;

struct BtreeRouteTracer {
    SCOPED_ENUM_DECL(Op, uint8_t);
    std::vector< bool > m_enabled_ops;
    std::vector< std::string > m_ops_routes;
    uint32_t m_max_buf_size_per_op; // Max size after which the buffer is rolled over
    bool m_log_if_rolled;
    mutable iomgr::FiberManagerLib::shared_mutex m_append_mtx;

    BtreeRouteTracer(uint32_t buf_size_per_op = 1 * 1024 * 1024, bool log_if_buf_rolled = false);
    void enable(Op op) { m_enabled_ops[uint32_cast(op)] = true; }
    void disable(Op op) { m_enabled_ops[uint32_cast(op)] = false; }
    void enable_all() { m_enabled_ops.assign(m_enabled_ops.size(), true); }
    void disable_all() { m_enabled_ops.assign(m_enabled_ops.size(), false); }
    bool is_enabled_for(Op op) const { return m_enabled_ops[uint32_cast(op)]; }

    void append_to(Op op, std::string const& route);
    std::string get(Op op) const;
    std::vector< std::string > get_all() const;
};

SCOPED_ENUM_DEF(BtreeRouteTracer, Op, uint8_t, PUT, GET, REMOVE, QUERY);

class BtreeStore;

class BtreeBase : public Index {
public:
    BtreeBase(BtreeConfig const& cfg, uuid_t uuid = uuid_t{}, uuid_t parent_uuid = uuid_t{}, uint32_t user_sb_size = 0);
    BtreeBase(BtreeConfig const& cfg, superblk< IndexSuperBlock >&& sb);
    virtual ~BtreeBase();

    UnderlyingBtree const* underlying_btree() const { return m_bt_private.get(); }
    UnderlyingBtree* underlying_btree() {
        return const_cast< UnderlyingBtree* >(s_cast< const BtreeBase* >(this)->underlying_btree());
    }

    BtreeSuperBlock const& bt_super_blk() const {
        return *(r_cast< BtreeSuperBlock const* >(super_blk()->underlying_index_sb.data()));
    }

    BtreeSuperBlock& bt_super_blk() {
        return const_cast< BtreeSuperBlock& >(s_cast< const BtreeBase* >(this)->bt_super_blk());
    }

    virtual BtreeNodePtr new_node(bnodeid_t id, bool is_leaf, BtreeNode::Allocator::Token token) const = 0;
    virtual BtreeNodePtr load_node(uint8_t* node_buf, bnodeid_t id, BtreeNode::Allocator::Token token) const = 0;

    // virtual BtreeNode* init_node(uint8_t* node_buf, bnodeid_t id, bool init_buf, bool is_leaf,
    //                              BtreeNode::Allocator::Token token) const = 0;

    uint64_t space_occupied() const override;
    uint32_t ordinal() const override;

    virtual uint32_t node_size() const;
    std::string name() const;
    BtreeRouteTracer& route_tracer();
    BtreeConfig const& bt_config() const { return m_bt_cfg; }
    [[nodiscard]] CPGuard bt_cp_guard();

public:
    virtual btree_status_t write_node(const BtreeNodePtr& node, CPContext* context);
    virtual void read_node_or_fail(bnodeid_t id, BtreeNodePtr& node) const;
    virtual BtreeNodePtr create_leaf_node(CPContext* context);
    virtual BtreeNodePtr create_interior_node(CPContext* context);
    virtual void remove_node(const BtreeNodePtr& node, locktype_t cur_lock, CPContext* context);

protected:
    virtual btree_status_t create_root_node();
    virtual BtreeNodePtr clone_temp_node(BtreeNode const& node);
    virtual btree_status_t read_and_lock_node(bnodeid_t id, BtreeNodePtr& node_ptr, locktype_t int_lock_type,
                                              locktype_t leaf_lock_type, CPContext* context) const;
    virtual btree_status_t get_child_and_lock_node(const BtreeNodePtr& node, uint32_t index, BtreeLinkInfo& child_info,
                                                   BtreeNodePtr& child_node, locktype_t int_lock_type,
                                                   locktype_t leaf_lock_type, CPContext* context) const;

    virtual btree_status_t upgrade_node_locks(const BtreeNodePtr& parent_node, const BtreeNodePtr& child_node,
                                              locktype_t& parent_cur_lock, locktype_t& child_cur_lock,
                                              CPContext* context);
    virtual btree_status_t upgrade_node_lock(const BtreeNodePtr& node, locktype_t& cur_lock, CPContext* context);
    virtual btree_status_t _lock_node(const BtreeNodePtr& node, locktype_t type, CPContext* context, const char* fname,
                                      int line) const;
    virtual void unlock_node(const BtreeNodePtr& node, locktype_t type) const;

#ifdef _DEBUG
public:
    struct NodeLockInfo {
        BtreeNode* node;
        Clock::time_point start_time;
        const char* fname;
        int line;

        void dump() const { LOGINFO("node locked by file: {}, line: {}", fname, line); }
    };

    struct BtreeThreadVariables {
        std::vector< BtreeBase::NodeLockInfo > wr_locked_nodes;
        std::vector< BtreeBase::NodeLockInfo > rd_locked_nodes;
    };

    // This workaround of BtreeThreadVariables is needed instead of directly declaring statics
    // to overcome the gcc bug, pointer here: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=66944
    static BtreeThreadVariables* thread_vars() {
        auto this_id(boost::this_fiber::get_id());
        static thread_local std::map< boost::fibers::fiber::id, std::unique_ptr< BtreeThreadVariables > > fiber_map;
        if (fiber_map.count(this_id)) { return fiber_map[this_id].get(); }
        fiber_map[this_id] = std::make_unique< BtreeThreadVariables >();
        return fiber_map[this_id].get();
    }
    virtual void observe_lock_time(const BtreeNodePtr& node, locktype_t type, uint64_t time_spent) const;
    virtual void check_lock_debug();

    static void _start_of_lock(const BtreeNodePtr& node, locktype_t ltype, const char* fname, int line);
    static bool remove_locked_node(const BtreeNodePtr& node, locktype_t ltype, NodeLockInfo* out_info);
    static uint64_t end_of_lock(const BtreeNodePtr& node, locktype_t ltype);
#endif

protected:
    shared< BtreeStore > m_store;
    unique< UnderlyingBtree > m_bt_private;
    BtreeLinkInfo m_root_node_info;

    BtreeConfig m_bt_cfg;
    BtreeMetrics m_metrics;
    BtreeRouteTracer m_route_tracer;
    std::atomic< uint64_t > m_total_nodes{0};
};

struct BtreeVisualizeVariables {
    uint64_t parent;
    uint64_t midPoint;
    uint64_t index;
};
} // namespace homestore