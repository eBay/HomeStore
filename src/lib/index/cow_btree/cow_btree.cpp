#include <homestore/btree/detail/btree_node.hpp>
#include "index/cow_btree/cow_btree.h"
#include "index/cow_btree/cow_btree_cp.h"
//#include "index/cow_btree/cow_btree_node.h"
#include "index/index_cp.h"
#include "common/homestore_config.hpp"
#include "common/homestore_utils.hpp"
#include "common/crash_simulator.hpp"
#include "device/virtual_dev.hpp"

namespace homestore {
#define COWBT_PERIODIC_LOG(level, cp_id, ...)                                                                          \
    HS_PERIODIC_DETAILED_LOG(level, cp, "cp_id", cp_id, "btree", m_base_btree.bt_config().name(), __VA_ARGS__)

static constexpr uint64_t btree_nodeid_bits = sizeof(uint32_t) * 8;
static constexpr uint64_t btree_ordinal_bits = 64 - btree_nodeid_bits;
static constexpr uint64_t btree_nodeid_mask = ((1ull << btree_nodeid_bits) - 1);
static constexpr uint64_t btree_ordinal_mask = ((1ull << btree_ordinal_bits) - 1) << btree_nodeid_bits;

static constexpr uint32_t initial_bnodeid_map_persistent_size = 512 * 1024;

static inline COWBtree::CompactNodeId to_compact_nodeid(bnodeid_t node_id) { return node_id & btree_nodeid_mask; }

static BlkId alloc_blks_or_fail(VirtualDev* vdev, uint32_t size, blk_alloc_hints const& hints) {
    BlkId out_blkid;
    BlkAllocStatus status = vdev->alloc_contiguous_blks(size, hints, out_blkid);
    HS_REL_ASSERT_EQ(status, BlkAllocStatus::SUCCESS,
                     "No space to write the bnode map, which cannot be proceeded further, crashing the system for now");
    return out_blkid;
}

static void write_or_fail(VirtualDev* vdev, sisl::io_blob const& blob, BlkId location) {
    auto err = vdev->sync_write(r_cast< const char* >(blob.cbytes()), blob.size(), location);
    HS_REL_ASSERT(!err, "Flush of full map failed with err={}. best is to crash the system and replay", err.message());
}

COWBtree::COWBtree(BtreeBase& bt, shared< VirtualDev > vdev,
                   shared< sisl::SimpleCache< bnodeid_t, BtreeNodePtr > > cache,
                   std::vector< unique< Journal > > journals, BtreeNode::Allocator::Token token, bool load_existing) :
        m_base_btree{bt},
        m_cache{std::move(cache)},
        m_nodeid_generator(std::numeric_limits< uint32_t >::max()),
        m_vdev{std::move(vdev)},
        m_btree_ordinal{bt.super_blk()->ordinal},
        m_ordinal_shifted{uint64_cast(m_btree_ordinal) << btree_nodeid_bits},
        m_bufalloc_token{token} {
    for (auto& cp_session : m_cp_sessions) {
        cp_session = std::make_unique< CPSession >(*this);
    }

    if (load_existing) {
        m_root_node_id = m_base_btree.bt_super_blk().root_node_id;
        if (m_root_node_id != empty_bnodeid) {
            HS_REL_ASSERT_EQ(m_root_node_id & btree_ordinal_mask, m_ordinal_shifted,
                             "Ordinal of root node_id inside the superblk doesn't match btree's ordinal");
        }

        // If we have full map persisted before, recover that
        for (uint32_t i{0}; i < cow_bt_super_blk().num_map_heads; ++i) {
            recover_bnode_map(cow_bt_super_blk().map_heads[i]);
        }

        // Apply all incremental journal entries containing map updates/removes. Each journal_buf listed here
        // corresponding to a journal written as part of cps, sorted by the cp_id
        for (auto& journal : journals) {
            apply_incremental_map(*journal);
        }
    } else {
        // New COWBtree, format the cow btree superblk area
        new (m_base_btree.bt_super_blk().underlying_btree_sb.data()) SuperBlock();
    }
}

static inline COWBtreeCPContext* to_my_cp_ctx(CPContext* context) {
    return IndexCPContext::convert< COWBtreeCPContext >(context, IndexStore::Type::COPY_ON_WRITE_BTREE);
}

BtreeNodePtr COWBtree::create_node(bool is_leaf, CPContext* context) {
    auto n = m_base_btree.new_node(generate_node_id(), is_leaf, m_bufalloc_token);
    // COWBtreeNode::construct(n);

    // Add the node to the cache
    auto status = m_cache->insert(n);
    HS_REL_ASSERT_EQ(status, sisl::SimpleCacheStatus::success,
                     "Unable to add alloc'd node to cache, low memory or duplicate inserts?");

    add_to_dirty_list(FlushNodeInfo{n}, to_my_cp_ctx(context));
    n->set_modified_cp_id(context->id());
    return n;
}

btree_status_t COWBtree::write_node(BtreeNodePtr const& node, CPContext*) {
    // All the required actions are performed during refresh_node with read_modify_write=true
    return btree_status_t::success;
}

btree_status_t COWBtree::read_node(bnodeid_t node_id, BtreeNodePtr& node) const {
retry:
    // Attempt to locate the node in the cache
    auto status = m_cache->get(node_id, node);
    if (status == sisl::SimpleCacheStatus::success) { return btree_status_t::success; }

    // Need to read from the blk, so check that in the map
    BlkId blkid = get_blkid_for_nodeid(node_id);
    if (!blkid.is_valid()) { return btree_status_t::not_found; }

    auto raw_buf = BtreeNode::Allocator::get(m_bufalloc_token).alloc_node_buf(m_base_btree.node_size());
    m_vdev->sync_read(r_cast< char* >(raw_buf), m_base_btree.node_size(), blkid);

    // Initialize the node
    node = m_base_btree.load_node(raw_buf, node_id, m_bufalloc_token);
    // COWBtreeNode::construct(node)

    // Add the node to the cache
    status = m_cache->insert(node);
    if (status == sisl::SimpleCacheStatus::duplicate) {
        // There is a race between 2 concurrent reads of same node, Re-read from cache again
        // COWBtreeNode::destruct(node.get());
        goto retry;
    } else if (status == sisl::SimpleCacheStatus::success) {
        return btree_status_t::success;
    } else {
        HS_DBG_ASSERT(false, "Insert read node to cache failed, probably because of low memory status={}",
                      enum_name(status));
        return btree_status_t::space_not_avail;
    }
}

btree_status_t COWBtree::refresh_node(BtreeNodePtr const& node, bool for_read_modify_write, CPContext* context) {
    if (context == nullptr || !for_read_modify_write) { return btree_status_t::success; }

    auto cp_ctx = to_my_cp_ctx(context);
    auto const mod_cp_id = node->get_modified_cp_id();
    auto const cur_cp_id = cp_ctx->id();
    if (mod_cp_id == cur_cp_id) {
        // For same cp, we don't need a copy, we can rewrite on the same buffer
        return btree_status_t::success;
    } else if (mod_cp_id > cur_cp_id) {
        return btree_status_t::cp_mismatch; // We are asked to provide the buffer of an older CP, which is not
                                            // possible
    } else {
        add_to_dirty_list(FlushNodeInfo{node}, cp_ctx);
        node->set_modified_cp_id(cur_cp_id);
    }
    return btree_status_t::success;
}

void COWBtree::remove_node(BtreeNodePtr const& node, CPContext* context) {
    // Add the node id to dirty deleted list, which will be applied during the cp flush
    auto cp_ctx = to_my_cp_ctx(context);
    add_to_remove_list(node->node_id(), cp_ctx);

    // Now we can remove the node from cache.
    BtreeNodePtr tmp;
    auto status = m_cache->remove(node->node_id(), tmp);
    HS_DBG_ASSERT_EQ(status, sisl::SimpleCacheStatus::success, "Race on cache removal of btree blkid?");
}

btree_status_t COWBtree::transact_nodes(const BtreeNodeList& new_nodes, const BtreeNodeList& removed_nodes,
                                        const BtreeNodePtr& left_child_node, const BtreeNodePtr& parent_node,
                                        CPContext* context) {
    for (const auto& node : new_nodes) {
        m_base_btree.write_node(node, context);
    }
    m_base_btree.write_node(left_child_node, context);
    m_base_btree.write_node(parent_node, context);

    for (const auto& node : removed_nodes) {
        m_base_btree.remove_node(node, locktype_t::WRITE, context);
    }
    return btree_status_t::success;
}

BtreeLinkInfo COWBtree::load_root_node_id() {
    return BtreeLinkInfo{m_root_node_id, m_base_btree.bt_super_blk().root_link_version};
}

btree_status_t COWBtree::on_root_changed(BtreeNodePtr const& new_root, CPContext* cp_ctx) {
    m_root_node_id = new_root->node_id();
    cp_session(cp_ctx->id())->m_new_root_id.store(m_root_node_id);
    return btree_status_t::success;
}

uint64_t COWBtree::space_occupied() const {
    size_t num_nodes{0};
    {
        std::shared_lock< iomgr::FiberManagerLib::shared_mutex > lg(m_bnodeid_map.m_mtx);
        num_nodes = m_bnodeid_map.m_map.size();
    }

    for (auto const& cp_session : m_cp_sessions) {
        num_nodes += cp_session->m_modified_nodes.size();
        num_nodes -= cp_session->m_deleted_nodes.size();
    }

    return num_nodes * m_vdev->block_size();
}

void COWBtree::destroy() {
    // Free all the blks allocated for the nodes
    std::unique_lock< iomgr::FiberManagerLib::shared_mutex > lg(m_bnodeid_map.m_mtx);
    BtreeNodePtr tmp;
    for (auto const [node_id, blkid] : m_bnodeid_map.m_map) {
        m_vdev->free_blk(blkid.to_blkid());
        m_cache->remove(m_ordinal_shifted | node_id, tmp);
    }

    // Free all the blks allocated for the map
    for (auto const& locs : m_bnodeid_map.m_locations) {
        m_vdev->free_blk(locs);
    }

    // Reset the map, cp_session etc.
    m_bnodeid_map.m_map.clear();
    m_bnodeid_map.m_updates_since_last_flush = 0;
    m_bnodeid_map.m_locations.clear();

    // Reset all the dirty nodes, deleted nodes etc.
    for (auto& cp_session : m_cp_sessions) {
        for (auto const& finfo : cp_session->m_modified_nodes) {
            m_cache->remove(finfo.node->node_id(), tmp);
        }
        cp_session->finish();
    }

    // Destroy this btree's superblk, so that it can be re-initialized again.
    m_base_btree.super_blk().destroy();
}

//////////////////////// COWBtree specific methods ////////////////////////////////////////
bnodeid_t COWBtree::generate_node_id() {
    std::unique_lock lg{m_id_mtx};
    return (m_ordinal_shifted | m_nodeid_generator.reserve());
}

BlkId COWBtree::get_blkid_for_nodeid(bnodeid_t nodeid) const { return lookup_bnode_map(to_compact_nodeid(nodeid)); }

void COWBtree::add_to_dirty_list(FlushNodeInfo finfo, COWBtreeCPContext* cp_ctx) {
    cp_ctx->increment_dirty_size(finfo.node->node_size());
    cp_session(cp_ctx->id())->m_modified_nodes.emplace_back(std::move(finfo));
}

void COWBtree::add_to_remove_list(bnodeid_t node_id, COWBtreeCPContext* cp_ctx) {
    cp_ctx->increment_pending_free_size(m_base_btree.node_size());
    cp_session(cp_ctx->id())->m_deleted_nodes.push_back(node_id);
}

// FlushUnit represents one contiguous block where all btree nodes that can be packed are done and written at once
struct NodeFlushUnit {
#pragma pack(1)
    struct JournalEntry {
        COWBtree::CompactBlkId nodes_location; // Location where nodes from this unit are written
        uint16_t n_nodes{0};                   // Total number of nodes written
        COWBtree::CompactNodeId nodes[1];      // Array of node ids written in the blk above

        uint32_t size() const { return size(n_nodes); }
        static uint32_t size(uint16_t num_nodes) {
            return sizeof(JournalEntry) + (num_nodes * sizeof(COWBtree::CompactNodeId)) -
                sizeof(COWBtree::CompactNodeId);
        }
    };
#pragma pack()

    COWBtreeCPContext* m_cp_ctx;
    JournalEntry* m_jentry{nullptr};
    std::vector< iovec > m_iovs;
    std::vector< COWBtree::FlushNodeInfo > m_flush_infos;
    BlkId m_nodes_location;
    uint32_t m_nodes_count{0};

    NodeFlushUnit(COWBtreeCPContext* cp_ctx, BlkId location, sisl::blob& journal_area) :
            m_cp_ctx{cp_ctx}, m_nodes_location{location} {
        if (journal_area.bytes() != nullptr) {
            m_jentry = new (journal_area.bytes()) JournalEntry();
            m_jentry->nodes_location = location;
        }
        m_iovs.reserve(location.blk_count());
        m_flush_infos.reserve(location.blk_count());
    }

    void add(COWBtree::FlushNodeInfo finfo) {
        HS_DBG_ASSERT_LT(m_nodes_count, m_nodes_location.blk_count(), "Adding more nodes than node allocated for");
        // m_node_bufs.emplace_back(cow_node->get_flush_version_buf(m_cp_ctx->id()));
        m_iovs.emplace_back(iovec{.iov_base = finfo.bytes(), .iov_len = finfo.node->node_size()});
        ++m_nodes_count;
        if (m_jentry) { m_jentry->nodes[m_jentry->n_nodes++] = to_compact_nodeid(finfo.node->node_id()); }
        m_flush_infos.emplace_back(std::move(finfo));
    }
};

struct BNodeMapWriteUnit {
#pragma pack(1)
    struct Header {
        COWBtree::CompactBlkId next_unit_location; // Location of where the next meta (for map) is present
        uint32_t size{sizeof(Header)};             // Total size of this unit.
        uint32_t n_entries{0};                     // Total number of entries in this unit
        uint32_t checksum{0};                      // Checksum excluding this header
    };

    // One Entry per continguos nodeids.
    struct MapEntry {
        COWBtree::CompactNodeId nodeid_start{0};
        uint16_t nodes_count{0};
        COWBtree::CompactBlkId nodes_locations[1];

        static size_t size(uint32_t count) {
            return sizeof(MapEntry) + (count ? (count - 1) * sizeof(COWBtree::CompactBlkId) : 0);
        }
        size_t size() const { return size(nodes_count); }

        bool merge_if_possible(COWBtree::CompactNodeId n, COWBtree::CompactBlkId b) {
            if (nodes_count == 0) {
                nodeid_start = n;
                nodes_locations[nodes_count++] = b;
                return true;
            } else if ((nodeid_start + nodes_count) == n) {
                nodes_locations[nodes_count++] = b;
                return true;
            }
            return false;
        }
    };
#pragma pack()

    VirtualDev* m_vdev;
    sisl::io_blob_safe m_buf;
    uint32_t m_available_space{0};
    BlkId m_location;
    MapEntry* m_cur_entry{nullptr};

public:
    // Guess the size expecting 64 nodes packed together.
    static constexpr const uint32_t expected_nodes_packed_per_entry = 64;

    static uint32_t size_guess(uint32_t num_nodes) {
        return MapEntry::size(num_nodes / expected_nodes_packed_per_entry);
    }

    static constexpr uint32_t const min_blks_per_write_unit = 128;

    BNodeMapWriteUnit(VirtualDev* vdev, uint32_t nodes_count) : m_vdev{vdev} {
        m_available_space = sisl::round_up(size_guess(nodes_count), m_vdev->block_size());
        auto const reqd_blks = (m_available_space - 1) / m_vdev->block_size() + 1;

        // First allocate the blks and adjust the available space to how much ever we were able to allocate
        // contiguously.

        blk_alloc_hints hints = {.partial_alloc_ok = true,
                                 .min_blks_per_piece = std::min(reqd_blks, min_blks_per_write_unit)};
        m_location = alloc_blks_or_fail(m_vdev, m_available_space, hints);
        m_available_space = m_location.blk_count() * m_vdev->block_size();

        // Allocate buffer to hold up that much disk space we allocated.
        m_buf = sisl::io_blob_safe(m_available_space, vdev->align_size(), sisl::buftag::metablk);
        memset(m_buf.bytes(), 0, m_available_space);

        // Initialize the in-memory pointers
        new (m_buf.bytes()) Header();
        m_available_space -= sizeof(Header);
        m_cur_entry = r_cast< MapEntry* >(m_buf.bytes() + sizeof(Header));
    }

    // Recovery constructor
    BNodeMapWriteUnit(VirtualDev* vdev, sisl::io_blob_safe buf, BlkId location) :
            m_vdev{vdev}, m_buf{std::move(buf)}, m_location{location} {
        HS_DBG_ASSERT_GE(m_buf.size(), header()->size, "Read buf is less than MapWriteUnit size on-disk");
        HS_REL_ASSERT_EQ(header()->checksum, compute_crc(), "CRC Mismatch on MapWriteUnit");

        m_available_space = m_buf.size() - header()->size;
        m_cur_entry = header()->n_entries ? r_cast< MapEntry* >(m_buf.bytes() + sizeof(Header)) : nullptr;
    }

    bool has_room() const { return (m_available_space > MapEntry::size(1)); }

    bool is_empty() const { return (header_const()->size == sizeof(Header)); }

    void add_entry(COWBtree::CompactNodeId n, COWBtree::CompactBlkId b) {
        HS_REL_ASSERT_EQ(has_room(), true, "Calling add_entry without any room");
        if (m_cur_entry->merge_if_possible(n, b)) {
            header()->size += sizeof(COWBtree::CompactBlkId);
            m_available_space -= sizeof(COWBtree::CompactBlkId);
        } else {
            ++(header()->n_entries);
            m_cur_entry = r_cast< MapEntry* >(uintptr_cast(m_cur_entry) + m_cur_entry->size());
            m_cur_entry->merge_if_possible(n, b);

            m_available_space -= MapEntry::size(1u);
            header()->size += MapEntry::size(1u);
        }
    }

    MapEntry* next_entry() {
        MapEntry* ret_entry = m_cur_entry;
        if (m_cur_entry) {
            uint8_t* next_ptr = uintptr_cast(m_cur_entry) + m_cur_entry->size();
            m_cur_entry = (next_ptr > (m_buf.bytes() + m_buf.size())) ? nullptr : r_cast< MapEntry* >(next_ptr);
        }
        return ret_entry;
    }

    void link(BNodeMapWriteUnit& next) { header()->next_unit_location = COWBtree::CompactBlkId{next.m_location}; }

    sisl::io_blob finalize() {
        ++(header()->n_entries); // We increment as the last entry would be open until we finalize

        // Trim down the alloc size and actual blks (if we alloced them)
        auto const occupied_blks = m_location.blk_count() - (m_available_space / m_vdev->block_size());
        auto const [valid, freeable] = m_location.split(occupied_blks);
        m_vdev->free_blk(freeable);
        m_location = valid;
        m_available_space = 0;

        // Write the checksum
        header()->checksum = compute_crc();

        return sisl::io_blob{m_buf.cbytes(), valid.blk_count() * m_vdev->block_size(), true /* is_aligned */};
    }

    Header* header() { return r_cast< Header* >(m_buf.bytes()); }
    Header const* header_const() const { return r_cast< Header const* >(m_buf.cbytes()); }

    uint32_t compute_crc() const {
        return crc32_ieee(init_crc32, r_cast< const uint8_t* >(header_const()) + sizeof(Header),
                          header_const()->size - sizeof(Header));
    }

    std::string to_string() const {
        std::string str;
        auto* hdr = header_const();
        fmt::vformat_to(
            std::back_inserter(str),
            fmt::string_view{
                "\nLocation: [{}], Header: [next_unit_location:[{}], size={}, n_entries={}, checksum={}]\n"},
            fmt::make_format_args(m_location.to_string(), hdr->next_unit_location.to_compact_string(), hdr->size,
                                  hdr->n_entries, hdr->checksum));

        auto* entry = r_cast< MapEntry const* >(m_buf.cbytes() + sizeof(Header));
        for (uint32_t i{0}; i < hdr->n_entries; ++i) {
            fmt::vformat_to(
                std::back_inserter(str), fmt::string_view{"  NodeEntry{}: [ids=[{}-{}], locations:["},
                fmt::make_format_args(i, entry->nodeid_start, entry->nodeid_start + entry->nodes_count - 1));

            for (uint16_t j{0}; j < entry->nodes_count; ++j) {
                fmt::vformat_to(std::back_inserter(str), fmt::string_view{"[{}],"},
                                fmt::make_format_args(entry->nodes_locations[j].to_compact_string()));
            }
            fmt::format_to(std::back_inserter(str), "]\n");
            entry = r_cast< MapEntry const* >(r_cast< uint8_t const* >(entry) + entry->size());
        }
        return str;
    }
};

std::tuple< bool, unique< COWBtree::Journal > > COWBtree::flush_nodes(COWBtreeCPContext* cp_ctx) {
    CPSession* session = cp_session(cp_ctx->id());

    // We prepare to flush nodes, by allocating blks in vdev to accomodate all the dirty blks. Its obviously not
    // possible to put all nodes in a single huge contiguous blk. However, it tries to allocate as big as possible and
    // then pack nodes inside these blks.
    if (!session->prepare_to_flush_nodes(cp_ctx)) {
        // Already flushed the cp and moved on.
        return std::make_tuple(false, nullptr);
    }

    // 3 steps on per btree CP node flush
    //
    // Step 1: Flush all the nodes by building flush units (with each unit consists of 1 contiguous blk worth) and
    // while doing so, keep updating the in-memory map as well as adding to incremental journal with the map
    // updates.
    do {
        auto [location, mod_it, journal_area] = session->next_dirty();
        if (!location.is_valid()) {
            break; // We are done with dirty buffers
        }

        NodeFlushUnit nfunit(cp_ctx, location, journal_area);
        for (uint16_t i{0}; i < location.blk_count(); ++i) {
            FlushNodeInfo finfo{std::move(*mod_it)};
            ++mod_it;

            // Keep updating the full inmemory map of nodeid and blkid.
            // IMPORTANT NODE: We do that before actually writing the data. It is ok to do so, under the assumption that
            // there will be no reads into the bnode map while this is being flushed because nodes are cached until
            // flush is completed. If for any reason we need to support skipping cache, then we should update this bnode
            // map after it has been written. We are doing this here as an optimization to avoid looping for every node
            // and then update.
            update_bnode_map(to_compact_nodeid(finfo.node->node_id()), CompactBlkId{location, i},
                             false /* in_recovery */);
            nfunit.add(std::move(finfo));
        }

        auto err = m_vdev->sync_writev(nfunit.m_iovs.data(), int_cast(nfunit.m_iovs.size()), nfunit.m_nodes_location);
        HS_REL_ASSERT(!err, "Flush of nodes failed during cp, best is to crash the system and retry on reboot");
    } while (true);

    if (session->done_flushing_nodes()) {
        //
        // Step 2: During cp io phase, all deleted nodes are tracked, we delete them from in-memory map and also
        // build the journal with this delete operation.
        //
        auto [it, end_it, journal_area] = session->next_deleted();
        CompactNodeId* delete_jentries = r_cast< CompactNodeId* >(journal_area.bytes());
        uint32_t deleted_count = 0;
        while (it != end_it) {
            auto nodeid = *it;
            delete_from_bnode_map(nodeid, false /* in_recovery */);
            if (delete_jentries) { delete_jentries[deleted_count++] = nodeid; }
            ++it;
        }

        COWBT_PERIODIC_LOG(DEBUG, cp_ctx->id(), "Flushed {} dirty nodes and deleted {} nodes",
                           session->m_modified_count, session->m_deleted_count);
        m_bnodeid_map.m_updates_since_last_flush.fetch_add(session->m_modified_count + session->m_deleted_count);

        // If map has to be updated, we need to hold onto the session and it will be completed after that is done.
        // Otherwise, we can complete the session now (which means all dirty node list, deleted node list, journal and
        // everything has been cleaned)
        if (cp_ctx->need_full_map_flush()) {
            return std::make_tuple(session->m_modified_count || session->m_deleted_count,
                                   std::move(session->m_journal));
        } else {
            auto journal = std::move(session->m_journal);

            // Step 3: Update the new root into the journal
            auto new_root = session->new_root_id();
            if (new_root != empty_bnodeid) { journal->header()->new_root_nodeid = to_compact_nodeid(new_root); }

            bool const has_modified = session->m_modified_count || session->m_deleted_count;
            session->finish();
            return std::make_tuple(has_modified, std::move(journal));
        }
    } else {
        return std::make_tuple(false, nullptr);
    }
}

void COWBtree::flush_map(COWBtreeCPContext* cp_ctx) {
    HS_DBG_ASSERT(cp_ctx->need_full_map_flush(), "Flush map called on a cp which doesn't need full map flush");

    if (m_bnodeid_map.m_updates_since_last_flush.load() == 0) {
        COWBT_PERIODIC_LOG(DEBUG, cp_ctx->id(), "No update of the bnodeid map since last flush, so ignoring");
        return;
    }

    CPSession* session = cp_session(cp_ctx->id());
    auto const entries = session->prepare_to_flush_map(cp_ctx);
    auto count = entries.size();
    if (count == 0) { return; }

    auto it = entries.begin();

    // Worst Estimate of 1 entry per count packed in a single blk
    std::vector< BlkId > map_locations;
    map_locations.reserve((BNodeMapWriteUnit::MapEntry::size(1) * count) / m_vdev->block_size());

    auto munit = std::make_unique< BNodeMapWriteUnit >(m_vdev.get(), count);
    while (count > 0) {
        if (!munit->has_room()) {
            auto new_unit = std::make_unique< BNodeMapWriteUnit >(m_vdev.get(), count);
            munit->link(*new_unit);

            auto const blob = munit->finalize();
            COWBT_PERIODIC_LOG(TRACE, cp_ctx->id(), "Flushing a map unit: {}", munit->to_string());
            write_or_fail(m_vdev.get(), blob, munit->m_location);
            map_locations.emplace_back(munit->m_location);

            munit = std::move(new_unit);
        }
        munit->add_entry(it->first, it->second);
        ++it;
        --count;
    }

    if (!munit->is_empty()) {
        auto const blob = munit->finalize();
        COWBT_PERIODIC_LOG(TRACE, cp_ctx->id(), "Flushing a map unit: {}", munit->to_string());
        write_or_fail(m_vdev.get(), blob, munit->m_location);
        map_locations.emplace_back(munit->m_location);
    }

    auto const [done, all_map_locations] = session->done_flushing_map(std::move(map_locations), entries.size());
    if (!done) {
        // Still there are other fibers flushing the map.
        return;
    }

#ifdef _PRERELEASE
    if (iomgr_flip::instance()->test_flip("crash_during_full_map_flush", ordinal())) {
        LOGINFOMOD(btree, "Simulating crash during the full map flush on btree={}", ordinal());
        hs()->crash_simulator().start_crash();
    }
#endif

    // We are the last fiber to finish parallel flush of map, its time to update the superblk with all map locations and
    // flush the superblk and free up old map blks.
    SuperBlock& sb = cow_bt_super_blk();
    sb.num_map_heads = 0;
    sb.cp_id = cp_ctx->id();
    for (auto const& map_locs : all_map_locations) {
        sb.map_heads[sb.num_map_heads++] = map_locs[0]; // Pick head of each map locs from different fibers
    }

    // Persist the superblk now with the updated root_id
    auto root_node = session->new_root_id();
    if (root_node != empty_bnodeid) { m_base_btree.bt_super_blk().root_node_id = root_node; }
    m_base_btree.super_blk().write();
    session->finish();

    // We have completed the flush of map and now we can free up the old map blks. It is ok if system crashed after
    // persisting superblk containing new map location and before freeing this blks, because these blks are in-memory
    // bitmap, hence it will not be marked as busy upon restart.
    for (auto const& loc : m_bnodeid_map.m_locations) {
        m_vdev->free_blk(loc);
    }

    // We need to replace the previous map_locations in-memory with this new set of locations where map is written
    m_bnodeid_map.m_locations.clear();
    for (auto const& loc_array : all_map_locations) {
        m_bnodeid_map.m_locations.insert(m_bnodeid_map.m_locations.end(), loc_array.begin(), loc_array.end());
    }
    m_bnodeid_map.m_updates_since_last_flush.store(0); // Reset the count, as we just flushed the full map
}

void COWBtree::update_bnode_map(CompactNodeId nodeid, CompactBlkId cblkid, bool in_recovery) {
    auto do_update = [this](CompactNodeId nodeid, CompactBlkId cblkid) -> bool {
        auto it = m_bnodeid_map.m_map.find(nodeid);
        bool newly_inserted{false};
        if (it != m_bnodeid_map.m_map.end()) {
            m_vdev->free_blk(it->second.to_blkid());
            it->second = cblkid;
        } else {
            m_bnodeid_map.m_map.emplace(nodeid, cblkid);
            newly_inserted = true;
        }
        return newly_inserted;
    };

    if (in_recovery) {
        if (do_update(nodeid, cblkid)) { m_nodeid_generator.reserve(nodeid); }
        m_vdev->commit_blk(cblkid.to_blkid());
    } else {
        std::unique_lock< iomgr::FiberManagerLib::shared_mutex > lg(m_bnodeid_map.m_mtx);
        do_update(nodeid, cblkid);
    }
}

void COWBtree::delete_from_bnode_map(CompactNodeId nodeid, bool in_recovery) {
    auto do_delete = [this](CompactNodeId nodeid) {
        m_vdev->free_blk(lookup_bnode_map(nodeid));
        m_bnodeid_map.m_map.erase(nodeid);
        m_nodeid_generator.unreserve(nodeid);
    };

    if (in_recovery) {
        std::unique_lock< iomgr::FiberManagerLib::shared_mutex > lg(m_bnodeid_map.m_mtx);
        do_delete(nodeid);
    } else {
        do_delete(nodeid);
    }
}

BlkId COWBtree::lookup_bnode_map(CompactNodeId nodeid) const {
    std::shared_lock< iomgr::FiberManagerLib::shared_mutex > lg(m_bnodeid_map.m_mtx);
    auto const it = m_bnodeid_map.m_map.find(nodeid);
    return (it == m_bnodeid_map.m_map.cend()) ? BlkId{} : it->second.to_blkid();
}

void COWBtree::recover_bnode_map(BlkId const& map_loc) {
    // LOGINFMOD(btree, "Recovering NodeID to blkid from location=[{}]", map_loc);

    BlkId next_loc = map_loc;
    do {
        auto [ec, buf] = m_vdev->sync_read(next_loc);
        HS_REL_ASSERT(!ec, "Error while reading bnodeid map, cannot proceed further");

        m_vdev->commit_blk(next_loc);
        m_bnodeid_map.m_locations.push_back(next_loc);

        BNodeMapWriteUnit munit(m_vdev.get(), std::move(buf), next_loc);
        for (uint32_t i{0}; i < munit.header()->n_entries; ++i) {
            BNodeMapWriteUnit::MapEntry* e = munit.next_entry();
            for (uint32_t n{0}; n < e->nodes_count; ++n) {
                update_bnode_map(e->nodeid_start + n, e->nodes_locations[n], true /* in_recovery */);
            }
        }
        next_loc = munit.header()->next_unit_location.to_blkid();
    } while (next_loc.is_valid());
}

uint32_t COWBtree::align_size() const { return m_vdev->align_size(); }

void COWBtree::apply_incremental_map(Journal& journal) {
    auto jhdr = journal.header();
    HS_REL_ASSERT_EQ(jhdr->ordinal, m_btree_ordinal, "Btree Ordinal mismatch between journal and in-memory");

    // If the full map recovered already have recorded this cp_id, we should skip these journals
    if (journal.m_cp_id <= cow_bt_super_blk().cp_id) {
        SPECIFIC_BT_LOG(INFO, m_base_btree,
                        "Btree journal for cp_id={} is SKIPPED, because full map already recovered with cp_id={}",
                        journal.m_cp_id, cow_bt_super_blk().cp_id);
        return;
    }

    if (jhdr->new_root_nodeid != EmptyCompactNodeId) {
        // Root was changed in this incremental map.
        m_root_node_id = m_ordinal_shifted | jhdr->new_root_nodeid;
    }

    for (uint32_t i{0}; i < jhdr->num_flush_units; ++i) {
        NodeFlushUnit::JournalEntry const* nf_jentry = r_cast< NodeFlushUnit::JournalEntry const* >(journal.m_cur_ptr);
        BlkId const location = nf_jentry->nodes_location.to_blkid();
        for (uint16_t n{0}; n < nf_jentry->n_nodes; ++n) {
            update_bnode_map(nf_jentry->nodes[n], CompactBlkId{location, n}, true /* in_recovery */);
        }
        journal.m_cur_ptr += nf_jentry->size();
    }

    auto* deleted_nodes = r_cast< CompactNodeId const* >(journal.m_cur_ptr);
    for (uint32_t i{0}; i < jhdr->num_delete_units; ++i) {
        delete_from_bnode_map(deleted_nodes[i], true /* in_recovery */);
    }
}

COWBtree::CPSession* COWBtree::cp_session(cp_id_t cp_id) {
    COWBtree::CPSession* session = m_cp_sessions[cp_id % CPManager::max_concurent_cps].get();
    if (sisl_unlikely(session->m_cp_id != cp_id)) {
        session->m_state = CPSession::FlushState::DIRTYING;
        session->m_cp_id = cp_id;
    }
    return session;
}

#if 0
FlushNodeInfo COWBtree::get_flush_version_buf(BtreeNodePtr node, cp_id_t cur_cp_id) {
    auto [ret_buf, buf_share_count] = node->share_phys_node_buf();

    if (buf_share_count != 0) {
        // Buffer was already shared with another cp session, we need to make a copy
        HS_DBG_ASSERT_EQ(node->get_modified_cp_id(), cur_cp_id - 1,
                         "We have shared buffer of node with cp, but its cp modified id is more than 1, we only "
                         "support 2 concurrent cp sessions");
        auto new_buf = hs_utils::iobuf_alloc(node->node_size(), sisl::buftag::btree_node, align_size());
        std::memcpy(new_buf, ret_buf, node->node_size());
        ret_buf = new_buf;
        node->set_phys_node_buf(new_buf);
    }

    node->set_modified_cp_id(cur_cp_id);
    return FlushNodeInfo{std::move(node), ret_buf};
}

void COWBtree::release_flush_version_buf(FlushNodeInfo const& f) {
    auto const buf_share_count = f->node->release_phys_node_buf();
    if (buf_share_count > 1) {
        // Some other cp session already has made a copy and updated the phys_node buf, so we need to free this buffer
        hs_utils::io_buf_free(f->buf, sisl::bufag::btree_node);
    }
}
#endif

////////////////////////////////////////////// CPSession Section //////////////////////////////////////////////
bool COWBtree::CPSession::prepare_to_flush_nodes(COWBtreeCPContext* cp_ctx) {
    std::lock_guard lg{m_flush_mtx};

    if (m_state == FlushState::NODES_FLUSHED) {
        return false; // Bail out if we have already flushed this session
    } else if (m_state == FlushState::NODES_FLUSHING) {
        ++m_flushing_req_count;
        return true; // Everything is prepared already, join the flush
    }

    m_modified_count = m_modified_nodes.size();
    m_deleted_count = m_deleted_nodes.size();

    if ((m_modified_count == 0) & (m_deleted_count == 0)) {
        // Nothing has been dirtied in this btree in this session to flush.
        m_state = FlushState::NODES_FLUSHED;
        return false;
    }

    auto const status =
        m_bt.m_vdev->alloc_blks(m_modified_count, blk_alloc_hints{.partial_alloc_ok = true}, m_node_locations);
    if ((status != BlkAllocStatus::SUCCESS) && (status != BlkAllocStatus::PARTIAL)) {
        HS_REL_ASSERT(false, "Blk allocation to persist btree pages failed, we are crashing for now");
    }

    // Setup all the iterators
    m_next_location_idx = 0;
    m_modified_it = m_modified_nodes.begin();
    m_deleted_it = m_deleted_nodes.begin();

    if (!cp_ctx->need_full_map_flush()) {
        // Setup the journal buffers
        // Size deterimination:
        // One location which is a blkid corresponds to 1 flush unit, so total journal size would be
        // Journal Header + (Number of flush units * Flush unit header) + Number of nodes + Number of deleted nodes
        auto const journal_size = sizeof(Journal::Header) +
            (NodeFlushUnit::JournalEntry::size(0) * m_node_locations.size()) +
            ((m_modified_count + m_deleted_count) * sizeof(CompactNodeId));
        m_journal = std::make_unique< Journal >(m_bt.m_btree_ordinal, journal_size, cp_ctx->id());
        m_journal->header()->num_flush_units = m_node_locations.size();
        m_journal->header()->num_delete_units = m_deleted_count;
    }

    m_state = FlushState::NODES_FLUSHING;
    ++m_flushing_req_count;
    return true;
}

std::tuple< BlkId, COWBtree::DirtyNodeList::iterator, sisl::blob > COWBtree::CPSession::next_dirty() {
    std::lock_guard lg{m_flush_mtx};
    HS_DBG_ASSERT_EQ(m_state, FlushState::NODES_FLUSHING,
                     "Unexpected state while pulling a dirty nodes, we expect all fibers have drained the iterator "
                     "before moving to flushed or collecting state");

    sisl::blob ret_blob;
    if (m_next_location_idx == m_node_locations.size()) {
        // We have reached the end of all nodes location's, which means there should be no more dirty
        HS_DBG_ASSERT(m_modified_it == m_modified_nodes.end(),
                      "Mismatch between number of blks allocated for node and dirty node iterator");
        return std::make_tuple(BlkId{}, m_modified_it, ret_blob);
    }

    HS_DBG_ASSERT(
        m_modified_it != m_modified_nodes.end(),
        "There are more blks allocated for nodes, but the dirty list doesn't have anymore node to fill it in");

    BlkId ret_loc = m_node_locations[m_next_location_idx++];
    auto ret_it = m_modified_it;
    m_modified_it += ret_loc.blk_count(); // Move the iterator past the blk_count().

    if (m_journal) {
        auto junit_size = NodeFlushUnit::JournalEntry::size(ret_loc.blk_count());
        ret_blob = sisl::blob{m_journal->allocate(junit_size), junit_size};
    }
    return std::make_tuple(ret_loc, ret_it, ret_blob);
}

std::tuple< COWBtree::DeletedNodeList::iterator, COWBtree::DeletedNodeList::iterator, sisl::blob >
COWBtree::CPSession::next_deleted() {
    std::lock_guard lg{m_flush_mtx};
    HS_DBG_ASSERT_EQ(m_state, FlushState::NODES_FLUSHED,
                     "Unexpected state while pulling a dirty nodes, we expect all fibers have drained the iterator "
                     "before moving to flushed or collecting state");
    auto ret_it = m_deleted_it;
    m_deleted_it = m_deleted_nodes.end(); // Set to end, so that any subsequent requests will get ret_it as end iterator

    sisl::blob ret_blob;
    if (m_journal) {
        uint32_t const jdel_size = m_deleted_count * sizeof(CompactNodeId);
        ret_blob = sisl::blob{m_journal->allocate(jdel_size), jdel_size};
    }
    return std::make_tuple(std::move(ret_it), m_deleted_nodes.end(), std::move(ret_blob));
}

bnodeid_t COWBtree::CPSession::new_root_id() { return m_new_root_id.exchange(empty_bnodeid); }

bool COWBtree::CPSession::done_flushing_nodes() {
    std::lock_guard lg{m_flush_mtx};
    HS_DBG_ASSERT_EQ(m_state, FlushState::NODES_FLUSHING,
                     "Received a flush done while state was not in flushing, some race condition?");
    if (--m_flushing_req_count == 0) {
        m_state = FlushState::NODES_FLUSHED;
        return true;
    }
    return false;
}

std::vector< std::pair< COWBtree::CompactNodeId, COWBtree::CompactBlkId > >
COWBtree::CPSession::prepare_to_flush_map(COWBtreeCPContext* cp_ctx) {
    std::lock_guard lg{m_flush_mtx};

    auto to_vector = [this](uint64_t count) {
        std::vector< std::pair< COWBtree::CompactNodeId, COWBtree::CompactBlkId > > ret;
        ret.reserve(count);
        for (uint32_t i{0}; ((i < count) && (m_next_full_map_it != m_bt.m_bnodeid_map.m_map.end()));
             ++m_next_full_map_it, ++i) {
            ret.emplace_back(*m_next_full_map_it);
        }
        return ret;
    };

    if (m_state == FlushState::MAP_FLUSHING) {
        // Some other fiber has started the flushing, get the next range of maps and iterate over and start flushing
        return to_vector(m_parallel_flush_range);
    } else if (m_state != FlushState::NODES_FLUSHED) {
        // The nodes themselves have not been flushed or we have already finished flushing map, so we don't need to
        // anything now
        HS_DBG_ASSERT(m_next_full_map_it == m_bt.m_bnodeid_map.m_map.end(),
                      "In {} state, but outstanding count is non zero", m_state);
        return {};
    } else {
        // First fiber to start flushing, prepare the iterator. First flusher wll also get reminder of range also
        m_state = FlushState::MAP_FLUSHING;

        // First fiber to flush the full map in this session. All fibers get equal portion to flush except the first
        // one which gets additional
        auto const total_count = m_bt.m_bnodeid_map.m_map.size();
        m_pending_map_entries_to_flush = total_count;
        m_parallel_flush_range = total_count / cp_ctx->m_parallel_flushers_count;
        m_next_full_map_it = m_bt.m_bnodeid_map.m_map.begin();
        return to_vector(m_parallel_flush_range + (total_count % cp_ctx->m_parallel_flushers_count));
    }
}

std::pair< bool, std::vector< std::vector< BlkId > > >
COWBtree::CPSession::done_flushing_map(std::vector< BlkId > map_locations, size_t num_flushed_entries) {
    std::lock_guard lg{m_flush_mtx};
    HS_DBG_ASSERT_EQ(m_state, FlushState::MAP_FLUSHING,
                     "Received a flush done while state was not in flushing, some race condition?");

    if (!map_locations.empty()) { m_location_chains.emplace_back(std::move(map_locations)); }
    m_pending_map_entries_to_flush -= num_flushed_entries;

    if (m_pending_map_entries_to_flush > 0) { return std::pair(false, std::vector< std::vector< BlkId > >{}); }
    HS_DBG_ASSERT(m_next_full_map_it == m_bt.m_bnodeid_map.m_map.end(),
                  "We have no pending fibers flushing map, but the iterator has not pointing to end");

    m_state = FlushState::MAP_FLUSHED;
    return std::pair(true, std::move(m_location_chains));
}

void COWBtree::CPSession::finish() {
    std::lock_guard lg{m_flush_mtx};
    m_modified_nodes.clear();
    m_deleted_nodes.clear();
    m_new_root_id.store(empty_bnodeid);
    m_state = FlushState::ALL_DONE;
    m_flushing_req_count = 0;

    m_node_locations.clear();
    m_next_location_idx = 0;
    m_modified_it = DirtyNodeList::iterator{};
    m_deleted_it = DeletedNodeList::iterator{};
    m_modified_count = 0;
    m_deleted_count = 0;
    m_journal.reset();

    m_next_full_map_it = m_bt.m_bnodeid_map.m_map.end();
    m_parallel_flush_range = 0;
    m_location_chains.clear();
}
} // namespace homestore