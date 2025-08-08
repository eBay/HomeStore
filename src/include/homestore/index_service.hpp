/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *    https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 *********************************************************************************/
#pragma once
#include <memory>
#include <unordered_map>
#include <vector>
#include <array>

#include <folly/futures/Future.h>
#include <iomgr/iomgr.hpp>
#include <sisl/fds/id_reserver.hpp>
#include <sisl/utility/enum.hpp>
#include <homestore/homestore_decl.hpp>
#include <homestore/superblk_handler.hpp>
#include <homestore/index/index_common.h>
#include <homestore/homestore.hpp>

namespace homestore {

class Index;
class VirtualDev;

#pragma pack(1)
struct IndexSuperBlock {
    static constexpr uint64_t indx_sb_magic{0xbedabb1e};
    static constexpr uint32_t indx_sb_version{0x3};

    // Common Area for all index implementations
    uint64_t magic{indx_sb_magic};
    uint32_t version{indx_sb_version};
    uuid_t uuid;                       // UUID of the index
    uuid_t parent_uuid;                // UUID of the parent container of index (controlled by user)
    uint32_t ordinal;                  // Ordinal of the Index (unique within the homestore instance)
    IndexStore::Type index_store_type; // Underlying store type for this index

    static constexpr size_t index_impl_sb_size = 512;
    std::array< uint8_t, index_impl_sb_size > underlying_index_sb;

    // User area of the superblock, which can be updated with cp guard.
    uint32_t user_sb_size;    // Size of the user superblk
    uint8_t user_sb_bytes[0]; // Raw bytes of the sb. Better to access with helper routine below

    sisl::blob user_sb() { return sisl::blob{&user_sb_bytes[0], user_sb_size}; }
};

struct IndexStoreSuperBlock {
    IndexStore::Type index_store_type;
};

#pragma pack()

class IndexServiceCallbacks {
public:
    virtual ~IndexServiceCallbacks() = default;
    virtual shared< Index > on_index_table_found(superblk< IndexSuperBlock >&&) {
        assert(0);
        return nullptr;
    }
};

class Index : public std::enable_shared_from_this< Index > {
protected:
    bool const m_is_ephemeral; // Is it a persistent btree?
    superblk< IndexSuperBlock > m_sb;

public:
    Index(bool is_ephermal) : m_is_ephemeral{is_ephermal}, m_sb{"index_table"} {}
    virtual ~Index() = default;

    bool is_ephemeral() const { return m_is_ephemeral; }

    // Destroys the index and remove all its resources. This could be delayed call as in actual destroy could
    // potentially takes place in subsequent checkpoints. Hence caller should not assume that destroy is completed
    // instantly. This is an idempotent call and the implementer of this method needs to support that.
    virtual folly::Future< folly::Unit > destroy() = 0;

    // Getters
    uuid_t uuid() const { return m_sb->uuid; }
    virtual uint64_t space_occupied() const = 0;
    virtual uint32_t ordinal() const = 0;

    superblk< IndexSuperBlock > const& super_blk() const { return m_sb; }
    superblk< IndexSuperBlock >& super_blk() {
        return const_cast< superblk< IndexSuperBlock >& >(s_cast< const Index* >(this)->super_blk());
    }
};

class IndexService {
private:
    unique< IndexServiceCallbacks > m_svc_cbs;
    std::unordered_map< ServiceSubType, shared< VirtualDev > > m_vdevs;
    std::vector< superblk< IndexSuperBlock > > m_index_sbs;
    std::vector< superblk< IndexStoreSuperBlock > > m_store_sbs;
    unique< sisl::IDReserver > m_ordinal_reserver;
    std::unordered_map< IndexStore::Type, shared< IndexStore > > m_index_stores;

    mutable std::shared_mutex m_index_map_mtx;
    std::map< uuid_t, shared< Index > > m_index_map;
    std::unordered_map< uint32_t, shared< Index > > m_ordinal_index_map;

public:
    IndexService(unique< IndexServiceCallbacks > cbs, std::vector< ServiceSubType > const& sub_types);

    // Creates the vdev that is needed to initialize the device
    void create_vdev(ServiceSubType sub_type, uint64_t size, HSDevType devType, uint32_t num_chunks);

    // Open the existing vdev which is represnted by the vdev_info_block
    shared< VirtualDev > open_vdev(ServiceSubType sub_type, const vdev_info& vb, bool load_existing);

    // Start the Index Service
    void start();

    // Stop the Index Service
    void stop();

    // Add/Remove Index Table to/from the index service
    void add_index_table(shared< Index > const& tbl);
    folly::Future< folly::Unit > destroy_index_table(shared< Index > const& tbl);

    shared< Index > get_index_table(uuid_t uuid) const;
    shared< Index > get_index_table(uint32_t ordinal) const;
    std::vector< shared< Index > > get_all_index_tables() const;

    IndexStore* lookup_store(IndexStore::Type store_type);
    uint64_t space_occupied() const;
    uint32_t reserve_ordinal();

    shared< IndexStore > lookup_or_create_store(IndexStore::Type store_type,
                                                std::vector< superblk< IndexStoreSuperBlock > > sbs);

private:
    shared< VirtualDev > get_vdev(ServiceSubType sub_type);
};

extern IndexService& index_service();

} // namespace homestore
