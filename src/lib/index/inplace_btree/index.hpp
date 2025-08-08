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

#include <vector>
#include <atomic>
#include <homestore/superblk_handler.hpp>
#include <homestore/homestore_decl.hpp>

namespace homestore {

using bnodeid_t = uint64_t;
class IndexTableBase;

#pragma pack(1)
struct index_table_sb {
    uint64_t magic{indx_sb_magic};
    uint32_t version{indx_sb_version};
    uuid_t uuid;        // UUID of the index
    uuid_t parent_uuid; // UUID of the parent container of index (controlled by user)

    // Btree Section
    bnodeid_t root_node{empty_bnodeid}; // Root Node ID
    uint64_t root_link_version{0};      // Link version to btree root node
    int64_t index_size{0};              // Size of the Index
    // seq_id_t last_seq_id{-1};           // TODO: See if this is needed

    uint32_t ordinal{0}; // Ordinal of the Index

    uint32_t user_sb_size; // Size of the user superblk
    uint8_t user_sb_bytes[0];
};
#pragma pack()

class IndexStoreBase;

// This class represents base abstract class of an Index. At present btree is the only implementation of Index
class Index {
private:
    superblk< IndexSuperBlock > m_sb;
    bool const m_is_ephemeral;

public:
    Index(bool is_ephermal) : m_is_ephemeral{is_ephermal} {}
    virtual bool is_ephemeral() const { return m_is_ephemeral; }
    virtual uuid_t uuid() const override { return m_sb->uuid; }
    virtual superblk< index_table_sb >& mutable_super_blk() { return m_sb; }
    virtual const superblk< index_table_sb >& mutable_super_blk() const { return m_sb; }
};

} // namespace homestore
