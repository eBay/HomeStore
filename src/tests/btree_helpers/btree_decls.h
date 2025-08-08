
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

#include <homestore/index_service.hpp>
#include <homestore/btree/detail/btree_internal.hpp>

template < IndexStore::Type StoreType >
struct FixedLenBtree {
    using BtreeType = Btree< TestFixedKey, TestFixedValue >;
    using KeyType = TestFixedKey;
    using ValueType = TestFixedValue;
    static constexpr btree_node_type leaf_node_type = btree_node_type::FIXED;
    static constexpr btree_node_type interior_node_type = btree_node_type::FIXED;
    static constexpr IndexStore::Type store_type = StoreType;
};

template < IndexStore::Type StoreType >
struct VarKeySizeBtree {
    using BtreeType = Btree< TestVarLenKey, TestFixedValue >;
    using KeyType = TestVarLenKey;
    using ValueType = TestFixedValue;
    static constexpr btree_node_type leaf_node_type = btree_node_type::VAR_KEY;
    static constexpr btree_node_type interior_node_type = btree_node_type::VAR_KEY;
    static constexpr IndexStore::Type store_type = StoreType;
};

template < IndexStore::Type StoreType >
struct VarValueSizeBtree {
    using BtreeType = Btree< TestFixedKey, TestVarLenValue >;
    using KeyType = TestFixedKey;
    using ValueType = TestVarLenValue;
    static constexpr btree_node_type leaf_node_type = btree_node_type::VAR_VALUE;
    static constexpr btree_node_type interior_node_type = btree_node_type::FIXED;
    static constexpr IndexStore::Type store_type = StoreType;
};

template < IndexStore::Type StoreType >
struct VarObjSizeBtree {
    using BtreeType = Btree< TestVarLenKey, TestVarLenValue >;
    using KeyType = TestVarLenKey;
    using ValueType = TestVarLenValue;
    static constexpr btree_node_type leaf_node_type = btree_node_type::VAR_OBJECT;
    static constexpr btree_node_type interior_node_type = btree_node_type::VAR_KEY;
    static constexpr IndexStore::Type store_type = StoreType;
};

template < IndexStore::Type StoreType >
struct PrefixIntervalBtree {
    using BtreeType = Btree< TestIntervalKey, TestIntervalValue >;
    using KeyType = TestIntervalKey;
    using ValueType = TestIntervalValue;
    static constexpr btree_node_type leaf_node_type = btree_node_type::FIXED_PREFIX;
    static constexpr btree_node_type interior_node_type = btree_node_type::FIXED;
    static constexpr IndexStore::Type store_type = StoreType;
};