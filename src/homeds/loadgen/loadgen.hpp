//
// Created by Kadayam, Hari on 2/22/19.
//

#ifndef HOMESTORE_LOADGEN_HPP
#define HOMESTORE_LOADGEN_HPP

#include "loadgen_common.hpp"
#include "keyset.hpp"

namespace homeds {
namespace loadgen {

template < typename V >
class LoadGenValue {
public:
    LoadGenValue() : m_exists(false) {}

private:
    bool m_exists;
};

template < typename K, typename V, typename Store >
class KVGenerator {
public:
    KVGenerator(const std::shared_ptr< Store > &store) : m_store(store) {}

    void register_keyset(const std::shared_ptr< KeySet < K > >& ks) {
        std::unique_lock< std::mutex >(m_rwlock);
        m_keysets.push_back(ks);
    }

    void unregister_keyset(const std::shared_ptr< KeySet < K > >& ks) {
        std::unique_lock< std::mutex >(m_rwlock);
        m_keysets.remove(ks);
    }

    std::vector< K* > generate_keys(const std::shared_ptr< KeySet< K > >& ks, KeyPattern gen_pattern, uint32_t n = 1) {
        return ks->generate_keys(gen_pattern, n);
    }

    // TODO: Do Value as well.
    void put_kv(const std::vector< K* >& keys) {
        for (auto &k : keys) {
            m_data_map.insert(k);
        }
    }

    std::vector< K* > get_kv() {

    }

private:
    std::shared_mutex                             m_rwlock;
    std::vector< std::shared_ptr< KeySet< K > > > m_keysets;
    std::map< K*, LoadGenValue< V > >             m_data_map;
    std::shared_ptr< Store >                      m_store;
};
} // namespace loadgen
} // namespace homeds

#endif // HOMESTORE_LOADGEN_HPP
