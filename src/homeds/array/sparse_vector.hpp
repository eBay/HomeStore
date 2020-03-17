//
// Created by Kadayam, Hari on 30/11/17.
//

#pragma once

#include <vector>
namespace homeds {

template < typename T >
class sparse_vector : public std::vector< T > {
public:
    T& operator[](const size_t index) {
        fill_void(index);
        return std::vector< T >::operator[](index);
    }

    T& at(const size_t index) {
        fill_void(index);
        return std::vector< T >::at(index);
    }

    const T& operator[](const size_t index) const {
        assert(index < std::vector< T >::size());
        return std::vector< T >::operator[](index);
    }

    const T& at(const size_t index) const { return std::vector< T >::at(index); }

private:
    void fill_void(const size_t index) {
        for (auto i = std::vector< T >::size(); i <= index; i++) {
            std::vector< T >::emplace_back();
        }
    }
};
} // namespace homeds
