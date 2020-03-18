//
// Created by Kadayam, Hari on 30/11/17.
//

#pragma once

#include <vector>
namespace homeds {

template < typename T, size_t ReserveCount >
class reserve_vector : public std::vector< T > {
public:
    reserve_vector() : std::vector< T >() { std::vector< T >::reserve(ReserveCount); }
};
} // namespace homeds
