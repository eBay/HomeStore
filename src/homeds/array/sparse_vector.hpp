//
// Created by Kadayam, Hari on 30/11/17.
//

#ifndef OMSTORE_AVECTOR_HPP_HPP
#define OMSTORE_AVECTOR_HPP_HPP

#include <vector>
#include <boost/optional.hpp>
namespace homeds {

template <typename T>
class sparse_vector : public std::vector <T > {
public:
    T& operator[] (const int index) {
        fill_void(index);
        return std::vector<T>::operator[](index);
    }

    T& at(const int index) {
        fill_void(index);
        return std::vector<T>::at(index);
    }

    const T& operator[] (const int index) const {
        assert(index < std::vector<T>::size());
        return std::vector<T>::operator[](index);
    }

    const T& at(const int index) const {
        return std::vector<T>::at(index);
    }

private:
    void fill_void(const int index) {
        for (auto i = std::vector<T>::size(); i <= index; i++) {
            std::vector<T>::emplace_back();
        }
    }
};
}
#endif //OMSTORE_AVECTOR_HPP_HPP
