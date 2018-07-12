/**
 * Copyright eBay Inc 2018
 */

#ifndef DYNAMIC_ARRAY_DS_H_
#define DYNAMIC_ARRAY_DS_H_


namespace homeds {

#include <cstring>
#include "malloc.h"
#include <assert.h>
#include <string.h>

    //TODO - MAKE CLASS THREAD SAFE

    /**
     * Array that grows in size as needed(Contigious memory). But never degrows.
     * @tparam T - class of element that array will hold
     */
    template<typename T>
    class Dynamic_Array {
    private:
        T *array;
        int size;
        int capacity;
        float load_factor;
        float growth_rate;
    public:

        Dynamic_Array(int initial_capacity, float load_factor, float growth_rate);

        ~Dynamic_Array();

        void insert_shift(int pos, T element);

        void remove_shift(int pos);

        int get_size();

        T& operator[](int pos);

        enum exception {
            MEMFAIL
        };
    private:
        void resize_array();

        bool is_resize_required();
    };

    template<typename T>
    Dynamic_Array<T>::Dynamic_Array(int initial_capacity, float load_factor, float growth_rate):capacity(
            initial_capacity), load_factor(load_factor), growth_rate(growth_rate) {
        if (load_factor < 0 || load_factor > 1 || growth_rate > 1 || growth_rate < 0) assert(0);
        array = (T *) malloc(initial_capacity * sizeof(T));
        if (array == NULL)
            throw MEMFAIL;
        size = initial_capacity;
    }

    template<typename T>
    Dynamic_Array<T>::~Dynamic_Array() {
        if (array) {
            free(array);
            array = NULL;
        }
    }

    template<typename T>
    int Dynamic_Array<T>::get_size() {
        return size;
    }

    template<typename T>
    void Dynamic_Array<T>::remove_shift(int pos) {
        if (pos >= size || pos < 0) assert(0);
        memmove(array + pos + 1, array + pos, size - pos - 1);
        size--;
    }

    template<typename T>
    void Dynamic_Array<T>::insert_shift(int pos, T element) {
        if (pos >= size || pos < 0) assert(0);
        if (is_resize_required()) {
            resize_array();
        }
        memmove(array + pos + 1, array + pos, size - pos);
        size++;
    }

    template<class T>
    T &Dynamic_Array<T>::operator[](int pos) {
        if (pos >= size || pos < 0) assert(0);
        return *(array + pos);
    }

    template<class T>
    bool Dynamic_Array<T>::is_resize_required() {
        if (size / capacity >= load_factor) return true;
        else return false;
    }

    template<class T>
    void Dynamic_Array<T>::resize_array() {
        int new_capacity = capacity + capacity*growth_rate;
        T *new_array = (T *) malloc(new_capacity * sizeof(T));
        memcpy(new_array, array, size);
        free(array);
        array= new_array;
    }
}

#endif