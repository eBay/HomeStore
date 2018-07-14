/**
 * Copyright eBay Inc 2018
 */

#ifndef SORTED_DYNAMIC_ARRAY_DS_H_
#define SORTED_DYNAMIC_ARRAY_DS_H_

#include <stdint.h>
#include <cassert>
#include <iostream>
#include <cstring>
#include <assert.h>


namespace homeds {


#define SortedDynamicArrayType typename ElementType, int INITIAL_CAPACITY, int LOAD_PERCENT, int GROWTH_PERCENT
#define SortedDynamicArrayTypeParams ElementType, INITIAL_CAPACITY, LOAD_PERCENT, GROWTH_PERCENT

    //TODO - MAKE CLASS THREAD SAFE

    /**
     * Array that grows in size as needed(Contigious memory). But never degrows.
     * It always keeps all elements sorted. Element type needs to have compare operator defined.
     * @tparam T - class of element that array will hold
     */
    template<SortedDynamicArrayType>
    class Sorted_Dynamic_Array {
    private:
        ElementType *m_array;
        uint64_t m_size;
    public:
        Sorted_Dynamic_Array();

        Sorted_Dynamic_Array(void *array, uint64_t size);

        ~Sorted_Dynamic_Array();

        //add element into array
        void add(ElementType element);

        //removes element into array
        void remove(ElementType element);

        int get_size() const;

        ElementType &operator[](int pos);

        ElementType *get_mem(void) const;

        void set_mem(void *array, uint64_t size);

        int get_no_of_elements() const;

        enum exception {
            MEMFAIL
        };

        std::string get_string_representation();

    private:
        //resizes array based on growth percent
        void resize_array();

        //checks load perce t and determines if resize needed
        bool is_resize_required();

        //right shifts all elements from pos to pos+1. And sets element at pos.
        void insert_shift(int pos, ElementType element);

        //removes element at pos and left shifts all succeding elements
        void remove_shift(int pos);

        // if found - returns +ve index of element
        // if not found - returns -ve index where element should be inserted
        int binary_search(ElementType element);

        //update element in place
        void update(int pos, ElementType element);

    };

    template<SortedDynamicArrayType>
    Sorted_Dynamic_Array<SortedDynamicArrayTypeParams>::Sorted_Dynamic_Array() {
        this->m_size = INITIAL_CAPACITY * sizeof(ElementType);
        this->m_array = (ElementType *) malloc(m_size);
    }

    template<SortedDynamicArrayType>
    Sorted_Dynamic_Array<SortedDynamicArrayTypeParams>::Sorted_Dynamic_Array(void *array, uint64_t size) {
        m_array = malloc(size);
        memcpy(m_array, array, size);
        m_size = size;
    }

    template<SortedDynamicArrayType>
    void Sorted_Dynamic_Array<SortedDynamicArrayTypeParams>::set_mem(void *array, uint64_t size) {
        this->m_array = array;
        this->m_size = size;
    }

    template<SortedDynamicArrayType>
    Sorted_Dynamic_Array<SortedDynamicArrayTypeParams>::~Sorted_Dynamic_Array() {
        if (m_array) {
            free(m_array);
            m_array = NULL;
        }
    }

    template<SortedDynamicArrayType>
    int
    Sorted_Dynamic_Array<SortedDynamicArrayTypeParams>::get_size() const {
        return m_size;
    }

    template<SortedDynamicArrayType>
    int
    Sorted_Dynamic_Array<SortedDynamicArrayTypeParams>::get_no_of_elements() const {
        return m_size / sizeof(ElementType);
    }

    template<SortedDynamicArrayType>
    void
    Sorted_Dynamic_Array<SortedDynamicArrayTypeParams>::add(ElementType element) {
        int pos = binary_search(element);
        if (pos < 0)
            insert_shift(pos, element);
        else
            update(pos, element);
    }

    template<SortedDynamicArrayType>
    void
    Sorted_Dynamic_Array<SortedDynamicArrayTypeParams>::remove(ElementType element) {

    }

    template<typename ElementType, int INITIAL_CAPACITY, int LOAD_PERCENT, int GROWTH_PERCENT>
    ElementType
    &Sorted_Dynamic_Array<SortedDynamicArrayTypeParams>::operator[](int pos) {
        int m_no_of_elements = m_size / sizeof(ElementType);
        if (pos >= m_no_of_elements || pos < 0) assert(0);
        return *(m_array + pos);
    }

    template<typename ElementType, int INITIAL_CAPACITY, int LOAD_PERCENT, int GROWTH_PERCENT>
    bool
    Sorted_Dynamic_Array<SortedDynamicArrayTypeParams>::is_resize_required() {
        int m_no_of_elements = m_size / sizeof(ElementType);
        if (m_no_of_elements / INITIAL_CAPACITY >= LOAD_PERCENT) return true;
        else return false;
    }

    template<SortedDynamicArrayType>
    void
    Sorted_Dynamic_Array<SortedDynamicArrayTypeParams>::resize_array() {
        int m_no_of_elements = m_size / sizeof(ElementType);
        int new_capacity = INITIAL_CAPACITY + INITIAL_CAPACITY * GROWTH_PERCENT;
        ElementType *new_array = (ElementType *) malloc(new_capacity * sizeof(ElementType));
        memcpy(new_array, m_array, m_no_of_elements);
        free(m_array);
        m_array = new_array;
    }

    template<SortedDynamicArrayType>
    int
    Sorted_Dynamic_Array<SortedDynamicArrayTypeParams>::binary_search() {
        return 0;
    }

    template<SortedDynamicArrayType>
    void
    Sorted_Dynamic_Array<SortedDynamicArrayTypeParams>::remove_shift(int pos) {
        int m_no_of_elements = m_size / sizeof(ElementType);
        if (pos >= m_no_of_elements || pos < 0) assert(0);
        memmove(m_array + pos + 1, m_array + pos, m_no_of_elements - pos - 1);
    }

    template<SortedDynamicArrayType>
    void
    Sorted_Dynamic_Array<SortedDynamicArrayTypeParams>::insert_shift(int pos, ElementType element) {
        int m_no_of_elements = m_size / sizeof(ElementType);
        if (pos >= m_no_of_elements || pos < 0) assert(0);
        if (is_resize_required()) {
            resize_array();
        }
        memmove(m_array + pos + 1, m_array + pos, m_no_of_elements - pos);
    }

    template<SortedDynamicArrayType>
    void
    Sorted_Dynamic_Array<SortedDynamicArrayTypeParams>::update(int pos, ElementType element) {

    }

    template<SortedDynamicArrayType>
    ElementType *Sorted_Dynamic_Array<SortedDynamicArrayTypeParams>::get_mem(void) const {
        return (void *) m_array;
    }

    template<SortedDynamicArrayType>
    std::string
    Sorted_Dynamic_Array<SortedDynamicArrayTypeParams>::get_string_representation() {
        return std::__cxx11::string();
    }
}

#endif