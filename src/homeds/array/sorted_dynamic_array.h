/**
 * Copyright eBay Inc 2018
 */

#ifndef SORTED_DYNAMIC_ARRAY_DS_H_
#define SORTED_DYNAMIC_ARRAY_DS_H_

#define SortedDynamicArrayType typename ElementType, uint8_t LOAD_PERCENT, uint8_t GROWTH_PERCENT
#define SortedDynamicArrayTypeParams ElementType, LOAD_PERCENT, GROWTH_PERCENT

#include <stdint.h>
#include <cassert>
#include <iostream>
#include <cstring>
#include <assert.h>
#include <sstream>
#include <mutex>

namespace homeds {

    /**
     * Sorted set data structure which can work on supplied memory location OR can create its own and work on it.
     * Its internally represeneted as array, that grows in size as needed(Contigious memory). But never degrows.
     * It always keeps all elements sorted. ElementType needs to have compare and to_string operator defined.
     * 
     * Internal format of *m_mem
     *      |header ElementType0 ElementType1 ElementType2/
     */
    template<SortedDynamicArrayType>
    class Sorted_Dynamic_Array {

    public:
        //allocates new memory for no_of elements
        Sorted_Dynamic_Array(uint32_t no_of_elements_capacity);

        //Copy constructor
        Sorted_Dynamic_Array(void *array, uint64_t size);

        ~Sorted_Dynamic_Array();

        ElementType* get(ElementType* element);

        //add element into array - returns true if added, false if just updated
        bool addOrUpdate(ElementType* element);

        //removes element into array
        void removeIfPresent(ElementType* element);

        uint32_t get_size() const;

        //view only - index based access
        ElementType operator[](uint32_t pos);

        ElementType *get_mem(void) const;

        void set_mem(void *array, uint64_t size);

        uint32_t get_no_of_elements_filled() const;

        uint32_t get_no_of_elements_total() const;

        enum exception {
            MEMFAIL
        };

        //Get internal representation as string to print
        std::string get_string_representation() const;

    private:
        void *m_mem; // actual memory where entire data structure is stored

        struct header {
            uint32_t m_no_of_elements_filled;// how many elements already filled in array from left to right
        };

        //----Transient derieved member - START  ----//
        // TODO - It might make sense to have mutex part of acutal memory *m_mem
        // TODO - This way, this memory array served by multiple dynamic_array instances are safe gaurded
        std::recursive_mutex m_mutex;
        uint64_t m_size; // total size(no of bytes) of array including non-filled elements
        header *m_header; // pointer to header
        ElementType *m_elements; // pointer to first element in array
        uint32_t sizeOfElement = sizeof(ElementType);
        uint32_t m_no_of_elements_total;// total # of elements

        //----Transient derieved member - END   ----//

        //resizes array based on growth percent
        void resize_array();

        //checks load perce t and determines if resize needed
        bool is_resize_required();

        //right shifts all elements from pos to pos+1. And sets element at pos.
        void insert_shift(uint32_t pos, ElementType* element);

        //removes element at pos and left shifts all succeding elements
        void remove_shift(uint32_t pos);

        // if found - returns +ve index of element
        // if not found - returns -ve index where element should be inserted
        uint32_t binary_search(ElementType* element);

        //update element in place
        void update(uint32_t pos, ElementType* element);

    };

    template<SortedDynamicArrayType>
    Sorted_Dynamic_Array<SortedDynamicArrayTypeParams>::Sorted_Dynamic_Array(uint32_t no_of_elements_capacity) {
        m_size = sizeof(struct header) + no_of_elements_capacity * sizeOfElement;
        m_mem = malloc(m_size);
        m_header = static_cast<header *>(m_mem);
        m_header->m_no_of_elements_filled = 0;
        m_elements = (ElementType *) ((uint8_t *) m_mem + sizeof(struct header));
        m_no_of_elements_total = no_of_elements_capacity;
    }

    template<SortedDynamicArrayType>
    Sorted_Dynamic_Array<SortedDynamicArrayTypeParams>::Sorted_Dynamic_Array(void *mem, uint64_t size) {
        assert((size - sizeof(struct header)) % sizeOfElement != 0);
        m_mem = malloc(size);
        memcpy(m_mem, mem, size);
        m_size = size;
        m_header = static_cast<header *>(m_mem);
        m_elements = (ElementType *) ((uint8_t *) m_mem + sizeof(struct header));
        m_no_of_elements_total = (size - sizeof(struct header)) / sizeOfElement;
    }

    template<SortedDynamicArrayType>
    void Sorted_Dynamic_Array<SortedDynamicArrayTypeParams>::set_mem(void *mem, uint64_t size) {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        m_mem = mem;
        m_size = size;
        m_header = static_cast<header *>(m_mem);
        m_elements = (ElementType *) ((uint8_t *) m_mem + sizeof(struct header));
        m_no_of_elements_total = (size - sizeof(struct header)) / sizeOfElement;
    }

    template<SortedDynamicArrayType>
    Sorted_Dynamic_Array<SortedDynamicArrayTypeParams>::~Sorted_Dynamic_Array() {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        if (m_mem) {
            m_header = NULL;
            m_elements = NULL;
            free(m_mem);
            m_mem = NULL;
        }
    }

    template<SortedDynamicArrayType>
    uint32_t 
    Sorted_Dynamic_Array<SortedDynamicArrayTypeParams>::get_size() const {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        return m_size;
    }

    template<SortedDynamicArrayType>
    uint32_t
    Sorted_Dynamic_Array<SortedDynamicArrayTypeParams>::get_no_of_elements_filled() const {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        return m_header->m_no_of_elements_filled;
    }

    template<SortedDynamicArrayType>
    uint32_t
    Sorted_Dynamic_Array<SortedDynamicArrayTypeParams>::get_no_of_elements_total() const {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        return m_no_of_elements_total;
    }

    template<SortedDynamicArrayType>
    bool
    Sorted_Dynamic_Array<SortedDynamicArrayTypeParams>::addOrUpdate(ElementType* element) {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        uint32_t pos = binary_search(element);
        pos < 0 ? insert_shift(-pos, element) : update(pos, element);
        if (pos < 0)return true;
        else return false;
    }

    template<SortedDynamicArrayType>
    void
    Sorted_Dynamic_Array<SortedDynamicArrayTypeParams>::removeIfPresent(ElementType* element) {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        uint32_t pos = binary_search(element);
        if (pos > 0)
            remove_shift(pos);
    }

    template<SortedDynamicArrayType>
    ElementType
    Sorted_Dynamic_Array<SortedDynamicArrayTypeParams>::operator[](uint32_t pos) {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        if (pos >= m_header->m_no_of_elements_filled || pos < 0) assert(0);
        return (ElementType) (m_mem + pos * sizeOfElement);//copy so read only
    }

    template<SortedDynamicArrayType>
    bool
    Sorted_Dynamic_Array<SortedDynamicArrayTypeParams>::is_resize_required() {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        if (m_header->m_no_of_elements_filled * 100 / m_no_of_elements_total >= LOAD_PERCENT) return true;
        else return false;
    }

    template<SortedDynamicArrayType>
    void
    Sorted_Dynamic_Array<SortedDynamicArrayTypeParams>::resize_array() {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        uint32_t no_of_new_elements = m_no_of_elements_total * GROWTH_PERCENT / 100;
        uint32_t new_size = m_size + no_of_new_elements * sizeOfElement;
        ElementType *mem = (ElementType *) malloc(new_size);
        memcpy(mem, m_mem, m_size);
        free(m_mem);
        m_mem = mem;
        m_no_of_elements_total += no_of_new_elements;
        m_size = new_size;
    }

    template<SortedDynamicArrayType>
    uint32_t
    Sorted_Dynamic_Array<SortedDynamicArrayTypeParams>::binary_search(ElementType* element) {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        if(m_header->m_no_of_elements_filled==0)return 0;
        uint32_t s = 0, e = m_header->m_no_of_elements_filled-1;
        while (s <= e) {
            uint32_t m = (s + e) >> 2;
            ElementType *middle = m_elements + m;
            if (*element < *middle) {
                e = m - 1;
            } else if (*element > *middle) {
                s = m + 1;
            } else {
                return m;
            }
        }
        return -s;
    }

    template<SortedDynamicArrayType>
    void
    Sorted_Dynamic_Array<SortedDynamicArrayTypeParams>::remove_shift(uint32_t pos) {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        if (pos >= m_header->m_no_of_elements_filled || pos < 0) assert(0);
        memmove(m_elements + pos, m_elements + pos + 1,
                m_header->m_no_of_elements_filled - pos - 1);
        m_header->m_no_of_elements_filled--;
    }

    template<SortedDynamicArrayType>
    void
    Sorted_Dynamic_Array<SortedDynamicArrayTypeParams>::insert_shift(uint32_t pos, ElementType *element) {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        if (pos >= m_header->m_no_of_elements_filled || pos < 0) assert(0);
        if (is_resize_required()) {
            resize_array();
        }
        memmove(m_elements + pos + 1, m_elements + pos, m_header->m_no_of_elements_filled - pos);
        m_header->m_no_of_elements_filled++;

        memcpy((void*)(m_elements + pos), (void*)element, sizeOfElement);
    }

    template<SortedDynamicArrayType>
    void
    Sorted_Dynamic_Array<SortedDynamicArrayTypeParams>::update(uint32_t pos, ElementType *element) {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        memcpy((void*)(m_elements + pos), (void*)element, sizeOfElement);
    }

    template<SortedDynamicArrayType>
    ElementType *Sorted_Dynamic_Array<SortedDynamicArrayTypeParams>::get_mem(void) const {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        return m_mem;
    }

    template<SortedDynamicArrayType>
    std::string
    Sorted_Dynamic_Array<SortedDynamicArrayTypeParams>::get_string_representation() const {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        uint32_t i = 0;
        std::stringstream ss;
        ss << "No of elements filled:" << m_header->m_no_of_elements_filled << " out of total "
           << m_no_of_elements_total << ",Elements:";
        ElementType *element = m_elements;
        while (i < m_header->m_no_of_elements_filled) {
            ss << *element->to_string() << ",";
            element += 1;
            i++;
        }

        return ss.str();
    }

    template<SortedDynamicArrayType>
    ElementType* Sorted_Dynamic_Array<SortedDynamicArrayTypeParams>::get(ElementType* element) {
        uint32_t pos = binary_search(element);
        if (pos < 0) return nullptr;
        else return m_elements + pos;
    }
}

#endif