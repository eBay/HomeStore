/**
 * Copyright eBay Inc 2018
 */

#ifndef Elastic_Array_DS_H_
#define Elastic_Array_DS_H_

#define ElasticArrayType typename ElementType, int LOAD_PERCENT, int GROWTH_PERCENT
#define ElasticArrayTypeParams ElementType, LOAD_PERCENT, GROWTH_PERCENT

#include <stdint.h>
#include <cassert>
#include <iostream>
#include <cstring>
#include <assert.h>
#include <sstream>
#include <mutex>
#include <sds_logging/logging.h>

namespace homeds {

    /**
     *  Array Data structure which can work on supplied memory location OR can create its own and work on it.
     * Its internally represeneted as array, that grows in size as needed(Contigious memory). Degrowth is not currently supported..
     *  ElementType needs to have '<' '>' '==' operators and to_string defined.
     * 
     * Concern of freeing memory allocated is delegated to caller if working memory is provide by client using 
     * set_mem or constructor. It frees memory if it itselft allocated to start with.
     * 
     * Internal format of *m_mem
     *      |header ElementType0 ElementType1 ElementType2/
     *      
     *  Max # of entries it can have is uint32_t
     *  Although locking is provided, its not completly thread safe since it can work on memory provided by client,
     *  which can be parrallely manipulated anywhere.
     */

    template<ElasticArrayType>
    class Elastic_Array {
    private:
        void *m_mem; // actual memory where entire data structure is stored

        struct header {
            uint32_t m_no_of_elements_filled;// how many elements already filled in array from left to right
        };

        //----Transient derieved member - START  ----//
        std::recursive_mutex m_mutex;
        uint32_t m_size; // total size(no of bytes) of array including non-filled elements
        uint32_t m_max_grow_to;// max no of element this ds will grow to.
        header *m_header; // pointer to header
        ElementType *m_elements; // pointer to first element in array
        uint32_t sizeOfElement = sizeof(ElementType);
        uint32_t m_no_of_elements_total;// total # of elements
        bool mallocated; // flag indicating if this DS itselft allocated memory. in that case it frees up by itself.
        //----Transient derieved member - END   ----//

        //resizes array based on growth percent. allocages new memory.
        void resize_array();

        //checks load perce t and determines if resize needed
        bool is_resize_required();

        // frees locally allocated memory not managed by client
        void free_mem_if_needed();

        //get new size of array based on growth percent
        uint32_t get_size_to_grow_to();

    public:

        struct binary_search_result {
            int start;
            int end;
        };

        //allocates new memory for no_of elements
        Elastic_Array(int no_of_elements_capacity, uint32_t max_grow_to);

        //Copy constructor
        Elastic_Array(void *mem, uint32_t size, uint32_t max_grow_to);

        Elastic_Array(const Elastic_Array &) = delete;

        //Does NOT frees memory holded by this DS.
        ~Elastic_Array();

        //right shifts all elements from pos to pos+1. And sets element at pos.
        // returns true if insert resulted in resize of structure. It returns new copy of structure.
        // Releaseing memory of existing structure is left to client
        void insert_shift(uint32_t pos, ElementType *element);

        //removes element at pos and left shifts all succeding elements
        void remove_shift(uint32_t spos, uint32_t epos);

        //update element in place
        void update(uint32_t pos, ElementType *element);

        ElementType *get(ElementType *element);

        uint32_t get_size() const;

        //view only - index based access
        ElementType *operator[](uint32_t pos);

        ElementType *get_mem(void) const;

        //set ds to point to existing memory location. Does not free memory it previously holds.
        void set_mem(void *array, uint32_t size, uint32_t max_grow_to);

        uint32_t get_no_of_elements_filled() const;

        uint32_t get_no_of_elements_total() const;

        std::string get_string_representation() const;

        //calculate new size of thsi data strcuture after adding element provided
        uint32_t estimate_size_after_addOrUpdate(uint32_t noOfElements);

        /**** BELOW METHODS WORK PROPERLY ONLY IF ARRAY IS SORTED. ***/

        // if found - returns +ve index of element
        // if not found - returns  (-(insertion point) – 1) index where start or end element should be inserted
        int binary_search(ElementType *element);

        //add element into array - returns true if added, false if just updated.
        bool addOrUpdate(ElementType *element);

        //removes element into array. 
        bool removeIfPresent(ElementType *element);
    };

    template<ElasticArrayType>
    Elastic_Array<ElasticArrayTypeParams>::Elastic_Array(int no_of_elements_capacity,
                                                         uint32_t max_grow_to) {
        m_size = sizeof(struct header) + no_of_elements_capacity * sizeOfElement;
        m_max_grow_to = max_grow_to;
        m_mem = malloc(m_size);
        memset(m_mem, 0, m_size);
        m_header = static_cast<header *>(m_mem);
        m_header->m_no_of_elements_filled = 0;
        m_elements = (ElementType *) ((uint8_t *) m_mem + sizeof(struct header));
        m_no_of_elements_total = no_of_elements_capacity;
        mallocated = true;
        if (no_of_elements_capacity > 0)LOGTRACE("**NEW ALLOC** - {}", get_string_representation());
    }

    template<ElasticArrayType>
    Elastic_Array<ElasticArrayTypeParams>::Elastic_Array(void *mem, uint32_t size,
                                                         uint32_t max_grow_to) {
        assert((size - sizeof(struct header)) % sizeOfElement == 0);
        m_mem = malloc(size);
        memcpy(m_mem, mem, size);
        m_size = size;
        max_grow_to = max_grow_to;
        m_header = static_cast<header *>(m_mem);
        m_elements = (ElementType *) ((uint8_t *) m_mem + sizeof(struct header));
        m_no_of_elements_total = (size - sizeof(struct header)) / sizeOfElement;
        mallocated = true;
        LOGTRACE("**COPY CONSTRUCTOR ALLOC** - {}", get_string_representation());
    }

    template<ElasticArrayType>
    void
    Elastic_Array<ElasticArrayTypeParams>::set_mem(void *mem, uint32_t size, uint32_t max_grow_to) {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        free_mem_if_needed();
        m_mem = mem;
        m_size = size;
        max_grow_to = max_grow_to;
        m_header = static_cast<header *>(m_mem);
        m_elements = (ElementType *) ((uint8_t *) m_mem + sizeof(struct header));
        m_no_of_elements_total = (size - sizeof(struct header)) / sizeOfElement;
        assert(m_header->m_no_of_elements_filled <= m_no_of_elements_total);
        LOGTRACE("**SET_MEM** - {}", get_string_representation());
    }

    template<ElasticArrayType>
    Elastic_Array<ElasticArrayTypeParams>::~Elastic_Array() {
        LOGTRACE("Destructing SDArray.");
        free_mem_if_needed();
    }

    template<ElasticArrayType>
    void
    Elastic_Array<ElasticArrayTypeParams>::free_mem_if_needed() {
        if (mallocated) {
            m_header = NULL;
            m_elements = NULL;
            free(m_mem);
            m_mem = NULL;
            mallocated = false;
        }
    }

    template<ElasticArrayType>
    uint32_t
    Elastic_Array<ElasticArrayTypeParams>::get_size() const {
        return m_size;
    }

    template<ElasticArrayType>
    uint32_t
    Elastic_Array<ElasticArrayTypeParams>::estimate_size_after_addOrUpdate(
            uint32_t noOfElements) {
        if ((m_header->m_no_of_elements_filled + noOfElements) * 100 / m_no_of_elements_total >= LOAD_PERCENT) {
            return get_size_to_grow_to();
        } else
            return m_size;
    }

    template<ElasticArrayType>
    uint32_t
    Elastic_Array<ElasticArrayTypeParams>::get_no_of_elements_filled() const {
        return m_header->m_no_of_elements_filled;
    }

    template<ElasticArrayType>
    uint32_t
    Elastic_Array<ElasticArrayTypeParams>::get_no_of_elements_total() const {
        return m_no_of_elements_total;
    }

    template<ElasticArrayType>
    bool
    Elastic_Array<ElasticArrayTypeParams>::addOrUpdate(ElementType *element) {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        int pos = binary_search(element);
        pos < 0 ? insert_shift(-pos - 1, element) : update(pos, element);
        if (pos < 0)return true;
        else return false;
    }

    template<ElasticArrayType>
    bool
    Elastic_Array<ElasticArrayTypeParams>::removeIfPresent(ElementType *element) {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        int pos = binary_search(element);
        if (pos >= 0) {
            remove_shift(pos, pos);
            return true;
        } else return false;
    }

    template<ElasticArrayType>
    ElementType *
    Elastic_Array<ElasticArrayTypeParams>::operator[](uint32_t pos) {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        if (pos >= m_header->m_no_of_elements_filled || pos < 0) assert(0);
        return (ElementType *) m_elements + pos;
    }

    template<ElasticArrayType>
    std::string
    Elastic_Array<ElasticArrayTypeParams>::get_string_representation() const {
        uint32_t i = 0;
        std::stringstream ss;
        ss << "No of elements filled:" << m_header->m_no_of_elements_filled << " out of total "
           << m_no_of_elements_total << ",Elements:";
        ElementType *element = m_elements;
        while (i < m_header->m_no_of_elements_filled) {
            ss << std::string(*element) << ",";
            element += 1;
            i++;
        }
        return ss.str();
    }
    
    template<ElasticArrayType>
    ElementType *Elastic_Array<ElasticArrayTypeParams>::get(ElementType *element) {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        int pos = binary_search(element);
        if (pos < 0) return nullptr;
        else return m_elements + pos;
    }

    template<ElasticArrayType>
    ElementType *Elastic_Array<ElasticArrayTypeParams>::get_mem(void) const {
        return (ElementType *) m_mem;
    }

    template<ElasticArrayType>
    int
    Elastic_Array<ElasticArrayTypeParams>::binary_search(ElementType *element) {
        int s = 0, e = m_header->m_no_of_elements_filled - 1;
        while (s <= e) {
            int m = (s + e) >> 1;
            ElementType *middle = m_elements + m;
            if (*element < *middle) {
                e = m - 1;
            } else if (*element > *middle) {
                s = m + 1;
            } else {
                return m;
            }
        }
        //return  (-(insertion point) – 1) if element not found
        return -s - 1;
    }


    template<ElasticArrayType>
    bool
    Elastic_Array<ElasticArrayTypeParams>::is_resize_required() {
        if (m_header->m_no_of_elements_filled * 100 / m_no_of_elements_total >= LOAD_PERCENT) return true;
        else return false;
    }

    template<ElasticArrayType>
    uint32_t
    Elastic_Array<ElasticArrayTypeParams>::get_size_to_grow_to() {
        uint32_t no_of_new_elements = m_no_of_elements_total * GROWTH_PERCENT / 100;
        assert(no_of_new_elements > 0);//Need to set initial capacity or growth percent higher 
        if (m_no_of_elements_total + no_of_new_elements > m_max_grow_to)
            no_of_new_elements = m_max_grow_to - m_no_of_elements_total;
        uint32_t sizeToGrow = m_size + no_of_new_elements * sizeOfElement;
        return sizeToGrow;
    }

    template<ElasticArrayType>
    void
    Elastic_Array<ElasticArrayTypeParams>::resize_array() {
        LOGTRACE("Before resize: {}", get_string_representation());
        uint32_t new_size = get_size_to_grow_to();
        ElementType *mem = (ElementType *) malloc(new_size);
        memset(mem, 0, new_size);
        memcpy(mem, m_mem, m_size);
        set_mem(mem, new_size, m_max_grow_to);
        mallocated = true;
        LOGTRACE("After resize: {}", get_string_representation());

    }

    template<ElasticArrayType>
    void
    Elastic_Array<ElasticArrayTypeParams>::remove_shift(uint32_t spos, uint32_t epos) {
        if (spos >= m_header->m_no_of_elements_filled || spos < 0 ||
            epos >= m_header->m_no_of_elements_filled || epos < 0)
            assert(0);
        memmove(m_elements + spos, m_elements + epos + 1,
                sizeOfElement * (m_header->m_no_of_elements_filled - epos - 1));
        m_header->m_no_of_elements_filled -= (epos - spos + 1);
        LOGTRACE("remove_shift: {}:{}->{}", spos,epos,get_string_representation());
    }

    template<ElasticArrayType>
    void
    Elastic_Array<ElasticArrayTypeParams>::insert_shift(uint32_t pos, ElementType *element) {
        if (pos > m_header->m_no_of_elements_filled || pos < 0) assert(0);
        assert(pos < m_max_grow_to);
        if (is_resize_required()) {
            resize_array();
        }
        memmove(m_elements + pos + 1, m_elements + pos, sizeOfElement * (m_header->m_no_of_elements_filled - pos));
        m_header->m_no_of_elements_filled++;

        memcpy((void *) (m_elements + pos), (void *) element, sizeOfElement);
        LOGTRACE(" after insert_shift: {}:{}->{}", pos, std::string(*element), get_string_representation());
    }

    template<ElasticArrayType>
    void
    Elastic_Array<ElasticArrayTypeParams>::update(uint32_t pos, ElementType *element) {
        memcpy((void *) (m_elements + pos), (void *) element, sizeOfElement);
        LOGTRACE(" after update: {}:{}->{}", pos, std::string(*element), get_string_representation());
    }

}

#endif