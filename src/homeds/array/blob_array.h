/**
 * Copyright eBay Inc 2018
 */

#ifndef Blob_Array_DS_H_
#define Blob_Array_DS_H_

#include <stdint.h>
#include "homeds/utility/useful_defs.hpp"
#include <vector>
#include <malloc.h>
#include "assert.h"
#include <iostream>
#include <sstream>
#include <utility/obj_life_counter.hpp>

namespace homeds {
/**
 * Blob array is fixed immutable array of elements which implement Blob interface:
 *      set_blob(const homeds::blob &b);
 *      homeds::blob get_blob();
 *      copy_blob(const homeds::blob &b);
 * There are methods which makes this mutable, but internally it facade, just works on new heap memory.
 *
 * Format is
 *      "header record0 record1...data0 data1"
 *
 * Any temp heap memory allocated by blob array  internally is freed on destruction.
 * However mem provided by set_mem is not freed. Its clients responsiblity to manage that.
 */
template < typename ElementType >
class Blob_Array {
private:
    struct header {
        uint16_t m_total_elements; // total elements in array
    } __attribute__((packed));

    struct record {
        uint16_t m_size;   // size of content
        uint16_t m_offset; // offset from m_blobs
    } __attribute__((packed));

    header* m_header;  // ptr to header
    record* m_records; // ptr to start of records
    uint8_t* m_data;   // actual content
    bool is_initialized = false;
    bool is_mallocated = false;
    void* m_arr; // ptr of blob_array structure

    // if we allocated temporary heap memory, it frees that.
    void free_mem_if_needed() {
        if (is_initialized && is_mallocated && m_arr != nullptr) {
            free(m_arr);
            m_arr = nullptr;
            m_header = nullptr;
            m_data = nullptr;
            m_records = nullptr;
        }
    }

    // get next record after current record
    record* get_next_rec(record* curr_rec) {
        uint16_t next_rec_offset = curr_rec->m_size + sizeof(uint16_t);
        return (record*)((uint8_t*)(curr_rec) + next_rec_offset);
    }

    // get record ptr
    record* get_record(uint16_t index) const {
        record* currec = m_records;
        currec = currec + index;
        return currec;
    }

    void init_ptr(uint16_t total_elements) {
        m_header = static_cast< header* >(m_arr);
        m_records = static_cast< record* >((void*)(((uint8_t*)m_arr) + sizeof(header)));
        m_data = static_cast< uint8_t* >((void*)(((uint8_t*)m_records) + total_elements * sizeof(record)));
        is_initialized = true;
    }

    uint8_t* get_data_ptr(uint16_t offset) const { return m_data + offset; }

    // TODO - change malloc to something like freelist allocator which uses preallocated space from thread local
    void* allocate(uint32_t size) {
        is_mallocated = true;
        return malloc(size);
    }

public:
    ~Blob_Array() { free_mem_if_needed(); }

    // creates empty array
    Blob_Array() {}

    Blob_Array(const Blob_Array& other) { set_elements(other); }

    uint16_t get_meta_size() const { return sizeof(record) * m_header->m_total_elements + sizeof(header); }

    // deep copy all elements from other array
    void set_elements(const Blob_Array& other) {
        free_mem_if_needed();
        uint32_t size = other.get_size();
        if (size == 0)
            return;
        m_arr = allocate(size);
        memcpy(m_arr, other.get_mem(), size);
        init_ptr(other.get_total_elements());
    }

    // creates temporary heap memory and copies element to it.
    void set_element(ElementType& e) {
        free_mem_if_needed();
        // calculate size of heap to allocate
        uint32_t size = e.get_blob().size + sizeof(record) + sizeof(header);
        m_arr = allocate(size);
        init_ptr(1);
        m_header->m_total_elements = 1;
        // copy element to heap
        record* curr_rec = m_records;
        curr_rec->m_size = e.get_blob().size;
        curr_rec->m_offset = 0;
        memcpy(get_data_ptr(0), (void*)e.get_blob().bytes, e.get_blob().size);
    }

    // creates temporary heap memory and copies elements to it.
    void set_elements(std::vector< ElementType >& elements) {
        free_mem_if_needed();
        // calculate size of heap to allocate
        uint32_t size = sizeof(record) * elements.size() + sizeof(header);
        for (ElementType& e : elements) {
            size += e.get_blob().size;
        }
        m_arr = allocate(size);
        init_ptr(elements.size());
        m_header->m_total_elements = elements.size();
        // copy all elements to heap
        uint16_t i = 0;
        uint16_t offset = 0;
        for (ElementType& e : elements) {
            record* curr_rec = get_record(i++);
            curr_rec->m_size = e.get_blob().size;
            curr_rec->m_offset = offset;
            memcpy(get_data_ptr(offset), (void*)e.get_blob().bytes, e.get_blob().size);
            offset += e.get_blob().size;
        }
    }

    // This instance works on memory provided as blob array. No bcopy here.
    void set_mem(void* arr, const uint32_t& expected_size) {
        free_mem_if_needed();
        m_arr = arr;
        m_header = static_cast< header* >(m_arr);
        init_ptr(m_header->m_total_elements);
        assert(m_header->m_total_elements < 1000); // for now we dont expect huge array
#ifndef NDEBUG
        assert(get_size() == expected_size);
#endif
    }

    // get memory referece to this structure storage
    void* get_mem() const {
        assert(is_initialized);
        return m_arr;
    }

    // returns current size of heap array.
    uint32_t get_size() const {
        if (!is_initialized)
            return 0;
        record* curr_rec = m_records;
        uint32_t size = get_meta_size();
        int total = get_total_elements() - 1;
        while (total >= 0) {
            size += get_record(total)->m_size;
            total--;
        }
        return size;
    }

    // access elements by index.Doesn't do bcopy
    void get(uint32_t index, ElementType& element, bool copy) const {
        assert(index < m_header->m_total_elements);
        assert(is_initialized);
        record* curr_rec = get_record(index);
        blob b;
        b.size = curr_rec->m_size;
        b.bytes = get_data_ptr(curr_rec->m_offset);
        if (copy) {
            element.copy_blob(b);
        } else {
            element.set_blob(b);
        }
    }

    // returns total elements in array
    uint32_t get_total_elements() const {
        if (!is_initialized)
            return 0;
        return m_header->m_total_elements;
    }

    void get_all(std::vector< ElementType >& vector, bool copy) {
        if (!is_initialized)
            return;
        for (auto i = 0u; i < get_total_elements(); i++) {
            ElementType e;
            get(i, e, copy);
            vector.emplace_back(e);
        }
    }

    // in-place remove
    void remove(uint32_t index) {
        assert(is_initialized);
        assert(index < get_total_elements());

        if (index != get_total_elements() - 1) { // move record, not data
            record* rec = get_record(index);
            uint8_t* move_to = (uint8_t*)rec;
            uint8_t* move_from = move_to + sizeof(record);
            uint32_t size_to_move = sizeof(record) * (get_total_elements() - index - 1);
            memmove((void*)move_to, (void*)move_from, size_to_move);
        }

        m_header->m_total_elements--;
#ifndef NDEBUG
        to_string();
#endif
    }

    // lays out in contigious memory
    void mem_align() {
        uint32_t data_offset = 0;
        uint8_t* m_new_data =
            static_cast< uint8_t* >((void*)(((uint8_t*)m_records) + get_total_elements() * sizeof(record)));
        for (auto i = 0u; i < get_total_elements(); i++) {
            record* rec = get_record(i);
            memmove(m_new_data, get_data_ptr(rec->m_offset), rec->m_size);
            m_new_data += rec->m_size;
            rec->m_offset = data_offset;
            data_offset += rec->m_size;
        }
        init_ptr(get_total_elements());
    }

    std::string to_string() const {
        assert(is_initialized);
        std::stringstream ss;
        for (auto i = 0u; i < m_header->m_total_elements; i++) {
            ElementType e;
            get(i, e, false);
            ss << e << ",";
        }
        return ss.str();
    }
};
} // namespace homeds
#endif
