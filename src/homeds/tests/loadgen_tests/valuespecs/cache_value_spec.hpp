//
// Modified by Amit Desai
//

#ifndef HOMESTORE_CACHE_VALUE_SPEC_HPP
#define HOMESTORE_CACHE_VALUE_SPEC_HPP

#include "homeds/loadgen/loadgen_common.hpp"
#include "homeds/btree/btree.hpp"
#include "homeds/loadgen/spec/value_spec.hpp"
#include <farmhash.h>

#define CACHE_ENTRY_SIZE 8192
namespace homeds {
namespace loadgen {
class CacheValueBuffer : public CacheBuffer< CacheKey > {
public:
    static CacheValueBuffer* make_object() { return sisl::ObjectAllocator< CacheValueBuffer >::make_object(); }

    void free_yourself() { sisl::ObjectAllocator< CacheValueBuffer >::deallocate(this); }

    friend void intrusive_ptr_add_ref(CacheValueBuffer* buf) { intrusive_ptr_add_ref((CacheBuffer< CacheKey >*)buf); }

    friend void intrusive_ptr_release(CacheValueBuffer* buf) { intrusive_ptr_release((CacheBuffer< CacheKey >*)buf); }
};

class CacheValue : public ValueSpec {

    boost::intrusive_ptr< CacheValueBuffer > m_buf;

#define INVALID_SEQ_ID UINT64_MAX
public:
    static std::shared_ptr< CacheValue > gen_value(ValuePattern spec, CacheValue* ref_value = nullptr) {
        std::array< uint16_t, CS_ARRAY_STACK_SIZE > carr;
        for (auto i = 0ul; i < CS_ARRAY_STACK_SIZE; i++)
            carr[i] = 1;
        switch (spec) {
        case ValuePattern::SEQUENTIAL_VAL:
        case ValuePattern::RANDOM_BYTES: {

            /* Seed */
            std::random_device rd;

            /* Random number generator */
            std::default_random_engine generator(rd());

            /* Distribution on which to apply the generator */
            std::uniform_int_distribution< long long unsigned > distribution(0, MAX_VALUES);

            auto sid = distribution(generator);
            uint8_t* raw_buf = generate_bytes(sid, CACHE_ENTRY_SIZE);
            CacheValue v = CacheValue(raw_buf, CACHE_ENTRY_SIZE);
            std::shared_ptr< CacheValue > temp = std::make_shared< CacheValue >(v);
            return temp;
        }
        default:
            // We do not support other gen spec yet
            break;
        }
        assert(0);
        CacheValue v = CacheValue();
        std::shared_ptr< CacheValue > temp = std::make_shared< CacheValue >(v);
        return temp;
    }

    CacheValue(){};
    CacheValue(uint8_t* data, size_t size) {
        boost::intrusive_ptr< homeds::MemVector > mvec(new homeds::MemVector());
        mvec->set(data, CACHE_ENTRY_SIZE, 0);

        auto buf = CacheValueBuffer::make_object();
        buf->set_memvec(mvec, 0, CACHE_ENTRY_SIZE);
        m_buf = boost::intrusive_ptr< CacheValueBuffer >(buf);
    }

    CacheValue(boost::intrusive_ptr< CacheValueBuffer > buf) : m_buf(buf){};

    virtual uint64_t get_hash_code() override {
        auto blob = m_buf->at_offset(0);
        assert(blob.size == CACHE_ENTRY_SIZE);
        return util::Hash64((const char*)blob.bytes, (size_t)blob.size);
    }

    boost::intrusive_ptr< CacheValueBuffer > get_buf() { return m_buf; }
    void set_buf(boost::intrusive_ptr< CacheValueBuffer > buf) { m_buf = buf; }

    static uint8_t* generate_bytes(uint64_t id, uint64_t size) {
        // generates 4k bytes with repeating id at loc
        uint64_t* raw_buf = (uint64_t*)malloc(size);
        for (auto b = 0U; b < size / sizeof(uint64_t); b++)
            raw_buf[b] = id;
        return (uint8_t*)raw_buf;
    }
};
} // namespace loadgen
} // namespace homeds

#endif // HOMESTORE_CACHE_VALUE_SPEC_HPP
