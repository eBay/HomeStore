/*
 * hashmap.hpp
 *
 *  Created on: 23-Feb-2017
 *      Author: hkadayam
 */

#ifndef SRC_LIBUTILS_FDS_HASH_HASHMAP_HPP_
#define SRC_LIBUTILS_FDS_HASH_HASHMAP_HPP_

#include <cds/intrusive/michael_list_dhp.h>
#include <cds/intrusive/michael_set.h>
#include <cds/intrusive/feldman_hashset_dhp.h>
#include <farmhash.h>

namespace homeds {
//////////// Common portion for various hash implementations //////////////////

/* Defines the abstract hash key with which we operate on */
class LFHashKey {
public:
    LFHashKey(uint8_t* bytes, int len) {
        m_bytes = bytes;
        m_len = len;
        m_hash_code = util::Hash32((const char*)bytes, (size_t)len);
    }

    virtual ~LFHashKey() {}
    virtual int compare(const LFHashKey& other) const {
        int cmplen = std::min(m_len, other.m_len);
        int x = memcmp(m_bytes, other.m_bytes, cmplen);

        if (x == 0) {
            return (other.m_len - m_len);
        } else {
            return x;
        }
    }

    virtual LFHashKey& operator=(LFHashKey& other) {
        m_bytes = other.m_bytes;
        m_len = other.m_len;
        m_hash_code = other.m_hash_code;
        return *this;
    }

    virtual size_t get_hash_code() const { return m_hash_code; }

private:
    uint8_t* m_bytes;
    int m_len;
    size_t m_hash_code;
};

/* Defines the hash value and comparator */
class LFHashValue : public cds::intrusive::michael_list::node< cds::gc::DHP > {
public:
    LFHashValue() {
        __ref_valid_t r(0);
        r.refcount = 1;
        r.validity = true;
        m_ref.store(r.to_integer(), std::memory_order_relaxed);
    }

    virtual ~LFHashValue() {}
    virtual void set_key(LFHashKey& k) = 0;
    virtual LFHashValue& operator=(LFHashValue& other) = 0;
    virtual const LFHashKey* extract_key() const = 0;

    bool is_valid() {
        __ref_valid_t r(m_ref.load(std::memory_order_relaxed));
        return r.validity;
    }

    int64_t get_ref_count() {
        __ref_valid_t r(m_ref.load(std::memory_order_relaxed));
        return r.refcount;
    }

    void inc_ref_count() {
        // Since increment of refcount happens with insert/update and
        // there is a second line of shield to check validity outside,
        // it is not mandatory to set the validity and refcount atomically.

#if __BYTE_ORDER__ == LITTLE_ENDIAN
        m_ref.fetch_add(1);
#else
        __ref_valid_t r;
        r.refcount++;
        m_ref.store(r.to_integer(), std::memory_order_relaxed);
#endif
    }

    bool inc_if_valid() {
        uint64_t oldn;
        uint64_t newn;
        bool valid;

        do {
            oldn = m_ref.load(std::memory_order_relaxed);
            valid = true;

            __ref_valid_t r(oldn);
            if (r.validity != true) {
                // Validity is one way traffic, once set invalid, that
                // item will not be made valid again. So no need to loop
                // and check again.
                valid = false;
                break;
            }
            r.refcount++;
            newn = r.to_integer();
        } while (!m_ref.compare_exchange_weak(oldn, newn));

        return valid;
    }

    // Decrement and refcount and if zero, set the invalid bit
    // Returns true if it is marked invalid, false otherwise.
    bool dec_invalidate_on_zero() {
        uint64_t oldn;
        uint64_t newn;
        bool invalidated;

        do {
            oldn = m_ref.load(std::memory_order_relaxed);
            invalidated = false;

            __ref_valid_t r(oldn);
            if (--(r.refcount) == 0) {
                r.validity = 0;
                invalidated = true;
            }
            newn = r.to_integer();
        } while (!m_ref.compare_exchange_weak(oldn, newn));

        return invalidated;
    }

    std::atomic< uint64_t > m_ref;

private:
    struct __ref_valid_t {
        uint64_t refcount : 63;
        uint64_t validity : 1;

        __ref_valid_t(int64_t n) { memcpy(this, &n, sizeof(int64_t)); }

        uint64_t to_integer() {
            uint64_t n;
            memcpy(&n, this, sizeof(int64_t));
            return n;
        }
    };

    // std::atomic<int64_t> m_ref;
};

struct hash_code {
    size_t operator()(const LFHashValue& hv) const { return hv.extract_key()->get_hash_code(); }

    size_t operator()(const LFHashKey& hk) const { return hk.get_hash_code(); }
};

struct hash_value_cmp {
    int operator()(const LFHashValue& v1, const LFHashValue& v2) const {
        return (v1.extract_key()->get_hash_code() - v2.extract_key()->get_hash_code());
    }
};

//////////// Fixed Total Size hash implementations //////////////////
/* Hash Bucket for hash table */
/*typedef cds::intrusive::MichaelList< cds::gc::DHP, HashValue,
    typename cds::intrusive::michael_list::make_traits<
        // hook option
        cds::intrusive::opt::hook< cds::intrusive::michael_list::base_hook< cds::opt::gc< cds::gc::DHP > > >
        // item comparator option
        ,cds::opt::compare< hash_value_cmp >
    >::type
> fixed_type_hash_bucket;*/

typedef cds::intrusive::MichaelList<
    cds::gc::DHP, LFHashValue,
    typename cds::intrusive::michael_list::make_traits<
        // hook option
        cds::intrusive::opt::hook< cds::intrusive::michael_list::base_hook< cds::opt::gc< cds::gc::DHP > > >
        // item comparator option
        ,
        cds::opt::compare< hash_value_cmp > >::type >
    fixed_type_hash_bucket;

typedef cds::intrusive::MichaelHashSet<
    cds::gc::DHP, fixed_type_hash_bucket,
    typename cds::intrusive::michael_set::make_traits< cds::opt::hash< hash_code > >::type >
    fixed_type_hash_set;

//////////// Dynamic Size but Unique hash implementations //////////////////
typedef cds::intrusive::FeldmanHashSet< cds::gc::DHP, LFHashValue,
                                        typename cds::intrusive::feldman_hashset::make_traits<
                                            cds::opt::hash< hash_code >, cds::opt::compare< hash_value_cmp > >::type >
    dynsize_type_hash_set;

#if 0
struct insert_handler
{
    void operator()(bool is_new, LFHashValue &cur_val, LFHashValue &upd_val )
    {
    	if (is_new) {
    		return;
    	}
    	upd_val = cur_val;
    	upd_val.m_ref.store(cur_val.m_ref.load(std::memory_order_relaxed), std::memory_order_relaxed);
    	upd_val.inc_ref_count();
    }
};
#endif

///////////// Actual Hash map ///////////////////////
template < typename HS >
class LFHashMap {
public:
    LFHashMap(size_t maxcount, size_t nload) : m_set(maxcount, nload) {}

    // TODO: Need to iterate over all entries and delete them.
    virtual ~LFHashMap() {}

    // Following are the flow for insert and remove
    // 1. Insert is a 2 step process if an entry is already present
    //		a) Verifies if it is not already marked invalid by remove and atomically increment refcount.
    //		b) Once outside the hashmap, do a get() and check if item is marked invalid.
    //
    // 2. Remove is a 2 step process
    // 		a) Decrement the refcount and if zero marks the item invalid atomically.
    // 		b) If we marked invalid at step a), go to hashmap and then delete the entry.
    //
    // Step 1b is required, because at step 1a, even if we identify the item is invalid
    // we will not be able to stop the update or can return an error to retry. Easiest
    // way is to check if this was marked invalid outside and then if marked invalid,
    // just retry the operation.
    bool insert(LFHashKey& k, LFHashValue& v, LFHashValue* outv) {
        assert(k.compare(*(v.extract_key())) == 0);
        bool new_insert;

        do {
            new_insert = m_set.insert(v);
            if (new_insert) {
                break;
            }

            // Copy the key portion for comparison.
            *outv = v;

            // Do a get and try to increase the refcount if still valid.
            typename HS::guarded_ptr gp(m_set.get(*outv));
            if (gp) {
                *outv = *gp;
                // outv->m_ref.store(gp->m_ref.load(std::memory_order_relaxed), std::memory_order_relaxed);
                if (outv->inc_if_valid()) {
                    // We didn't insert, but item is still valid and is
                    // atomically incremented its count.
                    new_insert = false;
                    break;
                }
            }
            // Either item is removed or marked invalid. So retry the insert and get
        } while (true);

        return new_insert;
    }

    bool get(LFHashKey& k, LFHashValue* outv) {
        outv->set_key(k);
        typename HS::guarded_ptr gp(m_set.get(*outv));
        if (!gp) {
            return false;
        }

        if (!outv->is_valid()) {
            return false;
        }
        *outv = *gp;
        return true;
    }

#if 0
    // Yet to support remove by key.
    bool remove(LFHashKey &k, LFHashValue *outv)
    {
        // Since remove needs to provide old value, just read the value first.
        bool found = get(k, outv);
        if (!found) {
            // Not found or removed by other thread.
            return false;
        }

        return (m_set.erase(*outv, remove_handler));
    }
#endif

    bool remove(LFHashValue& v) {
        // Decrement and set validity.
        if (v.dec_invalidate_on_zero()) {
            // Marked invalid, go ahead and delete from set.
            return m_set.erase(v);
        } else {
            // Still valid, since it races with insert.
            return false;
        }
    }

    ssize_t size() { return m_set.size(); }

private:
    HS m_set;
};

} // namespace homeds

#endif /* SRC_LIBUTILS_FDS_HASH_HASHMAP_HPP_ */
