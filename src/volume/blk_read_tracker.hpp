//
// Created by Amit Desai on 07/15/19.
//

#ifndef HOMESTORE_BLK_READ_TRACKER_STORE_SPEC_HPP
#define HOMESTORE_BLK_READ_TRACKER_STORE_SPEC_HPP

namespace homestore {

SDS_LOGGING_DECL(blk_read_tracker)
#define _BLKMSG_EXPAND(...) __VA_ARGS__

// clang-format off
#define BLKTRACKER_LOG(level, mod, req, fmt, ...)                                 \
    LOG##level##MOD(BOOST_PP_IF(BOOST_PP_IS_EMPTY(mod), base, mod),               \
                    "[blk_read_tracker={}]"                                       \
                    BOOST_PP_IF(BOOST_PP_IS_EMPTY(req), "{}: ", "")               \
                    fmt, "",                                                      \
                    BOOST_PP_EXPAND(_BLKMSG_EXPAND BOOST_PP_IF(BOOST_PP_IS_EMPTY(req), (""), (""))),\
                    ##__VA_ARGS__)

// clang-format on

#define BLK_READ_MAP_SIZE 128
struct Free_Blk_Entry {
    BlkId   m_blkId;
    uint8_t m_blk_offset : NBLKS_BITS;
    uint8_t m_nblks_to_free : NBLKS_BITS;

    Free_Blk_Entry(){};
    Free_Blk_Entry(const BlkId& m_blkId, uint8_t m_blk_offset, uint8_t m_nblks_to_free) :
            m_blkId(m_blkId),
            m_blk_offset(m_blk_offset),
            m_nblks_to_free(m_nblks_to_free) {}
};

struct BlkEvictionRecord : public homeds::HashNode, sisl::ObjLifeCounter< BlkEvictionRecord > {
    BlkId                            m_key;       // Key to access this cache
    sisl::atomic_counter< uint32_t > m_refcount;  // Refcount
    std::atomic< bool >              m_can_free;  // mark free for erasure
    std::vector< Free_Blk_Entry >    m_free_list; // list of pair(offset,size) to be freed when no ref left
    std::mutex                       m_mtx;       // This mutex prevents multiple writers to free list

    BlkEvictionRecord(BlkId& key) : m_key(key), m_refcount(0), m_can_free(false), m_free_list(0), m_mtx() {}

    friend void intrusive_ptr_add_ref(BlkEvictionRecord* ber) { ber->m_refcount.increment(); }

    friend void intrusive_ptr_release(BlkEvictionRecord* ber) {
        int cnt = ber->m_refcount.decrement();
        assert(cnt >= 0);
        if (cnt == 0) {
            ber->free_yourself();
        }
    }

    void add_to_free_list(Free_Blk_Entry& fbe) {
        m_mtx.lock();
        m_free_list.push_back(fbe);
        m_mtx.unlock();
    }

    BlkId&                         get_key() { return m_key; }
    std::vector< Free_Blk_Entry >* get_free_list() { return &m_free_list; }
    void                           free_yourself() { homeds::ObjectAllocator< BlkEvictionRecord >::deallocate(this); }
    void                           set_free_state() { m_can_free = true; }
    void                           reset_free_state() { m_can_free = false; }
    bool                           can_free() { return (m_can_free); }

    static BlkEvictionRecord* make_object(BlkId& bid) {
        return homeds::ObjectAllocator< BlkEvictionRecord >::make_object(bid);
    }

    //////////// Mandatory IntrusiveHashSet definitions ////////////////
    static void ref(BlkEvictionRecord& b) { intrusive_ptr_add_ref(&b); }

    static void set_free_state(BlkEvictionRecord& b) { b.set_free_state(); }

    static void reset_free_state(BlkEvictionRecord& b) { b.reset_free_state(); }

    static void deref(BlkEvictionRecord& b) { intrusive_ptr_release(&b); }

    static bool test_le(BlkEvictionRecord& b, int32_t check) { return b.m_refcount.test_le(check); }

    static bool test_le(const BlkEvictionRecord& b, int32_t check) { return b.m_refcount.test_le(check); }

    static const BlkId* extract_key(const BlkEvictionRecord& b) { return &(b.m_key); }
};

class BlkReadTrackerMetrics : public sisl::MetricsGroupWrapper {
public:
    explicit BlkReadTrackerMetrics(const char* vol_name) : sisl::MetricsGroupWrapper("BlkReadTracker", vol_name) {
        REGISTER_COUNTER(blktrack_pending_blk_read_map_sz, "Size of pending blk read map",
                         sisl::_publish_as::publish_as_gauge);
        REGISTER_COUNTER(blktrack_erase_blk_rescheduled, "Erase blk rescheduled due to concurrent rw");
        register_me_to_farm();
    }
};

class Blk_Read_Tracker {
    homeds::IntrusiveHashSet< BlkId, BlkEvictionRecord > m_pending_reads_map;
    BlkReadTrackerMetrics                                m_metrics;
    typedef std::function< void(Free_Blk_Entry) >        blk_remove_cb;
    blk_remove_cb                                        m_remove_cb;

public:
    Blk_Read_Tracker(const char* vol_name, blk_remove_cb remove_cb) :
            m_pending_reads_map(BLK_READ_MAP_SIZE),
            m_metrics(vol_name),
            m_remove_cb(remove_cb) {}

    void insert(BlkId& bid) {
        homeds::blob       b = BlkId::get_blob(bid);
        uint64_t           hash_code = util::Hash64((const char*)b.bytes, (size_t)b.size);
        BlkEvictionRecord* ber = BlkEvictionRecord::make_object(bid);
        BlkEvictionRecord* outber = nullptr;
        // insert into pending read map and set ref of value to 2(one for hashmap and one for client)
        // If value already present , insert() will just increase ref count of value by 1.
        bool inserted = m_pending_reads_map.insert(bid, *ber, &outber, hash_code);
        if (inserted) {
            COUNTER_INCREMENT(m_metrics, blktrack_pending_blk_read_map_sz, 1);
        } else { // record exists already, some other read happened
            homeds::ObjectAllocator< BlkEvictionRecord >::deallocate(ber);
        }
        BLKTRACKER_LOG(TRACE, blk_read_tracker, , "Marked read pending Bid:{},{}", bid, inserted);
    }

    void safe_remove_blks(bool is_read, std::vector< Free_Blk_Entry >* fbes, const std::error_condition& err) {
        if (fbes == nullptr) {
            return; // nothing to remove
        }
        if (is_read) {
            for (Free_Blk_Entry& fbe : *fbes) {
                safe_remove_blk_on_read(fbe);
            }
        } else {
            if (err != no_error) {
                return; // there was error in write, no need to erase any blks
            }
            for (Free_Blk_Entry& fbe : *fbes) {
                safe_remove_blk_on_write(fbe);
            }
        }
    }

    /* after read is finished, tis marked for safe removal*/
    void safe_remove_blk_on_read(Free_Blk_Entry& fbe) {
        homeds::blob b = BlkId::get_blob(fbe.m_blkId);
        uint64_t     hash_code = util::Hash64((const char*)b.bytes, (size_t)b.size);

        bool is_removed = m_pending_reads_map.check_and_remove(
            fbe.m_blkId, hash_code,
            [this](BlkEvictionRecord* ber) {
                // no more ref left
                if (ber->can_free()) {
                    for (auto& fbe : *ber->get_free_list()) {
                        m_remove_cb(fbe);
                    }
                }
            },
            true /* dec additional ref corresponding to insert by pending_read_blk_cb*/);
        if (is_removed) {
            COUNTER_DECREMENT(m_metrics, blktrack_pending_blk_read_map_sz, 1);
        }
        BLKTRACKER_LOG(TRACE, blk_read_tracker, , "UnMarked Read pending Bid:{},status:{}", fbe.m_blkId, is_removed);
    }

    /* after overwriting blk id in write flow, its marked for safe removal if cannot be freed immediatly*/
    void safe_remove_blk_on_write(Free_Blk_Entry& fbe) {
        BlkId              bid = fbe.m_blkId;
        homeds::blob       b = BlkId::get_blob(bid);
        uint64_t           hash_code = util::Hash64((const char*)b.bytes, (size_t)b.size);
        BlkEvictionRecord* outber = nullptr;
        bool               found = m_pending_reads_map.get(bid, &outber, hash_code); // get increases ref if found
        if (!found) {                                                                // no read pending
            m_remove_cb(fbe);
        } else if (found) {                // there is read pending
            outber->add_to_free_list(fbe); // thread safe addition
            outber->set_free_state();      // mark for removal

            // check_and_remove - If ref count becomes 1, it will be removed as only hashmap is holding the ref.
            bool is_removed =
                m_pending_reads_map.check_and_remove(bid, hash_code,
                                                     [this](BlkEvictionRecord* ber) {
                                                         // no more ref left
                                                         for (auto& fbe : *ber->get_free_list()) {
                                                             m_remove_cb(fbe);
                                                         }
                                                     },
                                                     true /* dec additional ref corresponding to get above*/);
            if (is_removed) {
                COUNTER_DECREMENT(m_metrics, blktrack_pending_blk_read_map_sz, 1);
            } else {
                COUNTER_INCREMENT(m_metrics, blktrack_erase_blk_rescheduled, 1);
            }
            BLKTRACKER_LOG(TRACE, blk_read_tracker, , "Marked erase write Bid:{},offset:{},nblks:{},status:{}", bid,
                           fbe.m_blk_offset, fbe.m_nblks_to_free, is_removed);
        }
    }

    uint64_t get_size() { return m_pending_reads_map.get_size(); }
};
} // namespace homestore

#endif
