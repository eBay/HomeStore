/**
 * Copyright eBay Inc 2018
 */

#ifndef Interval_Array_DS_H_
#define Interval_Array_DS_H_

#include "elastic_array.h"
#include <blkalloc/blk.h>
#include <sds_logging/logging.h>
#include <map>

using namespace std;
namespace homeds {

    template<int INTERVAL_SIZE_IN_BITS>
    struct Interval {

        uint64_t m_interval_start:INTERVAL_SIZE_IN_BITS;
        uint64_t m_interval_length:INTERVAL_SIZE_IN_BITS;

        Interval() : m_interval_start(0), m_interval_length(0), m_value(Value()) {}

        Interval(uint64_t m_interval_start, uint64_t m_interval_length) : m_interval_start(m_interval_start),
                                                                          m_interval_length(m_interval_length) {}

        uint64_t end() {
            return m_interval_start + m_interval_length - 1;
        }

        uint64_t start() {
            return m_interval_start;
        }

        bool operator<(Interval &other) {
            if (m_interval_start < other.m_interval_start)return true;
            else return false;
        }

        bool operator>(Interval &other) {
            if (m_interval_start > other.m_interval_start)return true;
            else return false;
        }

        bool operator==(Interval &other) {
            if (m_interval_start == other.m_interval_start)return true;
            else return false;
        }

        std::shared_ptr<Interval> overlap(Interval *other, uint64_t &offsetOut) {
            uint16_t s_overlap = std::max(this->start(), other->start());
            uint16_t e_overlap = std::min(this->end(), other->end());
            std::shared_ptr<Interval> overlap = nullptr;
            offsetOut = s_overlap - this->start();
            overlap = std::make_shared<Interval>(s_overlap, e_overlap - s_overlap + 1);
            return overlap;
        }

        std::shared_ptr<Interval> leftNonOverlap(Interval *other, uint64_t &offsetOut) {
            uint16_t s_overlap = std::max(this->start(), other->start());
            std::shared_ptr<Interval> overlap = nullptr;
            offsetOut = 0;
            if (this->start() < s_overlap) {
                overlap = std::make_shared<Interval>(this->start(), (s_overlap - 1) - this->start() + 1);
            }
            return overlap;
        }

        std::shared_ptr<Interval> rightNonOverlap(Interval *other, uint64_t &offsetOut) {
            uint16_t e_overlap = std::min(this->end(), other->end());
            std::shared_ptr<Interval> overlap = nullptr;
            offsetOut = 0;
            if (this->end() > e_overlap) {
                offsetOut = (e_overlap + 1) -
                            this->start();
                overlap = std::make_shared<Interval>(e_overlap + 1, this->end() - (e_overlap + 1) + 1);
            }
            return overlap;
        }

        /*Override Value and m_value in substruct of interval*/
        struct Value {
        }__attribute__ ((__packed__));
        Value m_value;

    }__attribute__ ((__packed__));

    template<ArrayType>
    class Interval_Array : public Elastic_Array<ArrayTypeParams> {
    public:
        //allocates new memory for no_of elements
        Interval_Array(int no_of_elements_capacity, uint32_t max_grow_to);

        //Copy constructor
        Interval_Array(void *mem, uint32_t size, uint32_t max_grow_to);

        //adds new interval and returns existing overlapping intervals
        void
        addInterval(ElementType *newInterval, std::vector<std::shared_ptr<ElementType> > &existingIntervalOverlaps);

        //get all intervals
        void getAllIntervals(std::vector<std::shared_ptr<ElementType>> &intervalList);

        //get intervals matching findInterval criteria
        void getIntervals(ElementType *findInterval,
                          std::vector<std::shared_ptr<ElementType>> &intervalList,
                          uint16_t &startIndex, uint16_t &endIndex);

    private:
        // performs inplace updates if possible instead of explicit insert/remove shifts.
        void optimized_cud(std::shared_ptr<ElementType> leadNonOverlap,
                           std::shared_ptr<ElementType> trailNonOverlap,
                           ElementType *newInterval, uint16_t startIndex, uint16_t endIndex,
                           bool remove);

    };

    /***************** IMPLEMENTATION ********************/
    template<ArrayType>
    Interval_Array<ArrayTypeParams>::Interval_Array(int no_of_elements_capacity, uint32_t max_grow_to)
            :Elastic_Array<ArrayTypeParams>(
            no_of_elements_capacity, max_grow_to) {
    }

    template<ArrayType>
    Interval_Array<ArrayTypeParams>::Interval_Array(void *mem, uint32_t size, uint32_t max_grow_to)
            :Elastic_Array<ArrayTypeParams>(
            mem, size, max_grow_to) {
    }

    template<ArrayType>
    void
    Interval_Array<ArrayTypeParams>::addInterval(ElementType *newInterval,
                                                 std::vector<std::shared_ptr<ElementType> > &existingIntervalOverlaps) {

        uint16_t startIndex = 0;//point where to delete ranges from.(inclusive). Also the insertion point for newInterval
        uint16_t endIndex = 0;// point where to delete range to. (inclusive)

        getIntervals(newInterval, existingIntervalOverlaps, startIndex, endIndex);

        std::shared_ptr<ElementType> leadNonOverlap = nullptr;
        std::shared_ptr<ElementType> trailNonOverlap = nullptr;
        ElementType *currentInterval = nullptr;


        if (startIndex < this->get_no_of_elements_filled()) {
            currentInterval = (*this)[startIndex];
            if (newInterval->start() > currentInterval->start() && newInterval->start() <= currentInterval->end()) {
                //partial left overlap
                uint64_t offset = 0;
                std::shared_ptr<Interval<8>> intersectInterval = currentInterval->leftNonOverlap(newInterval, offset);
                leadNonOverlap = std::make_shared<ElementType>((uint64_t)intersectInterval->m_interval_start,
                                                               (uint64_t)intersectInterval->m_interval_length,
                                                               currentInterval->m_value);

                leadNonOverlap->m_value.add(offset);
                assert(leadNonOverlap->m_value.m_blkid_offset + leadNonOverlap->m_interval_length <= leadNonOverlap->m_value.m_blkid.get_nblks());
            }
        }
        if (endIndex < this->get_no_of_elements_filled()) {
            currentInterval = (*this)[endIndex];
            if (newInterval->end() >= currentInterval->start() && newInterval->end() < currentInterval->end()) {
                //partial right overlap
                uint64_t offset = 0;
                std::shared_ptr<Interval<8>> intersectInterval = currentInterval->rightNonOverlap(newInterval, offset);
                trailNonOverlap = std::make_shared<ElementType>((uint64_t)intersectInterval->m_interval_start,
                                                               (uint64_t)intersectInterval->m_interval_length,
                                                                currentInterval->m_value);

                trailNonOverlap->m_value.add(offset);
                assert(trailNonOverlap->m_value.m_blkid_offset + trailNonOverlap->m_interval_length <= trailNonOverlap->m_value.m_blkid.get_nblks());
            }
        }

        bool is_completely_disjoint = false;// indicates no overlaps whatsoever
        if (existingIntervalOverlaps.size() == 0)
            is_completely_disjoint = true;

        LOGTRACE("Post overlap phase:{} -> {}", startIndex, endIndex);

        /** check for merges */
        bool merged = false;

        std::shared_ptr<ElementType> merged_interval = nullptr;
        bool is_intervals_mergable = false;

        if (startIndex > 0) {
            currentInterval = (*this)[startIndex - 1];
            currentInterval->merge_compare(currentInterval, newInterval, merged_interval, is_intervals_mergable);
            if (is_intervals_mergable) {
                if (is_completely_disjoint && startIndex == endIndex)endIndex--;
                newInterval = merged_interval.get();
                startIndex--;
                merged = true;
            }
        }
        LOGTRACE("Post left merge phase:{} -> {}", startIndex, endIndex);
        //check if right mergable or not 
        if (startIndex != endIndex && this->get_no_of_elements_filled() != 0 &&
            endIndex < this->get_no_of_elements_filled() - 1) {
            currentInterval = (*this)[endIndex + 1];
            currentInterval->merge_compare(currentInterval, newInterval, merged_interval, is_intervals_mergable);
            if (is_intervals_mergable) {// TODO - check if interval is right disjoint then do not do endIndex++
                newInterval = merged_interval.get();
                endIndex++;
                merged = true;
            }
        }
        LOGTRACE("Post right merge phase:{} -> {}", startIndex, endIndex);
        LOGTRACE("Prior to append:{}", this->to_string());
        assert(startIndex <= endIndex);

        bool remove = false;
        if (merged || !is_completely_disjoint) {
            // either merger or overlap happened
            //when right end of new range crosses over all existing ranges
            if (endIndex == this->get_no_of_elements_filled()) endIndex--;
            assert(startIndex <= endIndex);
            remove = true;
        } else {
            //disjoint
            if (startIndex != endIndex) {
                //eclipsing multipe intervals
                remove = true;
            }
        }
        optimized_cud(leadNonOverlap, trailNonOverlap, newInterval, startIndex,
                      endIndex, remove);
    }

    template<ArrayType>
    void
    Interval_Array<ArrayTypeParams>::optimized_cud(
            std::shared_ptr<ElementType> leadNonOverlap,
            std::shared_ptr<ElementType> trailNonOverlap,
            ElementType *newInterval, uint16_t startIndex, uint16_t endIndex,
            bool remove) {
        if (leadNonOverlap != nullptr) {
            if (startIndex <= endIndex && startIndex < this->get_no_of_elements_filled() && remove) {
                this->update(startIndex, leadNonOverlap.get());
            } else {
                this->insert_shift(startIndex, leadNonOverlap.get());
            }
            startIndex++;
        }

        if (startIndex <= endIndex && startIndex < this->get_no_of_elements_filled() && remove) {
            this->update(startIndex, newInterval);
        } else {
            this->insert_shift(startIndex, newInterval);
        }
        startIndex++;

        if (trailNonOverlap != nullptr) {
            if (startIndex <= endIndex && startIndex < this->get_no_of_elements_filled() && remove) {
                this->update(startIndex, trailNonOverlap.get());
            } else {
                this->insert_shift(startIndex, trailNonOverlap.get());
            }
            startIndex++;
        }

        if (remove && startIndex <= endIndex) {
            this->remove_shift(startIndex, endIndex);
        }
    }

    template<ArrayType>
    void
    Interval_Array<ArrayTypeParams>::getAllIntervals(
            std::vector<std::shared_ptr<ElementType> > &intervalList) {
        uint32_t i = 0;
        while (i < this->get_no_of_elements_filled()) {
            std::shared_ptr<ElementType> element = std::make_shared<ElementType>(*(*this)[i]);
            intervalList.push_back(element);
            i++;
        }

    }

    template<ArrayType>
    void
    Interval_Array<ArrayTypeParams>::getIntervals(ElementType *search,
                                                  std::vector<std::shared_ptr<ElementType> > &existing,
                                                  uint16_t &si, uint16_t &ei) {
        if (this->get_no_of_elements_filled() == 0)return;
        int st = this->binary_search(search);

        if (st < 0) {
            st = (-st - 1);//insertion point
            if (st > 0)st--;//consider one more on left as could be partial overlap
        }
        uint16_t ci = (uint16_t) st;
        si = ei = ci;
        std::shared_ptr<ElementType> intersect = nullptr;
        bool siFound = false;
        while (ci < this->get_no_of_elements_filled()) {
            ElementType *current = (*this)[ci];
            if (current->end() < search->start()) {
                //skip intervals which are out of range
                ci++;
                continue;
            }
            if (!siFound) {
                siFound = true;
                si = ei = ci;//set start index
            }
            if (search->end() < current->start()) {
                //reached end of our search
                break;
            }
            ei = ci;// set end index

            //there is intersect

            uint64_t offset = 0;
            std::shared_ptr<Interval<8>> intersectInterval = current->overlap(search, offset);
            intersect = std::make_shared<ElementType>((uint64_t)intersectInterval->m_interval_start,
                                                      (uint64_t)intersectInterval->m_interval_length,
                                                      current->m_value);

            intersect->m_value.add(offset);

            if (intersect != nullptr) {
                existing.push_back(intersect);
                intersect = nullptr;
            }

            ci++;
        }
        if(ci == this->get_no_of_elements_filled() && !siFound){
            si=ei=ci;
        }

        /* At this point, 
         if there is left overlap, startIndex will point to it. If not, it will point to insertion index
         if there is right overlap, endIndex will point to it. If not, it will point to  insertion index -1 or startIndex*/
        
#ifndef NDEBUG
        std::stringstream ss;
        for (std::shared_ptr<ElementType> interval : existing) {
            ss << interval->to_string() << "#";
        }
        LOGTRACE("getIntervals of {} ====> {},{} - {}", search->to_string(),si, ei, ss.str());
#endif
    }

}//end of namespace
#endif//end of ifdef