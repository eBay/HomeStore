/**
 * Copyright eBay Inc 2018
 */

#ifndef Interval_Array_DS_H_
#define Interval_Array_DS_H_

#include "homeds/array/elastic_array.h"

namespace homeds {
    struct Offset_BlkId {
        uint16_t m_offset:BIT_TO_REPRESENT_MAX_ENTRIES_DECLARE;
        struct BlkId m_blkid;

        Offset_BlkId(uint64_t offset, struct BlkId blkid) : m_offset(offset), m_blkid(blkid) {}

        bool operator<(struct Offset_BlkId &other) {
            if (m_offset < other.m_offset)return true;
            else return false;
        }

        bool operator>(struct Offset_BlkId &other) {
            if (m_offset > other.m_offset)return true;
            else return false;
        }

        bool operator==(struct Offset_BlkId &other) {
            if (m_offset == other.m_offset)return true;
            else return false;
        }

        std::string to_string() {
            std::stringstream ss;
            ss << m_offset << "--->" << m_blkid.to_string();
            return ss.str();
        };

        operator std::string() { return to_string(); }
    }__attribute__ ((__packed__));
    
    template<ElasticArrayType>
    class Interval_Array : Elastic_Array<ElasticArrayTypeParams> {
    public:
        void addInterval();
    };

    template<ElasticArrayType>
    void
    Interval_Array<ElasticArrayTypeParams>::addInterval(Offset_BlkId *newRange) {
        //all s/e offset and blockid are inclusive
        uint16_t new_sOffset = newRange->m_offset;
        uint8_t blocks_to_add = newRange->m_blkid.get_nblks();
        uint16_t new_eOffset = newRange->m_offset + blocks_to_add - 1;
        uint64_t new_sblockId = newRange->m_blkid.get_id();
        uint64_t new_eblockId = newRange->m_blkid.get_id() + newRange->m_blkid.get_nblks() - 1;
        uint16_t new_chunk_num = newRange->m_blkid.get_chunk_num();

        Offset_BlkId *startLeadingNonOverlappingPart = nullptr;
        Offset_BlkId *endTrailingNonOverlappingPart = nullptr;
        Offset_BlkId *currentRange = nullptr;

        //loop to find index of left overlap (partial or full)
        while (startIndex < this->get_no_of_elements_filled()) {
            currentRange = (*this)[startIndex];
            //all s/e offset and blockid are inclusive
            uint16_t curr_sOffset = currentRange->m_offset;
            uint16_t curr_eOffset = currentRange->m_offset + currentRange->m_blkid.get_nblks() - 1;
            uint64_t curr_sblockId = currentRange->m_blkid.get_id();
            uint16_t curr_chunk_num = currentRange->m_blkid.get_chunk_num();

            if (new_sOffset < curr_sOffset) {
                break;
            } else if (new_sOffset >= curr_sOffset && new_sOffset <= curr_eOffset) {
                //start did overlap (partially or fully)
                is_disjoint_interval = false;
                if (new_sOffset > curr_sOffset) {
                    //partial overlap
                    startLeadingNonOverlappingPart = new
                            Offset_BlkId(curr_sOffset,
                                         BlkId(curr_sblockId,
                                               (new_sOffset -
                                                curr_sOffset),
                                               curr_chunk_num));
                }
                break;
            }
            startIndex++;
        }
        // At this point, if there is overlap, startIndex will point to it. If not, it will point to insertion index
        endIndex = startIndex;
        LOGTRACE("Post left overlap phase:{} -> {}", startIndex, endIndex);

        //loop to find index of right overlap (partial or full)
        while (endIndex < this->get_no_of_elements_filled()) {
            currentRange = (*this)[endIndex];
            //all s/e offset and blockid are inclusive
            uint16_t curr_sOffset = currentRange->m_offset;
            uint16_t curr_eOffset = currentRange->m_offset + currentRange->m_blkid.get_nblks() - 1;
            uint64_t curr_sblockId = currentRange->m_blkid.get_id();
            uint16_t curr_chunk_num = currentRange->m_blkid.get_chunk_num();

            if (new_eOffset < curr_sOffset) {
                break; // end did not overlap
            } else if (new_eOffset >= curr_sOffset && new_eOffset <= curr_eOffset) {
                //start did overlap (partially or fully)
                is_disjoint_interval = false;
                is_right_overlap = true;
                if (new_eOffset < curr_eOffset) {
                    //partial overlap
                    endTrailingNonOverlappingPart = new
                            Offset_BlkId(new_eOffset + 1,
                                         BlkId(curr_sblockId +
                                               (new_eOffset -
                                                curr_sOffset + 1),
                                               (curr_eOffset -
                                                new_eOffset),
                                               curr_chunk_num));
                }
                break;
            }
            is_eclipsing_multiple_intervals = true;
            endIndex++;
        }
        if (!is_right_overlap && endIndex > startIndex) {
            endIndex--;
        }
        LOGTRACE("Post right overlap phase:{} -> {}", startIndex, endIndex);
        // At this point, if there is overlap, endIndex will point to it. If not, it will point to  insertion index -1 or startIndex

        //check if left mergable or not
        if (startIndex > 0) {
            currentRange = (*this)[startIndex - 1];
            uint16_t curr_sOffset = currentRange->m_offset;
            uint16_t curr_eOffset = currentRange->m_offset + currentRange->m_blkid.get_nblks() - 1;
            uint64_t curr_sblockId = currentRange->m_blkid.get_id();
            uint64_t curr_eblockId = curr_sblockId + currentRange->m_blkid.get_nblks() - 1;
            uint16_t curr_chunk_num = currentRange->m_blkid.get_chunk_num();

            if (curr_eOffset + 1 == new_sOffset && curr_eblockId + 1 == new_sblockId &&
                curr_chunk_num == new_chunk_num) {
                //contigious

                if (is_disjoint_interval && startIndex == endIndex) {
                    //did not overlap and start/end points to same entry
                    // we need to keep start and end at same position
                    // eg interval existing is 5-15, 20-27 and new interval comes as 16-17
                    // in this case start and end were pointingto 20-27 and we realized lef merge is needed
                    // so we point start and end  to 5-15
                    endIndex--;
                }
                startIndex--;
                is_disjoint_interval = false;
                newRange->m_offset = curr_sOffset;
                newRange->m_blkid.set_id(curr_sblockId);
                newRange->m_blkid.set_nblks(newRange->m_blkid.get_nblks() + currentRange->m_blkid.get_nblks());
            }
        }
        LOGTRACE("Post left merge phase:{} -> {}", startIndex, endIndex);
        //check if right mergable or not
        if (endIndex < this->get_no_of_elements_filled() - 1) {
            currentRange = (*this)[endIndex + 1];
            uint16_t curr_sOffset = currentRange->m_offset;
            uint64_t curr_sblockId = currentRange->m_blkid.get_id();
            uint16_t curr_chunk_num = currentRange->m_blkid.get_chunk_num();

            if (curr_sOffset - 1 == new_eOffset && curr_sblockId - 1 == new_eblockId &&
                curr_chunk_num == new_chunk_num) {
                //contigious
                endIndex++;
                is_disjoint_interval = false;
                newRange->m_blkid.set_nblks(newRange->m_blkid.get_nblks() + currentRange->m_blkid.get_nblks());
            }
        }
        LOGTRACE("Post right merge phase:{} -> {}", startIndex, endIndex);
        LOGTRACE("Is disjoint?:{} ", is_disjoint_interval);
        LOGTRACE("Prior to append:{}", this->get_string_representation());
        //TODO-reduce so many remove shift and insert shift , insetad use in place updates partially
        assert(startIndex <= endIndex);

#ifndef NDEBUG
        uint64_t nblks_before = count_nblks();
#endif

        if (!is_disjoint_interval) {
            // either merger or overlap happened

            //when righ end of new range crosses over all existing ranges
            if (endIndex == this->get_no_of_elements_filled()) endIndex--;

            this->remove_shift(startIndex, endIndex);
        } else {
            if (is_eclipsing_multiple_intervals) {
                this->remove_shift(startIndex, endIndex);
            }
        }

        // Not adding required elements
        std::vector<Offset_BlkId *> listToAdd;
        if (startLeadingNonOverlappingPart != nullptr) {
            listToAdd.push_back(startLeadingNonOverlappingPart);
        }
        listToAdd.push_back(newRange);
        if (endTrailingNonOverlappingPart != nullptr) {
            listToAdd.push_back(endTrailingNonOverlappingPart);
        }
        uint16_t index = startIndex;
        for (auto value : listToAdd) {
            this->insert_shift(index, value);
            index++;
        }

#ifndef NDEBUG
        validate_sanity_value_array(nblks_before);
#endif
        delete startLeadingNonOverlappingPart;
        delete endTrailingNonOverlappingPart;
    }

#ifndef NDEBUG

    uint64_t count_nblks() {
        uint64_t nblks = 0;
        for (uint32_t i = 0; i < this->get_no_of_elements_filled(); i++) {
            nblks += (*this)[i]->m_blkid.m_nblks;
        }
        return nblks;
    }

    // TODO - also check if all entries are not contigious, as it hsould had been merged already
    void validate_sanity_value_array(uint64_t nblks_before) {
        uint64_t nblks_after = count_nblks();
        if (nblks_after < nblks_before) {
            LOGDEBUG("Lost entry:{} -> {} :: {}", nblks_before, nblks_after, this->to_string());
            assert(0);
        }

        int i = 0;
        std::map<int, bool> mapOfWords;
        int prevsOffset = -1;
        int preveOffset = -1;
        //validate if keys are in ascending orde
        while (i < (int) this->get_no_of_elements_filled()) {
            Offset_BlkId *currentRange = (*this)[i];
            uint16_t soffset = currentRange->m_offset;
            uint16_t eoffset = currentRange->m_offset + currentRange->m_blkid.m_nblks - 1;
            std::pair<std::map<int, bool>::iterator, bool> result;
            result = mapOfWords.insert(std::make_pair(soffset, true));
            if (result.second == false) {
                //check uniqueness and sorted
                LOGDEBUG("Duplicate entry:{} -> {}", soffset, this->to_string());
                assert(0);
            }
            if (soffset < prevsOffset) {
                LOGDEBUG("Not Sorted-> {},{} -> {}", prevsOffset, soffset, this->to_string());
                assert(0);
            }
            if (soffset <= preveOffset) {
                LOGDEBUG("Overlapping-> {},{} -> {}", prevsOffset, soffset, this->to_string());
                assert(0);
            }
            if(eoffset>=MAX_NO_OF_VALUE_ENTRIES){
                LOGDEBUG("Overflow-> {}-> {}", soffset, this->to_string());
                assert(0);
            }
            prevsOffset = soffset;
            preveOffset = eoffset;
            i++;
        }
    }
}
#endif