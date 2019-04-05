/*
 * bitset.hpp
 *
 *  Created on: 11-Feb-2017
 *      Author: hkadayam
 */
#include <cassert>
#include <vector>
#include <algorithm>
#include "bitword.hpp"
#include "homeds/utility/useful_defs.hpp"

#pragma once

namespace homeds {
typedef Bitword< uint64_t > Bitword64;

struct bitblock {
    uint64_t start_bit;
    uint32_t nbits;
};

struct serialized_bitset {
    uint32_t serialized_size;
    Bitword< uint64_t > words[0];
} __attribute__((packed));

class Bitset {
private:
    uint64_t m_nbits;
    std::vector< Bitword64 > m_words;

public:
    explicit Bitset(uint64_t nbits) :
            m_words((nbits - 1) / Bitword64::size() + 1) {
        m_nbits = nbits;
    }

    explicit Bitset(std::vector< Bitword64 > &words) :
            m_words(words) {
        m_nbits = words.size() * Bitword64::size();
    }

    explicit Bitset(const homeds::blob &b) {
        auto sbitset = (serialized_bitset *)b.bytes;

        uint32_t nwords = (sbitset->serialized_size - sizeof(serialized_bitset))/ sizeof(Bitword64);
        m_words.reserve(nwords);

        for (auto i = 0U; i < nwords; i++) {
            m_words.emplace_back(sbitset->words[i]);
        }
        m_nbits = nwords * sizeof(Bitword64);
    }

    uint64_t get_total_bits() const {
        return m_nbits;
    }

    /* Serialize the bitset into the blob provided upto blob bytes. Returns if it able completely serialize within
     * the bytes specified.
     */
    bool serialize(const homeds::blob &b) {
        assert(b.size >= sizeof(serialized_bitset)); // We need to at least serialize size bytes

        uint32_t slot = 0;
        uint32_t max_slots = (b.size - sizeof(serialized_bitset))/sizeof(Bitword64);

        auto sbitset = (serialized_bitset *)b.bytes;
        sbitset->serialized_size = b.size;
        for (auto w : m_words) {
            if (slot >= max_slots) {
                break;
            }
            sbitset->words[slot++] = w;
        }

        return (b.size >= size_serialized());
    }

    /* Returns how much bytes it will occupy when this bitset is serialized */
    uint32_t size_serialized() const {
        return sizeof(serialized_bitset) + (sizeof(Bitword64) * m_words.size());
    }

    void set_reset_bits(uint64_t b, int nbits, bool value) {
        int offset = get_word_offset(b);

        while (nbits > 0) {
            Bitword64 *word = get_word(b);
            if (word == nullptr) {
                break;
            }
            int count = std::min(nbits, (int)Bitword64::size() - offset);
            word->set_reset_bits(offset, count, value);

            b += count;
            nbits -= count;
            offset = 0;
        }
    }

    void set_reset_bit(uint64_t b, bool value) {
        Bitword64 *word = get_word(b);
        int offset = get_word_offset(b);

        word->set_reset_bits(offset, 1, value);
    }

    void set_bit(uint64_t b) {
        set_reset_bit(b, true);
    }

    void set_bits(uint64_t b, int nbits) {
        set_reset_bits(b, nbits, true);
    }

    void reset_bit(uint64_t b) {
        set_reset_bit(b, false);
    }

    void reset_bits(uint64_t b, int nbits) {
        set_reset_bits(b, nbits, false);
    }

    bool get_bitval(uint64_t b) const {
        const Bitword64 *word = get_word_const(b);
        int offset = get_word_offset(b);

        return word->is_bit_set_reset(0, true);
    }

    bool is_bits_set_reset(uint64_t b, int nbits, bool expected) {
        int offset = get_word_offset(b);

        while (nbits > 0) {
            Bitword64 *word = get_word(b);
            if (word == nullptr) {
                break;
            }
            int count = std::min(nbits, (int)Bitword64::size() - offset);
            if (!word->is_bits_set_reset(offset, count, expected)) {
                return false;
            }

            b += count;
            nbits -= count;
            offset = 0;
        }

        return true;
    }

    bool is_bits_set(uint64_t b, int nbits) {
        return is_bits_set_reset(b, nbits, true);
    }

    bool is_bits_reset(uint64_t b, int nbits) {
        return is_bits_set_reset(b, nbits, false);
    }

    bitblock get_next_contiguous_n_reset_bits(uint64_t start_bit, uint32_t n) {
        int offset = get_word_offset(start_bit);
        bitblock retb = {0, 0};

        while (1) {
            Bitword64 *word = get_word(start_bit);
            if (word == nullptr) {
                break;
            }

            // Look for any free bits in the next iteration
            retb.start_bit = start_bit + word->get_next_reset_bits(offset, &retb.nbits);
            if (retb.nbits >= n) {
                break;
            }

            start_bit += (Bitword64::size() - offset);
            offset = 0;
        }

        return retb;
    }

    bitblock get_next_contiguous_reset_bits(uint64_t start_bit) {
        return(get_next_contiguous_n_reset_bits(start_bit, 1));
    }

    void print() {
        for (Bitword64 &w : m_words) {
            w.print();
        }
    }

private:
    Bitword64 *get_word(uint64_t b) {
        return (hs_unlikely(b >= m_nbits)) ? nullptr : &m_words[b / Bitword64::size()];
    }

    const Bitword64 *get_word_const(uint64_t b) const {
        return (hs_unlikely(b >= m_nbits)) ? nullptr : &m_words[b / Bitword64::size()];
    }

    int get_word_offset(uint64_t b) const {
        return (int) (b % Bitword64::size());
    }
};
}
