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
#include "omds/utility/useful_defs.hpp"

#pragma once

namespace omds {
typedef Bitword< uint64_t > Bitword64;

struct bitblock {
    uint64_t start_bit;
    uint32_t nbits;
};

class Bitset {
private:
    uint64_t m_nbits;
    std::vector< Bitword64 > m_words;

public:
    explicit Bitset(uint64_t nbits) :
            m_words((nbits - 1) / Bitword64::size() + 1) {
        m_nbits = nbits;
    }

    uint64_t get_total_bits() const {
        return m_nbits;
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

    bitblock get_next_contiguous_reset_bits(uint64_t start_bit) {
        int offset = get_word_offset(start_bit);
        bitblock retb = {0, 0};

        while (1) {
            Bitword64 *word = get_word(start_bit);
            if (word == nullptr) {
                break;
            }

            // Look for any free bits in the next iteration
            retb.start_bit = start_bit + word->get_next_reset_bits(offset, &retb.nbits);
            if (retb.nbits != 0) {
                break;
            }

            start_bit += (Bitword64::size() - offset);
            offset = 0;
        }

        return retb;
    }

    void print() {
        for (Bitword64 &w : m_words) {
            w.print();
        }
    }

private:
    Bitword64 *get_word(uint64_t b) {
        return (unlikely(b >= m_nbits)) ? nullptr : &m_words[b / Bitword64::size()];
    }

    const Bitword64 *get_word_const(uint64_t b) const {
        return (unlikely(b >= m_nbits)) ? nullptr : &m_words[b / Bitword64::size()];
    }

    int get_word_offset(uint64_t b) const {
        return (int) (b % Bitword64::size());
    }
};
}
