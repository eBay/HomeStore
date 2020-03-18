#include <limits.h>
#include <iostream>
#include <random>
#include <algorithm>
#include <chrono>
#include <gtest/gtest.h>
#include <sds_logging/logging.h>
#include <sds_options/options.h>
#include <utility/thread_buffer.hpp>
#include "main/homestore_header.hpp"
#include "homeds/bitmap/bitset.hpp"

SDS_LOGGING_INIT(logging, test_bitmap)
THREAD_BUFFER_INIT;

namespace homeds {

#define Ki 1024
#define Mi 1024 * Ki
#define Gi 1024 * Mi
#define MIN_LOWER_LIMIT 8

uint64_t max_nbits;
uint64_t fixed_nbits;

class RandNumGen {
private:
    uint64_t m_lower_limit;
    uint64_t m_upper_limit;

public:
    RandNumGen(uint64_t min, uint64_t max) : m_lower_limit(min), m_upper_limit(max) {}
    uint64_t get() {
        unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
        std::default_random_engine e(seed);
        std::uniform_int_distribution< uint64_t > u(m_lower_limit, m_upper_limit);
        return u(e);
    }
};

class BitmapTest : public ::testing::Test {
public:
    static std::string to_string(homeds::blob& b) {
        std::string out;
        Bitword64* p = (Bitword64*)b.bytes;
        // b.size must be rounded up to size of bitword64
        auto num_words = b.size / sizeof(Bitword64);
        for (auto i = 0U; i < num_words; i++) {
            out += p[i].to_string();
        }
        return out;
    }
    static uint64_t get_nbits() {
        if (fixed_nbits) {
            return fixed_nbits;
        }
        RandNumGen r(MIN_LOWER_LIMIT, max_nbits);
        return r.get();
    }

    // return in format of <i, nbits>, in which both i and nbits are randomly generated.
    static BitBlock gen_bitblock(uint64_t total_bits) {
        unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
        std::default_random_engine e(seed);
        std::uniform_int_distribution< uint64_t > u1(1, total_bits);

        std::uniform_int_distribution< uint64_t > u2(1, get_num_interval(total_bits));

        uint64_t i = 0, nbits = 0;
        do {
            i = u1(e);
            nbits = u2(e);
        } while (i + nbits >= total_bits);

        BitBlock b;
        b.start_bit = i;
        b.nbits = nbits;
        return b;
    }

    static uint32_t get_num_interval(uint64_t total_bits) {
        uint64_t range = 0;
        if (total_bits < Ki) {
            range = std::max(2ull, total_bits / 16ull);
        } else if (total_bits < Mi) {
            range = total_bits / 64;
        } else if (total_bits < Gi) {
            range = total_bits / 256;
        } else {
            range = 1024;
        }

        return range;
    }

    static void seq_set_bit(homeds::Bitset& bm, uint64_t start, uint64_t total_nbits) {
        for (uint64_t i = start; i < total_nbits; i++) {
            bm.set_bit(i);
        }
    }

    static void seq_set_bits(homeds::Bitset& bm, uint64_t start, uint64_t nbits, uint64_t total_nbits, uint64_t delta) {
        for (uint64_t i = start; i < total_nbits - nbits; i += delta * nbits) {
            bm.set_bits(i, nbits);
        }
    }

    static void reset_all_bits(homeds::Bitset& bm, uint64_t total_nbits) {
        for (uint64_t i = 0; i < total_nbits; i++) {
            bm.reset_bit(i);
        }
    }

    static void verify_all_reset(homeds::Bitset& bm, uint64_t total_nbits) {
        for (uint64_t i = 0; i < total_nbits; i++) {
            EXPECT_EQ(bm.get_bitval(i), false);
        }
    }

    // round up number of bits to number of Bitword64
    static uint64_t bits_to_word(uint64_t total_nbits) {
        uint32_t bits_per_word = (sizeof(Bitword64) << 3);
        if (total_nbits % bits_per_word == 0) {
            return (total_nbits / bits_per_word) * sizeof(Bitword64);
        } else {
            return (total_nbits / bits_per_word + 1) * sizeof(Bitword64);
        }
    }
};

// 1. Set/reset bit by bit sequencially
TEST_F(BitmapTest, SeqSetResetTest1) {
    uint64_t total_nbits = this->get_nbits();
    LOGINFO("total_nbits: {}", total_nbits);

    homeds::Bitset bm(total_nbits);
    EXPECT_EQ(bm.get_total_bits(), total_nbits);

    // 1. set bit by bit, then check
    seq_set_bit(bm, 0, total_nbits);

    for (uint64_t i = 0; i < total_nbits; i++) {
        EXPECT_EQ(bm.get_bitval(i), true);
    }

    // unsert and check
    reset_all_bits(bm, total_nbits);

    verify_all_reset(bm, total_nbits);
}

// 2. set_bits and reset_bits sequencially then verify
TEST_F(BitmapTest, SeqSetResetTest2) {
    uint64_t total_nbits = this->get_nbits();
    LOGINFO("total_nbits: {}", total_nbits);

    homeds::Bitset bm(total_nbits);
    EXPECT_EQ(bm.get_total_bits(), total_nbits);

    uint64_t start = 1, nbits = 7, delta = 3;
    seq_set_bits(bm, start, nbits, total_nbits, delta);

    // verify
    for (uint64_t i = start; i < total_nbits - nbits; i += delta * nbits) {
        EXPECT_EQ(bm.is_bits_set(i, nbits), true);
    }

    // reset
    for (uint64_t i = start; i < total_nbits; i += delta * nbits) {
        bm.reset_bits(i, nbits);
    }

    // verify again
    verify_all_reset(bm, total_nbits);
}

// Randomly set the bits then do verify
// Reset and then do verify again;
TEST_F(BitmapTest, RandomSetResetTest) {
    uint64_t total_nbits = this->get_nbits();
    LOGINFO("total_nbits: {}", total_nbits);

    homeds::Bitset bm(total_nbits);
    EXPECT_EQ(bm.get_total_bits(), total_nbits);
    // std::vector<std::pair<uint64_t, uint32_t>> bits_set;
    std::vector< BitBlock > bits_set;

    uint32_t num_attemps = this->get_num_interval(total_nbits);

    // randomly set the bits
    for (uint32_t i = 0; i < num_attemps; i++) {
        BitBlock b = this->gen_bitblock(total_nbits);
        bm.set_bits(b.start_bit, b.nbits);
        bits_set.push_back(b);
    }

    // verify
    for (auto& x : bits_set) {
        EXPECT_EQ(bm.is_bits_set(x.start_bit, x.nbits), true);
    }

    // reset
    for (auto& x : bits_set) {
        bm.reset_bits(x.start_bit, x.nbits);
    }

    verify_all_reset(bm, total_nbits);
}

// Seqencially fill with holes, then count contigous N bits
TEST_F(BitmapTest, ContiguousNbitsSimpleFillTest1) {
    uint64_t total_nbits = 30;
    homeds::Bitset bm(total_nbits);
    EXPECT_EQ(bm.get_total_bits(), total_nbits);

    bm.set_bits(0, 8);
    bm.set_bits(18, 12);

    BitBlock b = bm.get_next_contiguous_n_reset_bits(0, 10);
    EXPECT_EQ(b.start_bit, 8ull);
    EXPECT_EQ(b.nbits, 10ul);

    total_nbits = 128;
    homeds::Bitset bm2(total_nbits);
    bm2.set_bits(0, 48);
    bm2.set_bits(96, 32);

    // get contigous n bits *within* 64 (sizeof Bitword64) bytes boundary
    b = {0, 0};
    b = bm2.get_next_contiguous_n_reset_bits(40, 12);
    LOGINFO("b.start: {}, b.nbits: {}", b.start_bit, b.nbits);

    EXPECT_EQ(b.start_bit, 48ull);
    // Returns nbits more than 12, but 16, which is all the remaining bits in 64 Bytes;
    EXPECT_EQ(b.nbits, Bitword64::size() - 48ul);
}

// TODO: bitmap always return the first contigous zeros, even though it is less than requested n bits;
TEST_F(BitmapTest, DISABLED_ContiguousNbitsSimpleFillTest2) {
    uint64_t total_nbits = 64;
    homeds::Bitset bm(total_nbits);
    EXPECT_EQ(bm.get_total_bits(), total_nbits);
    // 11111111 00001111 00000011 01110000 11111000 00000000 10000000 11001100
    bm.set_bits(0, 8);
    bm.set_bits(12, 4);
#if 0
    bm.set_bits(22, 2);
    bm.set_bits(25, 3);
    bm.set_bits(31, 5);
    bm.set_bits(48, 1);
    bm.set_bits(56, 2);
    bm.set_bits(60, 2);
#endif
    BitBlock b = {0, 0};
    b = bm.get_next_contiguous_n_reset_bits(0, 6);
    // return value is: start_bit: 8, nbits: 4 which seems not correct
    EXPECT_EQ(b.start_bit, 16ull);
    EXPECT_EQ(b.nbits, 6ull);
#if 0 
    b = {0, 0};
    b = bm.get_next_contiguous_n_reset_bits(0, 11);
    EXPECT_EQ(b.start_bit, 16ull);
    EXPECT_EQ(b.nbits, 6ull);
#endif
}

//
// 1. Create bitmap with total nbits equal to two Bitword64
// 2. Fill the two words, but leave free bits at the end of first word and at the begining of 2nd word.
// 3. Verify that free bits could be allocated accross the boundary,
//    e.g. some bits from the 1st word, the remaining from the 2nd;
//
// TODO: Need to fix this issue, currently for the request of 48 free bits,
// get_next_contiguous_n_reset_bits could only return 32 free bits in the next word,
// even though there are 64 free bits across two words.
//
TEST_F(BitmapTest, DISABLED_ContiguousNbitsAcrossBoundaryTest1) {
    // set total nbits as 2 wrods
    uint64_t total_nbits = sizeof(Bitword64) << 3 << 1;

    homeds::Bitset bm(total_nbits);
    EXPECT_EQ(bm.get_total_bits(), total_nbits);

    // set 32 bits in first word
    bm.set_bits(0, 32);
    // set 32 bits in the 2nd word.
    bm.set_bits(96, 32);

    // bit 32 ~ 96 is free.
    // get 48 bits which has to accross two words;
    BitBlock b = bm.get_next_contiguous_n_reset_bits(0, 48);

    // return value is start_bit: 64, nbits: 32 which is not correct
    LOGINFO("start_bit: {}, nbits: {}", b.start_bit, b.nbits);
    EXPECT_EQ(b.start_bit, 32ull);
    EXPECT_EQ(b.nbits, 48ul);
}

//
// 1. Bitmap with 4 wrod, 1st and 4th word fill with 32 bits in the beginning
// 2. Leave 2nd and 3rd word totally free.
// 3. Allocate continous 96 bits, verfiy that we can get the free bits.
//
TEST_F(BitmapTest, DISABLED_ContiguousNbitsAcrossBoundaryTest2) {
    // set total nbits as 4 wrods
    uint64_t total_nbits = sizeof(Bitword64) << 3 << 2;

    LOGINFO("total bits: {}", total_nbits);
    homeds::Bitset bm(total_nbits);
    EXPECT_EQ(bm.get_total_bits(), total_nbits);

    // set 32 bits in 1st word
    bm.set_bits(0, 32);
    // set 32 bits in the 4th word.
    bm.set_bits(64 * 3, 32);

    // bit 32 ~ 192 is free.
    // get 128 bits which has to accross two words;
    BitBlock b = bm.get_next_contiguous_n_reset_bits(0, 96);

    // return value is start_bit: 224, nbits: 32 which is not correct
    LOGINFO("start_bit: {}, nbits: {}", b.start_bit, b.nbits);
    EXPECT_EQ(b.start_bit, 32ull);
    EXPECT_EQ(b.nbits, 96ul);
}

// 1. Sequencially fill the bits
// 2. then do verify by calling get_next_contiguous_n_reset_bits to assert on the free bits.
TEST_F(BitmapTest, ContiguousNbitsSeqFillTest) {
    uint64_t total_nbits = this->get_nbits();
    if (total_nbits < Mi) {
        total_nbits = Mi;
    }

    homeds::Bitset bm(total_nbits);
    EXPECT_EQ(bm.get_total_bits(), total_nbits);

    // seq fill with holes
    uint64_t start = 0, nbits = Bitword64::size(), delta = 2;
    LOGINFO("start: {}, nbits: {}, delta: {}", start, nbits, delta);
    seq_set_bits(bm, start, nbits, total_nbits, delta);

    // verify
    for (uint64_t i = start; i < total_nbits - delta * nbits; i += nbits * delta) {
        BitBlock b = bm.get_next_contiguous_n_reset_bits(i, nbits);
        EXPECT_EQ(b.start_bit, i + nbits);
        EXPECT_EQ(b.nbits, nbits);
    }

    reset_all_bits(bm, total_nbits);
    verify_all_reset(bm, total_nbits);
}

//
//
//
TEST_F(BitmapTest, SerializeSimpleTest1) {
    uint64_t total_nbits = 72;

    homeds::Bitset bm(total_nbits);
    EXPECT_EQ(bm.get_total_bits(), total_nbits);

    seq_set_bits(bm, 0, 4, total_nbits, 2);

    EXPECT_EQ(bm.size_serialized(), bits_to_word(total_nbits));

    homeds::blob b;
    auto ret = posix_memalign((void**)&b.bytes, 8192, bm.size_serialized());
    EXPECT_EQ(ret, 0);

    b.size = bm.size_serialized();
    memset(b.bytes, 0, b.size);

    assert(b.size % sizeof(Bitword64) == 0);

    auto ret_b = bm.serialize(b);
    EXPECT_EQ(ret_b, true);

    std::string str = to_string(b);
    LOGINFO("{}", to_string(b));
    bm.print();

    free(b.bytes);
}

TEST_F(BitmapTest, SerializeSimpleTest2) {
    uint64_t total_nbits = 64;

    homeds::Bitset bm(total_nbits);
    EXPECT_EQ(bm.get_total_bits(), total_nbits);

    bm.set_bits(8, 3);
    bm.set_bits(16, 2);

    EXPECT_EQ(bm.size_serialized(), bits_to_word(total_nbits));

    homeds::blob b;
    auto ret = posix_memalign((void**)&b.bytes, 8192, bm.size_serialized());
    EXPECT_EQ(ret, 0);

    b.size = bm.size_serialized();
    memset(b.bytes, 0, b.size);

    assert(b.size % sizeof(Bitword64) == 0);

    auto ret_b = bm.serialize(b);
    EXPECT_EQ(ret_b, true);

    std::string str = to_string(b);
    LOGINFO("{}", to_string(b));
    bm.print();

    free(b.bytes);
}

// 1. fill the bitmap
// 2. Do serilize;
// 3. Deserilize
// 4. Compare the two bitmap which should the exact the same;
//
TEST_F(BitmapTest, DeserializeTest) {
    uint64_t total_nbits = this->get_nbits();
    if (total_nbits < Ki) {
        total_nbits = Ki;
    }

    total_nbits = 72;

    homeds::Bitset bm(total_nbits);
    EXPECT_EQ(bm.get_total_bits(), total_nbits);

    // 1. fill
    seq_set_bits(bm, 0, 4, total_nbits, 2);

    EXPECT_EQ(bm.size_serialized(), bits_to_word(total_nbits));

    homeds::blob b1;
    auto ret = posix_memalign((void**)&b1.bytes, 8192, bm.size_serialized());
    EXPECT_EQ(ret, 0);
    b1.size = bm.size_serialized();
    memset(b1.bytes, 0, b1.size);

    assert(b1.size % sizeof(Bitword64) == 0);

    // 2. do serialize
    bool ret_b = bm.serialize(b1);
    EXPECT_EQ(ret_b, true);

    // 3. de-serialize b1 to generate a deep copy
    homeds::Bitset bm_copy(b1);

    // 4. verify the two bitmaps bit by bit
    // NOTE: total bits may not strictly be the same, but must be the same after rouned up to word;
    // This is because after serialize, we don't track the actual bits, but the actual words;
    EXPECT_EQ(bits_to_word(bm.get_total_bits()), bits_to_word(bm_copy.get_total_bits()));

    for (uint64_t i = 0; i < total_nbits; i++) {
        EXPECT_EQ(bm.get_bitval(i), bm_copy.get_bitval(i));
    }

    // print the two bitmap which should be exactly the same;
    bm.print();
    bm_copy.print();

    // Serilize again using bm_copy and compare b1 & b2
    homeds::blob b2;
    ret = posix_memalign((void**)&b2.bytes, 8192, bm_copy.size_serialized());
    EXPECT_EQ(ret, 0);
    b2.size = bm_copy.size_serialized();
    memset(b2.bytes, 0, b2.size);

    assert(b2.size % sizeof(Bitword64) == 0);

    ret_b = bm_copy.serialize(b2);
    EXPECT_EQ(ret_b, true);

    EXPECT_STREQ(bm.to_string().c_str(), bm_copy.to_string().c_str());

    free(b1.bytes);
    free(b2.bytes);
}
} // namespace homeds

SDS_OPTION_GROUP(test_bitmap,
                 (max_nbits, "", "max_nbits", "max number of bits",
                  ::cxxopts::value< uint64_t >()->default_value("1000000"), "number"),
                 (fixed_nbits, "", "fixed_nbits", "fixed number of bits",
                  ::cxxopts::value< uint64_t >()->default_value("0"), "number"))

SDS_OPTIONS_ENABLE(logging, test_bitmap)
int main(int argc, char* argv[]) {
    testing::InitGoogleTest(&argc, argv);
    SDS_OPTIONS_LOAD(argc, argv, logging, test_bitmap)
    sds_logging::SetLogger("test_bitmap");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");

    homeds::max_nbits = SDS_OPTIONS["max_nbits"].as< uint64_t >();
    homeds::fixed_nbits = SDS_OPTIONS["fixed_nbits"].as< uint64_t >();
    assert(homeds::max_nbits >= MIN_LOWER_LIMIT);
    if (homeds::fixed_nbits) {
        assert(homeds::fixed_nbits >= MIN_LOWER_LIMIT);
    }

    return RUN_ALL_TESTS();
}
