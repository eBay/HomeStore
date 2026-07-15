#include <map>
#include <unordered_map>

#include <sisl/logging/logging.h>
#include <sisl/options/options.h>
#include <gtest/gtest.h>

#include <homestore/blk.hpp>

SISL_LOGGING_INIT(HOMESTORE_LOG_MODS)
SISL_OPTIONS_ENABLE(logging, test_blkid, nuraft_mesg)

SISL_OPTION_GROUP(test_blkid,
                  (num_iterations, "", "num_iterations", "number of iterations",
                   ::cxxopts::value< uint32_t >()->default_value("1"), "number"));

using namespace homestore;
TEST(BlkIdTest, SingleBlkIdBasic) {
    blk_id b1;
    ASSERT_EQ(b1.is_valid(), false);
    ASSERT_EQ(b1.to_integer(), 0ULL);
    ASSERT_EQ(b1.to_string(), "Invalid_Blkid");

    blk_id b2{10, 5, 1};
    ASSERT_EQ(b2.is_valid(), true);
    ASSERT_EQ(b2.blk_num(), 10);
    ASSERT_EQ(b2.blk_count(), 5);
    ASSERT_EQ(b2.chunk_num(), 1);
    ASSERT_EQ(b2.is_multi(), false);

    sisl::blob buf = b2.serialize();
    ASSERT_EQ(buf.size(), sizeof(uint64_t));

    blk_id b3;
    b3.deserialize(buf, true);
    ASSERT_EQ(b3.is_valid(), true);
    ASSERT_EQ(b3, b2);

    blk_id b4{10, 6, 1};
    blk_id b5{9, 6, 1};
    blk_id b6{10, 5, 2};
    blk_id b7{10, 5, 1};
    ASSERT_LT(blk_id::compare(b2, b4), 0);
    ASSERT_GT(blk_id::compare(b2, b5), 0);
    ASSERT_LT(blk_id::compare(b2, b6), 0);
    ASSERT_EQ(blk_id::compare(b2, b7), 0);
}

TEST(BlkIdTest, SingleBlkIdInMap) {
    std::map< int, blk_id > m1;
    blk_id b1{30, 4, 2};
    m1.emplace(std::pair(84, blk_id{30, 4, 2}));
    ASSERT_EQ(m1.at(84), b1);

    std::map< blk_id, int > m2;
    m2.insert(std::pair(blk_id{30, 4, 2}, 94));
    m2.insert(std::pair(blk_id{30, 4, 1}, 96));

    auto const it1 = m2.find(blk_id{30, 4, 2});
    ASSERT_EQ(it1->second, 94);
    auto const it2 = m2.find(blk_id{30, 4, 3});
    ASSERT_EQ(it2, m2.cend());
}

TEST(BlkIdTest, MultiBlkIdTest) {
    multi_blk_id mb1;
    ASSERT_EQ(mb1.is_valid(), false);
    ASSERT_EQ(mb1.to_string(), "[]");
    ASSERT_EQ(mb1.is_multi(), true);
    ASSERT_EQ(mb1.num_pieces(), 0);

    mb1.add(10, 5, 1);
    ASSERT_EQ(mb1.is_valid(), true);
    ASSERT_EQ(mb1.blk_num(), 10);
    ASSERT_EQ(mb1.blk_count(), 5);
    ASSERT_EQ(mb1.chunk_num(), 1);
    ASSERT_EQ(mb1.is_multi(), true);

    std::array< blk_id, 5 > abs{blk_id{20, 8, 1}, blk_id{30, 1, 1}, blk_id{60, 9, 1}, blk_id{80, 5, 1},
                                blk_id{90, 2, 1}};
    for (auto const& b : abs) {
        mb1.add(b);
    }
    ASSERT_EQ(mb1.num_pieces(), 6);

    auto it = mb1.iterate();
    uint32_t i = 0;
    while (auto b = it.next()) {
        if (i == 0) {
            ASSERT_EQ(b->blk_num(), 10);
            ASSERT_EQ(b->blk_count(), 5);
        } else {
            ASSERT_EQ(*b, abs[i - 1]);
        }
        ++i;
    }
    ASSERT_EQ(i, 6);

    auto bl = mb1.serialize();
    multi_blk_id mb2;
    mb2.add(5, 6, 2);
    mb2.add(11, 10, 2);
    mb2.deserialize(bl, true); // Overwrite
    ASSERT_EQ(mb1, mb2);
}

TEST(BlkIdTest, MultiBlkIdInMap) {
    std::map< multi_blk_id, int > m1;
    std::unordered_map< multi_blk_id, int > m2;

    multi_blk_id mb1{30, 4, 2};
    mb1.add(90, 4, 2);
    mb1.add(80, 4, 2);
    mb1.add(20, 4, 2);
    mb1.add(10, 4, 2);
    ASSERT_EQ(mb1.num_pieces(), 5);

    m1.insert(std::pair(mb1, 92));
    m2.insert(std::pair(mb1, 92));

    multi_blk_id mb2{30, 4, 1};
    mb2.add(90, 4, 1);
    mb2.add(30, 4, 1);
    mb2.add(20, 4, 1);
    mb2.add(10, 4, 1);
    m1.insert(std::pair(mb2, 89));
    m2.insert(std::pair(mb2, 89)); // Insert exactly same except chunk_id different

    multi_blk_id mb3{30, 4, 1};
    mb3.add(90, 4, 1);
    mb3.add(30, 4, 1);
    mb3.add(20, 4, 1);
    mb3.add(10, 4, 1);
    m1.insert_or_assign(mb3, 90);
    m2.insert_or_assign(mb3, 90); // Update the value to validate == works correctly

    multi_blk_id mb4{30, 4, 2};
    mb4.add(80, 4, 2);
    ASSERT_EQ(mb4.num_pieces(), 2);
    m1.insert(std::pair(mb4, 93));
    m2.insert(std::pair(mb4, 93));

    multi_blk_id mb5{30, 4, 2};
    mb5.add(10, 3, 2);
    m1.insert(std::pair(mb5, 91));
    m2.insert(std::pair(mb5, 91));

    // Validate get on both the maps
    ASSERT_EQ(m1[mb1], 92);
    ASSERT_EQ(m2[mb1], 92);
    ASSERT_EQ(m1[mb3], 90);
    ASSERT_EQ(m2[mb3], 90);
    ASSERT_EQ(m1[mb4], 93);
    ASSERT_EQ(m2[mb4], 93);
    ASSERT_EQ(m1[mb5], 91);
    ASSERT_EQ(m2[mb5], 91);
    auto const it1 = m1.find(multi_blk_id{1, 1, 1});
    ASSERT_EQ(it1, m1.cend());
    auto const it2 = m2.find(multi_blk_id{100, 1, 2});
    ASSERT_EQ(it2, m2.cend());

    // Validate sorting order of std::map
    int prev_v{0};
    for (auto const [k, v] : m1) {
        ASSERT_GT(v, prev_v);
        prev_v = v;
    }
    ASSERT_EQ(m1.size(), 4u);
}

int main(int argc, char* argv[]) {
    int parsed_argc = argc;
    ::testing::InitGoogleTest(&parsed_argc, argv);
    SISL_OPTIONS_LOAD(parsed_argc, argv, logging, test_blkid);
    sisl::logging::SetLogger("test_blkid");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%t] %v");

    return RUN_ALL_TESTS();
}
