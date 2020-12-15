//
// Created by Kadayam, Hari on Sep 20 2020
//
#pragma once

#include <string>
#include <vector>
#include <array>
#include <atomic>
#include <cstdint>
#include <fmt/format.h>
#include <fmt/ostream.h>
#include <utility/enum.hpp>
#include <fds/bitword.hpp>
#include "blk.h"

namespace homestore {
typedef blk_count_t slab_idx_t;

static constexpr uint16_t slab_tbl_size{257};

// Lookup table that converts number_of_blks to slab
static constexpr std::array< slab_idx_t, slab_tbl_size > nblks_to_slab_tbl = {
    0, 0, 1, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6,
    6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8};

// Lookup table that converts number_of_blks to the lower slab and the difference with the lower slab
static constexpr std::array< std::pair< slab_idx_t, uint8_t >, slab_tbl_size > nblks_to_round_down_slab_tbl = {
    {{0, 0},   {0, 0},   {1, 0},   {1, 1},   {2, 0},   {2, 1},   {2, 2},   {2, 3},   {3, 0},   {3, 1},   {3, 2},
     {3, 3},   {3, 4},   {3, 5},   {3, 6},   {3, 7},   {4, 0},   {4, 1},   {4, 2},   {4, 3},   {4, 4},   {4, 5},
     {4, 6},   {4, 7},   {4, 8},   {4, 9},   {4, 10},  {4, 11},  {4, 12},  {4, 13},  {4, 14},  {4, 15},  {5, 0},
     {5, 1},   {5, 2},   {5, 3},   {5, 4},   {5, 5},   {5, 6},   {5, 7},   {5, 8},   {5, 9},   {5, 10},  {5, 11},
     {5, 12},  {5, 13},  {5, 14},  {5, 15},  {5, 16},  {5, 17},  {5, 18},  {5, 19},  {5, 20},  {5, 21},  {5, 22},
     {5, 23},  {5, 24},  {5, 25},  {5, 26},  {5, 27},  {5, 28},  {5, 29},  {5, 30},  {5, 31},  {6, 0},   {6, 1},
     {6, 2},   {6, 3},   {6, 4},   {6, 5},   {6, 6},   {6, 7},   {6, 8},   {6, 9},   {6, 10},  {6, 11},  {6, 12},
     {6, 13},  {6, 14},  {6, 15},  {6, 16},  {6, 17},  {6, 18},  {6, 19},  {6, 20},  {6, 21},  {6, 22},  {6, 23},
     {6, 24},  {6, 25},  {6, 26},  {6, 27},  {6, 28},  {6, 29},  {6, 30},  {6, 31},  {6, 32},  {6, 33},  {6, 34},
     {6, 35},  {6, 36},  {6, 37},  {6, 38},  {6, 39},  {6, 40},  {6, 41},  {6, 42},  {6, 43},  {6, 44},  {6, 45},
     {6, 46},  {6, 47},  {6, 48},  {6, 49},  {6, 50},  {6, 51},  {6, 52},  {6, 53},  {6, 54},  {6, 55},  {6, 56},
     {6, 57},  {6, 58},  {6, 59},  {6, 60},  {6, 61},  {6, 62},  {6, 63},  {7, 0},   {7, 1},   {7, 2},   {7, 3},
     {7, 4},   {7, 5},   {7, 6},   {7, 7},   {7, 8},   {7, 9},   {7, 10},  {7, 11},  {7, 12},  {7, 13},  {7, 14},
     {7, 15},  {7, 16},  {7, 17},  {7, 18},  {7, 19},  {7, 20},  {7, 21},  {7, 22},  {7, 23},  {7, 24},  {7, 25},
     {7, 26},  {7, 27},  {7, 28},  {7, 29},  {7, 30},  {7, 31},  {7, 32},  {7, 33},  {7, 34},  {7, 35},  {7, 36},
     {7, 37},  {7, 38},  {7, 39},  {7, 40},  {7, 41},  {7, 42},  {7, 43},  {7, 44},  {7, 45},  {7, 46},  {7, 47},
     {7, 48},  {7, 49},  {7, 50},  {7, 51},  {7, 52},  {7, 53},  {7, 54},  {7, 55},  {7, 56},  {7, 57},  {7, 58},
     {7, 59},  {7, 60},  {7, 61},  {7, 62},  {7, 63},  {7, 64},  {7, 65},  {7, 66},  {7, 67},  {7, 68},  {7, 69},
     {7, 70},  {7, 71},  {7, 72},  {7, 73},  {7, 74},  {7, 75},  {7, 76},  {7, 77},  {7, 78},  {7, 79},  {7, 80},
     {7, 81},  {7, 82},  {7, 83},  {7, 84},  {7, 85},  {7, 86},  {7, 87},  {7, 88},  {7, 89},  {7, 90},  {7, 91},
     {7, 92},  {7, 93},  {7, 94},  {7, 95},  {7, 96},  {7, 97},  {7, 98},  {7, 99},  {7, 100}, {7, 101}, {7, 102},
     {7, 103}, {7, 104}, {7, 105}, {7, 106}, {7, 107}, {7, 108}, {7, 109}, {7, 110}, {7, 111}, {7, 112}, {7, 113},
     {7, 114}, {7, 115}, {7, 116}, {7, 117}, {7, 118}, {7, 119}, {7, 120}, {7, 121}, {7, 122}, {7, 123}, {7, 124},
     {7, 125}, {7, 126}, {7, 127}, {8, 0}}};

struct blk_cache_entry {
public:
    blk_cache_entry() : blk_cache_entry{0, 0, 0} {}
    blk_cache_entry(const blk_num_t blk_num, const blk_count_t nblks, const blk_temp_t temp) {
        set_blk_num(blk_num);
        set_nblks(nblks);
        set_temperature(temp);
    }

    void set_blk_num(const blk_num_t blk_num) { m_blk_num = blk_num; }
    [[nodiscard]] blk_num_t get_blk_num() const { return m_blk_num; }

    void set_nblks(const blk_count_t nblks) {
        HS_DEBUG_ASSERT_LE(nblks, BlkId::max_blks_in_op());
        m_nblks = static_cast< blk_count_serialized_t >(nblks - 1);
    }
    [[nodiscard]] blk_count_t get_nblks() const { return static_cast< blk_count_t >(m_nblks) + 1; }

    void set_temperature(const blk_temp_t temp) { m_temp = temp; }
    [[nodiscard]] blk_temp_t get_temperature() const { return m_temp; }

    [[nodiscard]] std::string to_string() const {
        return fmt::format("BlkNum={} nblks={} temp={}", get_blk_num(), get_nblks(), get_temperature());
    }

private:
    blk_num_t m_blk_num;            // Blk number within the chunk
    blk_count_serialized_t m_nblks; // Total number of blocks
    blk_temp_t m_temp;              // Temperature of each page
} __attribute__((packed, aligned(1)));

struct blk_cache_alloc_req {
    blk_cache_alloc_req(const blk_count_t n, const blk_temp_t l, const bool contiguous, const slab_idx_t m = 0) :
            nblks{n}, preferred_level{l}, is_contiguous(contiguous), min_slab_idx{m} {}

    const blk_count_t nblks;
    const blk_temp_t preferred_level;
    const bool is_contiguous;
    const slab_idx_t min_slab_idx;
};

struct blk_cache_alloc_resp {
    blk_cache_alloc_resp() {
        out_blks.reserve(256);
        excess_blks.reserve(8);
    }

    void reset() {
        nblks_alloced = 0;
        nblks_zombied = 0;
        out_blks.clear();
        excess_blks.clear();
    }

    blk_count_t nblks_alloced{0};
    blk_count_t nblks_zombied{0};
    bool need_refill{false};
    std::vector< blk_cache_entry > out_blks;
    std::vector< blk_cache_entry > excess_blks;
};

struct blk_cache_fill_req {
    blk_num_t start_blk_num{0};    // Start blk number available to fill
    uint32_t nblks{0};             // Number of blks available to fill
    blk_temp_t preferred_level{1}; // Preferred temperature level to fill this cache in
    bool only_this_level{false};   // Is cache to be filled only in this level/temperature
};

struct blk_cache_refill_status {
    blk_cap_t slab_required_count{0};
    blk_cap_t slab_refilled_count{0};

    [[nodiscard]] bool need_refill() const {
        return (slab_required_count && (slab_refilled_count != slab_required_count));
    }

    [[nodiscard]] bool is_refill_done() const {
        return (slab_required_count == 0) || (slab_refilled_count == slab_required_count);
    }

    void mark_refill_done() { slab_refilled_count = slab_required_count; }
};

struct blk_cache_fill_session {
    uint64_t session_id;
    std::vector< blk_cache_refill_status > slab_requirements; // A slot for each slab about count of required/refilled
    blk_cap_t overall_refilled_num_blks{0};
    bool overall_refill_done{false};
    std::atomic< blk_cap_t > urgent_refill_blks_count{0}; // Send notification after approx this much blks refilled

    static uint64_t gen_session_id() {
        static std::atomic< uint64_t > s_session_id{1};
        return s_session_id.fetch_add(1, std::memory_order_relaxed);
    }

    blk_cache_fill_session(const size_t num_slabs, const bool fill_entire_cache) : session_id{gen_session_id()} {
        slab_requirements.reserve(num_slabs);
    }

    void urgent_need_atleast(const blk_cap_t wait_count) {
        urgent_refill_blks_count.store(overall_refilled_num_blks + wait_count, std::memory_order_release);
    }

    [[nodiscard]] bool need_notify() const {
        const auto urgent_count = urgent_refill_blks_count.load(std::memory_order_acquire);
        return ((urgent_count > 0) && ((overall_refilled_num_blks >= urgent_count) || overall_refill_done));
    }

    void set_urgent_satisfied() { urgent_refill_blks_count.store(0, std::memory_order_release); }

    [[nodiscard]] bool is_urgent_req_pending() const {
        return urgent_refill_blks_count.load(std::memory_order_acquire);
    }

    void reset() {
        session_id = gen_session_id();
        slab_requirements.clear();
        overall_refill_done = false;
        overall_refilled_num_blks = 0;
        urgent_refill_blks_count.store(0, std::memory_order_release);
    }

    std::string to_string() const {
        return fmt::format("session={} slab_reqs={} blks_refilled_so_far={} refill_done={}", session_id,
                           fmt::join(slab_requirements, ","), overall_refilled_num_blks, overall_refill_done);
    }
};

struct SlabCacheConfig {
    struct _slab_config {
        blk_count_t slab_size;      // Size of this slab (in terms of number of blks)
        blk_cap_t max_entries;      // Max entries allowed in this slab
        float refill_threshold_pct; // At what percentage empty should we start refilling this slab cache
        std::vector< float > m_level_distribution_pct; // How to distribute entries into multiple levels
        std::string m_name;                            // Name of the base blk allocator
    };

    std::string m_name;
    std::vector< _slab_config > m_per_slab_cfg;

    [[nodiscard]] std::string to_string() const {
        std::string str;
        for (const auto& s : m_per_slab_cfg) {
            fmt::format_to(std::back_inserter(str),
                           "[nblks={} max_entries={} refill_threshold={} level distribution=[{}]], ", s.slab_size,
                           s.max_entries, s.refill_threshold_pct, fmt::join(s.m_level_distribution_pct, ","));
        }
        return str;
    }
    [[nodiscard]] std::string get_name() const { return m_name; }
};

class FreeBlkCache {
public:
    virtual ~FreeBlkCache() = default;

    /**
     * @brief Try to allocate nblks on a preferred temperature level. Note the level is just a hint and if there is
     * no available block in that level in cache, it automatically checks for other levels in the same slab and allocate
     * based on that.
     *
     * @param req Request which comprises number_of_blks, preferred_temp_level to allocate, is_contiguous blocks are
     * needed or vector of multiple blocks is ok.
     * @param resp
     * @return BlkAllocStatus
     */
    virtual BlkAllocStatus try_alloc_blks(const blk_cache_alloc_req& req, blk_cache_alloc_resp& resp) = 0;

    virtual BlkAllocStatus try_free_blks(const blk_cache_entry& entry, std::vector< blk_cache_entry >& excess_blks,
                                         blk_count_t& num_zombied) = 0;
    virtual BlkAllocStatus try_free_blks(const std::vector< blk_cache_entry >& blks,
                                         std::vector< blk_cache_entry >& excess_blks, blk_count_t& num_zombied) = 0;
    virtual blk_cap_t try_fill_cache(const blk_cache_fill_req& fill_req, blk_cache_fill_session& fill_session) = 0;

    virtual std::shared_ptr< blk_cache_fill_session > create_cache_fill_session(const bool fill_entire_cache) = 0;
    virtual void close_cache_fill_session(blk_cache_fill_session& fill_session) = 0;

    virtual blk_num_t total_free_blks() const = 0;

    static slab_idx_t find_slab(const blk_count_t nblks) {
        if (sisl_unlikely(nblks >= slab_tbl_size)) { return static_cast< slab_idx_t >(sisl::logBase2(nblks - 1)) + 1; }
        return nblks_to_slab_tbl[nblks];
    }

    static std::pair< slab_idx_t, blk_count_t > find_round_down_slab(const blk_count_t nblks) {
        if (sisl_unlikely(nblks >= slab_tbl_size)) {
            auto s = find_slab(nblks + 1) - 1;
            return std::make_pair<>(s, nblks - (1 << s));
        }
        return nblks_to_round_down_slab_tbl[nblks];
    }
};
} // namespace homestore

namespace fmt {
template <>
struct formatter< homestore::blk_cache_refill_status > {
    template < typename ParseContext >
    constexpr auto parse(ParseContext& ctx) {
        return ctx.begin();
    }

    template < typename FormatContext >
    auto format(const homestore::blk_cache_refill_status& s, FormatContext& ctx) {
        return format_to(ctx.out(), "{}/{}", s.slab_refilled_count, s.slab_required_count);
    }
};

template <>
struct formatter< homestore::SlabCacheConfig > {
    template < typename ParseContext >
    constexpr auto parse(ParseContext& ctx) {
        return ctx.begin();
    }

    template < typename FormatContext >
    auto format(const homestore::SlabCacheConfig& s, FormatContext& ctx) {
        return format_to(ctx.out(), "{}", s.to_string());
    }
};
} // namespace fmt