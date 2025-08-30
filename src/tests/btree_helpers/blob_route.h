#pragma once

#include "btree_test_kvs.hpp"

constexpr size_t pg_width = sizeof(uint16_t) * 8;
constexpr size_t shard_width = (sizeof(uint64_t) * 8) - pg_width;
constexpr size_t shard_mask = std::numeric_limits< uint64_t >::max() >> pg_width;
constexpr uint16_t max_chunks = 1000;

struct BlobRouteByChunk {
    // homestore::chunk_num_t == uint16_t
    uint16_t chunk{0};
    uint64_t shard{0};
    uint64_t blob{0};
    auto operator<=>(BlobRouteByChunk const&) const = default;
    sisl::blob to_blob() const {
        return sisl::blob{uintptr_cast(const_cast< BlobRouteByChunk* >(this)), sizeof(*this)};
    }
};
#pragma pack()

namespace fmt {
template <>
struct formatter< BlobRouteByChunk > {
    template < typename ParseContext >
    constexpr auto parse(ParseContext& ctx) {
        return ctx.begin();
    }

    template < typename FormatContext >
    auto format(BlobRouteByChunk const& r, FormatContext& ctx) {
        return format_to(ctx.out(), "{:04x}:{:04x}:{:012x}:{:016x}", r.chunk, (r.shard >>shard_width),
                         (r.shard & shard_mask), r.blob);
    }
};

} // namespace fmt

class BlobRouteByChunkKey : public homestore::BtreeKey {
private:
    BlobRouteByChunk key_;

public:
    BlobRouteByChunkKey() = default;
    BlobRouteByChunkKey(const BlobRouteByChunk key) : key_(key) {}
    BlobRouteByChunkKey(const BlobRouteByChunkKey& other) : BlobRouteByChunkKey(other.serialize(), true) {}
    BlobRouteByChunkKey(const homestore::BtreeKey& other) : BlobRouteByChunkKey(other.serialize(), true) {}
    BlobRouteByChunkKey(const sisl::blob& b, bool copy) :
            homestore::BtreeKey(), key_{*(r_cast< const BlobRouteByChunk* >(b.cbytes()))} {}

    ~BlobRouteByChunkKey() override = default;

    int compare(const homestore::BtreeKey& o) const override {
        const BlobRouteByChunkKey& other = s_cast< const BlobRouteByChunkKey& >(o);
        if (key_ < other.key_) {
            return -1;
        } else if (key_ > other.key_) {
            return 1;
        } else {
            return 0;
        }
    }

    sisl::blob serialize() const override { return key_.to_blob(); }
    uint32_t serialized_size() const override { return sizeof(key_); }
    static bool is_fixed_size() { return true; }
    static uint32_t get_fixed_size() { return (sizeof(key_)); }
    std::string to_string() const { return fmt::format("{}", key_); }

    void deserialize(const sisl::blob& b, bool copy) override {
        key_ = *(r_cast< const BlobRouteByChunk* >(b.cbytes()));
    }

    static uint32_t get_max_size() { return get_fixed_size(); }
    friend std::ostream& operator<<(std::ostream& os, const BlobRouteByChunkKey& k) {
        os << fmt::format("{}", k.key());
        return os;
    }

    BlobRouteByChunk key() const { return key_; }
};

template <>
struct std::hash< BlobRouteByChunk > {
    std::size_t operator()(BlobRouteByChunk const& r) const noexcept {
        std::size_t seed = 0;
        boost::hash_combine(seed, r.chunk);
        boost::hash_combine(seed, r.shard);
        boost::hash_combine(seed, r.blob);
        return seed;
    }
};
