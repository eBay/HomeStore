//
// Modified by Yaming Kuang
//

#pragma once

#include <cassert>
#include <cstdint>
#include <random>
#include <sstream>
#include <string>

#include "homeds/loadgen/loadgen_common.hpp"
#include "homeds/loadgen/spec/key_spec.hpp"

namespace homeds {
namespace loadgen {

//
//
class LogStoreKey : public KeySpec {
#define MAX_VDEV_ALLOC_SIZE 8192
#define VDEV_BLK_SIZE 512

public:
    LogStoreKey() {}

    static LogStoreKey gen_key(KeyPattern spec, LogStoreKey* ref_key = nullptr) {
        static std::atomic< uint64_t > seq_num = 0;
        seq_num.fetch_add(1, std::memory_order_relaxed);
        return LogStoreKey(seq_num.load());
    }

    LogStoreKey(uint64_t seq) : m_seq_num(seq) {}

    virtual bool operator==(const KeySpec& other) const override {
        assert(0);
        return true;
    }

    virtual bool is_consecutive(KeySpec& k) override {
        assert(0);
        return false;
    }

    virtual int compare(KeySpec* other) const {
        LogStoreKey* k = dynamic_cast< LogStoreKey* >(other);
        return to_string().compare(k->to_string());
    }

    std::string to_string() const {
        ostringstream os;
        os << m_seq_num;
        return os.str();
    }

    uint64_t get_key() const { return m_seq_num; }

private:
    uint64_t m_seq_num = 0;
};

template < typename charT, typename traits >
std::basic_ostream< charT, traits >& operator<<(std::basic_ostream< charT, traits >& outStream,
                                                const LogStoreKey& log_store_key) {
    // copy the stream formatting
    std::basic_ostringstream< charT, traits > outStringStream;
    outStringStream.copyfmt(outStream);

    // print the stream
    outStringStream << log_store_key.to_string();
    outStream << outStringStream.str();

    return outStream;
}

} // namespace loadgen
} // namespace homeds
