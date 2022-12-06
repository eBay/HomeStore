#pragma once

#include <cstdint>
#include <memory>

#include "log_store.hpp"

namespace homestore {
class RaftLogStore {
public:
    RaftLogStore() = default;
    RaftLogStore(const RaftLogStore&) = delete;
    RaftLogStore& operator=(const RaftLogStore&) = delete;
    RaftLogStore(RaftLogStore&&) noexcept = delete;
    RaftLogStore& operator=(RaftLogStore&&) noexcept = delete;
    ~RaftLogStore() = default;

    [[nodiscard]] uint32_t next_slot() const { return 0; }

private:
    std::shared_ptr< HomeLogStore > m_hlogstore;
};
} // namespace homestore