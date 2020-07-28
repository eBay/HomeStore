#include "log_store.hpp"

namespace homestore {
class RaftLogStore {
public:
    RaftLogStore::RaftLogStore() {}

    ulong next_slot() const override {}

private:
    std::shared_ptr< HomeLogStore > m_hlogstore;
};
} // namespace homestore