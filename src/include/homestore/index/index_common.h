#pragma once
#include <string>
#include <sisl/utility/enum.hpp>

namespace homestore {
class IndexStore {
public:
    SCOPED_ENUM_DECL(Type, uint8_t);

    IndexStore() = default;
    virtual ~IndexStore() = default;
    virtual void stop() = 0;

    virtual std::string store_type() const = 0;
    virtual void on_recovery_completed() = 0;
};

SCOPED_ENUM_DEF(IndexStore, Type, uint8_t, MEM_BTREE, COPY_ON_WRITE_BTREE, INPLACE_BTREE);
} // namespace homestore