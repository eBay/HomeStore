#pragma once
#include <homestore/replication/repl_dev.h>

namespace homestore {
class SoloReplDev : public ReplDev {
public:
    void async_alloc_write(const sisl::blob& header, const sisl::blob& key, const sisl::sg_list& value,
                           void* user_ctx) override {}
};

} // namespace homestore
