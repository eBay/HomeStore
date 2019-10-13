#pragma once

#include "keyvalue.hpp"
#include "status.hpp"

#include <stdlib.h>
#include <string.h>

namespace homestore {

class Record {
public:
    enum Type : uint8_t { INSERTION = 0, DELETION = 1, COMMAND = 2 };

    struct Holder {
        Holder(Record& _rec) : rec(_rec) {}
        ~Holder() { rec.free(); }
        Record& rec;
    };

    Record() : seqNum(-1), type(INSERTION) {}

    Record(Type _type) : seqNum(-1), type(_type) {}

    Record(const uint64_t _seq_num, const Type _type) : seqNum(_seq_num), type(_type) {}

    size_t size() const { return kv.size() + meta.size; }

    void moveTo(Record& dst) {
        kv.moveTo(dst.kv);
        meta.moveTo(dst.meta);
        dst.seqNum = seqNum;
        dst.type = type;
        clear();
    }

    void copyTo(Record& dst) const {
        kv.copyTo(dst.kv);
        meta.copyTo(dst.meta);
        dst.seqNum = seqNum;
        dst.type = type;
    }

    Status clone(const Record& src) {
        if (kv.key.data || kv.value.data) {
            return Status(Status::ALREADY_INITIALIZED);
        }

        kv.key.alloc(src.kv.key.size, src.kv.key.data);
        kv.value.alloc(src.kv.value.size, src.kv.value.data);
        meta.alloc(src.meta);
        seqNum = src.seqNum;
        type = src.type;

        return Status();
    }

    // Caution: this function should be called only when
    //          this record has its own memory region
    //          (clone for example).
    void free() {
        kv.key.free();
        kv.value.free();
        meta.free();
    }
    void clear() {
        kv.clear();
        meta.clear();
        seqNum = -1;
        type = INSERTION;
    }

    bool empty() const { return kv.key.empty() && kv.value.empty(); }

    bool isIns() const { return type == INSERTION; }
    bool isDel() const { return type == DELETION; }
    bool isCmd() const { return type == COMMAND; }

    struct Less {
        bool operator()(const Record* a, const Record* b) const { return a->kv.key < b->kv.key; }
    };

    KV       kv;
    SizedBuf meta;
    uint64_t seqNum;
    Type     type;
};

} // namespace homestore