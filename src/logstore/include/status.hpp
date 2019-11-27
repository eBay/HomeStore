#pragma once

namespace homestore {

class Status {
public:
    enum Value {
        OK = 0,
        INVALID_PARAMETERS = -1,
        ALREADY_EXIST = -2,
        NOT_INITIALIZED = -3,
        ALLOCATION_FAILURE = -4,
        ALREADY_INITIALIZED = -5,
        LOG_FILE_NOT_FOUND = -6,
        INVALID_SEQNUM = -7,
        SEQNUM_NOT_FOUND = -8,

        LOG_NOT_SYNCED = -14,
        ALREADY_PURGED = -15,
        KEY_NOT_FOUND = -16,

        ITERATOR_INIT_FAIL = -18,
        OUT_OF_RANGE = -19,
        ALREADY_LOADED = -20,
        FILE_NOT_EXIST = -21,
        KVS_NOT_FOUND = -22,

        ALREADY_CLOSED = -24,
        ALREADY_SHUTDOWN = -25,
        INVALID_HANDLE_USAGE = -26,
        NO_LOGS = -27,
        OPERATION_IN_PROGRESS = -28,
        ALREADY_REMOVED = -29,

        ALREADY_FLUSHED = -35,

        CHECKSUM_ERROR = -41,

        INVALID_RECORD = -43,

        TIMEOUT = -52,

        INVALID_OFFSET = -54,
        HANDLE_IS_BEING_CLOSED = -55,
        ERROR = -32768
    };

    Status() : val(OK) {}
    Status(int _val) : val((Value)_val) {}
    Status(Value _val) : val(_val) {}

    explicit    operator bool() { return ok(); }
    inline bool operator==(const Status::Value _val) const { return (val == _val) ? true : false; }
                operator int() const { return (int)val; }
    Value       getValue() const { return val; }
    bool        ok() const { return val == OK; }

private:
    Value val;
};

}