#pragma once

#if defined(WIN32) || defined(_WIN32)
#error "Unsupported platform, POSIX only!"
#endif

extern "C" {
#include <endian.h>
}

#include <cassert>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>

// Copied from NuKV JungleDB project written by Jung-Sang Ahn and modified by Harihara Kadayam

namespace homestore {

struct SEBuf {
    /**
     * Empty buffer.
     */
    SEBuf() = default;

    /**
     * Reference to given address.
     */
    SEBuf(size_t _len, const void* _buf) : len(_len), buf((void*)_buf) {}

    /**
     * Reference to given string object.
     */
    SEBuf(const std::string& str) : len(str.size()), buf((void*)str.data()) {}

    /**
     * Allocate own memory.
     * If given length is 0, it will return an empty buffer.
     */
    static SEBuf alloc(size_t _len) {
        if (!_len) return SEBuf();
        return SEBuf(_len, malloc(_len));
    }

    /**
     * Free own memory.
     */
    inline void free() {
        ::free(buf);
        clear();
    }

    /**
     * Clear internal pointer without free.
     * User is responsible for managing memory to avoid memory leak.
     */
    inline void clear() {
        buf = nullptr;
        len = 0;
    }

    /**
     * Return `true` if this buffer is empty.
     */
    inline bool empty() const { return (buf == nullptr); }

    /**
     * Return the size of this buffer.
     */
    inline size_t size() const { return len; }

    /**
     * Return the pointer to the data of this buffer.
     */
    inline void* data() const { return buf; }

    /**
     * Create a std::string object that is clone of this buffer.
     */
    inline std::string toString() const { return std::string((const char*)buf, len); }

    /**
     * Return a string replacing non-readable character with `.`.
     * The max length of string will be upto given `limit`.
     */
    std::string rStr(size_t limit = 16) const;

    /**
     * Move ownership of data to given buffer `dst`.
     */
    inline void moveTo(SEBuf& dst) {
        dst = *this;
        clear();
    }

    /**
     * Make a copy of data and set it to given buffer `dst`.
     */
    inline void copyTo(SEBuf& dst) const {
        dst = alloc(len);
        if (len) { memcpy(dst.buf, buf, len); }
    }

    size_t len{0};
    void* buf{nullptr};

    /**
     * To easily free buffer (to avoid memory leak by mistake),
     * similar to `std::lock_guard`.
     */
    struct AutoFree {
        AutoFree(SEBuf& buf) : bufToHold(buf) {}
        ~AutoFree() { bufToHold.free(); }
        SEBuf& bufToHold;
    };
};
using SEBufHolder = SEBuf::AutoFree;

struct SEBufSerializer {
    SEBufSerializer(const SEBuf& _buf) : buf(_buf), offset(0), errHappened(false) {}

    inline bool isValid(size_t len) {
        if (errHappened || len + pos() > buf.len) {
            errHappened = true;
            return false;
        }
        return true;
    }

    inline bool ok() const { return !errHappened; }

    inline void pos(size_t _pos) {
        assert(_pos <= buf.len);
        offset = _pos;
    }

    inline size_t pos() const { return offset; }

    inline void clearError() { errHappened = false; }

    inline void* data() {
        uint8_t* ptr = (uint8_t*)buf.buf;
        return ptr + pos();
    }

    inline void putU64(uint64_t val) {
        if (!isValid(sizeof(val))) return;
        uint64_t u64 = htobe64(val);
        memcpy(data(), &u64, sizeof(u64));
        pos(pos() + sizeof(u64));
    }

    inline void putU32(uint32_t val) {
        if (!isValid(sizeof(val))) return;
        uint32_t u32 = htobe32(val);
        memcpy(data(), &u32, sizeof(u32));
        pos(pos() + sizeof(u32));
    }

    inline void putU16(uint16_t val) {
        if (!isValid(sizeof(val))) return;
        uint16_t u16 = htobe16(val);
        memcpy(data(), &u16, sizeof(u16));
        pos(pos() + sizeof(u16));
    }

    inline void putU8(uint8_t val) {
        if (!isValid(sizeof(val))) return;
        memcpy(data(), &val, sizeof(val));
        pos(pos() + sizeof(val));
    }

    inline void putRaw(size_t len, const void* src) {
        memcpy(data(), src, len);
        pos(pos() + len);
    }

    inline void put(size_t len, const void* src) {
        putU32(len);
        if (!isValid(len)) return;
        putRaw(len, src);
    }

    inline void putString(const std::string& str) { put(str.size(), str.data()); }

    inline void putSEBuf(const SEBuf& buf) { put(buf.len, buf.buf); }

    inline uint64_t getU64() {
        if (!isValid(sizeof(uint64_t))) return 0;
        uint64_t u64;
        memcpy(&u64, data(), sizeof(u64));
        pos(pos() + sizeof(u64));
        return be64toh(u64);
    }

    inline uint32_t getU32() {
        if (!isValid(sizeof(uint32_t))) return 0;
        uint32_t u32;
        memcpy(&u32, data(), sizeof(u32));
        pos(pos() + sizeof(u32));
        return be32toh(u32);
    }

    inline uint16_t getU16() {
        if (!isValid(sizeof(uint16_t))) return 0;
        uint16_t u16;
        memcpy(&u16, data(), sizeof(u16));
        pos(pos() + sizeof(u16));
        return be16toh(u16);
    }

    inline uint8_t getU8() {
        if (!isValid(sizeof(uint8_t))) return 0;
        uint8_t u8;
        memcpy(&u8, data(), sizeof(u8));
        pos(pos() + sizeof(u8));
        return u8;
    }

    inline void* getRaw(size_t len) {
        void* _data = data();
        pos(pos() + len);
        return _data;
    }

    inline void* get(size_t& len) {
        len = getU32();
        if (!isValid(len)) return nullptr;
        return getRaw(len);
    }

    inline std::string getString() {
        size_t _len;
        void* _data = get(_len);
        if (!_data) return std::string();
        return std::string((const char*)_data, _len);
    }

    inline SEBuf getSEBuf() {
        size_t _len;
        void* _data = get(_len);
        return SEBuf(_len, _data);
    }

    const SEBuf& buf;
    size_t offset;
    bool errHappened;
};

} // namespace homestore
