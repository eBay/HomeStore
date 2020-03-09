#pragma once

#include <iostream>
#include <sstream>
#include <string>

#include <string.h>

namespace homestore {

struct SizedBufFlags {
    static const uint8_t NEED_TO_FREE = 0x1;
    static const uint8_t NEED_TO_DELETE = 0x2;
};

// Note: SizedBuf will NOT create its own memory.
//       It will only point to the address given by user.
//       User is responsible for managing the actual memory region.
struct SizedBuf {
    struct Holder {
        Holder(SizedBuf& _src) : src(_src) {}
        ~Holder() { src.free(); }
        SizedBuf& src;
    };

    SizedBuf() : flags(0x0), size(0), data(nullptr) {}

    SizedBuf(size_t _size) : flags(0x0), size(0), data(nullptr) { alloc(_size, nullptr); }

    SizedBuf(size_t _size, void* _data) : flags(0x0) { set(_size, _data); }

    SizedBuf(const SizedBuf& src) : flags(0x0) {
        set(src.size, src.data);
        flags = src.flags;
    }

    SizedBuf(const std::string& str) : flags(0x0) { set(str.size(), (void*)str.data()); }

    SizedBuf(const char* str_char) : flags(0x0) { set(strlen(str_char), (void*)str_char); }

    SizedBuf& operator=(const SizedBuf& src) {
        flags = src.flags;
        size = src.size;
        data = src.data;
        return *this;
    }

    void moveTo(SizedBuf& dst) {
        dst.flags = flags;
        dst.size = size;
        dst.data = data;
        flags = 0x0;
        size = 0;
        data = nullptr;
    }

    void copyTo(SizedBuf& dst) const { dst.alloc(*this); }

    void referTo(const SizedBuf& src) {
        size = src.size;
        data = src.data;
        flags = 0x0;
    }

    // l  < r: return negative
    // l == r: return 0
    // l  > r: return positive
    static inline int cmp(const SizedBuf& l, const SizedBuf& r) {
        if (l.size == r.size) {
            if (l.size == 0)
                return 0;
            return memcmp(l.data, r.data, l.size);
        } else {
            size_t len = std::min(l.size, r.size);
            int    cmp = memcmp(l.data, r.data, len);
            if (cmp != 0)
                return cmp;
            else {
                return (int)((int)l.size - (int)r.size);
            }
        }
    }

    inline bool operator==(const SizedBuf& other) const {
        if (size != other.size)
            return false;
        if (size) {
            return memcmp(data, other.data, size) == 0;
        } else if (other.size == 0) {
            // Both are empty.
            return true;
        }
        return false;
    }

    inline bool operator!=(const SizedBuf& other) const { return !operator==(other); }

    friend inline bool operator<(const SizedBuf& l, const SizedBuf& r) {
        if (l.size == r.size) {
            if (l.size == 0)
                return false; // Both are empty.
            return (memcmp(l.data, r.data, l.size) < 0);
        } else if (l.size < r.size) {
            if (l.size == 0)
                return true;
            return (memcmp(l.data, r.data, l.size) <= 0);
        } else { // l.size > r.size
            if (r.size == 0)
                return false;
            return (memcmp(l.data, r.data, r.size) < 0);
        }

        return false;
    }

    friend inline bool operator<=(const SizedBuf& l, const SizedBuf& r) {
        if (l.size == r.size) {
            if (l.size == 0)
                return true; // Both are empty.
            return (memcmp(l.data, r.data, l.size) <= 0);
        } else if (l.size < r.size) {
            if (l.size == 0)
                return true;
            return (memcmp(l.data, r.data, l.size) <= 0);
        } else { // l.size > r.size
            if (r.size == 0)
                return false;
            return (memcmp(l.data, r.data, r.size) < 0);
        }

        return false;
    }

    friend inline bool operator>(const SizedBuf& l, const SizedBuf& r) { return !operator<=(l, r); }

    friend inline bool operator>=(const SizedBuf& l, const SizedBuf& r) { return !operator<(l, r); }

#define MSG_MAX 24
    friend std::ostream& operator<<(std::ostream& output, const SizedBuf& sb) {
        if (sb.size == 0) {
            output << "(empty)";
            return output;
        }

        output << "(" << sb.size << ") ";
        size_t size_local = std::min(sb.size, (uint32_t)MSG_MAX);
        for (size_t ii = 0; ii < size_local; ++ii) {
            char cc = ((char*)sb.data)[ii];
            if (0x20 <= cc && cc <= 0x7d) {
                output << cc;
            } else {
                output << '.';
            }
        }
        if (sb.size > MSG_MAX)
            output << "...";
        return output;
    }

    std::string toReadableString() const {
        std::stringstream ss;
        ss << *this;
        return ss.str();
    }

    // set(): Just assign the given pointer.
    //        User is responsible for memory management.
    void set(const SizedBuf& src) {
        set(src.size, src.data);
        flags = src.flags;
    }

    void set(const char* str_char) { set(strlen(str_char), (void*)str_char); }

    void set(const std::string& str) { set(str.size(), (void*)str.data()); }

    void set(size_t _size, void* _data) {
        clear();
        size = _size;
        data = static_cast< uint8_t* >(_data);
    }

    // alloc(): Allocate own memory using malloc().
    //          Users should explicitly call free().
    void alloc(const SizedBuf& src) { alloc(src.size, src.data); }

    void alloc(const char* str_char) { alloc(strlen(str_char), (void*)str_char); }

    void alloc(const std::string& str) { alloc(str.size(), (void*)str.data()); }

    void alloc(size_t _size) { alloc(_size, nullptr); }

    void alloc(size_t _size, void* _data) {
        clear();

        if (_size == 0) {
            data = nullptr;
            flags = 0x0;
            return;
        }

        size = _size;
        data = reinterpret_cast< uint8_t* >(malloc(size));
        if (_data) {
            // Source data is given: copy.
            memcpy(data, _data, size);
        } else {
            // NULL: just allocate space
            //       (set to 0 optionally).
            memset(data, 0x0, size);
        }
        flags |= SizedBufFlags::NEED_TO_FREE;
    }

    void resize(size_t _size) {
        if (!(flags & SizedBufFlags::NEED_TO_FREE)) {
            // Not owning the memory, fail.
            return;
        }

        uint8_t* new_ptr = reinterpret_cast< uint8_t* >(::realloc(data, _size));
        if (new_ptr) {
            data = new_ptr;
            size = _size;
        }
    }

    std::string toString() { return std::string((const char*)data, size); }

    bool free() {
        if (flags & SizedBufFlags::NEED_TO_FREE) {
            ::free(data);
            flags &= ~SizedBufFlags::NEED_TO_FREE;
            clear();
            return true;

        } else if (flags & SizedBufFlags::NEED_TO_DELETE) {
            delete[] data;
            flags &= ~SizedBufFlags::NEED_TO_DELETE;
            clear();
            return true;
        }
        return false;
    }

    void setNeedToFree() { flags |= SizedBufFlags::NEED_TO_FREE; }
    void setNeedToDelete() { flags |= SizedBufFlags::NEED_TO_DELETE; }

    void clear() {
        flags = 0x0;
        size = 0;
        data = nullptr;
    }

    bool empty() const { return (size == 0); }

    uint8_t  flags;
    uint32_t size;
    uint8_t* data;
};

}