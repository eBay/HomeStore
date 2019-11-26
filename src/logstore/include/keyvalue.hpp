#pragma once

#include "sized_buf.hpp"

#include <string>
#include <iostream>

#include <string.h>

namespace homestore {

// Note: same as SizedBuf, KV doesn't have its own memory.
//       User is responsible for managing memory regions.
class KV {
public:
    struct Holder {
        Holder(KV& _kv) : kv(_kv) {}
        ~Holder() { kv.free(); }
        KV& kv;
    };

    KV() {}

    KV(size_t _key_size, void* _key_data, size_t _value_size, void* _value_data) {
        key.set(_key_size, _key_data);
        value.set(_value_size, _value_data);
    }

    KV(const SizedBuf& _key, const SizedBuf& _value) : key(_key), value(_value) {}

    KV(const KV& src) { set(src.key, src.value); }

    KV(const std::string& _key, const std::string& _value) { set(_key, _value); }

    KV(const char* _key, const char* _value) { set(_key, _value); }

    size_t size() const { return key.size + value.size; }

    void moveTo(KV& dst) {
        key.moveTo(dst.key);
        value.moveTo(dst.value);
    }

    void copyTo(KV& dst) const {
        key.copyTo(dst.key);
        value.copyTo(dst.value);
    }

    // set(): Just assign the given pointer.
    //        User is responsible for memory management.
    void set(const char* _key, const char* _value) {
        key.set(strlen(_key), (void*)_key);
        value.set(strlen(_value), (void*)_value);
    }

    void set(const std::string& _key, const std::string& _value) {
        key.set(_key.size(), (void*)_key.data());
        value.set(_value.size(), (void*)_value.data());
    }

    void set(const SizedBuf& _key, const SizedBuf& _value) {
        key = _key;
        value = _value;
    }

    // alloc(): Allocate own memory using new[].
    //          It will be automatically deallocated by destructor.
    void alloc(const char* _key, const char* _value) {
        key.alloc(strlen(_key), (void*)_key);
        value.alloc(strlen(_value), (void*)_value);
    }

    void alloc(const std::string& _key, const std::string& _value) {
        key.alloc(_key.size(), (void*)_key.data());
        value.alloc(_value.size(), (void*)_value.data());
    }

    void alloc(const SizedBuf& _key, const SizedBuf& _value) {
        key.alloc(_key.size, _key.data);
        value.alloc(_value.size, _value.data);
    }

    void free() {
        key.free();
        value.free();
    }

    void clear() {
        key.clear();
        value.clear();
    }

    SizedBuf key;
    SizedBuf value;
};

}