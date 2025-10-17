// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_SANITIZER_H
#define BITCOIN_UTIL_SANITIZER_H

#include <cstddef>
#include <cstdlib>
#include <type_traits>

#if defined(__has_feature)
#  if __has_feature(memory_sanitizer)
#    include <sanitizer/msan_interface.h>
#    define BITCOIN_HAVE_MEMORY_SANITIZER 1
#  endif
#endif

namespace util {
namespace sanitizer {

inline void UnpoisonCString(const char* value)
{
#if defined(BITCOIN_HAVE_MEMORY_SANITIZER)
    if (value != nullptr) {
        __msan_unpoison_string(value);
    }
#else
    (void)value;
#endif
}

template <typename T>
inline void Unpoison(const T& value)
{
#if defined(BITCOIN_HAVE_MEMORY_SANITIZER)
    __msan_unpoison(const_cast<void*>(static_cast<const void*>(&value)), sizeof(T));
#else
    (void)value;
#endif
}

inline void UnpoisonMemory(const void* addr, std::size_t size)
{
#if defined(BITCOIN_HAVE_MEMORY_SANITIZER)
    if (addr != nullptr && size != 0) {
        __msan_unpoison(const_cast<void*>(addr), size);
    }
#else
    (void)addr;
    (void)size;
#endif
}

template <typename T>
inline void UnpoisonArray(T* data, std::size_t count)
{
#if defined(BITCOIN_HAVE_MEMORY_SANITIZER)
    if (data != nullptr && count != 0) {
        using NonConstT = typename std::remove_const<T>::type;
        __msan_unpoison(const_cast<NonConstT*>(data), sizeof(T) * count);
    }
#else
    (void)data;
    (void)count;
#endif
}

inline const char* GetEnvUnpoisoned(const char* name)
{
    const char* value{std::getenv(name)};
    Unpoison(value);
    UnpoisonCString(value);
    return value;
}

} // namespace sanitizer
} // namespace util

#ifdef BITCOIN_HAVE_MEMORY_SANITIZER
#  undef BITCOIN_HAVE_MEMORY_SANITIZER
#endif

#endif // BITCOIN_UTIL_SANITIZER_H
