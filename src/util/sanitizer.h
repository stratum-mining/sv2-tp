// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_SANITIZER_H
#define BITCOIN_UTIL_SANITIZER_H

#include <cstdlib>

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

inline const char* GetEnvUnpoisoned(const char* name)
{
    const char* value{std::getenv(name)};
    UnpoisonCString(value);
    return value;
}

} // namespace sanitizer
} // namespace util

#ifdef BITCOIN_HAVE_MEMORY_SANITIZER
#  undef BITCOIN_HAVE_MEMORY_SANITIZER
#endif

#endif // BITCOIN_UTIL_SANITIZER_H
