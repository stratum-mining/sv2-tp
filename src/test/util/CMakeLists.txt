# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

add_library(test_util STATIC EXCLUDE_FROM_ALL
  coverage.cpp
  net.cpp
  random.cpp
)

target_link_libraries(test_util
  PRIVATE
    core_interface
    Boost::headers
)
