# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

include(AddWindowsResources)

configure_file(${PROJECT_SOURCE_DIR}/cmake/bitcoin-build-config.h.in bitcoin-build-config.h USE_SOURCE_PERMISSIONS @ONLY)
include_directories(${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR})

#=============================
# Subprojects
#=============================
# Subprojects include subdirectories that do or could have tests
# and/or benchmark binaries.
# These need to be included before CMAKE_*_OUTPUT_DIRECTORY variables
# are set, so output locations of subproject tests and libraries are
# not overridden.
if (NOT WITH_EXTERNAL_LIBMULTIPROCESS)
  include(../cmake/libmultiprocess.cmake)
  add_libmultiprocess(ipc/libmultiprocess)
endif()
include(../cmake/secp256k1.cmake)
add_secp256k1(secp256k1)

# Set top-level target output locations.
if(NOT CMAKE_RUNTIME_OUTPUT_DIRECTORY)
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)
endif()
if(NOT CMAKE_LIBRARY_OUTPUT_DIRECTORY)
  set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
endif()
if(NOT CMAKE_ARCHIVE_OUTPUT_DIRECTORY)
  set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
endif()

add_custom_target(generate_build_info
  BYPRODUCTS ${PROJECT_BINARY_DIR}/src/bitcoin-build-info.h
  COMMAND ${CMAKE_COMMAND} -DBUILD_INFO_HEADER_PATH=${PROJECT_BINARY_DIR}/src/bitcoin-build-info.h -DSOURCE_DIR=${PROJECT_SOURCE_DIR} -P ${PROJECT_SOURCE_DIR}/cmake/script/GenerateBuildInfo.cmake
  COMMENT "Generating bitcoin-build-info.h"
  VERBATIM
)
add_library(bitcoin_clientversion STATIC EXCLUDE_FROM_ALL
  clientversion.cpp
)
target_link_libraries(bitcoin_clientversion
  PRIVATE
    core_interface
)
add_dependencies(bitcoin_clientversion generate_build_info)

add_subdirectory(crypto)
add_subdirectory(util)
add_subdirectory(ipc)
add_subdirectory(sv2)

## bitcoin_consensus library is not needed for sv2-tp; omit it entirely.

# Home for common functionality shared by different executables and libraries.
# Similar to `bitcoin_util` library, but higher-level.
add_library(bitcoin_common STATIC EXCLUDE_FROM_ALL
  base58.cpp
  bech32.cpp
  arith_uint256.cpp
  consensus/merkle.cpp
  chainparams.cpp
  chainparamsbase.cpp
  common/args.cpp
  common/config.cpp
  common/settings.cpp
  common/system.cpp
  hash.cpp
  deploymentinfo.cpp
  interfaces/echo.cpp
  init/common.cpp
  key.cpp
  pubkey.cpp
  primitives/block.cpp
  primitives/transaction.cpp
  netaddress.cpp
  netbase.cpp
  common/sockman.cpp
  uint256.cpp
)
target_link_libraries(bitcoin_common
  PRIVATE
    core_interface
    bitcoin_util
    secp256k1
    Boost::headers
    $<$<PLATFORM_ID:Windows>:ws2_32>
)

include(InstallBinaryComponent)

if(BUILD_MINE)
  add_executable(sv2-tp
    sv2-tp.cpp
    init/basic.cpp
  )
  add_windows_resources(sv2-tp sv2-tp-res.rc)
  add_windows_application_manifest(sv2-tp)
  target_link_libraries(sv2-tp
    core_interface
    bitcoin_common
    bitcoin_ipc
    bitcoin_sv2
  )
  install_binary_component(sv2-tp HAS_MANPAGE)
endif()

## Kernel library is not used in this repository; remove optional subdirectory.

add_subdirectory(test/util)

if(BUILD_TESTS)
  add_subdirectory(test)
endif()

if(BUILD_FUZZ_BINARY)
  add_subdirectory(test/fuzz)
endif()
