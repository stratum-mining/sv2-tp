#!/usr/bin/env bash
#
# Copyright (c) 2019-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C.UTF-8

export CI_IMAGE_NAME_TAG="mirror.gcr.io/ubuntu:24.04"

export CI_CONTAINER_CAP="--cap-add SYS_PTRACE"  # If run with (ASan + LSan), the container needs access to ptrace (https://github.com/google/sanitizers/issues/764)

export CONTAINER_NAME=ci_native_asan
export APT_LLVM_V="20"
export PACKAGES="clang-${APT_LLVM_V} llvm-${APT_LLVM_V} libclang-rt-${APT_LLVM_V}-dev libboost-dev libcapnp-dev capnproto"
export NO_DEPENDS=1
export GOAL="install"
export CI_LIMIT_STACK_SIZE=1
export BITCOIN_CONFIG="\
 -DSANITIZERS=address,float-divide-by-zero,integer,undefined \
 -DCMAKE_C_COMPILER=clang \
 -DCMAKE_CXX_COMPILER=clang++ \
 -DCMAKE_C_FLAGS='-ftrivial-auto-var-init=pattern' \
 -DCMAKE_CXX_FLAGS='-ftrivial-auto-var-init=pattern' \
 -DAPPEND_CXXFLAGS='-std=c++23' \
 -DAPPEND_CPPFLAGS='-DARENA_DEBUG -DDEBUG_LOCKORDER' \
"
