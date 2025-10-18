// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <test/sv2_test_setup.h>

#include <chainparamsbase.h>
#include <common/args.h>
#include <key.h>
#include <util/chaintype.h>
#include <util/string.h>
#include <util/time.h>
#include <array>
#include <cstring>
#include <string>

#ifdef MEMORY_SANITIZER
#include <sanitizer/msan_interface.h>
#endif

Sv2BasicTestingSetup::Sv2BasicTestingSetup()
{
#ifdef MEMORY_SANITIZER
    // MSan flags the std::string temporaries created for these literals when selecting params.
    static const char* kChainNames[] = {"", "main", "testnet3", "testnet4", "signet", "regtest"};
    for (const char* name : kChainNames) {
        __msan_unpoison(const_cast<char*>(name), std::strlen(name) + 1);
    }
#endif
#ifdef MEMORY_SANITIZER
    __msan_scoped_disable_interceptor_checks msan_disable_scope;
#endif
    // Select a default chain for tests to satisfy BaseParams() users.
    SelectBaseParams(ChainType::REGTEST);
#ifdef MEMORY_SANITIZER
    const CBaseChainParams& params{BaseParams()};
    __msan_unpoison(const_cast<CBaseChainParams*>(&params), sizeof(CBaseChainParams));
    auto& data_dir = const_cast<std::string&>(params.DataDir());
    __msan_unpoison(&data_dir, sizeof(data_dir));
    const char* data_dir_chars{data_dir.c_str()};
    __msan_unpoison(const_cast<char*>(data_dir_chars), data_dir.size() + 1);
#endif

    // Default mock time anchored to Bitcoin genesis so certificate helpers see a realistic clock.
    SetMockTime(TEST_GENESIS_TIME);

    // Create an isolated temporary datadir for this test process.
    const auto micros = count_microseconds(Now<SteadyMicroseconds>().time_since_epoch());
    const std::string subdir = util::Join(std::array<std::string, 2>{"sv2_tests", util::ToString(micros)}, "");
    fs::path tmp = fs::path(fs::temp_directory_path());
    m_tmp_root = tmp / fs::u8path(subdir);
    fs::create_directories(m_tmp_root);

    // Set datadir arg so any code that writes under datadir uses the temp path.
    gArgs.ForceSetArg("-datadir", fs::PathToString(m_tmp_root));

    // Keep logs in memory via G_TEST_LOG_FUN in main.cpp; avoid file logging noise.
    gArgs.ForceSetArg("-debuglogfile", "0");

    // Initialize ECC context needed by key and crypto operations used in tests.
    m_ecc = std::make_unique<ECC_Context>();
}

Sv2BasicTestingSetup::~Sv2BasicTestingSetup()
{
    SetMockTime(std::chrono::seconds{0});

    try {
        fs::remove_all(m_tmp_root);
    } catch (const std::exception&) {
        // Best effort cleanup.
    }
    m_ecc.reset();
}
