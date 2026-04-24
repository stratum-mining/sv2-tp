// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * See https://www.boost.org/doc/libs/1_78_0/libs/test/doc/html/boost_test/adv_scenarios/single_header_customizations/multiple_translation_units.html
 */
#define BOOST_TEST_MODULE Bitcoin Core Test Suite

#include <boost/test/included/unit_test.hpp>

#include <util/translation.h>
// Provide a default translation function symbol for libraries that expect it.
const TranslateFn G_TRANSLATION_FUN{nullptr};


#include <functional>
#include <iostream>

#ifdef WIN32
#include <boost/test/results_collector.hpp>
#include <cstdio>
#include <cstdlib>

// Some tests intentionally leak a TPTester on Windows because libmultiprocess
// teardown deadlocks during thread-local cleanup (libmultiprocess#231,
// bitcoin#32387). Those leaked threads can also fault during static destruction
// at process exit. Once Boost.Test has reported its results, bypass static
// destructors entirely so the process exits cleanly with the right code.
struct WinExitFixture {
    ~WinExitFixture()
    {
        std::fflush(stdout);
        std::fflush(stderr);
        const auto& results = boost::unit_test::results_collector.results(
            boost::unit_test::framework::master_test_suite().p_id);
        _exit(results.passed() ? 0 : 1);
    }
};
BOOST_GLOBAL_FIXTURE(WinExitFixture);
#endif

/** Redirect debug log to unit_test.log files */
std::function<void(const std::string&)> G_TEST_LOG_FUN = [](const std::string& s) {
    static const bool should_log{std::any_of(
        &boost::unit_test::framework::master_test_suite().argv[1],
        &boost::unit_test::framework::master_test_suite().argv[boost::unit_test::framework::master_test_suite().argc],
        [](const char* arg) {
            return std::string{"DEBUG_LOG_OUT"} == arg;
        })};
    if (!should_log) return;
    std::cout << s;
};

/**
 * Retrieve the command line arguments from boost.
 * Allows usage like:
 * `test_sv2 --run_test="net_tests/cnode_listen_port" -- -checkaddrman=1 -debug=sv2`
 * which would return `["-checkaddrman=1", "-debug=sv2"]`.
 */
std::function<std::vector<const char*>()> G_TEST_COMMAND_LINE_ARGUMENTS = []() {
    std::vector<const char*> args;
    for (int i = 1; i < boost::unit_test::framework::master_test_suite().argc; ++i) {
        args.push_back(boost::unit_test::framework::master_test_suite().argv[i]);
    }
    return args;
};

/**
 * Retrieve the boost unit test name.
 */
std::function<std::string()> G_TEST_GET_FULL_NAME = []() {
    return boost::unit_test::framework::current_test_case().full_name();
};
