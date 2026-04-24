// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <boost/test/unit_test.hpp>

#include <test/sv2_test_setup.h>          // Sv2BasicTestingSetup fixture
#include <test/sv2_tp_tester.h>
#include <sv2/messages.h>

/*
 * Regression / lifecycle test: construct and destruct TPTester multiple times
 * to ensure clean shutdown of the EventLoop, IPC proxies, and Template Provider.
 * This aims to catch reference counting or lingering thread issues early.
 */
BOOST_FIXTURE_TEST_SUITE(sv2_tester_lifecycle_tests, Sv2BasicTestingSetup)

#ifndef WIN32
BOOST_AUTO_TEST_CASE(tp_tester_repeated_construction)
{
    // Run a few iterations; keep count modest to stay fast in CI while
    // still exercising repeated setup/teardown paths.
    constexpr int ITERS = 2;
    for (int i = 0; i < ITERS; ++i) {
        BOOST_TEST_MESSAGE("Lifecycle iteration " << i);
        {
            TPTester tester{};
            // Perform a minimal handshake + setup so the Template Provider
            // allocates resources and creates at least one client connection.
            tester.handshake();

            // Send SetupConnection
            auto setup = tester.SetupConnectionMsg();
            tester.receiveMessage(setup);
            // Consume SetupConnection.Success reply
            tester.PeerReceiveBytes();

            // Provide coinbase output constraints to trigger initial template work
            std::vector<uint8_t> coinbase_output_constraint_bytes{
                0x01, 0x00, 0x00, 0x00, // coinbase_output_max_additional_size
                0x00, 0x00              // coinbase_output_max_sigops
            };
            node::Sv2NetMsg constraints{node::Sv2MsgType::COINBASE_OUTPUT_CONSTRAINTS, std::move(coinbase_output_constraint_bytes)};
            tester.receiveMessage(constraints);
            // Expect NewTemplate + SetNewPrevHash pair (ignore exact size here)
            tester.PeerReceiveBytes();
        }
        // On leaving scope: destructor of TPTester should cleanly tear down.
        // If any dangling references or threads exist they should surface as
        // test hangs or use-after-frees under sanitizers / valgrind.
    }
}
#else
// TODO: Re-enable on Windows once the libmultiprocess shutdown hang is fixed
// upstream. Tearing down the IPC EventLoop / per-thread state at process
// exit deadlocks std::thread::join on mingw winpthreads. Tracked in
// libmultiprocess#231 (rewrites the EventLoop wakeup primitive and adds
// shutdownWrite() in ~Connection) and bitcoin#32387.
#endif

BOOST_AUTO_TEST_SUITE_END()
