// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/sha256.h>
#include <ipc/capnp/common-types.h>
#include <ipc/capnp/common.capnp.h>
#include <ipc/serialized.h>
#include <primitives/block.h>
#include <script/script.h>

#include <boost/test/unit_test.hpp>
#include <capnp/message.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <iostream>
#include <optional>
#include <vector>

namespace {
struct DataOutput {
    ipc::capnp::messages::BlockRef::Builder field;
    auto init(size_t size) { return field.initHash(size); }
    [[maybe_unused]] auto get() { return field.getHash(); }
    [[maybe_unused]] void setHas() {}
};

struct IpcFixture {
    mp::EventLoop loop{"serialized-test", [](mp::LogMessage) {}};
    mp::EventLoopRef loop_ref{loop};
    decltype(loop.m_io_context.provider->newTwoWayPipe()) pipe{loop.m_io_context.provider->newTwoWayPipe()};
    std::optional<mp::Connection> connection{std::in_place, loop, kj::mv(pipe.ends[0])};
    mp::InvokeContext context{*connection};
    ~IpcFixture()
    {
        loop.m_task_set->add(kj::evalLater([&] {
            connection.reset();
            pipe.ends[1] = nullptr;
            loop_ref.reset();
        }));
        loop.loop();
    }
};

template <typename Payload>
auto& PayloadBytes(Payload& value)
{
    return value;
}

template <typename T>
auto& PayloadBytes(ipc::Serialized<T>& value)
{
    return value.bytes;
}

template <typename Payload>
void CheckOwnedRoundTrip(mp::InvokeContext& context)
{
    Payload original;
    auto& original_bytes = PayloadBytes(original);
    original_bytes = {0x01, 0x02, 0x00, 0xff};
    Payload copy;
    {
        capnp::MallocMessageBuilder message;
        auto field = message.initRoot<ipc::capnp::messages::BlockRef>();
        mp::BuildField(mp::TypeList<Payload>{}, context, DataOutput{field}, original);
        auto data = field.asReader().getHash();
        mp::ReadField(mp::TypeList<Payload>{}, context, mp::ValueField{data}, mp::ReadDestUpdate{copy});
        BOOST_CHECK(PayloadBytes(copy) == original_bytes);
        field.getHash()[0] = 0x42;
    }
    BOOST_CHECK(PayloadBytes(copy) == original_bytes);
}

template <typename Payload>
void CheckEmptyRoundTrip(mp::InvokeContext& context)
{
    capnp::MallocMessageBuilder message;
    auto field = message.initRoot<ipc::capnp::messages::BlockRef>();
    Payload empty;
    mp::BuildField(mp::TypeList<Payload>{}, context, DataOutput{field}, empty);
    auto data = field.asReader().getHash();
    Payload copy;
    PayloadBytes(copy) = {1};
    mp::ReadField(mp::TypeList<Payload>{}, context, mp::ValueField{data}, mp::ReadDestUpdate{copy});
    BOOST_CHECK(PayloadBytes(copy).empty());
}
CBlock TestBlock(size_t count)
{
    CBlock block;
    block.nVersion = 4;
    for (size_t i = 0; i < count; ++i) {
        CMutableTransaction tx;
        tx.vin.resize(1);
        tx.vin[0].prevout.n = i;
        if (count > 1) tx.vin[0].scriptWitness.stack.emplace_back(3570, static_cast<unsigned char>(i));
        tx.vout.emplace_back(1, CScript{} << OP_TRUE);
        block.vtx.push_back(MakeTransactionRef(std::move(tx)));
    }
    return block;
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(ipc_serialized_tests, IpcFixture)

BOOST_AUTO_TEST_CASE(owned_roundtrip)
{
    CheckOwnedRoundTrip<std::vector<unsigned char>>(context);
    // Deliberately invalid block bytes: retaining them must not decode a block.
    CheckOwnedRoundTrip<ipc::Serialized<CBlock>>(context);
}

BOOST_AUTO_TEST_CASE(empty_roundtrip)
{
    CheckEmptyRoundTrip<std::vector<unsigned char>>(context);
    CheckEmptyRoundTrip<ipc::Serialized<CBlock>>(context);
}

BOOST_AUTO_TEST_CASE(benchmark)
{
    if (!std::getenv("IPC_SERIALIZED_BENCH")) return;
    // Production selects accelerated SHA before decoding transactions.
    std::cout << "SHA256: " << SHA256AutoDetect() << '\n';
    for (const size_t count : {size_t{1}, size_t{1021}}) {
        capnp::MallocMessageBuilder message;
        auto field = message.initRoot<ipc::capnp::messages::BlockRef>();
        const auto block = TestBlock(count);
        mp::BuildField(mp::TypeList<CBlock>{}, context, DataOutput{field}, block);
        auto data = field.asReader().getHash();
        std::vector<double> decoded, serialized;
        volatile size_t observed_size{0};
        for (int i = -5; i < 101; ++i) {
            const auto measure = [&]<typename T>() {
                const auto start = std::chrono::steady_clock::now();
                {
                    const auto value = mp::ReadField(mp::TypeList<T>{}, context, mp::ValueField{data}, mp::ReadDestTemp<T>());
                    // Keep the result observable without timing Boost assertions.
                    if constexpr (std::is_same_v<T, CBlock>) observed_size = value.vtx.size();
                    else observed_size = value.bytes.size();
                }
                return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count();
            };
            // Alternate order to reduce systematic cache bias.
            double a, b;
            if (i % 2) { a = measure.template operator()<CBlock>(); b = measure.template operator()<ipc::Serialized<CBlock>>(); }
            else { b = measure.template operator()<ipc::Serialized<CBlock>>(); a = measure.template operator()<CBlock>(); }
            if (i >= 0) { decoded.push_back(a); serialized.push_back(b); }
        }
        BOOST_CHECK(observed_size == count || observed_size == data.size());
        std::sort(decoded.begin(), decoded.end());
        std::sort(serialized.begin(), serialized.end());
        std::cout << "bytes=" << data.size() << " txs=" << count << " CBlock_ms=" << decoded[50]
                  << " Serialized_ms=" << serialized[50] << " samples=101\n";
        const auto opaque = mp::ReadField(mp::TypeList<ipc::Serialized<CBlock>>{}, context, mp::ValueField{data}, mp::ReadDestTemp<ipc::Serialized<CBlock>>());
        BOOST_CHECK(std::equal(data.begin(), data.end(), opaque.bytes.begin(), opaque.bytes.end()));
    }
}

BOOST_AUTO_TEST_SUITE_END()
