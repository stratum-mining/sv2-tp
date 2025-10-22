// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <sv2/noise.h>
#include <logging.h>
#include <random.h>
#include <span.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/check_globals.h>
#include <test/fuzz/fuzz.h>
#include <test/sv2_test_setup.h>
#include <functional>
#include <string_view>
#include <cstddef>

#include <cstdlib>
#include <cstdint>
#include <util/vector.h>

// Exposed by the fuzz harness to pass through double-dash arguments.
extern const std::function<std::vector<const char*>()> G_TEST_COMMAND_LINE_ARGUMENTS;

namespace {

void Initialize()
{
    // Add test context for debugging. Usage:
    // --debug=sv2 --loglevel=sv2:trace
    static const auto testing_setup = std::make_unique<const Sv2BasicTestingSetup>();

    // Optional: enable console logging when requested via double-dash args.
    // Recognized flags: --printtoconsole=1, --debug=sv2, --loglevel=sv2:trace
    // These flags are passed through the fuzz harness and exposed via G_TEST_COMMAND_LINE_ARGUMENTS.
    bool want_console{false};
    bool want_sv2_debug{false};
    bool want_sv2_trace{false};
    if (G_TEST_COMMAND_LINE_ARGUMENTS) {
        for (const char* arg : G_TEST_COMMAND_LINE_ARGUMENTS()) {
            if (!arg) continue;
            std::string_view s{arg};
            // Accept both forms in case a caller wants to force console logging explicitly.
            if (s == "--printtoconsole" || s == "--printtoconsole=1") want_console = true;
            if (s == "--debug=sv2" || s == "--debug=1" || s == "--debug=all") want_sv2_debug = true;
            if (s == "--loglevel=sv2:trace" || s == "--loglevel=trace") want_sv2_trace = true;
        }
    }
    if (want_console || std::getenv("SV2_FUZZ_LOG")) {
        // Turn on console logging and ensure SV2 category is enabled at the desired level.
        LogInstance().m_print_to_console = true;
        LogInstance().EnableCategory(BCLog::SV2);
        if (want_sv2_trace) {
            LogInstance().SetCategoryLogLevel({{BCLog::SV2, BCLog::Level::Trace}});
        } else if (want_sv2_debug || std::getenv("SV2_FUZZ_LOG_DEBUG")) {
            LogInstance().SetCategoryLogLevel({{BCLog::SV2, BCLog::Level::Debug}});
        }
        // Start logging to flush any buffered messages.
        LogInstance().StartLogging();
    }
}
} // namespace

bool MaybeDamage(FuzzedDataProvider& provider, std::vector<std::byte>& transport)
{
    if (transport.size() == 0) return false;

    // Optionally damage 1 bit in the ciphertext.
    const bool damage = provider.ConsumeBool();
    if (damage) {
        unsigned damage_bit = provider.ConsumeIntegralInRange<unsigned>(0,
                                                                        transport.size() * 8U - 1U);
        unsigned damage_pos = damage_bit >> 3;
        LogTrace(BCLog::SV2, "Damage byte %d of %d\n", damage_pos, transport.size());
        std::byte damage_val{(uint8_t)(1U << (damage_bit & 7))};
        transport.at(damage_pos) ^= damage_val;
    }
    return damage;
}

FUZZ_TARGET(sv2_noise_cipher_roundtrip, .init = Initialize)
{
    const CheckGlobals check_globals{};
    SeedRandomStateForTest(SeedRand::ZEROS);
    // Test that Sv2Noise's encryption and decryption agree.

    // To conserve fuzzer entropy, deterministically generate Alice and Bob keys.
    FuzzedDataProvider provider(buffer.data(), buffer.size());
    auto seed_ent = provider.ConsumeBytes<std::byte>(32);
    seed_ent.resize(32);
    CExtKey seed;
    seed.SetSeed(seed_ent);

    CExtKey tmp;
    if (!seed.Derive(tmp, 0)) return;
    CKey alice_authority_key{tmp.key};

    if (!seed.Derive(tmp, 1)) return;
    CKey alice_static_key{tmp.key};

    if (!seed.Derive(tmp, 2)) return;
    CKey alice_ephemeral_key{tmp.key};

    if (!seed.Derive(tmp, 10)) return;
    CKey bob_authority_key{tmp.key};

    if (!seed.Derive(tmp, 11)) return;
    CKey bob_static_key{tmp.key};

    if (!seed.Derive(tmp, 12)) return;
    CKey bob_ephemeral_key{tmp.key};

    if (!seed.Derive(tmp, 13)) return;
    CKey malory_authority_key{tmp.key};

    const bool use_fixture_times = provider.ConsumeBool();
    const bool sign_with_expected_authority = use_fixture_times ? true : provider.ConsumeBool();

    uint32_t now{0};
    uint32_t valid_from{0};
    uint32_t valid_to{0};
    uint16_t version{0};

    Sv2SignatureNoiseMessage bob_certificate;

    if (use_fixture_times) {
        SetMockTime(TEST_GENESIS_TIME);
        bob_certificate = MakeSkewTolerantCertificate(bob_static_key, bob_authority_key, now, valid_from, valid_to);
    } else {
        now = provider.ConsumeIntegralInRange<uint32_t>(10000U, UINT32_MAX);
        uint32_t past = provider.ConsumeIntegralInRange<uint32_t>(0, now);
        uint32_t future = provider.ConsumeIntegralInRange<uint32_t>(now, UINT32_MAX);
        valid_from = provider.ConsumeBool() ? past : future;
        valid_to = provider.ConsumeBool() ? future : past;
        version = provider.ConsumeBool() ? 0 : provider.ConsumeIntegral<uint16_t>();

        const CKey& signing_authority_key = sign_with_expected_authority ? bob_authority_key : malory_authority_key;
        bob_certificate = Sv2SignatureNoiseMessage(version, valid_from, valid_to,
                                                   XOnlyPubKey(bob_static_key.GetPubKey()), signing_authority_key);
    }

    SetMockTime(std::chrono::seconds{now});

    const bool certificate_valid_for_expected = bob_certificate.Validate(XOnlyPubKey(bob_authority_key.GetPubKey()));
    bool expected_valid = sign_with_expected_authority && version == 0 && (valid_from <= now) && (valid_to >= now);
    if (use_fixture_times) {
        expected_valid = true;
        version = 0;
    }
    assert(certificate_valid_for_expected == expected_valid);
    bool valid_certificate = certificate_valid_for_expected;

    if (sign_with_expected_authority) {
        const bool alternate_valid = bob_certificate.Validate(XOnlyPubKey(malory_authority_key.GetPubKey()));
        assert(!alternate_valid);
    }

    LogTrace(BCLog::SV2,
             "Certificate scenario fixture=%d, version=%u, now=%u, valid_from=%u, valid_to=%u, signed_expected=%d, valid=%d\n",
             use_fixture_times,
             version,
             now,
             valid_from,
             valid_to,
             sign_with_expected_authority,
             valid_certificate);

    // Alice's static is not used in the test
    // Alice needs to verify Bob's certificate, so we pass his authority key
    auto alice_handshake = std::make_unique<Sv2HandshakeState>(std::move(alice_static_key), XOnlyPubKey(bob_authority_key.GetPubKey()));
    alice_handshake->SetEphemeralKey(std::move(alice_ephemeral_key));
    // Bob is the responder and does not receive (or verify) Alice's certificate,
    // so we don't pass her authority key.
    auto bob_handshake = std::make_unique<Sv2HandshakeState>(std::move(bob_static_key), std::move(bob_certificate));
    bob_handshake->SetEphemeralKey(std::move(bob_ephemeral_key));

    // Handshake Act 1: e ->

    std::vector<std::byte> transport;
    transport.resize(Sv2HandshakeState::ELLSWIFT_PUB_KEY_SIZE);
    // Alice generates her ephemeral public key and write it into the buffer:
    alice_handshake->WriteMsgEphemeralPK(transport);

    bool damage_e = MaybeDamage(provider, transport);

    // Bob reads the ephemeral key ()
    // With EllSwift encoding this step can't fail
    bob_handshake->ReadMsgEphemeralPK(transport);
    ClearShrink(transport);

    // Handshake Act 2: <- e, ee, s, es, SIGNATURE_NOISE_MESSAGE
    transport.resize(Sv2HandshakeState::HANDSHAKE_STEP2_SIZE);
    bob_handshake->WriteMsgES(transport);

    bool damage_es = MaybeDamage(provider, transport);

    // This ignores the remote possibility that the fuzzer finds two equivalent
    // EllSwift encodings by flipping a single ephemeral key bit.
    assert(alice_handshake->ReadMsgES(transport) == (valid_certificate && !damage_e && !damage_es));

    if (!valid_certificate || damage_e || damage_es) return;

    // Construct Sv2Cipher from the Sv2HandshakeState and test transport
    auto alice{Sv2Cipher(/*initiator=*/true, std::move(alice_handshake))};
    auto bob{Sv2Cipher(/*initiator=*/false, std::move(bob_handshake))};
    alice.FinishHandshake();
    bob.FinishHandshake();

    // Use deterministic RNG to generate content rather than creating it from
    // the fuzzer input.
    InsecureRandomContext rng(provider.ConsumeIntegral<uint64_t>());

    LIMITED_WHILE(provider.remaining_bytes(), 1000)
    {
        ClearShrink(transport);

        // Alice or Bob sends a message
        bool from_alice = provider.ConsumeBool();

        // Set content length (slightly above NOISE_MAX_CHUNK_SIZE)
        unsigned length = provider.ConsumeIntegralInRange<unsigned>(0, NOISE_MAX_CHUNK_SIZE + 100);
        std::vector<std::byte> plain(length);
        for (auto& val : plain)
            val = std::byte{(uint8_t)rng()};

        const size_t encrypted_size = Sv2Cipher::EncryptedMessageSize(plain.size());
        transport.resize(encrypted_size);

        assert((from_alice ? alice : bob).EncryptMessage(plain, transport));

        const bool damage = MaybeDamage(provider, transport);

        std::vector<std::byte> plain_read;
        plain_read.resize(plain.size());

        bool ok = (from_alice ? bob : alice).DecryptMessage(transport, plain_read);
        assert(!ok == damage);
        if (!ok) break;

        assert(plain == plain_read);
    }

    if (std::getenv("SV2_FUZZ_SABOTAGE")) {
        LogTrace(BCLog::SV2, "Sabotage triggered via SV2_FUZZ_SABOTAGE env var, aborting");
#if defined(__GNUC__)
        __builtin_trap();
#else
        std::abort();
#endif
    }
}
