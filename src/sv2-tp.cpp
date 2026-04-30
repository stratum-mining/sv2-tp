// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <chainparamsbase.h>
#include <chainparams.h>
#include <clientversion.h>
#include <common/args.h>
#include <common/system.h>
#include <compat/compat.h>
#include <init/common.h>
#include <interfaces/init.h>
#include <interfaces/ipc.h>
#include <logging.h>
#include <sv2/template_provider.h>
#include <tinyformat.h>
#include <util/chaintype.h>
#include <util/fs.h>
#include <util/fs_helpers.h>
#include <util/syserror.h>
#include <util/translation.h>

#include <cerrno>
#ifndef WIN32
#include <csignal>
#endif
#include <fstream>
#include <system_error>

static const char* const HELP_USAGE{R"(
sv2-tp implements the Stratum v2 Template Provider role. It connects to Bitcoin
Core via IPC.

Usage:
  sv2-tp [options]
)"};

static const char* HELP_EXAMPLES{R"(
Examples:
  # Start separate bitcoin node that sv2-tp can connect to.
  bitcoin -m node -testnet4 -ipcbind=unix

  # Connect to the node:
  sv2-tp -testnet4 -debug=sv2 -loglevel=sv2:trace

  # Now start the SRI Job Declarator Client of Pool role, you should see
  # it connect in the logs.
)"};

const TranslateFn G_TRANSLATION_FUN{nullptr};

namespace {
constexpr const char* SV2_TP_PID_FILENAME{"sv2-tp.pid"};
bool g_generated_pid{false};

fs::path GetPidFile(const ArgsManager& args)
{
    return AbsPathForConfigVal(args, args.GetPathArg("-pid", SV2_TP_PID_FILENAME));
}

[[nodiscard]] bool CreatePidFile(const ArgsManager& args)
{
    if (args.IsArgDisabled("-pid")) return true;

    std::ofstream file{GetPidFile(args)};
    if (file) {
#ifdef WIN32
        file << GetCurrentProcessId() << '\n';
#else
        file << getpid() << '\n';
#endif
        g_generated_pid = true;
        LogInfo("Created PID file %s", fs::PathToString(GetPidFile(args)));
        return true;
    }

    LogError("Unable to create PID file '%s': %s", fs::PathToString(GetPidFile(args)), SysErrorString(errno));
    return false;
}

void RemovePidFile(const ArgsManager& args)
{
    if (!g_generated_pid) return;
    const auto pid_path{GetPidFile(args)};
    if (std::error_code error; !fs::remove(pid_path, error)) {
        std::string msg{error ? error.message() : "File does not exist"};
        LogPrintf("Unable to remove PID file (%s): %s\n", fs::PathToString(pid_path), msg);
    }
}

class PidFileGuard
{
public:
    explicit PidFileGuard(const ArgsManager& args) : m_args(args) {}
    ~PidFileGuard() { RemovePidFile(m_args); }

private:
    const ArgsManager& m_args;
};
} // namespace

static void AddArgs(ArgsManager& args)
{
    SetupHelpOptions(args);
    SetupChainParamsBaseOptions(args);

    const auto defaultBaseParams = CreateBaseChainParams(ChainType::MAIN);
    const auto testnetBaseParams = CreateBaseChainParams(ChainType::TESTNET);
    const auto testnet4BaseParams = CreateBaseChainParams(ChainType::TESTNET4);
    const auto signetBaseParams = CreateBaseChainParams(ChainType::SIGNET);
    const auto regtestBaseParams = CreateBaseChainParams(ChainType::REGTEST);

    args.AddArg("-version", "Print version and exit", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    args.AddArg("-datadir=<dir>", "Specify non-default Bitcoin Core data directory", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    args.AddArg("-conf=<file>", "Specify path to the configuration file (default: sv2-tp.conf inside the datadir). Set -conf=0 to disable loading any configuration file.", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    args.AddArg("-pid=<file>", strprintf("Specify pid file. Relative paths will be prefixed by a net-specific datadir location. (default: %s)", SV2_TP_PID_FILENAME), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    args.AddArg("-ipcconnect=<address>", "Connect to bitcoin-node process in the background to perform online operations. Valid <address> values are 'unix' to connect to the default socket, 'unix:<socket path>' to connect to a socket at a nonstandard path. Default value: unix", ArgsManager::ALLOW_ANY, OptionsCategory::IPC);
    args.AddArg("-sv2bind=<addr>[:<port>]", strprintf("Bind to given address and always listen on it (default: 127.0.0.1). Use [host]:port notation for IPv6."), ArgsManager::ALLOW_ANY | ArgsManager::NETWORK_ONLY, OptionsCategory::CONNECTION);
    args.AddArg("-sv2port=<port>", strprintf("Listen for Stratum v2 connections on <port> (default: %u, testnet3: %u, testnet4: %u, signet: %u, regtest: %u).", defaultBaseParams->Sv2Port(), testnetBaseParams->Sv2Port(), testnet4BaseParams->Sv2Port(), signetBaseParams->Sv2Port(), regtestBaseParams->Sv2Port()), ArgsManager::ALLOW_ANY | ArgsManager::NETWORK_ONLY, OptionsCategory::CONNECTION);
    args.AddArg("-templateinterval", strprintf("Minimum seconds between fee-based template updates. New blocks always propagate immediately. (default: %d)", Sv2TemplateProviderOptions().template_interval.count()), ArgsManager::ALLOW_ANY, OptionsCategory::BLOCK_CREATION);
    args.AddArg("-sv2feedelta", strprintf("Minimum fee delta for Template Provider to send update upstream (default: %d sat)", uint64_t(Sv2TemplateProviderOptions().fee_delta)), ArgsManager::ALLOW_ANY, OptionsCategory::BLOCK_CREATION);
    init::AddLoggingArgs(args);
}

static bool g_interrupt{false};

#ifndef WIN32
static void registerSignalHandler(int signal, void(*handler)(int))
{
    struct sigaction sa;
    sa.sa_handler = handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(signal, &sa, nullptr);
}
static void HandleSIGTERM(int)
{
    g_interrupt = true;
}

#endif

MAIN_FUNCTION
{
    ArgsManager& args = gArgs;
    PidFileGuard pid_file_guard{args};
    AddArgs(args);
    std::string error_message;
    if (!args.ParseParameters(argc, argv, error_message)) {
        tfm::format(std::cerr, "Error parsing command line arguments: %s\n", error_message);
        return EXIT_FAILURE;
    }
    if (!args.ReadConfigFiles(error_message, true)) {
        tfm::format(std::cerr, "Error reading config files: %s\n", error_message);
        return EXIT_FAILURE;
    }
    if (HelpRequested(args) || args.IsArgSet("-version")) {
        std::string output{strprintf("%s sv2-tp version", CLIENT_NAME) + " " + FormatFullVersion() + "\n"};
        if (args.IsArgSet("-version")) {
            output += FormatParagraph(LicenseInfo());
        } else {
            output += HELP_USAGE;
            output += args.GetHelpMessage();
            output += HELP_EXAMPLES;
        }
        tfm::format(std::cout, "%s", output);
        return EXIT_SUCCESS;
    }
    if (!CheckDataDirOption(args)) {
        tfm::format(std::cerr, "Error: Specified data directory \"%s\" does not exist.\n", args.GetArg("-datadir", ""));
        return EXIT_FAILURE;
    }
    SelectParams(args.GetChainType());

    // Set logging options using sv2-tp defaults
    init::SetLoggingOptions(args);
    if (auto result{init::SetLoggingCategories(args)}; !result) {
        tfm::format(std::cerr, "Error: %s\n", util::ErrorString(result).original);
        return EXIT_FAILURE;
    }
    if (auto result{init::SetLoggingLevel(args)}; !result) {
        tfm::format(std::cerr, "Error: %s\n", util::ErrorString(result).original);
        return EXIT_FAILURE;
    }
    LogInstance().m_print_to_console = args.GetBoolArg("-printtoconsole", DEFAULT_PRINTTOCONSOLE);
    if (!init::StartLogging(args)) {
        tfm::format(std::cerr, "Error: StartLogging failed\n");
        return EXIT_FAILURE;
    }

    if (!CreatePidFile(args)) {
        tfm::format(std::cerr, "Error: Unable to create PID file at %s\n", fs::PathToString(GetPidFile(args)));
        return EXIT_FAILURE;
    }

    const ChainType chain_type = args.GetChainType();
    LogPrintf("Starting sv2-tp on %s network\n", ChainTypeToString(chain_type));

    ECC_Context ecc_context{};
    std::string sha256_algo = SHA256AutoDetect();
    LogInfo("Using the '%s' SHA256 implementation\n", sha256_algo);
    RandomInit();

    // Parse -sv2... params
    Sv2TemplateProviderOptions options{};

    const std::string sv2_port_arg = args.GetArg("-sv2port", "");

    // TODO: check -sv2port using something like CheckHostPortOptions
    options.port =  static_cast<uint16_t>(gArgs.GetIntArg("-sv2port", BaseParams().Sv2Port()));

    if (args.IsArgSet("-sv2bind")) { // Specific bind address
        std::optional<std::string> sv2_bind{args.GetArg("-sv2bind")};
        if (sv2_bind) {
            if (!SplitHostPort(sv2_bind.value(), options.port, options.host)) {
                tfm::format(std::cerr, "Invalid port %d\n", options.port);
                return EXIT_FAILURE;
            }
        }
    }

    options.fee_delta = args.GetIntArg("-sv2feedelta", Sv2TemplateProviderOptions().fee_delta);

    if (args.IsArgSet("-templateinterval")) {
        if (args.GetIntArg("-templateinterval", 0) < 1) {
            tfm::format(std::cerr, "-templateinterval must be at least one second\n");
            return EXIT_FAILURE;
        }
        options.template_interval = std::chrono::seconds(args.GetIntArg("-templateinterval", 0));
    }

    // Connect to bitcoin-node via IPC
    //
    // If the node is not available, keep retrying in a loop every 10 seconds.
    std::unique_ptr<interfaces::Init> mine_init{interfaces::MakeBasicInit("sv2-tp", argc > 0 ? argv[0] : "")};
    assert(mine_init);
    std::unique_ptr<interfaces::Init> node_init;
    std::string address{args.GetArg("-ipcconnect", "unix")};

    LogPrintf("Attempting IPC connection to bitcoin-node at %s\n", address);
    LogPrintf("Ensure Bitcoin Core is running with '-ipcbind=unix' and the correct network (%s)\n",
              ChainTypeToString(chain_type));

    while (true) {
        try {
            node_init = mine_init->ipc()->connectAddress(address);
            LogPrintf("Connected to bitcoin-node via IPC at: %s\n", address);
            break;  // Success: break out of the loop
        } catch (const std::exception& exception) {
            LogPrintf("IPC connection failed: %s\n", exception.what());
            LogPrintf("Retrying in 10 seconds... (Ensure Bitcoin Core is running with '-ipcbind=unix')\n");
            std::this_thread::sleep_for(std::chrono::seconds(10));
        }
    }
    assert(node_init);
    std::unique_ptr<interfaces::Mining> mining{node_init->makeMining()};
    assert(mining);

    auto tp = std::make_unique<Sv2TemplateProvider>(*mining);

    if (!tp->Start(options)) {
        tfm::format(std::cerr, "Unable to start Stratum v2 Template Provider");
        return EXIT_FAILURE;
    }

    LogPrintf("sv2-tp listening for Stratum v2 connections on %s:%d\n",
              options.host, options.port);

#ifndef WIN32
    registerSignalHandler(SIGTERM, HandleSIGTERM);
    registerSignalHandler(SIGINT, HandleSIGTERM);
#endif

    while (!g_interrupt && !tp->BackendDisconnected()) {
        UninterruptibleSleep(100ms);
    }

    const bool backend_disconnected = tp->BackendDisconnected();

    tp.reset();

    return backend_disconnected ? EXIT_FAILURE : EXIT_SUCCESS;
}
