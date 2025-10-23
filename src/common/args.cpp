// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <common/args.h>

#include <chainparamsbase.h>
#include <common/settings.h>
#include <logging.h>
#include <sync.h>
#include <tinyformat.h>
#include <util/chaintype.h>
#include <util/check.h>
#include <util/fs.h>
#include <util/fs_helpers.h>
#include <util/strencodings.h>
#include <util/string.h>

#ifdef WIN32
#include <codecvt>
#include <shellapi.h>
#include <shlobj.h>
#endif

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <variant>

const char * const BITCOIN_CONF_FILENAME = "sv2-tp.conf";

ArgsManager gArgs;

/**
 * Interpret a string argument as a boolean.
 *
 * The definition of LocaleIndependentAtoi<int>() requires that non-numeric string values
 * like "foo", return 0. This means that if a user unintentionally supplies a
 * non-integer argument here, the return value is always false. This means that
 * -foo=false does what the user probably expects, but -foo=true is well defined
 * but does not do what they probably expected.
 *
 * The return value of LocaleIndependentAtoi<int>(...) is zero when given input not
 * representable as an int.
 *
 * For a more extensive discussion of this topic (and a wide range of opinions
 * on the Right Way to change this code), see PR12713.
 */
static bool InterpretBool(const std::string& strValue)
{
    if (strValue.empty())
        return true;
    return (LocaleIndependentAtoi<int>(strValue) != 0);
}

static std::string SettingName(const std::string& arg)
{
    return arg.size() > 0 && arg[0] == '-' ? arg.substr(1) : arg;
}

/**
 * Parse "name" and "section.name" settings keys.
 */
KeyInfo InterpretKey(std::string key)
{
    KeyInfo result;
    // Split section name from key name for keys like "testnet.foo" or "regtest.bar"
    size_t option_index = key.find('.');
    if (option_index != std::string::npos) {
        result.section = key.substr(0, option_index);
        key.erase(0, option_index + 1);
    }
    result.name = key;
    return result;
}

/**
 * Interpret settings value based on registered flags.
 *
 * @param[in]   key      key information to know if key was negated
 * @param[in]   value    string value of setting to be parsed
 * @param[in]   flags    ArgsManager registered argument flags
 * @param[out]  error    Error description if settings value is not valid
 *
 * @return parsed settings value if it is valid, otherwise nullopt accompanied
 * by a descriptive error string
 */
std::optional<std::string> InterpretValue(const KeyInfo& key, const std::string* value,
    unsigned int flags, std::string& error)
{
    if (!value && (flags & ArgsManager::DISALLOW_ELISION)) {
        error = strprintf("Can not set -%s with no value. Please specify value with -%s=value.", key.name, key.name);
        return std::nullopt;
    }
    return value ? *value : "";
}

// Define default constructor and destructor that are not inline, so code instantiating this class doesn't need to
// #include class definitions for all members.
// For example, m_settings has an internal dependency on univalue.
ArgsManager::ArgsManager() = default;
ArgsManager::~ArgsManager() = default;

std::set<std::string> ArgsManager::GetUnsuitableSectionOnlyArgs() const
{
    std::set<std::string> unsuitables;

    LOCK(cs_args);

    // if there's no section selected, don't worry
    if (m_network.empty()) return std::set<std::string> {};

    // if it's okay to use the default section for this network, don't worry
    if (m_network == ChainTypeToString(ChainType::MAIN)) return std::set<std::string> {};

    for (const auto& arg : m_network_only_args) {
        if (OnlyHasDefaultSectionSetting(m_settings, m_network, SettingName(arg))) {
            unsuitables.insert(arg);
        }
    }
    return unsuitables;
}

std::list<SectionInfo> ArgsManager::GetUnrecognizedSections() const
{
    // Section names to be recognized in the config file.
    static const std::set<std::string> available_sections{
        ChainTypeToString(ChainType::REGTEST),
        ChainTypeToString(ChainType::SIGNET),
        ChainTypeToString(ChainType::TESTNET),
        ChainTypeToString(ChainType::TESTNET4),
        ChainTypeToString(ChainType::MAIN),
    };

    LOCK(cs_args);
    std::list<SectionInfo> unrecognized = m_config_sections;
    unrecognized.remove_if([](const SectionInfo& appeared){ return available_sections.find(appeared.m_name) != available_sections.end(); });
    return unrecognized;
}

void ArgsManager::SelectConfigNetwork(const std::string& network)
{
    LOCK(cs_args);
    m_network = network;
}

bool ArgsManager::ParseParameters(int argc, const char* const argv[], std::string& error)
{
    LOCK(cs_args);
    m_settings.command_line_options.clear();

    for (int i = 1; i < argc; i++) {
        std::string key(argv[i]);

#ifdef __APPLE__
        // At the first time when a user gets the "App downloaded from the
        // internet" warning, and clicks the Open button, macOS passes
        // a unique process serial number (PSN) as -psn_... command-line
        // argument, which we filter out.
        if (key.starts_with("-psn_")) continue;
#endif

        std::optional<std::string> val;
        size_t is_index = key.find('=');
        if (is_index != std::string::npos) {
            val = key.substr(is_index + 1);
            key.erase(is_index);
        }
#ifdef WIN32
        key = ToLower(key);
        if (key[0] == '/')
            key[0] = '-';
#endif

        if (key[0] != '-') {
            if (!m_accept_any_command && m_command.empty()) {
                // The first non-dash arg is a registered command
                std::optional<unsigned int> flags = GetArgFlags(key);
                if (!flags || !(*flags & ArgsManager::COMMAND)) {
                    error = strprintf("Invalid command '%s'", argv[i]);
                    return false;
                }
            }
            m_command.push_back(key);
            while (++i < argc) {
                // The remaining args are command args
                m_command.emplace_back(argv[i]);
            }
            break;
        }

        // Transform --foo to -foo
        if (key.length() > 1 && key[1] == '-')
            key.erase(0, 1);

        // Transform -foo to foo
        key.erase(0, 1);
        KeyInfo keyinfo = InterpretKey(key);
        std::optional<unsigned int> flags = GetArgFlags('-' + keyinfo.name);

        // Unknown command line options and command line options with dot
        // characters (which are returned from InterpretKey with nonempty
        // section strings) are not valid.
        if (!flags || !keyinfo.section.empty()) {
            error = strprintf("Invalid parameter %s", argv[i]);
            return false;
        }

    std::optional<std::string> value = InterpretValue(keyinfo, val ? &*val : nullptr, *flags, error);
        if (!value) return false;

        m_settings.command_line_options[keyinfo.name].push_back(*value);
    }

    return true;
}

std::optional<unsigned int> ArgsManager::GetArgFlags(const std::string& name) const
{
    LOCK(cs_args);
    for (const auto& arg_map : m_available_args) {
        const auto search = arg_map.second.find(name);
        if (search != arg_map.second.end()) {
            return search->second.m_flags;
        }
    }
    return std::nullopt;
}

fs::path ArgsManager::GetPathArg(std::string arg, const fs::path& default_value) const
{
    if (IsArgDisabled(arg)) return fs::path{};
    std::optional<std::string> path = GetArg(arg);
    if (!path || path->empty()) return default_value;
    fs::path result = fs::PathFromString(*path).lexically_normal();
    // Remove trailing slash, if present.
    return result.has_filename() ? result : result.parent_path();
}

fs::path ArgsManager::GetDataDir(bool net_specific) const
{
    LOCK(cs_args);
    fs::path& path = net_specific ? m_cached_network_datadir_path : m_cached_datadir_path;

    // Used cached path if available
    if (!path.empty()) return path;

    const fs::path datadir{GetPathArg("-datadir")};
    if (!datadir.empty()) {
        path = fs::absolute(datadir);
        if (!fs::is_directory(path)) {
            path = "";
            return path;
        }
    } else {
        path = GetDefaultDataDir();
    }

    if (net_specific && !BaseParams().DataDir().empty()) {
        path /= fs::PathFromString(BaseParams().DataDir());
    }

    return path;
}

void ArgsManager::ClearPathCache()
{
    LOCK(cs_args);

    m_cached_datadir_path = fs::path();
    m_cached_network_datadir_path = fs::path();
}

std::optional<const ArgsManager::Command> ArgsManager::GetCommand() const
{
    Command ret;
    LOCK(cs_args);
    auto it = m_command.begin();
    if (it == m_command.end()) {
        // No command was passed
        return std::nullopt;
    }
    if (!m_accept_any_command) {
        // The registered command
        ret.command = *(it++);
    }
    while (it != m_command.end()) {
        // The unregistered command and args (if any)
        ret.args.push_back(*(it++));
    }
    return ret;
}

std::vector<std::string> ArgsManager::GetArgs(const std::string& strArg) const
{
    return GetSettingsList(strArg);
}

bool ArgsManager::IsArgSet(const std::string& strArg) const
{
    return GetSetting(strArg).has_value();
}

bool ArgsManager::IsArgDisabled(const std::string& strArg) const
{
    const auto value = GetSetting(strArg);
    if (!value) return false;
    const std::string lower = ToLower(*value);
    return lower == "0" || lower == "false";
}

std::string ArgsManager::GetArg(const std::string& strArg, const std::string& strDefault) const
{
    return GetArg(strArg).value_or(strDefault);
}

std::optional<std::string> ArgsManager::GetArg(const std::string& strArg) const
{
    return SettingToString(GetSetting(strArg));
}

std::optional<std::string> SettingToString(const std::optional<std::string>& value)
{
    return value;
}

std::string SettingToString(const std::optional<std::string>& value, const std::string& strDefault)
{
    return value ? *value : strDefault;
}

int64_t ArgsManager::GetIntArg(const std::string& strArg, int64_t nDefault) const
{
    return GetIntArg(strArg).value_or(nDefault);
}

std::optional<int64_t> ArgsManager::GetIntArg(const std::string& strArg) const
{
    return SettingToInt(GetSetting(strArg));
}

std::optional<int64_t> SettingToInt(const std::optional<std::string>& value)
{
    if (!value) return std::nullopt;
    return LocaleIndependentAtoi<int64_t>(*value);
}

int64_t SettingToInt(const std::optional<std::string>& value, int64_t nDefault)
{
    return SettingToInt(value).value_or(nDefault);
}

bool ArgsManager::GetBoolArg(const std::string& strArg, bool fDefault) const
{
    return GetBoolArg(strArg).value_or(fDefault);
}

std::optional<bool> ArgsManager::GetBoolArg(const std::string& strArg) const
{
    return SettingToBool(GetSetting(strArg));
}

std::optional<bool> SettingToBool(const std::optional<std::string>& value)
{
    if (!value) return std::nullopt;
    return InterpretBool(*value);
}

bool SettingToBool(const std::optional<std::string>& value, bool fDefault)
{
    return SettingToBool(value).value_or(fDefault);
}

bool ArgsManager::SoftSetArg(const std::string& strArg, const std::string& strValue)
{
    LOCK(cs_args);
    if (IsArgSet(strArg)) return false;
    ForceSetArg(strArg, strValue);
    return true;
}

bool ArgsManager::SoftSetBoolArg(const std::string& strArg, bool fValue)
{
    if (fValue)
        return SoftSetArg(strArg, std::string("1"));
    else
        return SoftSetArg(strArg, std::string("0"));
}

void ArgsManager::ForceSetArg(const std::string& strArg, const std::string& strValue)
{
    LOCK(cs_args);
    m_settings.forced_settings[SettingName(strArg)] = strValue;
}

void ArgsManager::AddCommand(const std::string& cmd, const std::string& help)
{
    Assert(cmd.find('=') == std::string::npos);
    Assert(cmd.at(0) != '-');

    LOCK(cs_args);
    m_accept_any_command = false; // latch to false
    std::map<std::string, Arg>& arg_map = m_available_args[OptionsCategory::COMMANDS];
    auto ret = arg_map.emplace(cmd, Arg{"", help, ArgsManager::COMMAND});
    Assert(ret.second); // Fail on duplicate commands
}

void ArgsManager::AddArg(const std::string& name, const std::string& help, unsigned int flags, const OptionsCategory& cat)
{
    Assert((flags & ArgsManager::COMMAND) == 0); // use AddCommand

    // Split arg name from its help param
    size_t eq_index = name.find('=');
    if (eq_index == std::string::npos) {
        eq_index = name.size();
    }
    std::string arg_name = name.substr(0, eq_index);

    LOCK(cs_args);
    std::map<std::string, Arg>& arg_map = m_available_args[cat];
    auto ret = arg_map.emplace(arg_name, Arg{name.substr(eq_index, name.size() - eq_index), help, flags});
    assert(ret.second); // Make sure an insertion actually happened

    if (flags & ArgsManager::NETWORK_ONLY) {
        m_network_only_args.emplace(arg_name);
    }
}

void ArgsManager::AddHiddenArgs(const std::vector<std::string>& names)
{
    for (const std::string& name : names) {
        AddArg(name, "", ArgsManager::ALLOW_ANY, OptionsCategory::HIDDEN);
    }
}

void ArgsManager::ClearArgs()
{
    LOCK(cs_args);
    m_settings = {};
    m_available_args.clear();
    m_network_only_args.clear();
}

void ArgsManager::CheckMultipleCLIArgs() const
{
    LOCK(cs_args);
    std::vector<std::string> found{};
    auto cmds = m_available_args.find(OptionsCategory::CLI_COMMANDS);
    if (cmds != m_available_args.end()) {
        for (const auto& [cmd, argspec] : cmds->second) {
            if (IsArgSet(cmd)) {
                found.push_back(cmd);
            }
        }
        if (found.size() > 1) {
            throw std::runtime_error(strprintf("Only one of %s may be specified.", util::Join(found, ", ")));
        }
    }
}

std::string ArgsManager::GetHelpMessage() const
{
    std::string usage;
    LOCK(cs_args);
    for (const auto& arg_map : m_available_args) {
        if (arg_map.first == OptionsCategory::HIDDEN) break;
        if (arg_map.first == OptionsCategory::WALLET_DEBUG_TEST) continue;
        switch(arg_map.first) {
            case OptionsCategory::OPTIONS:
                usage += HelpMessageGroup("Options:");
                break;
            case OptionsCategory::CONNECTION:
                usage += HelpMessageGroup("Connection options:");
                break;
            case OptionsCategory::DEBUG_TEST:
                usage += HelpMessageGroup("Debugging/Testing options:");
                break;
            case OptionsCategory::NODE_RELAY:
                usage += HelpMessageGroup("Node relay options:");
                break;
            case OptionsCategory::BLOCK_CREATION:
                usage += HelpMessageGroup("Block creation options:");
                break;
            case OptionsCategory::RPC:
                usage += HelpMessageGroup("RPC server options:");
                break;
            case OptionsCategory::IPC:
                usage += HelpMessageGroup("IPC interprocess connection options:");
                break;
            case OptionsCategory::WALLET:
                usage += HelpMessageGroup("Wallet options:");
                break;
            case OptionsCategory::CHAINPARAMS:
                usage += HelpMessageGroup("Chain selection options:");
                break;
            case OptionsCategory::GUI:
                usage += HelpMessageGroup("UI Options:");
                break;
            case OptionsCategory::COMMANDS:
                usage += HelpMessageGroup("Commands:");
                break;
            case OptionsCategory::REGISTER_COMMANDS:
                usage += HelpMessageGroup("Register Commands:");
                break;
            case OptionsCategory::CLI_COMMANDS:
                usage += HelpMessageGroup("CLI Commands:");
                break;
            default:
                break;
        }

        for (const auto& arg : arg_map.second) {
            if (arg.second.m_flags & ArgsManager::DEBUG_ONLY) continue;
            std::string name;
            if (arg.second.m_help_param.empty()) {
                name = arg.first;
            } else {
                name = arg.first + arg.second.m_help_param;
            }
            usage += HelpMessageOpt(name, arg.second.m_help_text);
        }
    }
    return usage;
}

bool HelpRequested(const ArgsManager& args)
{
    return args.IsArgSet("-?") || args.IsArgSet("-h") || args.IsArgSet("-help");
}

void SetupHelpOptions(ArgsManager& args)
{
    args.AddArg("-help", "Print this help message and exit (also -h or -?)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    args.AddHiddenArgs({"-h", "-?"});
}

static const int screenWidth = 79;
static const int optIndent = 2;
static const int msgIndent = 7;

std::string HelpMessageGroup(const std::string &message) {
    return std::string(message) + std::string("\n\n");
}

std::string HelpMessageOpt(const std::string &option, const std::string &message) {
    return std::string(optIndent,' ') + std::string(option) +
           std::string("\n") + std::string(msgIndent,' ') +
           FormatParagraph(message, screenWidth - msgIndent, msgIndent) +
           std::string("\n\n");
}

fs::path GetDefaultDataDir()
{
    // Windows:
    //   old: C:\Users\Username\AppData\Roaming\Bitcoin
    //   new: C:\Users\Username\AppData\Local\Bitcoin
    // macOS: ~/Library/Application Support/Bitcoin
    // Unix-like: ~/.bitcoin
#ifdef WIN32
    // Windows
    // Check for existence of datadir in old location and keep it there
    fs::path legacy_path = GetSpecialFolderPath(CSIDL_APPDATA) / "Bitcoin";
    if (fs::exists(legacy_path)) return legacy_path;

    // Otherwise, fresh installs can start in the new, "proper" location
    return GetSpecialFolderPath(CSIDL_LOCAL_APPDATA) / "Bitcoin";
#else
    fs::path pathRet;
    char* pszHome = getenv("HOME");
    if (pszHome == nullptr || strlen(pszHome) == 0)
        pathRet = fs::path("/");
    else
        pathRet = fs::path(pszHome);
#ifdef __APPLE__
    // macOS
    return pathRet / "Library/Application Support/Bitcoin";
#else
    // Unix-like
    return pathRet / ".bitcoin";
#endif
#endif
}

bool CheckDataDirOption(const ArgsManager& args)
{
    const fs::path datadir{args.GetPathArg("-datadir")};
    return datadir.empty() || fs::is_directory(fs::absolute(datadir));
}

fs::path ArgsManager::GetConfigFilePath() const
{
    LOCK(cs_args);
    return *Assert(m_config_path);
}

void ArgsManager::SetConfigFilePath(fs::path path)
{
    LOCK(cs_args);
    assert(!m_config_path);
    m_config_path = path;
}

ChainType ArgsManager::GetChainType() const
{
    std::variant<ChainType, std::string> arg = GetChainArg();
    if (auto* parsed = std::get_if<ChainType>(&arg)) return *parsed;
    throw std::runtime_error(strprintf("Unknown chain %s.", std::get<std::string>(arg)));
}

std::string ArgsManager::GetChainTypeString() const
{
    auto arg = GetChainArg();
    if (auto* parsed = std::get_if<ChainType>(&arg)) return ChainTypeToString(*parsed);
    return std::get<std::string>(arg);
}

std::variant<ChainType, std::string> ArgsManager::GetChainArg() const
{
    auto get_net = [&](const std::string& arg) {
        LOCK(cs_args);
        std::optional<std::string> value = common::GetSetting(m_settings, /* section= */ "", SettingName(arg),
            /* ignore_default_section_config= */ false,
            /*ignore_nonpersistent=*/false,
            /* get_chain_type= */ true);
        return value ? InterpretBool(*value) : false;
    };

    const bool fRegTest = get_net("-regtest");
    const bool fSigNet  = get_net("-signet");
    const bool fTestNet = get_net("-testnet");
    const bool fTestNet4 = get_net("-testnet4");
    const auto chain_arg = GetArg("-chain");

    if ((int)chain_arg.has_value() + (int)fRegTest + (int)fSigNet + (int)fTestNet + (int)fTestNet4 > 1) {
        throw std::runtime_error("Invalid combination of -regtest, -signet, -testnet, -testnet4 and -chain. Can use at most one.");
    }
    if (chain_arg) {
        if (auto parsed = ChainTypeFromString(*chain_arg)) return *parsed;
        // Not a known string, so return original string
        return *chain_arg;
    }
    if (fRegTest) return ChainType::REGTEST;
    if (fSigNet) return ChainType::SIGNET;
    if (fTestNet) return ChainType::TESTNET;
    if (fTestNet4) return ChainType::TESTNET4;
    return ChainType::MAIN;
}

bool ArgsManager::UseDefaultSection(const std::string& arg) const
{
    return m_network == ChainTypeToString(ChainType::MAIN) || m_network_only_args.count(arg) == 0;
}

std::optional<std::string> ArgsManager::GetSetting(const std::string& arg) const
{
    LOCK(cs_args);
    return common::GetSetting(
        m_settings, m_network, SettingName(arg), !UseDefaultSection(arg),
        /*ignore_nonpersistent=*/false, /*get_chain_type=*/false);
}

std::vector<std::string> ArgsManager::GetSettingsList(const std::string& arg) const
{
    LOCK(cs_args);
    return common::GetSettingsList(m_settings, m_network, SettingName(arg), !UseDefaultSection(arg));
}

void ArgsManager::logArgsPrefix(
    const std::string& prefix,
    const std::string& section,
    const std::map<std::string, std::vector<std::string>>& args) const
{
    std::string section_str = section.empty() ? "" : "[" + section + "] ";
    for (const auto& arg : args) {
        for (const auto& value : arg.second) {
            std::optional<unsigned int> flags = GetArgFlags('-' + arg.first);
            if (flags) {
                std::string value_str = (*flags & SENSITIVE) ? "****" : value;
                LogPrintf("%s %s%s=%s\n", prefix, section_str, arg.first, value_str);
            }
        }
    }
}

void ArgsManager::LogArgs() const
{
    LOCK(cs_args);
    for (const auto& section : m_settings.ro_config) {
        logArgsPrefix("Config file arg:", section.first, section.second);
    }
    logArgsPrefix("Command-line arg:", "", m_settings.command_line_options);
}

namespace common {
#ifdef WIN32
WinCmdLineArgs::WinCmdLineArgs()
{
    wchar_t** wargv = CommandLineToArgvW(GetCommandLineW(), &argc);
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>, wchar_t> utf8_cvt;
    argv = new char*[argc];
    args.resize(argc);
    for (int i = 0; i < argc; i++) {
        args[i] = utf8_cvt.to_bytes(wargv[i]);
        argv[i] = &*args[i].begin();
    }
    LocalFree(wargv);
}

WinCmdLineArgs::~WinCmdLineArgs()
{
    delete[] argv;
}

std::pair<int, char**> WinCmdLineArgs::get()
{
    return std::make_pair(argc, argv);
}
#endif
} // namespace common
