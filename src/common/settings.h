// Copyright (c) 2019-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COMMON_SETTINGS_H
#define BITCOIN_COMMON_SETTINGS_H

#include <map>
#include <optional>
#include <string>
#include <vector>

namespace common {

//! Stored settings. This struct combines settings from the command line, a
//! read-only configuration file, and a read-write runtime settings file.
struct Settings {
    //! Map of setting name to forced setting value.
    std::map<std::string, std::string> forced_settings;
    //! Map of setting name to list of command line values.
    std::map<std::string, std::vector<std::string>> command_line_options;
    //! Map of config section name and setting name to list of config file values.
    std::map<std::string, std::map<std::string, std::vector<std::string>>> ro_config;
};
//! arguments, runtime read-write settings, and the read-only config file.
//!
//! @param ignore_default_section_config - ignore values in the default section
//!                                        of the config file (part before any
//!                                        [section] keywords)
//! @param ignore_nonpersistent - ignore non-persistent settings values (forced
//!                               settings values and values specified on the
//!                               command line). Only return settings in the
//!                               read-only config and read-write settings
//!                               files.
//! @param get_chain_type - enable special backwards compatible behavior
//!                         for GetChainType
std::optional<std::string> GetSetting(const Settings& settings,
    const std::string& section,
    const std::string& name,
    bool ignore_default_section_config,
    bool ignore_nonpersistent,
    bool get_chain_type);

//! Get combined setting value similar to GetSetting(), except if setting was
//! specified multiple times, return a list of all the values specified.
std::vector<std::string> GetSettingsList(const Settings& settings,
    const std::string& section,
    const std::string& name,
    bool ignore_default_section_config);

//! Return true if a setting is set in the default config file section, and not
//! overridden by a higher priority command-line or network section value.
//!
//! This is used to provide user warnings about values that might be getting
//! ignored unintentionally.
bool OnlyHasDefaultSectionSetting(const Settings& settings, const std::string& section, const std::string& name);

//! Map lookup helper.
template <typename Map, typename Key>
auto FindKey(Map&& map, Key&& key) -> decltype(&map.at(key))
{
    auto it = map.find(key);
    return it == map.end() ? nullptr : &it->second;
}

} // namespace common

#endif // BITCOIN_COMMON_SETTINGS_H
