// Copyright (c) 2019-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <common/settings.h>

#include <optional>
#include <string>
#include <vector>

namespace common {
namespace {

[[nodiscard]] const ::std::vector<::std::string>* FindConfigSection(const Settings& settings, const ::std::string& section, const ::std::string& name)
{
    if (auto* map = FindKey(settings.ro_config, section)) {
        if (auto* values = FindKey(*map, name)) {
            return values;
        }
    }
    return nullptr;
}

[[nodiscard]] const ::std::string& PickConfigValue(const ::std::vector<::std::string>& values, bool get_chain_type)
{
    return get_chain_type ? values.back() : values.front();
}

} // namespace

::std::optional<::std::string> GetSetting(const Settings& settings,
    const ::std::string& section,
    const ::std::string& name,
    bool ignore_default_section_config,
    bool ignore_nonpersistent,
    bool get_chain_type)
{
    if (!ignore_nonpersistent) {
        if (const ::std::string* forced = FindKey(settings.forced_settings, name)) {
            return *forced;
        }
        if (const auto* cmd_values = FindKey(settings.command_line_options, name); cmd_values && !cmd_values->empty()) {
            return cmd_values->back();
        }
    }

    if (!section.empty()) {
        if (const auto* network_values = FindConfigSection(settings, section, name); network_values && !network_values->empty()) {
            return PickConfigValue(*network_values, get_chain_type);
        }
    }

    if (!ignore_default_section_config) {
        if (const auto* default_values = FindConfigSection(settings, "", name); default_values && !default_values->empty()) {
            return PickConfigValue(*default_values, get_chain_type);
        }
    }

    return ::std::nullopt;
}

::std::vector<::std::string> GetSettingsList(const Settings& settings,
    const ::std::string& section,
    const ::std::string& name,
    bool ignore_default_section_config)
{
    ::std::vector<::std::string> result;

    if (const ::std::string* forced = FindKey(settings.forced_settings, name)) {
        result.push_back(*forced);
        return result;
    }

    if (const auto* cmd_values = FindKey(settings.command_line_options, name)) {
        result.insert(result.end(), cmd_values->begin(), cmd_values->end());
    }

    if (!section.empty()) {
        if (const auto* network_values = FindConfigSection(settings, section, name)) {
            result.insert(result.end(), network_values->begin(), network_values->end());
        }
    }

    if (!ignore_default_section_config) {
        if (const auto* default_values = FindConfigSection(settings, "", name)) {
            result.insert(result.end(), default_values->begin(), default_values->end());
        }
    }

    return result;
}

bool OnlyHasDefaultSectionSetting(const Settings& settings, const ::std::string& section, const ::std::string& name)
{
    if (const auto* forced = FindKey(settings.forced_settings, name); forced != nullptr) {
        return false;
    }

    if (const auto* cmd_values = FindKey(settings.command_line_options, name); cmd_values && !cmd_values->empty()) {
        return false;
    }

    if (!section.empty()) {
        if (const auto* network_values = FindConfigSection(settings, section, name); network_values && !network_values->empty()) {
            return false;
        }
    }

    const auto* default_values = FindConfigSection(settings, "", name);
    const bool has_default = default_values && !default_values->empty();
    return has_default;
}

} // namespace common
