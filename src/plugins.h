#pragma once

#include <string>
#include <vector>

namespace nl {

struct PluginDef {
    std::wstring name;
    std::wstring exe;
    std::wstring args;
    int timeoutMs = 8000;
};

struct PluginResult {
    bool ok = false;
    int  risk = -1;
    std::wstring verdict;
    std::wstring note;
};

void PluginsLoadFrom(const std::wstring& dir);

size_t PluginsCount();

std::vector<PluginResult> PluginsRun(const std::wstring& ip);

}
