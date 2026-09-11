#pragma once
#include <string>
#include <vector>

struct FwRule {
    std::wstring name;
    std::wstring remoteIp;
    bool         enabled = true;
};

bool FwAvailable();
bool FwListNetLurkerRules(std::vector<FwRule>& out);
bool FwRemoveRule(const std::wstring& name);
std::wstring FwRuleNameFor(const std::wstring& ip);
