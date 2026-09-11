#pragma once
#include "common.h"
#include "netmon.h"
#include <functional>

namespace nl {

struct AiConfig {
    std::wstring endpoint = L"https://api.openai.com/v1/chat/completions";
    std::wstring model    = L"gpt-4o-mini";
    std::wstring apiKey;
    bool Valid() const { return !apiKey.empty() && !endpoint.empty() && !model.empty(); }
};

AiConfig LoadAiConfig();
void     SaveAiConfig(const AiConfig& cfg);
std::wstring ConfigPath();

struct ProcContext {
    std::wstring cmdline, integrity, parent, sha256, product, version;
    double cpu = 0.0;
    unsigned long long ram = 0;
    unsigned long threads = 0;
    bool elevated = false, suspended = false;
    unsigned long long uptimeMs = 0;
    bool valid = false;
};

std::wstring BuildAnalysisPrompt(const Conn& c, const std::vector<Conn>& all,
                                 const ProcContext& pc = ProcContext{});

void AnalyzeAsync(const AiConfig& cfg, const std::wstring& prompt,
                  std::function<void(bool ok, std::wstring text)> done);

std::wstring BuildBulkPrompt(const std::vector<Conn>& conns);

std::wstring LocalHeuristicAnalysis(const Conn& c);

}
