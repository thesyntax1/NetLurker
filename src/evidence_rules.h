#pragma once
#include <string>

namespace nl {
// Text from processes/providers must remain text when opened in a spreadsheet.
inline std::wstring CsvText(std::wstring text) {
    for (auto& c : text) if (c==L'\n' || c==L'\r') c=L' ';
    const auto first=text.find_first_not_of(L" \t\v\f");
    if(first!=std::wstring::npos && std::wstring(L"=+-@").find(text[first])!=std::wstring::npos) text=L"'"+text;
    if(text.find_first_of(L";\"")==std::wstring::npos) return text;
    std::wstring result=L"\"";
    for(wchar_t c:text) { if(c==L'\"') result+=L'\"'; result+=c; }
    return result+L"\"";
}

struct SourcePlan { bool dnsbl, abuse, pdns, rdap, vt, plugins; };
inline SourcePlan PlanSources(bool threat, bool rdap, bool abuseKey, bool vtKey, bool plugins) {
    return {threat, threat && abuseKey, threat, rdap, vtKey, threat && plugins};
}

inline std::wstring LabelCsvOrigin(const std::wstring& table, bool demo) {
    std::wstring out; size_t start=0; bool header=true;
    while (start<table.size()) {
        auto end=table.find(L'\n',start);
        if(end==std::wstring::npos) end=table.size()-1;
        out += header ? L"data_source;" : demo ? L"demo;" : L"live;";
        out += table.substr(start,end-start+1);
        header=false; start=end+1;
    }
    return out;
}

// A DNSBL's resolver/rate-limit codes are errors, not reputation. Only the
// documented listing codes of our configured zones are accepted.
inline bool DnsblListingCode(bool spamhaus, unsigned a, unsigned b, unsigned c, unsigned d) {
    if (a != 127 || b != 0 || c != 0) return false;
    return spamhaus ? (d == 2 || d == 3 || d == 4 || d == 5 || d == 6 || d == 7 || d == 9)
                    : d == 2;
}

inline bool BannerVersionMatch(const std::wstring& lower, const std::wstring& signature) {
    if (signature.empty()) return false;
    size_t pos = 0;
    while ((pos = lower.find(signature, pos)) != std::wstring::npos) {
        const size_t end = pos + signature.size();
        if (signature.back() == L'.' || end == lower.size() ||
            lower[end] < L'0' || lower[end] > L'9') return true;
        pos = end;
    }
    return false;
}

// Provider results are merged, never assigned wholesale over other evidence.
template <class Evidence>
inline void MergeAbuseEvidence(Evidence& destination, const Evidence& source) {
    destination.abuseScore = source.abuseScore;
    destination.totalReports = source.totalReports;
    destination.lastReport = source.lastReport;
    destination.isTor = source.isTor;
    destination.isWhitelisted = source.isWhitelisted;
}
} // namespace nl
