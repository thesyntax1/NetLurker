#pragma once
#include <string>

namespace nl {
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
