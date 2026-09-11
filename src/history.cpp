#include "history.h"
#include "i18n.h"
#include <ctime>
#include <cwchar>
#include <unordered_set>

namespace nl {

unsigned long long HistEntry::DurationMs() const {
    if (startExact && startTs) {
        const unsigned long long endWall = (unsigned long long)time(nullptr) * 1000ull -
                                           (NowMs() > lastSeen ? NowMs() - lastSeen : 0);
        return endWall > startTs ? endWall - startTs : 0;
    }
    return lastSeen > firstSeen ? lastSeen - firstSeen : 0;
}

std::wstring HistEntry::DurationText() const {
    const std::wstring d = FormatDurationLong(DurationMs() / 1000);
    return startExact ? d : (L"\u2265 " + d);
}

std::wstring HistEntry::TimeText() const {
    time_t t;
    if (startExact && startTs) {
        t = (time_t)(startTs / 1000ull);
    } else {
        unsigned long long nowTick = NowMs();
        time_t nowSec = time(nullptr);
        long long deltaSec = (long long)((nowTick > firstSeen ? nowTick - firstSeen : 0) / 1000);
        t = nowSec - (time_t)deltaSec;
    }
    tm lt;
    localtime_s(&lt, &t);
    wchar_t buf[32];
    swprintf(buf, 32, L"%02d:%02d:%02d", lt.tm_hour, lt.tm_min, lt.tm_sec);
    return buf;
}

void History::Update(const std::vector<Conn>& conns) {
    const unsigned long long now = NowMs();
    std::unordered_set<std::wstring> seen;
    seen.reserve(conns.size() * 2);

    std::vector<HistEntry> fresh;
    std::unordered_map<std::wstring, std::pair<double, double>> perApp;
    for (const auto& c : conns) {
        perApp[c.procName].first  += c.rateIn;
        perApp[c.procName].second += c.rateOut;
    }
    for (auto& kv : perApp) m_appRates[kv.first].Push(kv.second.first, kv.second.second, now);

    if (m_appRates.size() > 512) {
        for (auto it = m_appRates.begin(); it != m_appRates.end(); ) {
            if (perApp.find(it->first) == perApp.end()) it = m_appRates.erase(it);
            else ++it;
        }
    }

    for (const auto& c : conns) {
        if (c.IsListening()) continue;
        if (!c.isRemotePublic && c.remotePort == 0) continue;
        const std::wstring key = c.Key();
        if (!seen.insert(key).second) continue;

        auto it = m_index.find(key);
        if (it == m_index.end()) {
            HistEntry e;
            e.key         = key;
            e.proc        = c.procName;
            e.path        = c.procPath;
            e.pid         = c.pid;
            e.proto       = c.ProtoText();
            e.localAddr   = c.LocalText();
            e.remoteIp    = c.remoteIp;
            e.remotePort  = c.remotePort;
            e.country     = c.country;
            e.countryCode = c.countryCode;
            e.org         = c.org;
            e.host        = c.host;
            e.domain      = c.domain;
            e.banner      = c.banner;
            e.module      = c.module;
            e.threatScore = c.threatScore;
            e.threatDnsbl = c.threatDnsbl;
            e.threatPdns  = c.threatPdns;
            e.certIssuer  = c.certIssuer;
            e.certSubject = c.certSubject;
            e.certSelfSigned = c.certSelfSigned;
            e.certExpired    = c.certExpired;
            e.certMismatch   = c.certMismatch;
            e.firstSeen   = c.firstSeen ? c.firstSeen : now;
            e.startTs     = c.createTs;
            e.startExact  = c.createTs != 0;
            e.lastSeen    = now;
            e.bytesIn     = c.bytesIn;
            e.bytesOut    = c.bytesOut;
            e.riskScore   = c.riskScore;
            e.risk        = c.risk;
            e.riskReason  = c.riskReason;
            e.active      = true;

            fresh.push_back(std::move(e));
        } else {
            HistEntry& e = m_entries[it->second];
            e.lastSeen = now;
            e.active   = true;
            if (c.bytesIn  > e.bytesIn)  e.bytesIn  = c.bytesIn;
            if (c.bytesOut > e.bytesOut) e.bytesOut = c.bytesOut;
            if (c.riskScore > e.riskScore) { e.riskScore = c.riskScore; e.risk = c.risk; e.riskReason = c.riskReason; }
            if ((e.country.empty() || e.country == Tr(L"querying…")) && !c.geoPending)
                { e.country = c.country; e.countryCode = c.countryCode; }
            if (e.org.empty() || e.org == L"—") e.org = c.org;
            if (e.host.empty() || e.host == L"—") e.host = c.host;
            if (e.domain.empty()) e.domain = c.domain;
            if (e.banner.empty()) e.banner = c.banner;
            if (e.threatScore < 0)          { e.threatScore = c.threatScore; e.threatDnsbl = c.threatDnsbl; e.threatPdns = c.threatPdns; }
            if (e.certIssuer.empty())       { e.certIssuer = c.certIssuer; e.certSubject = c.certSubject;
                                              e.certSelfSigned = c.certSelfSigned; e.certExpired = c.certExpired; }
        }
    }

    if (!fresh.empty()) {

        m_entries.insert(m_entries.begin(), fresh.rbegin(), fresh.rend());
        if (m_entries.size() > kMaxEntries) m_entries.resize(kMaxEntries);
        m_index.clear();
        m_index.reserve(m_entries.size() * 2);
        for (size_t i = 0; i < m_entries.size(); ++i) m_index[m_entries[i].key] = i;
    }

    m_closed = 0;
    m_totalIn = m_totalOut = 0;
    for (auto& e : m_entries) {
        if (e.active && seen.find(e.key) == seen.end()) e.active = false;
        if (!e.active) m_closed++;
        m_totalIn  += e.bytesIn;
        m_totalOut += e.bytesOut;
    }
}

const RateHistory* History::AppRates(const std::wstring& proc) const {
    auto it = m_appRates.find(proc);
    return (it == m_appRates.end()) ? nullptr : &it->second;
}

static std::vector<CountItem> TopN(std::unordered_map<std::wstring, CountItem>& map, size_t n) {
    std::vector<CountItem> v;
    v.reserve(map.size());
    for (auto& kv : map) v.push_back(kv.second);
    std::sort(v.begin(), v.end(), [](const CountItem& a, const CountItem& b) {
        if (a.value != b.value) return a.value > b.value;
        return a.count > b.count;
    });
    if (v.size() > n) v.resize(n);
    return v;
}

std::vector<CountItem> History::TopCountries(const std::vector<Conn>& live, size_t n) const {
    std::unordered_map<std::wstring, CountItem> map;
    for (const auto& c : live) {
        if (!c.isRemotePublic || c.country.empty()) continue;
        if (c.country[0] == L'(' || c.geoPending) continue;
        auto& it = map[c.country];
        it.label = c.country;
        it.sub   = c.countryCode;
        it.count++;
        it.value = it.count;
    }
    for (const auto& e : m_entries) {
        if (e.country.empty() || e.country[0] == L'(') continue;
        auto& it = map[e.country];
        if (it.label.empty()) { it.label = e.country; it.sub = e.countryCode; }
    }
    return TopN(map, n);
}

std::vector<CountItem> History::TopOrgs(const std::vector<Conn>& live, size_t n) const {
    std::unordered_map<std::wstring, CountItem> map;
    for (const auto& c : live) {
        if (!c.isRemotePublic || c.org.empty() || c.org == L"—") continue;
        auto& it = map[c.org];
        it.label = c.org;
        it.sub   = c.countryCode;
        it.count++;
        it.value = it.count;
    }
    return TopN(map, n);
}

std::vector<CountItem> History::TopApps(const std::vector<Conn>& live, size_t n) const {
    std::unordered_map<std::wstring, CountItem> map;
    for (const auto& c : live) {
        auto& it = map[c.procName];
        it.label = c.procName;
        it.count++;
        it.value += c.rateIn + c.rateOut;
    }

    bool anyRate = false;
    for (auto& kv : map) if (kv.second.value > 0) { anyRate = true; break; }
    if (!anyRate) for (auto& kv : map) kv.second.value = kv.second.count;
    else          for (auto& kv : map) {
        wchar_t buf[64];
        swprintf(buf, 64, Tr(L"%d connections"), kv.second.count);
        kv.second.sub = buf;
    }
    return TopN(map, n);
}

std::vector<CountItem> History::TopPorts(const std::vector<Conn>& live, size_t n) const {
    std::unordered_map<std::wstring, CountItem> map;
    for (const auto& c : live) {
        if (c.IsListening()) continue;
        if (!c.isRemotePublic) continue;
        std::wstring key = std::to_wstring(c.remotePort);
        auto& it = map[key];
        it.label = key;
        const wchar_t* svc = PortServiceName(c.remotePort);
        it.sub = svc ? svc : Tr(L"unknown");
        it.count++;
        it.value = it.count;
    }
    return TopN(map, n);
}

}
