#pragma once
#include "common.h"
#include "netmon.h"
#include <unordered_map>
#include <deque>

namespace nl {

struct HistEntry {
    std::wstring key;
    std::wstring proc;
    std::wstring path;
    DWORD        pid = 0;
    std::wstring proto;
    std::wstring localAddr;
    std::wstring remoteIp;
    unsigned short remotePort = 0;
    std::wstring country;
    std::wstring countryCode;
    std::wstring org;
    std::wstring host;
    std::wstring domain;
    std::wstring banner;
    std::wstring module;
    int          threatScore = -1;
    std::wstring threatDnsbl;
    int          threatPdns  = 0;
    std::wstring certIssuer;
    std::wstring certSubject;
    bool         certSelfSigned = false;
    bool         certExpired    = false;
    bool         certMismatch   = false;
    unsigned long long firstSeen = 0;
    unsigned long long lastSeen  = 0;
    unsigned long long startTs   = 0;
    bool               startExact = false;
    unsigned long long bytesIn   = 0;
    unsigned long long bytesOut  = 0;
    int          riskScore = 0;
    Risk         risk = Risk::Safe;
    std::wstring riskReason;
    bool         active = true;

    unsigned long long DurationMs() const;
    std::wstring DurationText() const;
    std::wstring TimeText() const;
};

struct RateHistory {
    std::deque<float> in, out;
    std::deque<unsigned long long> ts;
    static const unsigned long long WindowMs = 120000;
    void Push(double i, double o, unsigned long long now) {
        in.push_back((float)i);
        out.push_back((float)o);
        ts.push_back(now);
        while (!ts.empty() && now - ts.front() > WindowMs) {
            in.pop_front(); out.pop_front(); ts.pop_front();
        }
        while (in.size() > 2048) { in.pop_front(); out.pop_front(); ts.pop_front(); }
    }
    unsigned long long SpanMs() const {
        return (ts.size() < 2) ? 0 : ts.back() - ts.front();
    }
};

struct CountItem {
    std::wstring label;
    std::wstring sub;
    double value = 0;
    int    count = 0;
};

class History {
public:
    void Update(const std::vector<Conn>& conns);

    const std::vector<HistEntry>& Entries() const { return m_entries; }
    const RateHistory* AppRates(const std::wstring& proc) const;

    std::vector<CountItem> TopCountries(const std::vector<Conn>& live, size_t n) const;
    std::vector<CountItem> TopOrgs(const std::vector<Conn>& live, size_t n) const;
    std::vector<CountItem> TopApps(const std::vector<Conn>& live, size_t n) const;
    std::vector<CountItem> TopPorts(const std::vector<Conn>& live, size_t n) const;

    unsigned long long TotalIn()  const { return m_totalIn; }
    unsigned long long TotalOut() const { return m_totalOut; }
    size_t ClosedCount() const { return m_closed; }
    size_t AlertCount()  const { return m_alerts; }
    void   NoteAlert() { m_alerts++; }

private:
    std::vector<HistEntry> m_entries;
    std::unordered_map<std::wstring, size_t> m_index;
    std::unordered_map<std::wstring, RateHistory> m_appRates;
    unsigned long long m_totalIn = 0, m_totalOut = 0;
    size_t m_closed = 0;
    size_t m_alerts = 0;
    static const size_t kMaxEntries = 4000;
};

}
