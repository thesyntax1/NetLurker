#pragma once

#include "common.h"
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <deque>
#include <thread>
#include <atomic>
#include <condition_variable>

namespace nl {

struct ThreatInfo {
    int    abuseScore  = -1;
    int    totalReports = 0;
    unsigned long long lastReport = 0;
    bool   isTor       = false;
    bool   isWhitelisted = false;
    std::wstring dnsbl;
    int    passiveDns  = 0;
    std::wstring pdnsNames;

    std::wstring rdapName;
    std::wstring rdapOrg;
    std::wstring rdapAbuse;
    std::wstring rdapCidr;
    unsigned long long rdapRegistered = 0;

    int    pluginRisk = -1;
    std::wstring pluginVerdict;
    std::wstring pluginNote;

    int    vtMalicious = 0;
    int    vtSuspicious = 0;
    int    vtTotal     = 0;
    int    vtReputation = 0;
    unsigned long long vtDate = 0;

    bool   resolved    = false;
    bool   failed      = false;
    unsigned long long ts = 0;
};

class ThreatResolver {
public:
    ThreatResolver();
    ~ThreatResolver();

    void Start();
    void Stop();
    void SetOnline(bool on);
    void SetRdapOnline(bool on);
    void SetAbuseKey(const std::wstring& key);
    void SetVtKey(const std::wstring& key);

    bool Get(const std::wstring& ip, ThreatInfo& out, bool enqueue);
    void Invalidate(const std::wstring& ip);

    void LoadCache();
    void SaveCache();
    size_t PendingCount();
    size_t CacheCount();

private:
    struct Entry {
        ThreatInfo info;
        bool queuedD = false, queuedA = false, queuedP = false, queuedR = false, queuedV = false, queuedG = false;
    };

    mutable std::mutex m_mtx;
    std::unordered_map<std::wstring, Entry> m_cache;
    std::deque<std::wstring> m_qDnsbl, m_qAbuse, m_qPdns, m_qRdap, m_qVt, m_qPlug;
    std::condition_variable m_cv;
    std::atomic<bool> m_stop{false};
    std::atomic<bool> m_online{true};
    std::atomic<bool> m_rdapOnline{true};
    std::wstring m_abuseKey;
    std::wstring m_vtKey;
    std::thread m_tDnsbl, m_tAbuse, m_tPdns, m_tRdap, m_tVt, m_tPlug;

    void DnsblWorker();
    void AbuseWorker();
    void PdnsWorker();
    void RdapWorker();
    void VtWorker();
    void PlugWorker();

    std::wstring CachePath() const;
    void EnqueueLocked(const std::wstring& ip, Entry& e);
    void TouchResolvedLocked(const std::wstring& ip);
};

}
