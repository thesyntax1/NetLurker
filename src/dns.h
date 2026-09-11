#pragma once

#include "common.h"
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <mutex>

namespace nl {

struct DnsCacheRow {
    std::wstring domain;
    std::wstring ip;
    bool         suspect = false;
};

class DnsCacheService {
public:

    void Refresh();

    std::wstring DomainFor(const std::wstring& ip) const;

    bool IsHostsRedirect(const std::wstring& ip) const;

    int HostsEntryCount() const;

    std::vector<DnsCacheRow> TopDomains() const;
    size_t CacheSize() const;

private:
    void LoadHosts();

    mutable std::mutex m_mtx;

    std::unordered_map<std::wstring, std::vector<std::pair<std::wstring, unsigned long>>> m_byIp;
    std::unordered_set<std::wstring> m_hostsIps;
    int m_hostsEntries = 0;
    unsigned long long m_lastDns = 0, m_lastHosts = 0;
};

std::wstring MacVendor(const std::wstring& mac);

}
