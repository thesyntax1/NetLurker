#pragma once

#include "common.h"
#include <string>
#include <unordered_map>
#include <mutex>
#include <deque>
#include <thread>
#include <atomic>
#include <condition_variable>

namespace nl {

struct CertInfo {
    bool   ok = false;
    std::wstring subject;
    std::wstring issuer;
    std::wstring sans;
    std::wstring thumbprint;
    std::wstring version;
    unsigned long long notBefore = 0;
    unsigned long long notAfter  = 0;
    bool   selfSigned   = false;
    bool   expired      = false;
    bool   notYetValid  = false;
    std::wstring error;
    bool   resolved = false;
    unsigned long long ts = 0;
};

bool TlsFetchCertificate(const std::wstring& ip, int port, const std::wstring& sni,
                         CertInfo& out, int timeoutMs = 6000);

class CertResolver {
public:
    CertResolver();
    ~CertResolver();

    void Start();
    void Stop();
    void SetOnline(bool on);

    bool Get(const std::wstring& ipPort, CertInfo& out, bool enqueue,
             const std::wstring& sni = L"");
    void Invalidate(const std::wstring& ipPort);

    void LoadCache();
    void SaveCache();
    size_t PendingCount();

private:
    struct Entry {
        CertInfo info;
        bool queued = false;
        std::wstring sni;
    };

    mutable std::mutex m_mtx;
    std::unordered_map<std::wstring, Entry> m_cache;
    std::deque<std::wstring> m_q;
    std::condition_variable m_cv;
    std::atomic<bool> m_stop{false};
    std::atomic<bool> m_online{true};
    std::thread m_worker;

    void Worker();
    std::wstring CachePath() const;
};

}
