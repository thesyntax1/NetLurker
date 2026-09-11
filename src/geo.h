#pragma once
#include "common.h"
#include <unordered_map>
#include <deque>
#include <mutex>
#include <thread>
#include <atomic>
#include <condition_variable>

namespace nl {

enum class GeoStatus { Ok = 0, Pending, Offline, QueryFailed, NotFound };

struct GeoInfo {
    std::wstring country;
    std::wstring countryCode;
    std::wstring city;
    std::wstring region;
    std::wstring org;
    std::wstring isp;
    std::wstring asn;
    std::wstring asname;
    std::wstring host;
    bool  hosting = false;
    bool  proxy   = false;
    bool  mobile  = false;
    bool  resolved = false;
    bool  failed   = false;
    GeoStatus status = GeoStatus::Pending;
    bool  queued   = false;
    unsigned int attempts = 0;
    unsigned long long nextTry = 0;
    unsigned long long ts = 0;

    std::wstring StatusText() const;
    std::wstring Location() const;
    std::wstring Flags() const;
};

class GeoResolver {
public:
    GeoResolver();
    ~GeoResolver();

    void Start();
    void Stop();

    void SetOnline(bool v);
    bool Online() const { return m_online; }

    bool Get(const std::wstring& ip, GeoInfo& out, bool enqueueIfMissing = true);
    unsigned long Version() const { return m_version.load(); }
    size_t PendingCount();
    size_t CacheCount();

    void LoadCache();
    void SaveCache();

private:
    void EnqueueLocked(const std::wstring& ip);
    void GeoWorker();
    void DnsWorker();

    std::unordered_map<std::wstring, GeoInfo> m_cache;
    std::deque<std::wstring> m_geoQueue;
    std::deque<std::wstring> m_dnsQueue;
    std::mutex m_mtx;
    std::condition_variable m_cv;
    std::thread m_geoThread;
    std::thread m_dnsThread;
    std::atomic<bool> m_run{false};
    std::atomic<bool> m_online{true};
    std::atomic<unsigned long> m_version{0};
    std::atomic<int>  m_dirty{0};
};

}
