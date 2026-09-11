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

struct BannerInfo {
    bool   ok = false;
    std::wstring status;
    std::wstring server;
    std::wstring powered;
    std::wstring contentType;
    std::wstring error;
    bool   resolved = false;
    unsigned long long ts = 0;
};

class BannerResolver {
public:
    BannerResolver();
    ~BannerResolver();

    void Start();
    void Stop();
    void SetOnline(bool on);

    bool Get(const std::wstring& ipPort, BannerInfo& out, bool enqueue);
    void Invalidate(const std::wstring& ipPort);

    void LoadCache();
    void SaveCache();
    size_t PendingCount();

private:
    struct Entry {
        BannerInfo info;
        bool queued = false;
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

bool BannerIsEol(const std::wstring& server);

}
