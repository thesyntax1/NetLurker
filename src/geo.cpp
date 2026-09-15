#include "geo.h"
#include "i18n.h"
#include "http.h"
#include "json.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <fstream>
#include <sstream>
#include <ctime>

namespace nl {

static const unsigned long long kCacheTtlSec = 7ull * 24 * 3600;
static const unsigned long long kRevalidateSec = 24ull * 3600;

static const unsigned long long kRetryBaseSec = 20;
static const unsigned long long kRetryMaxSec  = 600;

static unsigned long long RetryDelay(unsigned int attempts) {
    unsigned long long d = kRetryBaseSec;
    for (unsigned int i = 1; i < attempts && d < kRetryMaxSec; ++i) d *= 2;
    return d > kRetryMaxSec ? kRetryMaxSec : d;
}

std::wstring GeoInfo::StatusText() const {
    switch (status) {
        case GeoStatus::Offline:     return Tr(L"(offline)");
        case GeoStatus::QueryFailed: return Tr(L"(lookup failed)");
        case GeoStatus::NotFound:    return Tr(L"(unknown)");
        default:                     return L"";
    }
}

std::wstring GeoInfo::Location() const {
    std::wstring s;
    if (!city.empty())   s = city;
    if (!region.empty()) s += (s.empty() ? region : (L", " + region));
    return s;
}

std::wstring GeoInfo::Flags() const {
    std::wstring s;
    auto add = [&](const wchar_t* t) { if (!s.empty()) s += L" · "; s += t; };
    if (hosting) add(Tr(L"data center"));
    if (proxy)   add(Tr(L"proxy/VPN"));
    if (mobile)  add(Tr(L"mobile network"));
    return s;
}

GeoResolver::GeoResolver() {}
GeoResolver::~GeoResolver() { Stop(); }

void GeoResolver::Start() {
    if (m_run.exchange(true)) return;
    LoadCache();
    m_geoThread = std::thread(&GeoResolver::GeoWorker, this);
    m_dnsThread = std::thread(&GeoResolver::DnsWorker, this);
}

void GeoResolver::Stop() {
    if (!m_run.exchange(false)) return;
    m_cv.notify_all();
    if (m_geoThread.joinable()) m_geoThread.join();
    if (m_dnsThread.joinable()) m_dnsThread.join();
    SaveCache();
}

size_t GeoResolver::PendingCount() {
    std::lock_guard<std::mutex> lk(m_mtx);
    return m_geoQueue.size();
}

size_t GeoResolver::CacheCount() {
    std::lock_guard<std::mutex> lk(m_mtx);
    return m_cache.size();
}

bool GeoResolver::Get(const std::wstring& ip, GeoInfo& out, bool enqueue) {
    if (ip.empty() || ip == L"0.0.0.0" || ip == L"::") return false;
    std::lock_guard<std::mutex> lk(m_mtx);
    const unsigned long long now = (unsigned long long)time(nullptr);
    auto it = m_cache.find(ip);
    if (it != m_cache.end()) {
        GeoInfo& g = it->second;

        if (g.status == GeoStatus::Ok && g.ts && now - g.ts > kRevalidateSec) {
            GeoInfo fresh;
            fresh.attempts = 0;
            g = fresh;
            if (enqueue) EnqueueLocked(ip);
        }

        else if (g.failed && enqueue && m_online.load() && now >= g.nextTry) {
            g.nextTry = now + RetryDelay(g.attempts + 1);
            EnqueueLocked(ip);
        }

        else if (!g.resolved && !g.queued && enqueue && m_online.load()) {
            EnqueueLocked(ip);
        }
        out = g;
        out.country = g.status == GeoStatus::Ok ? g.country : g.StatusText();
        return true;
    }
    if (enqueue) {
        m_cache[ip] = GeoInfo{};
        EnqueueLocked(ip);
    }
    return false;
}

void GeoResolver::EnqueueLocked(const std::wstring& ip) {
    auto& g = m_cache[ip];
    if (g.queued) return;
    g.queued = true;
    m_geoQueue.push_back(ip);
    m_dnsQueue.push_back(ip);
    m_cv.notify_all();
}

void GeoResolver::SetOnline(bool v) {
    const bool was = m_online.exchange(v);
    if (!v || was) return;

    std::lock_guard<std::mutex> lk(m_mtx);
    for (auto& kv : m_cache) {
        GeoInfo& g = kv.second;
        if (g.status == GeoStatus::Ok) continue;
        g.attempts = 0;
        g.nextTry  = 0;
        if (!g.queued) EnqueueLocked(kv.first);
    }
}

static std::wstring CachePath() { return AppDataDir() + L"\\geoip_cache.tsv"; }

void GeoResolver::LoadCache() {
    std::ifstream f(Narrow(CachePath()).c_str());
    if (!f.is_open()) return;
    const unsigned long long now = (unsigned long long)time(nullptr);
    std::string line;
    std::lock_guard<std::mutex> lk(m_mtx);
    while (std::getline(f, line)) {
        if (line.empty()) continue;
        std::vector<std::string> col;
        std::string cur;
        std::istringstream ss(line);
        while (std::getline(ss, cur, '\t')) col.push_back(cur);
        if (col.size() < 11) continue;
        unsigned long long ts = strtoull(col[10].c_str(), nullptr, 10);
        if (now > ts && now - ts > kCacheTtlSec) continue;
        GeoInfo g;
        g.country     = Widen(col[1]);
        g.countryCode = Widen(col[2]);
        g.city        = Widen(col[3]);
        g.region      = Widen(col[4]);
        g.org         = Widen(col[5]);
        g.asn         = Widen(col[6]);
        g.asname      = Widen(col[7]);
        g.host        = Widen(col[8]);
        int flags     = atoi(col[9].c_str());
        g.hosting = (flags & 1) != 0;
        g.proxy   = (flags & 2) != 0;
        g.mobile  = (flags & 4) != 0;
        g.failed  = (flags & 8) != 0;
        if (g.failed) continue;
        g.resolved = true;
        g.status   = GeoStatus::Ok;
        g.ts = ts;
        m_cache[Widen(col[0])] = g;
    }
}

void GeoResolver::SaveCache() {
    std::unordered_map<std::wstring, GeoInfo> copy;
    {
        std::lock_guard<std::mutex> lk(m_mtx);
        copy = m_cache;
    }
    std::ofstream f(Narrow(CachePath()).c_str(), std::ios::trunc);
    if (!f.is_open()) return;
    const unsigned long long now = (unsigned long long)time(nullptr);
    auto clean = [](std::wstring s) {
        for (auto& ch : s) if (ch == L'\t' || ch == L'\n' || ch == L'\r') ch = L' ';
        return Narrow(s);
    };
    for (const auto& kv : copy) {
        const GeoInfo& g = kv.second;

        if (!g.resolved || g.failed || g.status != GeoStatus::Ok) continue;
        int flags = (g.hosting ? 1 : 0) | (g.proxy ? 2 : 0) | (g.mobile ? 4 : 0) | (g.failed ? 8 : 0);
        f << clean(kv.first) << '\t' << clean(g.country) << '\t' << clean(g.countryCode) << '\t'
          << clean(g.city) << '\t' << clean(g.region) << '\t' << clean(g.org) << '\t'
          << clean(g.asn) << '\t' << clean(g.asname) << '\t' << clean(g.host) << '\t'
          << flags << '\t' << (g.ts ? g.ts : now) << '\n';
    }
}

void GeoResolver::GeoWorker() {
    while (m_run.load()) {
        std::vector<std::wstring> batch;
        {
            std::unique_lock<std::mutex> lk(m_mtx);
            if (m_geoQueue.empty()) {
                m_cv.wait_for(lk, std::chrono::milliseconds(400));
                continue;
            }
            while (!m_geoQueue.empty() && batch.size() < 100) {
                batch.push_back(m_geoQueue.front());
                m_geoQueue.pop_front();
            }
        }
        if (batch.empty()) continue;

        if (!m_online.load()) {
            const unsigned long long now = (unsigned long long)time(nullptr);
            std::lock_guard<std::mutex> lk(m_mtx);
            for (auto& ip : batch) {
                auto& g = m_cache[ip];
                g.queued = false;
                g.failed = true; g.resolved = true;
                g.status = GeoStatus::Offline;
                g.ts = 0;
                g.attempts++;
                g.nextTry = now + RetryDelay(g.attempts);
            }
            m_version++;
            continue;
        }

        std::string payload = "[";
        for (size_t i = 0; i < batch.size(); ++i) {
            if (i) payload += ",";
            payload += "\"" + json::Escape(Narrow(batch[i])) + "\"";
        }
        payload += "]";

        auto res = http::Request("POST",
            "http://ip-api.com/batch?fields=status,message,country,countryCode,region,regionName,"
            "city,isp,org,as,asname,reverse,mobile,proxy,hosting,query",
            payload, "application/json", "", 8000, L"", http::RequestPolicy::PublicGeolocation);

        const unsigned long long now = (unsigned long long)time(nullptr);
        std::lock_guard<std::mutex> lk(m_mtx);
        if (!res.ok) {
            for (auto& ip : batch) {
                auto& g = m_cache[ip];
                g.queued = false;
                g.resolved = true; g.failed = true;
                g.status = GeoStatus::QueryFailed;
                g.ts = 0;
                g.attempts++;
                g.nextTry = now + RetryDelay(g.attempts);
            }
        } else {
            auto objs = json::SplitObjects(res.body);
            for (auto& o : objs) {
                std::string q, st;
                if (!json::GetString(o, "query", q)) continue;
                std::wstring wip = Widen(q);
                auto& g = m_cache[wip];
                g.resolved = true;
                g.queued   = false;
                g.ts = now;
                json::GetString(o, "status", st);
                if (st != "success") {

                    g.failed = true;
                    g.status = GeoStatus::NotFound;
                    g.attempts = 0;
                    g.nextTry  = now + kRevalidateSec;
                    continue;
                }
                g.failed   = false;
                g.status   = GeoStatus::Ok;
                g.attempts = 0;
                std::string s;
                if (json::GetString(o, "country", s))     g.country     = Widen(s);
                if (json::GetString(o, "countryCode", s)) g.countryCode = Widen(s);
                if (json::GetString(o, "city", s))        g.city        = Widen(s);
                if (json::GetString(o, "regionName", s))  g.region      = Widen(s);
                if (json::GetString(o, "isp", s))         g.isp         = Widen(s);
                if (json::GetString(o, "org", s) && !s.empty()) g.org    = Widen(s);
                if (g.org.empty())                        g.org         = g.isp;
                if (json::GetString(o, "as", s))          g.asn         = Widen(s);
                if (json::GetString(o, "asname", s))      g.asname      = Widen(s);
                if (json::GetString(o, "reverse", s) && !s.empty() && g.host.empty())
                    g.host = Widen(s);

                size_t hp;
                auto boolField = [&](const char* name) {
                    hp = o.find(std::string("\"") + name + "\":");
                    if (hp == std::string::npos) return false;
                    return o.compare(hp + strlen(name) + 3, 4, "true") == 0;
                };
                g.hosting = boolField("hosting");
                g.proxy   = boolField("proxy");
                g.mobile  = boolField("mobile");
            }
            for (auto& ip : batch) {
                auto& g = m_cache[ip];
                g.queued = false;
                if (!g.resolved) {

                    g.resolved = true; g.failed = true;
                    g.status = GeoStatus::QueryFailed;
                    g.ts = 0;
                    g.attempts++;
                    g.nextTry = now + RetryDelay(g.attempts);
                }
            }
        }
        m_version++;
        if (++m_dirty >= 25) { m_dirty = 0; }

        for (int i = 0; i < 45 && m_run.load(); ++i) Sleep(100);
    }
}

void GeoResolver::DnsWorker() {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    while (m_run.load()) {
        std::wstring ip;
        {
            std::unique_lock<std::mutex> lk(m_mtx);
            if (m_dnsQueue.empty()) {
                m_cv.wait_for(lk, std::chrono::milliseconds(400));
                continue;
            }
            ip = m_dnsQueue.front();
            m_dnsQueue.pop_front();
        }
        if (ip.empty()) continue;

        std::wstring host;
        sockaddr_in6 sa6; ZeroMemory(&sa6, sizeof(sa6));
        sockaddr_in  sa4; ZeroMemory(&sa4, sizeof(sa4));
        wchar_t name[NI_MAXHOST] = L"";
        int rc = -1;

        std::wstring pure = ip;
        size_t pct = pure.find(L'%');
        if (pct != std::wstring::npos) pure = pure.substr(0, pct);

        if (pure.find(L':') != std::wstring::npos) {
            sa6.sin6_family = AF_INET6;
            if (InetPtonW(AF_INET6, pure.c_str(), &sa6.sin6_addr) == 1)
                rc = GetNameInfoW((sockaddr*)&sa6, sizeof(sa6), name, NI_MAXHOST, nullptr, 0, NI_NAMEREQD);
        } else {
            sa4.sin_family = AF_INET;
            if (InetPtonW(AF_INET, pure.c_str(), &sa4.sin_addr) == 1)
                rc = GetNameInfoW((sockaddr*)&sa4, sizeof(sa4), name, NI_MAXHOST, nullptr, 0, NI_NAMEREQD);
        }
        if (rc == 0 && name[0]) host = name;

        {
            std::lock_guard<std::mutex> lk(m_mtx);
            auto& g = m_cache[ip];
            if (!host.empty()) g.host = host;
            else if (g.host.empty()) g.host = L"—";
        }
        m_version++;
    }
    WSACleanup();
}

}
