#include "threat.h"
#include "plugins.h"
#include "http.h"
#include "json.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <ctime>
#include <unordered_set>

using namespace nl;

namespace {

unsigned long long UnixFromYmd(int y, int m, int d, int hh = 0, int mm = 0, int ss = 0) {
    if (y < 1970 || m < 1 || m > 12 || d < 1 || d > 31) return 0;
    y -= m <= 2;
    const int era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = (unsigned)(y - era * 400);
    const unsigned doy = (unsigned)((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1);
    const unsigned doe = (unsigned)(yoe * 365 + yoe / 4 - yoe / 100 + doy);
    long long days = era * 146097LL + (long long)doe - 719468LL;
    return (unsigned long long)(days * 86400LL + hh * 3600 + mm * 60 + ss);
}

unsigned long long ParseIsoDate(const std::string& s) {
    int y = 0, mo = 0, d = 0, h = 0, mi = 0, se = 0;
    if (sscanf(s.c_str(), "%d-%d-%dT%d:%d:%d", &y, &mo, &d, &h, &mi, &se) >= 6 ||
        sscanf(s.c_str(), "%d-%d-%d %d:%d:%d", &y, &mo, &d, &h, &mi, &se) >= 6)
        return UnixFromYmd(y, mo, d, h, mi, se);
    return 0;
}

struct DnsblZone { const wchar_t* label; const char* suffix; };

std::string ReverseIp4(const std::string& ip) {
    unsigned a = 0, b = 0, c = 0, d = 0;
    if (sscanf(ip.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return "";
    if (a > 255 || b > 255 || c > 255 || d > 255) return "";
    char buf[64];
    sprintf_s(buf, "%u.%u.%u.%u", d, c, b, a);
    return buf;
}

bool DnsblHit(const std::string& queryName) {
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(queryName.c_str(), nullptr, &hints, &res) != 0) return false;
    bool hit = false;
    for (auto* ai = res; ai; ai = ai->ai_next) {
        if (ai->ai_family == AF_INET) {
            sockaddr_in* sa = (sockaddr_in*)ai->ai_addr;
            unsigned char b1 = (unsigned char)(sa->sin_addr.S_un.S_addr & 0xFF);
            if (b1 == 127) { hit = true; break; }
        }
    }
    freeaddrinfo(res);
    return hit;
}

void ParseBlockReports(const std::string& body,
                       std::unordered_map<std::string, ThreatInfo>& out) {
    const char* key = "\"reportedAddress\"";
    size_t p = body.find(key);
    if (p == std::string::npos) return;
    p = body.find('[', p);
    if (p == std::string::npos) return;
    int depth = 0;
    size_t q = p;
    for (; q < body.size(); ++q) {
        if (body[q] == '[') depth++;
        else if (body[q] == ']') { depth--; if (!depth) break; }
    }
    if (q >= body.size()) return;
    std::string arr = body.substr(p, q - p + 1);
    for (const auto& obj : json::SplitObjects(arr)) {
        std::string ip;
        double score = 0, reports = 0;
        std::string last;
        if (!json::GetString(obj, "ipAddress", ip)) continue;
        json::GetNumber(obj, "abuseConfidenceScore", score);
        json::GetNumber(obj, "numReports", reports);
        json::GetString(obj, "mostRecentReport", last);
        ThreatInfo t;
        t.abuseScore   = (int)score;
        t.totalReports = (int)reports;
        t.lastReport   = ParseIsoDate(last);
        out[ip] = t;
    }
}

void ParseSingleCheck(const std::string& body, ThreatInfo& t) {
    double score = 0, reports = 0;
    json::GetNumber(body, "abuseConfidenceScore", score);
    json::GetNumber(body, "totalReports", reports);
    std::string last, usage;
    json::GetString(body, "lastReportedAt", last);
    json::GetString(body, "usageType", usage);
    double tor = 0, white = 0;
    json::GetNumber(body, "isTor", tor);
    json::GetNumber(body, "isWhitelisted", white);
    t.abuseScore    = (int)score;
    t.totalReports  = (int)reports;
    t.lastReport    = ParseIsoDate(last);
    t.isTor         = tor > 0.5;
    t.isWhitelisted = white > 0.5;
}

bool FindVcardValue(const std::string& obj, const std::string& name, std::string& out) {
    std::string pat = "[\"" + name + "\",{},";
    size_t p = obj.find(pat);
    if (p == std::string::npos) return false;
    const char* t = "\"text\",\"";
    size_t q = obj.find(t, p);
    if (q == std::string::npos) return false;
    q += strlen(t);
    size_t e = obj.find('"', q);
    if (e == std::string::npos) return false;
    out = obj.substr(q, e - q);
    return true;
}

void ParseRdapEntities(const std::string& body, std::wstring& org, std::wstring& abuseMail) {
    size_t p = body.find("\"entities\"");
    if (p == std::string::npos) return;
    p = body.find('[', p);
    if (p == std::string::npos) return;
    int depth = 0;
    size_t q = p;
    for (; q < body.size(); ++q) {
        if (body[q] == '[') depth++;
        else if (body[q] == ']') { depth--; if (!depth) break; }
    }
    if (q >= body.size()) return;
    std::string arr = body.substr(p, q - p + 1);
    for (const auto& obj : json::SplitObjects(arr)) {
        size_t rp = obj.find("\"roles\"");
        bool isAbuse = false;
        if (rp != std::string::npos) {
            size_t rb = obj.find(']', rp);
            isAbuse = obj.find("\"abuse\"", rp) != std::string::npos &&
                      (rb == std::string::npos || obj.find("\"abuse\"", rp) < rb);
        }
        std::string fn;
        if (org.empty() && FindVcardValue(obj, "fn", fn)) org = Widen(fn);
        if (isAbuse && abuseMail.empty() && FindVcardValue(obj, "email", fn))
            abuseMail = Widen(fn);
    }
}

unsigned long long ParseRegistrationDate(const std::string& body) {
    size_t p = body.find("\"eventAction\":\"registration\"");
    if (p == std::string::npos) return 0;
    size_t q = body.find("\"eventDate\":\"", p);
    if (q == std::string::npos) return 0;
    q += 13;
    size_t e = body.find('"', q);
    if (e == std::string::npos) return 0;
    return ParseIsoDate(body.substr(q, e - q));
}

http::Response HttpFollow(const std::string& method, std::string url, const std::string& body,
                          const std::wstring& extraHeaders, int timeoutMs) {
    for (int i = 0; i < 4; ++i) {
        http::Response r = http::Request(method, url, body, "application/json", "", timeoutMs, extraHeaders);
        if (r.ok || r.location.empty()) return r;
        url = Narrow(r.location);
    }
    http::Response r;
    r.error = "yonlendirme dongusu";
    return r;
}

void ParseVtResponse(const std::string& body, ThreatInfo& t) {

    size_t p = body.find("\"last_analysis_stats\"");
    if (p != std::string::npos) {
        p = body.find('{', p);
        if (p != std::string::npos) {
            int depth = 0;
            size_t q = p;
            for (; q < body.size(); ++q) {
                if (body[q] == '{') depth++;
                else if (body[q] == '}') { depth--; if (!depth) break; }
            }
            if (q < body.size()) {
                std::string stats = body.substr(p, q - p + 1);
                double mal = 0, susp = 0, harm = 0, undet = 0, timeout = 0;
                json::GetNumber(stats, "malicious", mal);
                json::GetNumber(stats, "suspicious", susp);
                json::GetNumber(stats, "harmless", harm);
                json::GetNumber(stats, "undetected", undet);
                json::GetNumber(stats, "timeout", timeout);
                t.vtMalicious  = (int)mal;
                t.vtSuspicious = (int)susp;
                t.vtTotal      = (int)(mal + susp + harm + undet + timeout);
            }
        }
    }
    double rep = 0;
    json::GetNumber(body, "reputation", rep);
    t.vtReputation = (int)rep;
    p = body.find("\"last_analysis_date\"");
    if (p != std::string::npos) {
        p = body.find(':', p);
        if (p != std::string::npos) {
            std::string num;
            for (size_t i = p + 1; i < body.size() && (body[i] == ' ' || (body[i] >= '0' && body[i] <= '9')); ++i)
                num += body[i];
            t.vtDate = _strtoui64(num.c_str(), nullptr, 10);
        }
    }
}

std::string Sanitize(const std::wstring& s) {
    std::string r = Narrow(s);
    for (auto& ch : r)
        if (ch == '\t' || ch == '\r' || ch == '\n') ch = ' ';
    return r;
}

std::string ToSlash24(const std::string& ip) {
    unsigned a = 0, b = 0, c = 0, d = 0;
    if (sscanf(ip.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return "";
    char buf[64];
    sprintf_s(buf, "%u.%u.%u.0/24", a, b, c);
    return buf;
}

const unsigned long long kCacheTtlSec = 7ull * 24 * 3600;
const unsigned long long kRevalidateSec = 24ull * 3600;

}

std::wstring ThreatResolver::CachePath() const {
    return AppDataDir() + L"\\threat_cache.tsv";
}

ThreatResolver::ThreatResolver()  { LoadCache(); }
ThreatResolver::~ThreatResolver() { Stop(); }

void ThreatResolver::Start() {
    m_stop = false;
    m_tDnsbl = std::thread(&ThreatResolver::DnsblWorker, this);
    m_tAbuse = std::thread(&ThreatResolver::AbuseWorker, this);
    m_tPdns  = std::thread(&ThreatResolver::PdnsWorker, this);
    m_tRdap  = std::thread(&ThreatResolver::RdapWorker, this);
    m_tVt    = std::thread(&ThreatResolver::VtWorker, this);
    m_tPlug  = std::thread(&ThreatResolver::PlugWorker, this);
}

void ThreatResolver::Stop() {
    m_stop = true;
    m_cv.notify_all();
    if (m_tDnsbl.joinable()) m_tDnsbl.join();
    if (m_tAbuse.joinable()) m_tAbuse.join();
    if (m_tPdns.joinable())  m_tPdns.join();
    if (m_tRdap.joinable())  m_tRdap.join();
    if (m_tVt.joinable())    m_tVt.join();
    if (m_tPlug.joinable())  m_tPlug.join();
    SaveCache();
}

void ThreatResolver::SetOnline(bool on) {
    const bool was = m_online.exchange(on);
    if (!on || was) return;

    std::lock_guard<std::mutex> lk(m_mtx);
    for (auto& kv : m_cache) {
        Entry& e = kv.second;
        if (e.info.resolved && !e.info.failed) continue;
        e.info.failed = false;
        EnqueueLocked(kv.first, e);
    }
}
void ThreatResolver::SetRdapOnline(bool on) { m_rdapOnline = on; }

void ThreatResolver::SetAbuseKey(const std::wstring& key) {
    std::lock_guard<std::mutex> lk(m_mtx);
    m_abuseKey = key;
}

void ThreatResolver::SetVtKey(const std::wstring& key) {
    std::lock_guard<std::mutex> lk(m_mtx);
    m_vtKey = key;
}

void ThreatResolver::EnqueueLocked(const std::wstring& ip, Entry& e) {
    if (!e.queuedD) { e.queuedD = true; m_qDnsbl.push_back(ip); }
    if (!e.queuedA) { e.queuedA = true; m_qAbuse.push_back(ip); }
    if (!e.queuedP) { e.queuedP = true; m_qPdns.push_back(ip); }
    if (m_rdapOnline && !e.queuedR) { e.queuedR = true; m_qRdap.push_back(ip); }
    if (!e.queuedV) { e.queuedV = true; m_qVt.push_back(ip); }
    if (!e.queuedG && PluginsCount() > 0) { e.queuedG = true; m_qPlug.push_back(ip); }
    m_cv.notify_all();
}

void ThreatResolver::TouchResolvedLocked(const std::wstring& ip) {
    auto it = m_cache.find(ip);
    if (it == m_cache.end()) return;
    Entry& e = it->second;
    if (!e.queuedD && !e.queuedA && !e.queuedP && !e.queuedR && !e.queuedV && !e.queuedG) {
        e.info.resolved = true;
        e.info.ts       = (unsigned long long)time(nullptr);
    }
}

bool ThreatResolver::Get(const std::wstring& ip, ThreatInfo& out, bool enqueue) {
    std::lock_guard<std::mutex> lk(m_mtx);
    auto it = m_cache.find(ip);
    if (it != m_cache.end()) {
        Entry& e = it->second;
        const unsigned long long now = (unsigned long long)time(nullptr);
        if (e.info.resolved && e.info.ts && now - e.info.ts > kRevalidateSec) {

            e.info = ThreatInfo{};
            if (enqueue && m_online) EnqueueLocked(ip, e);
        } else if (enqueue && m_online && !e.info.resolved &&
                   !e.queuedD && !e.queuedA && !e.queuedP &&
                   !e.queuedR && !e.queuedV && !e.queuedG) {

            EnqueueLocked(ip, e);
        }
        out = e.info;
        return true;
    }
    if (!enqueue) return false;
    Entry e;
    if (m_online) EnqueueLocked(ip, e);
    m_cache.emplace(ip, e);
    out = e.info;
    return true;
}

void ThreatResolver::Invalidate(const std::wstring& ip) {
    std::lock_guard<std::mutex> lk(m_mtx);
    auto it = m_cache.find(ip);
    if (it == m_cache.end()) {
        Entry e;
        if (m_online) EnqueueLocked(ip, e);
        m_cache.emplace(ip, e);
        return;
    }
    Entry& e = it->second;
    if (e.queuedD || e.queuedA || e.queuedP) return;
    e.info = ThreatInfo{};
    if (m_online) EnqueueLocked(ip, e);
}

size_t ThreatResolver::PendingCount() {
    std::lock_guard<std::mutex> lk(m_mtx);
    size_t n = 0;
    for (const auto& kv : m_cache)
        if (kv.second.queuedD || kv.second.queuedA || kv.second.queuedP ||
            kv.second.queuedR || kv.second.queuedV) ++n;
    return n;
}

size_t ThreatResolver::CacheCount() {
    std::lock_guard<std::mutex> lk(m_mtx);
    return m_cache.size();
}

void ThreatResolver::LoadCache() {
    std::wstring path = CachePath();
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    const DWORD cap = 8u * 1024 * 1024;
    std::string data;
    data.resize(cap);
    DWORD got = 0;
    BOOL ok = ReadFile(h, &data[0], cap, &got, nullptr);
    CloseHandle(h);
    if (!ok || !got) return;
    data.resize(got);

    std::lock_guard<std::mutex> lk(m_mtx);
    size_t p = 0;
    while (p < data.size()) {
        size_t e = data.find('\n', p);
        if (e == std::string::npos) e = data.size();
        std::string line = data.substr(p, e - p);
        p = e + 1;
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
        if (line.empty()) continue;

        std::vector<std::string> f;
        size_t a = 0;
        while (a <= line.size()) {
            size_t t = line.find('\t', a);
            f.push_back(line.substr(a, t == std::string::npos ? std::string::npos : t - a));
            if (t == std::string::npos) break;
            a = t + 1;
        }
        if (f.size() < 10) continue;
        Entry en;
        en.info.abuseScore    = atoi(f[1].c_str());
        en.info.totalReports  = atoi(f[2].c_str());
        en.info.lastReport    = _strtoui64(f[3].c_str(), nullptr, 10);
        en.info.isTor         = atoi(f[4].c_str()) != 0;
        en.info.isWhitelisted = atoi(f[5].c_str()) != 0;
        en.info.dnsbl         = Widen(f[6]);
        en.info.passiveDns    = atoi(f[7].c_str());
        en.info.pdnsNames     = Widen(f[8]);
        en.info.ts            = _strtoui64(f[9].c_str(), nullptr, 10);

        if (f.size() >= 20) {
            en.info.rdapName       = Widen(f[10]);
            en.info.rdapOrg        = Widen(f[11]);
            en.info.rdapAbuse      = Widen(f[12]);
            en.info.rdapCidr       = Widen(f[13]);
            en.info.rdapRegistered = _strtoui64(f[14].c_str(), nullptr, 10);
            en.info.vtMalicious    = atoi(f[15].c_str());
            en.info.vtSuspicious   = atoi(f[16].c_str());
            en.info.vtTotal        = atoi(f[17].c_str());
            en.info.vtReputation   = atoi(f[18].c_str());
            en.info.vtDate         = _strtoui64(f[19].c_str(), nullptr, 10);
        }
        en.info.resolved      = true;
        m_cache[Widen(f[0])] = en;
    }
}

void ThreatResolver::SaveCache() {
    std::lock_guard<std::mutex> lk(m_mtx);
    if (m_cache.empty()) return;
    std::wstring path = CachePath();
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;

    const unsigned long long now = (unsigned long long)time(nullptr);
    for (const auto& kv : m_cache) {
        const ThreatInfo& t = kv.second.info;
        if (!t.resolved || !t.ts || now - t.ts > kCacheTtlSec) continue;
        std::string line = Narrow(kv.first) + "\t" +
                           std::to_string(t.abuseScore) + "\t" +
                           std::to_string(t.totalReports) + "\t" +
                           std::to_string(t.lastReport) + "\t" +
                           (t.isTor ? "1" : "0") + "\t" +
                           (t.isWhitelisted ? "1" : "0") + "\t" +
                           Sanitize(t.dnsbl) + "\t" +
                           std::to_string(t.passiveDns) + "\t" +
                           Sanitize(t.pdnsNames) + "\t" +
                           std::to_string(t.ts) + "\t" +
                           Sanitize(t.rdapName) + "\t" +
                           Sanitize(t.rdapOrg) + "\t" +
                           Sanitize(t.rdapAbuse) + "\t" +
                           Sanitize(t.rdapCidr) + "\t" +
                           std::to_string(t.rdapRegistered) + "\t" +
                           std::to_string(t.vtMalicious) + "\t" +
                           std::to_string(t.vtSuspicious) + "\t" +
                           std::to_string(t.vtTotal) + "\t" +
                           std::to_string(t.vtReputation) + "\t" +
                           std::to_string(t.vtDate) + "\r\n";
        DWORD wr = 0;
        WriteFile(h, line.data(), (DWORD)line.size(), &wr, nullptr);
    }
    CloseHandle(h);
}

void ThreatResolver::DnsblWorker() {
    static const DnsblZone kZones[] = {
        { L"SBL/XBL",        "sbl-xbl.spamhaus.org" },
        { L"Blocklist.de",   "bl.blocklist.de" },
        { L"Sorbs",          "spam.dnsbl.sorbs.net" },
        { L"Barracuda",      "b.barracudacentral.org" },
        { L"UCEPROTECT",     "dnsbl-1.uceprotect.net" },
    };

    for (;;) {
        std::wstring ip;
        {
            std::unique_lock<std::mutex> lk(m_mtx);
            m_cv.wait_for(lk, std::chrono::milliseconds(500), [&] {
                return m_stop.load() || !m_qDnsbl.empty();
            });
            if (m_stop.load()) return;
            if (m_qDnsbl.empty()) continue;
            ip = m_qDnsbl.front();
            m_qDnsbl.pop_front();
            auto it = m_cache.find(ip);
            if (it != m_cache.end()) it->second.queuedD = false;
        }

        std::wstring hits;
        const std::string rev = ReverseIp4(Narrow(ip));
        if (!rev.empty()) {
            for (const auto& z : kZones) {
                if (m_stop.load()) return;
                if (DnsblHit(rev + "." + z.suffix)) {
                    if (!hits.empty()) hits += L", ";
                    hits += z.label;
                }
            }
        }

        {
            std::lock_guard<std::mutex> lk(m_mtx);
            auto it = m_cache.find(ip);
            if (it != m_cache.end()) {
                it->second.info.dnsbl = hits.empty() ? L"—" : hits;
                TouchResolvedLocked(ip);
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
}

void ThreatResolver::AbuseWorker() {
    for (;;) {
        std::wstring ip;
        {
            std::unique_lock<std::mutex> lk(m_mtx);
            m_cv.wait_for(lk, std::chrono::milliseconds(500), [&] {
                return m_stop.load() || !m_qAbuse.empty();
            });
            if (m_stop.load()) return;
            if (m_qAbuse.empty()) continue;
            ip = m_qAbuse.front();
            m_qAbuse.pop_front();
            auto it = m_cache.find(ip);
            if (it != m_cache.end()) it->second.queuedA = false;
        }

        std::wstring key;
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            key = m_abuseKey;
        }

        if (key.empty()) {
            std::lock_guard<std::mutex> lk(m_mtx);
            TouchResolvedLocked(ip);
            std::this_thread::sleep_for(std::chrono::milliseconds(30));
            continue;
        }

        std::vector<std::wstring> batch;
        batch.push_back(ip);
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            const std::string net = ToSlash24(Narrow(ip));
            std::unordered_set<std::wstring> picked;
            for (auto it = m_qAbuse.begin(); it != m_qAbuse.end() && batch.size() < 16;) {
                if (!net.empty() && ToSlash24(Narrow(*it)) == net) {
                    picked.insert(*it);
                    batch.push_back(*it);
                    it = m_qAbuse.erase(it);
                } else {
                    ++it;
                }
            }
            for (const auto& x : picked) {
                auto e = m_cache.find(x);
                if (e != m_cache.end()) e->second.queuedA = false;
            }
        }

        bool ok = false;
        {
            const std::string net = ToSlash24(Narrow(ip));
            const std::string body = "network=" + net + "&maxAgeInDays=30";
            std::wstring hdr = L"Key: " + key + L"\r\nAccept: application/json";
            http::Response r = http::Request("POST",
                "https://api.abuseipdb.com/api/v2/check-block",
                body, "application/x-www-form-urlencoded", "", 20000, hdr);
            if (r.ok) {
                std::unordered_map<std::string, ThreatInfo> byIp;
                ParseBlockReports(r.body, byIp);
                std::lock_guard<std::mutex> lk(m_mtx);
                for (const auto& bip : batch) {
                    auto it = m_cache.find(bip);
                    if (it == m_cache.end()) continue;
                    auto hit = byIp.find(Narrow(bip));
                    if (hit != byIp.end()) it->second.info = hit->second;
                    else {

                        it->second.info.abuseScore   = 0;
                        it->second.info.totalReports = 0;
                    }
                    TouchResolvedLocked(bip);
                }
                ok = true;
            }
        }

        if (!ok) {

            for (const auto& bip : batch) {
                if (m_stop.load()) return;
                std::wstring hdr = L"Key: " + key + L"\r\nAccept: application/json";
                http::Response r = http::Request("GET",
                    "https://api.abuseipdb.com/api/v2/check?ipAddress=" + Narrow(bip) +
                    "&maxAgeInDays=90&verbose",
                    "", "application/json", "", 20000, hdr);
                if (r.ok) {
                    ThreatInfo t;
                    ParseSingleCheck(r.body, t);
                    std::lock_guard<std::mutex> lk(m_mtx);
                    auto it = m_cache.find(bip);
                    if (it != m_cache.end()) it->second.info = t;
                    TouchResolvedLocked(bip);
                } else {
                    std::lock_guard<std::mutex> lk(m_mtx);
                    auto it = m_cache.find(bip);
                    if (it != m_cache.end()) {
                        it->second.info.failed = true;
                        TouchResolvedLocked(bip);
                    }
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(1500));
            }
            continue;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    }
}

void ThreatResolver::RdapWorker() {
    for (;;) {
        std::wstring ip;
        {
            std::unique_lock<std::mutex> lk(m_mtx);
            m_cv.wait_for(lk, std::chrono::milliseconds(500), [&] {
                return m_stop.load() || !m_qRdap.empty();
            });
            if (m_stop.load()) return;
            if (m_qRdap.empty()) continue;
            ip = m_qRdap.front();
            m_qRdap.pop_front();
            auto it = m_cache.find(ip);
            if (it != m_cache.end()) it->second.queuedR = false;
        }

        {
            http::Response r = HttpFollow("GET", "https://rdap.org/ip/" + Narrow(ip),
                                          "", L"Accept: application/json", 20000);
            if (r.ok && !r.body.empty()) {
                ThreatInfo t;
                std::string name, cidr;
                json::GetString(r.body, "name", name);
                t.rdapName = Widen(name);
                ParseRdapEntities(r.body, t.rdapOrg, t.rdapAbuse);
                t.rdapRegistered = ParseRegistrationDate(r.body);

                size_t p = r.body.find("\"cidr0_cidrs\"");
                if (p != std::string::npos) {
                    p = r.body.find('{', p);
                    if (p != std::string::npos) {
                        std::string one;
                        std::string pref;
                        double len = 0;
                        size_t e = r.body.find('}', p);
                        if (e != std::string::npos) one = r.body.substr(p, e - p + 1);
                        json::GetString(one, "v4prefix", pref);
                        json::GetNumber(one, "length", len);
                        if (!pref.empty()) {
                            t.rdapCidr = Widen(pref);
                            if (len > 0) t.rdapCidr += L"/" + std::to_wstring((int)len);
                        }
                    }
                } else {
                    std::string start;
                    json::GetString(r.body, "startAddress", start);
                    t.rdapCidr = Widen(start);
                }
                std::lock_guard<std::mutex> lk(m_mtx);
                auto it = m_cache.find(ip);
                if (it != m_cache.end()) {
                    it->second.info.rdapName       = t.rdapName;
                    it->second.info.rdapOrg        = t.rdapOrg;
                    it->second.info.rdapAbuse      = t.rdapAbuse;
                    it->second.info.rdapCidr       = t.rdapCidr;
                    it->second.info.rdapRegistered = t.rdapRegistered;
                }
            }
        }

        {
            std::lock_guard<std::mutex> lk(m_mtx);
            TouchResolvedLocked(ip);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    }
}

void ThreatResolver::VtWorker() {
    for (;;) {
        std::wstring ip;
        {
            std::unique_lock<std::mutex> lk(m_mtx);
            m_cv.wait_for(lk, std::chrono::milliseconds(500), [&] {
                return m_stop.load() || !m_qVt.empty();
            });
            if (m_stop.load()) return;
            if (m_qVt.empty()) continue;
            ip = m_qVt.front();
            m_qVt.pop_front();
            auto it = m_cache.find(ip);
            if (it != m_cache.end()) it->second.queuedV = false;
        }

        std::wstring key;
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            key = m_vtKey;
        }

        if (key.empty()) {

            std::lock_guard<std::mutex> lk(m_mtx);
            TouchResolvedLocked(ip);
            std::this_thread::sleep_for(std::chrono::milliseconds(30));
            continue;
        }

        {
            std::wstring hdr = L"x-apikey: " + key + L"\r\nAccept: application/json";
            http::Response r = http::Request("GET",
                "https://www.virustotal.com/api/v3/ip_addresses/" + Narrow(ip),
                "", "application/json", "", 20000, hdr);
            if (r.ok && !r.body.empty()) {
                ThreatInfo t;
                ParseVtResponse(r.body, t);
                std::lock_guard<std::mutex> lk(m_mtx);
                auto it = m_cache.find(ip);
                if (it != m_cache.end()) {
                    it->second.info.vtMalicious  = t.vtMalicious;
                    it->second.info.vtSuspicious = t.vtSuspicious;
                    it->second.info.vtTotal      = t.vtTotal;
                    it->second.info.vtReputation = t.vtReputation;
                    it->second.info.vtDate       = t.vtDate;
                }
            } else if (r.status == 401 || r.status == 403) {

                std::lock_guard<std::mutex> lk(m_mtx);
                m_vtKey.clear();
            }
        }

        {
            std::lock_guard<std::mutex> lk(m_mtx);
            TouchResolvedLocked(ip);
        }

        for (int i = 0; i < 16 && !m_stop.load(); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
}

void ThreatResolver::PlugWorker() {
    for (;;) {
        std::wstring ip;
        {
            std::unique_lock<std::mutex> lk(m_mtx);
            m_cv.wait_for(lk, std::chrono::milliseconds(500), [&] {
                return m_stop.load() || !m_qPlug.empty();
            });
            if (m_stop.load()) return;
            if (m_qPlug.empty()) continue;
            ip = m_qPlug.front();
            m_qPlug.pop_front();
            auto it = m_cache.find(ip);
            if (it != m_cache.end()) it->second.queuedG = false;
        }

        std::vector<PluginResult> results = PluginsRun(ip);
        if (!results.empty()) {
            int best = -1;
            std::wstring verdict, note;
            for (const auto& r : results) {
                if (r.risk > best) {
                    best = r.risk;
                    verdict = r.verdict;
                    note = r.note;
                }
            }
            std::lock_guard<std::mutex> lk(m_mtx);
            auto it = m_cache.find(ip);
            if (it != m_cache.end()) {
                it->second.info.pluginRisk = best;
                it->second.info.pluginVerdict = verdict;
                it->second.info.pluginNote = note;
                TouchResolvedLocked(ip);
            }
        } else {
            std::lock_guard<std::mutex> lk(m_mtx);
            TouchResolvedLocked(ip);
        }
    }
}

void ThreatResolver::PdnsWorker() {
    for (;;) {
        std::wstring ip;
        {
            std::unique_lock<std::mutex> lk(m_mtx);
            m_cv.wait_for(lk, std::chrono::milliseconds(500), [&] {
                return m_stop.load() || !m_qPdns.empty();
            });
            if (m_stop.load()) return;
            if (m_qPdns.empty()) continue;
            ip = m_qPdns.front();
            m_qPdns.pop_front();
            auto it = m_cache.find(ip);
            if (it != m_cache.end()) it->second.queuedP = false;
        }

        int count = 0;
        std::wstring names;
        {
            http::Response r = http::Request("GET",
                "https://cve.circl.lu/pdns/query/" + Narrow(ip),
                "", "application/json", "", 20000);
            if (r.ok && !r.body.empty()) {
                std::vector<std::string> objs = json::SplitObjects(r.body);
                count = (int)objs.size();
                if (count > 5000) count = 5000;

                std::vector<std::pair<unsigned long long, std::string>> recs;
                std::unordered_map<std::string, unsigned long long> best;
                for (const auto& o : objs) {
                    std::string rrname, last;
                    if (!json::GetString(o, "rrname", rrname)) continue;
                    if (rrname.empty()) continue;
                    json::GetString(o, "time_last", last);
                    unsigned long long t = ParseIsoDate(last);
                    if (t > best[rrname]) best[rrname] = t;
                }
                std::vector<std::pair<unsigned long long, std::string>> ranked;
                for (const auto& kv : best) ranked.push_back({ kv.second, kv.first });
                std::sort(ranked.begin(), ranked.end(),
                          [](const auto& a, const auto& b) { return a.first > b.first; });
                std::wstring joined;
                for (size_t i = 0; i < ranked.size() && i < 3; ++i) {
                    if (i) joined += L", ";
                    joined += Widen(ranked[i].second);
                }
                names = joined;
            }
        }

        {
            std::lock_guard<std::mutex> lk(m_mtx);
            auto it = m_cache.find(ip);
            if (it != m_cache.end()) {
                it->second.info.passiveDns = count;
                it->second.info.pdnsNames  = names;
                it->second.info.failed     = (count == 0 && names.empty());
                TouchResolvedLocked(ip);
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    }
}
