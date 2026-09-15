#include "threat.h"
#include "evidence_rules.h"
#include "provider_evidence.h"
#include "iso_date.h"
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

unsigned long long ParseIsoDate(const std::string& s) { return IsoEpoch(s); }

struct DnsblZone { const wchar_t* label; const char* suffix; };

std::string ReverseIp4(const std::string& ip) {
    unsigned a = 0, b = 0, c = 0, d = 0;
    if (sscanf(ip.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return "";
    if (a > 255 || b > 255 || c > 255 || d > 255) return "";
    char buf[64];
    sprintf_s(buf, "%u.%u.%u.%u", d, c, b, a);
    return buf;
}

bool DnsblHit(const std::string& queryName, bool spamhaus, bool& incomplete) {
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(queryName.c_str(), nullptr, &hints, &res) != 0) {
        // getaddrinfo does not expose an authoritative DNS RCODE. Do not claim clean.
        incomplete = true;
        return false;
    }
    bool hit = false;
    for (auto* ai = res; ai; ai = ai->ai_next) {
        if (ai->ai_family != AF_INET || !ai->ai_addr) { incomplete = true; continue; }
        auto* sa = reinterpret_cast<sockaddr_in*>(ai->ai_addr);
        const auto bytes = reinterpret_cast<const unsigned char*>(&sa->sin_addr);
        if (DnsblListingCode(spamhaus, bytes[0], bytes[1], bytes[2], bytes[3])) hit = true;
        else incomplete = true;
    }
    if (!res) incomplete = true;
    freeaddrinfo(res);
    return hit;
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
    strictjson::Value root;
    if (!strictjson::Parse(body, root)) return 0;
    for (const auto& event : root.At("events").array)
        if (event.At("eventAction").text == "registration") return IsoEpoch(event.At("eventDate").text);
    return 0;
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

const unsigned long long kRevalidateSec = 24ull * 3600;

}

std::wstring ThreatResolver::CachePath() const {
    return AppDataDir() + L"\\threat_cache_v2.tsv";
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

void ThreatResolver::Configure(bool threat, bool rdap, const std::wstring& abuseKey, const std::wstring& vtKey) {
    std::lock_guard<std::mutex> lk(m_mtx);
    if (threat==m_sourcesOnline && rdap==m_rdapOnline && abuseKey==m_abuseKey && vtKey==m_vtKey) return;
    ++m_generation;
    m_sourcesOnline=threat; m_rdapOnline=rdap; m_abuseKey=abuseKey; m_vtKey=vtKey;
    m_online=threat || rdap || !vtKey.empty();
    m_qDnsbl.clear(); m_qAbuse.clear(); m_qPdns.clear(); m_qRdap.clear(); m_qVt.clear(); m_qPlug.clear();
    for (auto& pair : m_cache) {
        pair.second=Entry{};
        if (m_online) EnqueueLocked(pair.first,pair.second);
    }
    m_cv.notify_all();
}

void ThreatResolver::EnqueueLocked(const std::wstring& ip, Entry& e) {
    const auto plan = PlanSources(m_sourcesOnline, m_rdapOnline, !m_abuseKey.empty(), !m_vtKey.empty(), PluginsCount() > 0);
    if (plan.dnsbl && !e.queuedD) { e.queuedD = true; m_qDnsbl.push_back(ip); }
    if (plan.abuse && !e.queuedA) { e.queuedA = true; m_qAbuse.push_back(ip); }
    if (plan.pdns && !e.queuedP) { e.queuedP = true; m_qPdns.push_back(ip); }
    if (plan.rdap && !e.queuedR) { e.queuedR = true; m_qRdap.push_back(ip); }
    if (plan.vt && !e.queuedV) { e.queuedV = true; m_qVt.push_back(ip); }
    if (plan.plugins && !e.queuedG) { e.queuedG = true; m_qPlug.push_back(ip); }
    TouchResolvedLocked(ip);
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
    if (e.queuedD || e.queuedA || e.queuedP || e.queuedR || e.queuedV || e.queuedG) return;
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

// Aggregate disk records cannot preserve provider identity/failure/configuration state.
// Never promote an old/corrupt record to live evidence. Independent live results remain in memory.
void ThreatResolver::LoadCache() { DeleteFileW(CachePath().c_str()); }
void ThreatResolver::SaveCache() { DeleteFileW(CachePath().c_str()); }

void ThreatResolver::DnsblWorker() {
    static const DnsblZone kZones[] = {
        { L"SBL/XBL",        "sbl-xbl.spamhaus.org" },
        { L"Blocklist.de",   "bl.blocklist.de" },
        { L"Barracuda",      "b.barracudacentral.org" },
        { L"UCEPROTECT",     "dnsbl-1.uceprotect.net" },
    };

    for (;;) {
        std::wstring ip;
        unsigned long long generation = 0;
        {
            std::unique_lock<std::mutex> lk(m_mtx);
            m_cv.wait_for(lk, std::chrono::milliseconds(500), [&] {
                return m_stop.load() || !m_qDnsbl.empty();
            });
            if (m_stop.load()) return;
            if (m_qDnsbl.empty()) continue;
            ip = m_qDnsbl.front();
            m_qDnsbl.pop_front();
            generation = m_generation;
            auto it = m_cache.find(ip);

        }

        std::wstring hits;
        bool incomplete = false;
        const std::string rev = ReverseIp4(Narrow(ip));
        if (rev.empty()) incomplete = true;
        if (!rev.empty()) {
            for (const auto& z : kZones) {
                if (m_stop.load()) return;
                if (generation != m_generation) break;
                if (DnsblHit(rev + "." + z.suffix, std::string(z.suffix) == "sbl-xbl.spamhaus.org", incomplete)) {
                    if (!hits.empty()) hits += L", ";
                    hits += z.label;
                }
            }
        }

        {
            std::lock_guard<std::mutex> lk(m_mtx);
            if (generation != m_generation) continue;
            auto it = m_cache.find(ip);
            if (it != m_cache.end()) {
                it->second.info.dnsbl = hits.empty() ? L"—" : hits;
                it->second.info.dnsblIncomplete = incomplete;
                if (auto completed = m_cache.find(ip); completed != m_cache.end()) completed->second.queuedD = false;
                TouchResolvedLocked(ip);
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
}

void ThreatResolver::AbuseWorker() {
    for (;;) {
        std::wstring ip, key;
        unsigned long long generation = 0;
        {
            std::unique_lock<std::mutex> lk(m_mtx);
            m_cv.wait_for(lk, std::chrono::milliseconds(500), [&] { return m_stop.load() || !m_qAbuse.empty(); });
            if (m_stop.load()) return;
            if (m_qAbuse.empty()) continue;
            ip=m_qAbuse.front(); m_qAbuse.pop_front(); key=m_abuseKey; generation=m_generation;
        }
        provider::Abuse parsed;
        bool valid=false;
        if (!key.empty()) {
            // check-block omissions do NOT prove an individual address has score zero.
            // Query only the requested IP and require its identity in the response.
            const auto r=http::Request("GET", "https://api.abuseipdb.com/api/v2/check?ipAddress="+Narrow(ip)+"&maxAgeInDays=90&verbose",
                "", "application/json", "", 20000, L"Key: "+key+L"\r\nAccept: application/json");
            valid=r.ok && provider::ReadAbuse(r.body,Narrow(ip),parsed);
        }
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            if (generation != m_generation) continue;
            auto it=m_cache.find(ip);
            if (it!=m_cache.end()) {
                if (valid && key==m_abuseKey) {
                    ThreatInfo value;
                    value.abuseScore=parsed.abuseScore; value.totalReports=parsed.totalReports;
                    value.isTor=parsed.isTor; value.isWhitelisted=parsed.isWhitelisted;
                    value.lastReport=ParseIsoDate(parsed.lastReport);
                    MergeAbuseEvidence(it->second.info,value);
                } else if (!key.empty()) it->second.info.failed=true;
                it->second.queuedA=false;
                TouchResolvedLocked(ip);
            }
        }
        for (int i=0; i<15 && !m_stop.load(); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void ThreatResolver::RdapWorker() {
    for (;;) {
        std::wstring ip;
        unsigned long long generation = 0;
        {
            std::unique_lock<std::mutex> lk(m_mtx);
            m_cv.wait_for(lk, std::chrono::milliseconds(500), [&] {
                return m_stop.load() || !m_qRdap.empty();
            });
            if (m_stop.load()) return;
            if (m_qRdap.empty()) continue;
            ip = m_qRdap.front();
            m_qRdap.pop_front();
            generation = m_generation;
            auto it = m_cache.find(ip);

        }

        {
            http::Response r = HttpFollow("GET", "https://rdap.org/ip/" + Narrow(ip),
                                          "", L"Accept: application/json", 20000);
            strictjson::Value root;
            if (r.ok && strictjson::Parse(r.body, root) && root.At("objectClassName").text == "ip network" &&
                !root.At("startAddress").text.empty() && !root.At("endAddress").text.empty()) {
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
            if (generation != m_generation) continue;
                auto it = m_cache.find(ip);
                if (it != m_cache.end()) {
                    it->second.info.rdapName       = t.rdapName;
                    it->second.info.rdapOrg        = t.rdapOrg;
                    it->second.info.rdapAbuse      = t.rdapAbuse;
                    it->second.info.rdapCidr       = t.rdapCidr;
                    it->second.info.rdapRegistered = t.rdapRegistered;
                }
            } else {
                std::lock_guard<std::mutex> lk(m_mtx);
            if (generation != m_generation) continue;
                auto it = m_cache.find(ip);
                if (it != m_cache.end()) it->second.info.failed = true;
            }
        }

        {
            std::lock_guard<std::mutex> lk(m_mtx);
            if (generation != m_generation) continue;
            if (auto completed = m_cache.find(ip); completed != m_cache.end()) completed->second.queuedR = false;
            TouchResolvedLocked(ip);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    }
}

void ThreatResolver::VtWorker() {
    for (;;) {
        std::wstring ip;
        unsigned long long generation = 0;
        {
            std::unique_lock<std::mutex> lk(m_mtx);
            m_cv.wait_for(lk, std::chrono::milliseconds(500), [&] {
                return m_stop.load() || !m_qVt.empty();
            });
            if (m_stop.load()) return;
            if (m_qVt.empty()) continue;
            ip = m_qVt.front();
            m_qVt.pop_front();
            generation = m_generation;
            auto it = m_cache.find(ip);

        }

        std::wstring key;
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            if (generation != m_generation) continue;
            key = m_vtKey;
        }

        if (key.empty()) {

            std::lock_guard<std::mutex> lk(m_mtx);
            if (generation != m_generation) continue;
            if (auto completed = m_cache.find(ip); completed != m_cache.end()) completed->second.queuedV = false;
            TouchResolvedLocked(ip);
            std::this_thread::sleep_for(std::chrono::milliseconds(30));
            continue;
        }

        {
            std::wstring hdr = L"x-apikey: " + key + L"\r\nAccept: application/json";
            http::Response r = http::Request("GET",
                "https://www.virustotal.com/api/v3/ip_addresses/" + Narrow(ip),
                "", "application/json", "", 20000, hdr);
            provider::VirusTotal parsed;
            const bool valid=r.ok && provider::ReadVt(r.body,Narrow(ip),parsed);
            std::lock_guard<std::mutex> lk(m_mtx);
            if (generation != m_generation) continue;
            auto it=m_cache.find(ip);
            if (it!=m_cache.end()) {
                if (valid && key==m_vtKey) {
                    it->second.info.vtMalicious=parsed.malicious;
                    it->second.info.vtSuspicious=parsed.suspicious;
                    it->second.info.vtTotal=parsed.total;
                    it->second.info.vtReputation=parsed.reputation;
                } else it->second.info.failed=true;
            }
            // Authentication failure is evidence of an unavailable provider, not a clean verdict.

        }

        {
            std::lock_guard<std::mutex> lk(m_mtx);
            if (generation != m_generation) continue;
            if (auto completed = m_cache.find(ip); completed != m_cache.end()) completed->second.queuedV = false;
            TouchResolvedLocked(ip);
        }

        for (int i = 0; i < 16 && !m_stop.load(); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
}

void ThreatResolver::PlugWorker() {
    for (;;) {
        std::wstring ip;
        unsigned long long generation = 0;
        {
            std::unique_lock<std::mutex> lk(m_mtx);
            m_cv.wait_for(lk, std::chrono::milliseconds(500), [&] {
                return m_stop.load() || !m_qPlug.empty();
            });
            if (m_stop.load()) return;
            if (m_qPlug.empty()) continue;
            ip = m_qPlug.front();
            m_qPlug.pop_front();
            generation = m_generation;
            auto it = m_cache.find(ip);

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
            if (generation != m_generation) continue;
            auto it = m_cache.find(ip);
            if (it != m_cache.end()) {
                it->second.info.pluginRisk = best;
                it->second.info.pluginVerdict = verdict;
                it->second.info.pluginNote = note;
                if (auto completed = m_cache.find(ip); completed != m_cache.end()) completed->second.queuedG = false;
                TouchResolvedLocked(ip);
            }
        } else {
            std::lock_guard<std::mutex> lk(m_mtx);
            if (generation != m_generation) continue;
            if (auto completed = m_cache.find(ip); completed != m_cache.end()) completed->second.queuedG = false;
            TouchResolvedLocked(ip);
        }
    }
}

void ThreatResolver::PdnsWorker() {
    for (;;) {
        std::wstring ip;
        unsigned long long generation = 0;
        {
            std::unique_lock<std::mutex> lk(m_mtx);
            m_cv.wait_for(lk, std::chrono::milliseconds(500), [&] {
                return m_stop.load() || !m_qPdns.empty();
            });
            if (m_stop.load()) return;
            if (m_qPdns.empty()) continue;
            ip = m_qPdns.front();
            m_qPdns.pop_front();
            generation = m_generation;
            auto it = m_cache.find(ip);

        }

        provider::PassiveDns parsed;
        const auto response=http::Request("GET", "https://cve.circl.lu/pdns/query/"+Narrow(ip), "", "application/json", "", 20000);
        const bool valid=response.ok && provider::ReadPdns(response.body,Narrow(ip),parsed);
        const int count=valid ? parsed.records : -1;
        std::wstring names;
        for (const auto& name : parsed.names) { if (!names.empty()) names+=L", "; names+=Widen(name); }

        {
            std::lock_guard<std::mutex> lk(m_mtx);
            if (generation != m_generation) continue;
            auto it = m_cache.find(ip);
            if (it != m_cache.end()) {
                it->second.info.passiveDns = count;
                it->second.info.pdnsNames  = names;
                it->second.info.failed     = it->second.info.failed || !valid;
                if (auto completed = m_cache.find(ip); completed != m_cache.end()) completed->second.queuedP = false;
                TouchResolvedLocked(ip);
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    }
}
