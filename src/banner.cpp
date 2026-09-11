#include "banner.h"
#include "i18n.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <vector>

using namespace nl;

namespace {

const unsigned long long kTtlSec = 7ull * 24 * 3600;
const unsigned long long kRevalidateSec = 24ull * 3600;

SOCKET TcpConnectTimeout(const std::wstring& ip, int port, int timeoutMs) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons((u_short)port);
    if (InetPtonA(AF_INET, Narrow(ip).c_str(), &sa.sin_addr) != 1) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    u_long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);
    int rc = connect(s, (sockaddr*)&sa, sizeof(sa));
    if (rc == SOCKET_ERROR) {
        if (WSAGetLastError() != WSAEWOULDBLOCK) {
            closesocket(s);
            return INVALID_SOCKET;
        }
        fd_set w;
        FD_ZERO(&w);
        FD_SET(s, &w);
        timeval tv;
        tv.tv_sec  = timeoutMs / 1000;
        tv.tv_usec = (timeoutMs % 1000) * 1000;
        if (select(0, nullptr, &w, nullptr, &tv) <= 0) {
            closesocket(s);
            return INVALID_SOCKET;
        }
        int err = 0;
        int elen = sizeof(err);
        getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&err, &elen);
        if (err != 0) {
            closesocket(s);
            return INVALID_SOCKET;
        }
    }
    u_long blk = 0;
    ioctlsocket(s, FIONBIO, &blk);
    return s;
}

bool FetchBanner(const std::wstring& ip, int port, BannerInfo& out, int timeoutMs) {
    out = BannerInfo{};
    SOCKET s = TcpConnectTimeout(ip, port, (std::min)(timeoutMs, 4000));
    if (s == INVALID_SOCKET) {
        out.error = Tr(L"TCP connection failed");
        return false;
    }

    std::wstring ipHeader = ip.find(L':') != std::wstring::npos ? (L"[" + ip + L"]") : ip;
    std::wstring req = L"HEAD / HTTP/1.1\r\nHost: " + ipHeader + L":" + std::to_wstring(port) +
                       L"\r\nConnection: close\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
                       L"Accept: */*\r\n\r\n";
    std::string reqA = Narrow(req);
    int sent = send(s, reqA.data(), (int)reqA.size(), 0);
    if (sent != (int)reqA.size()) {
        closesocket(s);
        out.error = Tr(L"could not send the request");
        return false;
    }

    std::string buf;
    buf.reserve(8192);
    const unsigned long long deadline = (unsigned long long)time(nullptr) * 1000ull + timeoutMs;
    for (;;) {
        unsigned long long now = (unsigned long long)time(nullptr) * 1000ull;
        if (now >= deadline) break;
        int remain = (int)(deadline - now);
        fd_set r;
        FD_ZERO(&r);
        FD_SET(s, &r);
        timeval tv;
        tv.tv_sec  = remain / 1000;
        tv.tv_usec = (remain % 1000) * 1000;
        int sel = select(0, &r, nullptr, nullptr, &tv);
        if (sel <= 0) break;
        char tmp[2048];
        int got = recv(s, tmp, sizeof(tmp), 0);
        if (got <= 0) break;
        buf.append(tmp, got);
        if (buf.size() > 8192 || buf.find("\r\n\r\n") != std::string::npos) break;
    }
    closesocket(s);

    if (buf.empty()) {
        out.error = Tr(L"no response (not an HTTP service?)");
        return false;
    }

    size_t eol = buf.find("\r\n");
    if (eol == std::string::npos) eol = buf.find('\n');
    out.status = Widen(buf.substr(0, eol == std::string::npos ? buf.size() : eol));
    if (out.status.size() > 80) out.status = out.status.substr(0, 80);

    std::wstring lower = ToLower(Widen(buf));
    auto hdr = [&](const std::wstring& name) -> std::wstring {
        size_t p = lower.find(name + L":");
        if (p == std::wstring::npos) return L"";
        size_t s = p + name.size() + 1;
        size_t e = lower.find(L"\r\n", s);
        if (e == std::wstring::npos) e = lower.size();
        std::wstring v = Trim(Widen(buf).substr(s, e - s));
        return v.size() > 120 ? v.substr(0, 120) : v;
    };
    out.server      = hdr(L"server");
    out.powered     = hdr(L"x-powered-by");
    out.contentType = hdr(L"content-type");

    out.ok = true;
    return true;
}

}

std::wstring BannerResolver::CachePath() const {
    return AppDataDir() + L"\\banner_cache.tsv";
}

BannerResolver::BannerResolver()  { LoadCache(); }
BannerResolver::~BannerResolver() { Stop(); }

void BannerResolver::Start() {
    m_stop = false;
    m_worker = std::thread(&BannerResolver::Worker, this);
}

void BannerResolver::Stop() {
    m_stop = true;
    m_cv.notify_all();
    if (m_worker.joinable()) m_worker.join();
    SaveCache();
}

void BannerResolver::SetOnline(bool on) { m_online = on; }

bool BannerResolver::Get(const std::wstring& ipPort, BannerInfo& out, bool enqueue) {
    std::lock_guard<std::mutex> lk(m_mtx);
    auto it = m_cache.find(ipPort);
    if (it != m_cache.end()) {
        const unsigned long long now = (unsigned long long)time(nullptr);
        if (m_online && enqueue && !it->second.queued && it->second.info.ts &&
            now > it->second.info.ts && now - it->second.info.ts > kRevalidateSec) {
            it->second.queued = true;
            m_q.push_back(ipPort);
            m_cv.notify_all();
        }
        out = it->second.info;
        return true;
    }
    if (!enqueue) return false;
    Entry e;
    if (m_online) { e.queued = true; m_q.push_back(ipPort); m_cv.notify_all(); }
    m_cache.emplace(ipPort, e);
    out = e.info;
    return true;
}

void BannerResolver::Invalidate(const std::wstring& ipPort) {
    std::lock_guard<std::mutex> lk(m_mtx);
    auto it = m_cache.find(ipPort);
    if (it == m_cache.end()) {
        Entry e;
        if (m_online) { e.queued = true; m_q.push_back(ipPort); m_cv.notify_all(); }
        m_cache.emplace(ipPort, e);
        return;
    }
    if (it->second.queued) return;
    it->second.info = BannerInfo{};
    if (m_online) { it->second.queued = true; m_q.push_back(ipPort); m_cv.notify_all(); }
}

size_t BannerResolver::PendingCount() {
    std::lock_guard<std::mutex> lk(m_mtx);
    return m_q.size();
}

void BannerResolver::LoadCache() {
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
        if (f.size() < 7) continue;
        Entry en;
        en.info.ok          = atoi(f[1].c_str()) != 0;
        en.info.status      = Widen(f[2]);
        en.info.server      = Widen(f[3]);
        en.info.powered     = Widen(f[4]);
        en.info.contentType = Widen(f[5]);
        en.info.ts          = _strtoui64(f[6].c_str(), nullptr, 10);
        en.info.resolved    = true;
        m_cache[Widen(f[0])] = en;
    }
}

void BannerResolver::SaveCache() {
    std::lock_guard<std::mutex> lk(m_mtx);
    if (m_cache.empty()) return;
    std::wstring path = CachePath();
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;

    const unsigned long long now = (unsigned long long)time(nullptr);
    for (const auto& kv : m_cache) {
        const BannerInfo& t = kv.second.info;
        if (!t.resolved || !t.ts || now - t.ts > kTtlSec) continue;
        std::string line = Narrow(kv.first) + "\t" +
                           (t.ok ? "1" : "0") + "\t" +
                           Narrow(t.status) + "\t" + Narrow(t.server) + "\t" +
                           Narrow(t.powered) + "\t" + Narrow(t.contentType) + "\t" +
                           std::to_string(t.ts) + "\r\n";
        DWORD wr = 0;
        WriteFile(h, line.data(), (DWORD)line.size(), &wr, nullptr);
    }
    CloseHandle(h);
}

void BannerResolver::Worker() {
    for (;;) {
        std::wstring key;
        {
            std::unique_lock<std::mutex> lk(m_mtx);
            m_cv.wait_for(lk, std::chrono::milliseconds(500), [&] {
                return m_stop.load() || !m_q.empty();
            });
            if (m_stop.load()) return;
            if (m_q.empty()) continue;
            key = m_q.front();
            m_q.pop_front();
            auto it = m_cache.find(key);
            if (it != m_cache.end()) it->second.queued = false;
        }

        size_t c = key.find_last_of(L':');
        if (c == std::wstring::npos || c == 0 || c + 1 >= key.size()) continue;
        std::wstring ip = key.substr(0, c);
        int port = _wtoi(key.substr(c + 1).c_str());
        if (port <= 0 || port > 65535) port = 80;

        BannerInfo bi;
        FetchBanner(ip, port, bi, 6000);
        if (m_stop.load()) return;

        {
            std::lock_guard<std::mutex> lk(m_mtx);
            auto it = m_cache.find(key);
            if (it != m_cache.end()) {
                it->second.info = bi;
                it->second.info.resolved = true;
                it->second.info.ts = (unsigned long long)time(nullptr);
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(400));
    }
}

namespace nl {
bool BannerIsEol(const std::wstring& server) {
    if (server.empty()) return false;
    const std::wstring s = ToLower(server);
    static const wchar_t* eol[] = {
        L"microsoft-iis/5", L"microsoft-iis/6", L"microsoft-iis/7.0", L"microsoft-iis/7.5",
        L"apache/1.", L"apache/2.0", L"apache/2.2",
        L"nginx/0.", L"nginx/1.0", L"nginx/1.2", L"nginx/1.4", L"nginx/1.6", L"nginx/1.8",
        L"openssl/0.9", L"openssl/1.0.0", L"openssl/1.0.1",
        L"php/5.", L"php/7.0", L"php/7.1", L"php/7.2", L"php/7.3", L"php/7.4",
        L"lighttpd/1.4.2", L"tomcat/4", L"tomcat/5", L"tomcat/6", L"tomcat/7",
        L"jboss", L"resin/3", L"coyote/1.0",
    };
    for (const wchar_t* t : eol)
        if (s.find(t) != std::wstring::npos) return true;
    return false;
}

}
