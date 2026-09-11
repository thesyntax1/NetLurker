#include "cert.h"
#include "i18n.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wincrypt.h>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <chrono>

#ifndef X509_ALT_NAME
#define X509_ALT_NAME ((LPCSTR) 9)
#endif

using namespace nl;

namespace {

const unsigned long long kOkTtlSec   = 7ull * 24 * 3600;
const unsigned long long kFailTtlSec = 24ull * 3600;
const unsigned long long kRevalidateSec = 24ull * 3600;

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

unsigned long long FileTimeToUnix(FILETIME ft) {
    SYSTEMTIME st;
    if (!FileTimeToSystemTime(&ft, &st)) return 0;
    return UnixFromYmd(st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
}

void Push16(std::vector<BYTE>& v, unsigned x) { v.push_back((BYTE)(x >> 8)); v.push_back((BYTE)x); }
void Push24(std::vector<BYTE>& v, unsigned long x) {
    v.push_back((BYTE)(x >> 16)); v.push_back((BYTE)(x >> 8)); v.push_back((BYTE)x);
}

std::vector<BYTE> BuildClientHello(const std::wstring& sni) {
    std::vector<BYTE> hs;
    hs.push_back(0x01);
    Push24(hs, 0);
    Push16(hs, 0x0303);

    unsigned long tick = (unsigned long)GetTickCount();
    hs.push_back((BYTE)(tick >> 24)); hs.push_back((BYTE)(tick >> 16));
    hs.push_back((BYTE)(tick >> 8));  hs.push_back((BYTE)tick);
    static const BYTE pad[28] = { 0x0d,0x0e,0x0a,0x0d,0xbe,0xef,0xca,0xfe,0x00,0x11,0x22,0x33,
                                  0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,
                                  0x01,0x02,0x03,0x04 };
    hs.insert(hs.end(), pad, pad + sizeof(pad));

    hs.push_back(0);

    static const WORD suites[] = {
        0xC02F, 0xC02B, 0xC030, 0xC028, 0xC013, 0xC014,
        0xC027, 0x009C, 0x009D, 0x002F, 0x0035, 0x000A,
    };
    Push16(hs, sizeof(suites));
    for (WORD s : suites) Push16(hs, s);

    hs.push_back(1); hs.push_back(0);

    std::vector<BYTE> ext;
    if (!sni.empty()) {
        std::string name = Narrow(sni);
        if (name.size() > 255) name.resize(255);
        Push16(ext, 0x0000);
        Push16(ext, 3 + (unsigned)name.size());
        Push16(ext, 1 + (unsigned)name.size());
        ext.push_back(0);
        Push16(ext, (unsigned)name.size());
        ext.insert(ext.end(), name.begin(), name.end());
    }
    Push16(ext, 0x000a);
    Push16(ext, 8);
    Push16(ext, 6);
    Push16(ext, 0x001d); Push16(ext, 0x0017); Push16(ext, 0x0018);
    Push16(ext, 0x000b);
    Push16(ext, 2);
    ext.push_back(1); ext.push_back(0);
    Push16(ext, 0x000d);
    Push16(ext, 14);
    Push16(ext, 12);
    Push16(ext, 0x0804); Push16(ext, 0x0401); Push16(ext, 0x0501);
    Push16(ext, 0x0403); Push16(ext, 0x0601); Push16(ext, 0x0805);
    Push16(ext, 0x0017);
    Push16(ext, 0);
    Push16(ext, 0xff01);
    Push16(ext, 1);
    ext.push_back(0);

    Push16(hs, (unsigned)ext.size());
    hs.insert(hs.end(), ext.begin(), ext.end());

    unsigned long hlen = (unsigned long)hs.size() - 4;
    hs[1] = (BYTE)(hlen >> 16); hs[2] = (BYTE)(hlen >> 8); hs[3] = (BYTE)hlen;

    std::vector<BYTE> rec;
    rec.push_back(0x16);
    rec.push_back(0x03); rec.push_back(0x01);
    Push16(rec, (unsigned)hs.size());
    rec.insert(rec.end(), hs.begin(), hs.end());
    return rec;
}

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

bool ReadTlsResponse(SOCKET s, std::vector<BYTE>& certDer, std::wstring& version,
                     std::wstring& err, int timeoutMs) {
    std::vector<BYTE> buf;
    std::vector<BYTE> hs;
    bool sawHello = false;
    bool sawCcs   = false;

    const unsigned long long deadline = (unsigned long long)time(nullptr) * 1000ull + timeoutMs;

    for (;;) {
        if (buf.size() > 512u * 1024) { err = Tr(L"response too large"); return false; }
        unsigned long long now = (unsigned long long)time(nullptr) * 1000ull;
        if (now >= deadline) { err = Tr(L"timeout"); return false; }

        while (buf.size() < 5) {
            int remain = (int)(deadline - now);
            if (remain <= 0) { err = Tr(L"timeout"); return false; }
            fd_set r;
            FD_ZERO(&r);
            FD_SET(s, &r);
            timeval tv;
            tv.tv_sec  = remain / 1000;
            tv.tv_usec = (remain % 1000) * 1000;
            int sel = select(0, &r, nullptr, nullptr, &tv);
            if (sel <= 0) { err = Tr(L"timeout"); return false; }
            BYTE tmp[2048];
            int got = recv(s, (char*)tmp, sizeof(tmp), 0);
            if (got <= 0) {
                err = sawHello ? Tr(L"connection closed") : Tr(L"no response (not TLS?)");
                return false;
            }
            buf.insert(buf.end(), tmp, tmp + got);
            now = (unsigned long long)time(nullptr) * 1000ull;
        }

        BYTE type = buf[0];
        unsigned rlen = ((unsigned)buf[3] << 8) | buf[4];

        while (buf.size() < 5 + rlen) {
            int remain = (int)(deadline - now);
            if (remain <= 0) { err = Tr(L"timeout"); return false; }
            fd_set r;
            FD_ZERO(&r);
            FD_SET(s, &r);
            timeval tv;
            tv.tv_sec  = remain / 1000;
            tv.tv_usec = (remain % 1000) * 1000;
            int sel = select(0, &r, nullptr, nullptr, &tv);
            if (sel <= 0) { err = Tr(L"timeout"); return false; }
            BYTE tmp[4096];
            int got = recv(s, (char*)tmp, sizeof(tmp), 0);
            if (got <= 0) { err = Tr(L"connection closed"); return false; }
            buf.insert(buf.end(), tmp, tmp + got);
            now = (unsigned long long)time(nullptr) * 1000ull;
        }

        if (type == 0x15) {
            err = Tr(L"server rejected the TLS handshake");
            return false;
        }
        if (type == 0x14) {
            if (!sawHello) { err = Tr(L"no certificate presented (resumed session)"); return false; }
            sawCcs = true;
            buf.erase(buf.begin(), buf.begin() + 5 + rlen);
            continue;
        }
        if (type != 0x16) { err = Tr(L"unexpected TLS record"); return false; }

        hs.insert(hs.end(), buf.begin() + 5, buf.begin() + 5 + rlen);
        buf.erase(buf.begin(), buf.begin() + 5 + rlen);

        while (hs.size() >= 4) {
            unsigned mlen = ((unsigned)hs[1] << 16) | ((unsigned)hs[2] << 8) | hs[3];
            if (hs.size() < 4 + mlen) break;
            BYTE mtype = hs[0];

            if (mtype == 2 && !sawHello) {
                if (mlen < 2) { err = Tr(L"unexpected TLS record"); return false; }
                sawHello = true;
                BYTE maj = hs[4], min = hs[5];
                if (maj == 3 && min == 4) {
                    err = Tr(L"server speaks TLS 1.3 only (certificate is encrypted)");
                    return false;
                }
                if (maj != 3 || (min != 1 && min != 2 && min != 3)) {
                    err = Tr(L"unknown TLS version");
                    return false;
                }
                version = L"TLS 1." + std::to_wstring(min);
            } else if (mtype == 11 && sawHello) {

                if (mlen >= 6) {
                    unsigned clen = ((unsigned)hs[7] << 16) | ((unsigned)hs[8] << 8) | hs[9];
                    if ((unsigned long)mlen >= 6 + (unsigned long)clen) {
                        certDer.assign(hs.begin() + 10, hs.begin() + 10 + clen);
                        return true;
                    }
                }
                err = Tr(L"malformed certificate body");
                return false;
            }
            (void)sawCcs;
            hs.erase(hs.begin(), hs.begin() + 4 + mlen);
        }
    }
}

}

namespace nl {

bool TlsFetchCertificate(const std::wstring& ip, int port, const std::wstring& sni,
                         CertInfo& out, int timeoutMs) {
    out = CertInfo{};
    out.ok = false;

    SOCKET s = TcpConnectTimeout(ip, port, (std::min)(timeoutMs, 4000));
    if (s == INVALID_SOCKET) {
        out.error = Tr(L"TCP connection failed");
        return false;
    }

    std::vector<BYTE> hello = BuildClientHello(sni);
    int sent = send(s, (const char*)hello.data(), (int)hello.size(), 0);
    if (sent != (int)hello.size()) {
        closesocket(s);
        out.error = Tr(L"could not send ClientHello");
        return false;
    }

    std::vector<BYTE> der;
    std::wstring version, err;
    if (!ReadTlsResponse(s, der, version, err, timeoutMs)) {
        closesocket(s);
        out.error = err;
        return false;
    }
    closesocket(s);

    if (der.empty() || der.size() > 1u * 1024 * 1024) {
        out.error = Tr(L"could not read the certificate");
        return false;
    }

    PCCERT_CONTEXT ctx = CertCreateCertificateContext(X509_ASN_ENCODING, der.data(),
                                                      (DWORD)der.size());
    if (!ctx) {
        out.error = Tr(L"certificate could not be decoded as DER");
        return false;
    }

    auto nameStr = [&](PCERT_INFO info) {
        wchar_t cn[256] = L"";
        CertGetNameStringW(ctx, CERT_NAME_ATTR_TYPE, 0, (void*)szOID_COMMON_NAME,
                           cn, 256);
        return std::wstring(cn);
    };

    out.subject = nameStr(ctx->pCertInfo);
    {
        wchar_t iss[256] = L"";
        CertGetNameStringW(ctx, CERT_NAME_ATTR_TYPE, CERT_NAME_ISSUER_FLAG,
                           (void*)szOID_COMMON_NAME, iss, 256);
        out.issuer = iss;
    }

    {
        PCERT_EXTENSION ext = CertFindExtension(szOID_SUBJECT_ALT_NAME2,
                                                ctx->pCertInfo->cExtension,
                                                ctx->pCertInfo->rgExtension);
        if (ext) {
            DWORD sz = 0;
            CERT_ALT_NAME_INFO* alt = nullptr;
            if (CryptDecodeObjectEx(X509_ASN_ENCODING, X509_ALT_NAME,
                                    ext->Value.pbData, ext->Value.cbData,
                                    CRYPT_DECODE_ALLOC_FLAG, nullptr, &alt, &sz) && alt) {
                std::wstring names;
                int cnt = 0;
                for (DWORD i = 0; i < alt->cAltEntry && cnt < 4; ++i) {
                    const CERT_ALT_NAME_ENTRY& e = alt->rgAltEntry[i];
                    if (e.dwAltNameChoice == CERT_ALT_NAME_DNS_NAME && e.pwszDNSName) {
                        if (cnt++) names += L", ";
                        names += e.pwszDNSName;
                    }
                }
                LocalFree(alt);
                out.sans = names;
            }
        }
        if (out.sans.empty()) out.sans = out.subject;
    }

    out.selfSigned = CertCompareCertificateName(X509_ASN_ENCODING,
                                                &ctx->pCertInfo->Issuer,
                                                &ctx->pCertInfo->Subject) == TRUE;

    out.notBefore = FileTimeToUnix(ctx->pCertInfo->NotBefore);
    out.notAfter  = FileTimeToUnix(ctx->pCertInfo->NotAfter);
    const unsigned long long now = (unsigned long long)time(nullptr);
    if (out.notAfter && now > out.notAfter)  out.expired = true;
    if (out.notBefore && now < out.notBefore) out.notYetValid = true;

    {
        BYTE hash[32] = {0};
        DWORD hl = sizeof(hash);
        if (CryptHashCertificate(0, CALG_SHA_256, 0, der.data(), (DWORD)der.size(),
                                 hash, &hl)) {
            wchar_t hex[68] = L"";
            for (DWORD i = 0; i < hl; ++i)
                swprintf(hex + i * 2, 3, L"%02X", (unsigned)hash[i]);
            out.thumbprint = hex;
        }
    }

    out.version = version;
    CertFreeCertificateContext(ctx);
    out.ok = true;
    return true;
}

std::wstring CertResolver::CachePath() const {
    return AppDataDir() + L"\\cert_cache.tsv";
}

CertResolver::CertResolver()  { LoadCache(); }
CertResolver::~CertResolver() { Stop(); }

void CertResolver::Start() {
    m_stop = false;
    m_worker = std::thread(&CertResolver::Worker, this);
}

void CertResolver::Stop() {
    m_stop = true;
    m_cv.notify_all();
    if (m_worker.joinable()) m_worker.join();
    SaveCache();
}

void CertResolver::SetOnline(bool on) { m_online = on; }

bool CertResolver::Get(const std::wstring& ipPort, CertInfo& out, bool enqueue,
                       const std::wstring& sni) {
    std::lock_guard<std::mutex> lk(m_mtx);
    auto it = m_cache.find(ipPort);
    if (it != m_cache.end()) {
        if (!sni.empty() && it->second.queued) it->second.sni = sni;
        const unsigned long long now = (unsigned long long)time(nullptr);
        if (m_online && enqueue && !it->second.queued && it->second.info.ts &&
            now > it->second.info.ts && now - it->second.info.ts > kRevalidateSec) {
            it->second.queued = true;
            if (!sni.empty()) it->second.sni = sni;
            m_q.push_back(ipPort);
            m_cv.notify_all();
        }
        out = it->second.info;
        return true;
    }
    if (!enqueue) return false;
    Entry e;
    e.sni = sni;
    if (m_online) { e.queued = true; m_q.push_back(ipPort); m_cv.notify_all(); }
    m_cache.emplace(ipPort, e);
    out = e.info;
    return true;
}

void CertResolver::Invalidate(const std::wstring& ipPort) {
    std::lock_guard<std::mutex> lk(m_mtx);
    auto it = m_cache.find(ipPort);
    if (it == m_cache.end()) {
        Entry e;
        if (m_online) { e.queued = true; m_q.push_back(ipPort); m_cv.notify_all(); }
        m_cache.emplace(ipPort, e);
        return;
    }
    if (it->second.queued) return;
    it->second.info = CertInfo{};
    if (m_online) { it->second.queued = true; m_q.push_back(ipPort); m_cv.notify_all(); }
}

size_t CertResolver::PendingCount() {
    std::lock_guard<std::mutex> lk(m_mtx);
    return m_q.size();
}

void CertResolver::LoadCache() {
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
        if (f.size() < 12) continue;
        Entry en;
        en.info.ok          = atoi(f[1].c_str()) != 0;
        en.info.subject     = Widen(f[2]);
        en.info.issuer      = Widen(f[3]);
        en.info.sans        = Widen(f[4]);
        en.info.thumbprint  = Widen(f[5]);
        en.info.version     = Widen(f[6]);
        en.info.notBefore   = _strtoui64(f[7].c_str(), nullptr, 10);
        en.info.notAfter    = _strtoui64(f[8].c_str(), nullptr, 10);
        en.info.selfSigned  = atoi(f[9].c_str()) != 0;
        en.info.ts          = _strtoui64(f[10].c_str(), nullptr, 10);
        en.info.error       = Widen(f[11]);
        en.info.resolved    = true;
        m_cache[Widen(f[0])] = en;
    }
}

void CertResolver::SaveCache() {
    std::lock_guard<std::mutex> lk(m_mtx);
    if (m_cache.empty()) return;
    std::wstring path = CachePath();
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;

    const unsigned long long now = (unsigned long long)time(nullptr);
    for (const auto& kv : m_cache) {
        const CertInfo& t = kv.second.info;
        if (!t.resolved || !t.ts) continue;
        const unsigned long long ttl = t.ok ? kOkTtlSec : kFailTtlSec;
        if (now - t.ts > ttl) continue;
        std::string line = Narrow(kv.first) + "\t" +
                           (t.ok ? "1" : "0") + "\t" +
                           Narrow(t.subject) + "\t" + Narrow(t.issuer) + "\t" +
                           Narrow(t.sans) + "\t" + Narrow(t.thumbprint) + "\t" +
                           Narrow(t.version) + "\t" +
                           std::to_string(t.notBefore) + "\t" +
                           std::to_string(t.notAfter) + "\t" +
                           (t.selfSigned ? "1" : "0") + "\t" +
                           std::to_string(t.ts) + "\t" +
                           Narrow(t.error) + "\r\n";
        DWORD wr = 0;
        WriteFile(h, line.data(), (DWORD)line.size(), &wr, nullptr);
    }
    CloseHandle(h);
}

void CertResolver::Worker() {
    for (;;) {
        std::wstring key;
        std::wstring sni;
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
            if (it != m_cache.end()) {
                it->second.queued = false;
                sni = it->second.sni;
            }
        }

        size_t c = key.find_last_of(L':');
        if (c == std::wstring::npos || c == 0 || c + 1 >= key.size()) continue;
        std::wstring ip = key.substr(0, c);
        int port = _wtoi(key.substr(c + 1).c_str());
        if (port <= 0 || port > 65535) port = 443;

        CertInfo ci;
        TlsFetchCertificate(ip, port, sni, ci, 8000);
        if (m_stop.load()) return;

        {
            std::lock_guard<std::mutex> lk(m_mtx);
            auto it = m_cache.find(key);
            if (it != m_cache.end()) {
                it->second.info = ci;
                it->second.info.resolved = true;
                it->second.info.ts = (unsigned long long)time(nullptr);
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(350));
    }
}

}
