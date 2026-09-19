#pragma once
#include "common.h"
#include <winhttp.h>
#include <cwctype>

namespace nl { namespace http {
struct ParsedUrl {
    std::wstring host, path;
    INTERNET_PORT port = 0;
    bool secure = false;
    bool PublicGeolocationBatch() const {
        return !secure && host == L"ip-api.com" && port == 80 &&
            (path == L"/batch" || path.compare(0, 7, L"/batch?") == 0);
    }
    bool Loopback() const {
        auto lower = host;
        for (auto& c : lower) c = static_cast<wchar_t>(towlower(c));
        return lower == L"localhost" || lower == L"127.0.0.1" || lower == L"::1" || lower == L"[::1]";
    }
};
inline bool ParseUrl(const std::wstring& url, ParsedUrl& out) {
    if (url.empty() || url.find(L'#') != std::wstring::npos) return false;
    for (wchar_t c : url) if (c <= L' ' || c == 127) return false;
    URL_COMPONENTS u{};
    u.dwStructSize = sizeof(u);
    u.dwHostNameLength = u.dwUrlPathLength = u.dwExtraInfoLength = u.dwUserNameLength = u.dwPasswordLength = static_cast<DWORD>(-1);
    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &u) || !u.dwHostNameLength || !u.nPort ||
        u.dwUserNameLength || u.dwPasswordLength ||
        (u.nScheme != INTERNET_SCHEME_HTTP && u.nScheme != INTERNET_SCHEME_HTTPS)) return false;
    out.host.assign(u.lpszHostName, u.dwHostNameLength);
    out.path = u.dwUrlPathLength ? std::wstring(u.lpszUrlPath, u.dwUrlPathLength) : L"/";
    if (u.dwExtraInfoLength) out.path.append(u.lpszExtraInfo, u.dwExtraInfoLength);
    out.port = u.nPort;
    out.secure = u.nScheme == INTERNET_SCHEME_HTTPS;
    return true;
}
} }
