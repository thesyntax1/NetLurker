#include "http.h"
#include "common.h"
#include "http_url.h"

namespace nl { namespace http {

Response Request(const std::string& method, const std::string& url, const std::string& body,
                 const std::string& contentType, const std::string& authBearer, int timeoutMs,
                 const std::wstring& extraHeaders) {
    Response res;
    ParsedUrl parsed;
    if (!ParseUrl(Widen(url), parsed)) { res.error = "invalid URL"; return res; }
    if ((!body.empty() || !authBearer.empty() || !extraHeaders.empty()) && !parsed.secure && !parsed.Loopback()) {
        res.error = "HTTPS required for credentials or request bodies"; return res;
    }
    if (authBearer.find_first_of("\r\n") != std::string::npos || contentType.find_first_of("\r\n") != std::string::npos) {
        res.error = "invalid header value"; return res;
    }

    HINTERNET hSession = WinHttpOpen(L"NetLurker/1.0",
                                     WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                     WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        hSession = WinHttpOpen(L"NetLurker/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                               WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    }
    if (!hSession) { res.error = "WinHttpOpen failed"; return res; }
    WinHttpSetTimeouts(hSession, timeoutMs, timeoutMs, timeoutMs, timeoutMs);

    HINTERNET hConnect = WinHttpConnect(hSession, parsed.host.c_str(), parsed.port, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); res.error = "could not connect to host"; return res; }

    HINTERNET hReq = WinHttpOpenRequest(hConnect, Widen(method).c_str(), parsed.path.c_str(), nullptr,
                                        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                        parsed.secure ? WINHTTP_FLAG_SECURE : 0);
    if (!hReq) {
        WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        res.error = "could not build request"; return res;
    }

    // Provider keys/custom headers and AI request bodies must never follow redirects.
    DWORD redirectPolicy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
    if (!WinHttpSetOption(hReq, WINHTTP_OPTION_REDIRECT_POLICY, &redirectPolicy, sizeof(redirectPolicy))) {
        WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        res.error = "could not disable redirects"; return res;
    }

    std::wstring headers = L"Content-Type: " + Widen(contentType) + L"\r\n";
    if (!authBearer.empty()) headers += L"Authorization: Bearer " + Widen(authBearer) + L"\r\n";
    if (!extraHeaders.empty()) headers += extraHeaders + L"\r\n";

    BOOL sent = WinHttpSendRequest(hReq, headers.c_str(), (DWORD)-1L,
                                   body.empty() ? WINHTTP_NO_REQUEST_DATA : (LPVOID)body.data(),
                                   (DWORD)body.size(), (DWORD)body.size(), 0);
    if (sent) sent = WinHttpReceiveResponse(hReq, nullptr);

    if (!sent) {
        DWORD e = GetLastError();
        char buf[128];
        wsprintfA(buf, "network error (code %lu)", (unsigned long)e);
        res.error = buf;
    } else {
        DWORD code = 0, len = sizeof(code);
        WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &code, &len, WINHTTP_NO_HEADER_INDEX);
        res.status = (int)code;

        if (code >= 300 && code < 400) {
            wchar_t loc[2048] = L"";
            DWORD ll = sizeof(loc);
            if (WinHttpQueryHeaders(hReq, WINHTTP_QUERY_LOCATION, WINHTTP_HEADER_NAME_BY_INDEX,
                                    loc, &ll, WINHTTP_NO_HEADER_INDEX))
                res.location = loc;
        }

        constexpr size_t limit = 2u * 1024 * 1024;
        char chunk[16384];
        for (;;) {
            DWORD read = 0;
            if (!WinHttpReadData(hReq, chunk, sizeof(chunk), &read)) {
                res.error = "incomplete response"; break;
            }
            if (!read) break;
            if (read > limit - res.body.size()) { res.error = "response too large"; break; }
            res.body.append(chunk, read);
        }
        res.ok = (code >= 200 && code < 300 && res.error.empty());
        if (!res.error.empty()) res.body.clear(); // partial JSON must never be treated as evidence
        if (!res.ok && res.error.empty()) res.error = "HTTP " + std::to_string((int)code);
    }

    WinHttpCloseHandle(hReq);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return res;
}

}}
