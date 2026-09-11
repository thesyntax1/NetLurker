#include "http.h"
#include "common.h"
#include <winhttp.h>

namespace nl { namespace http {

Response Request(const std::string& method, const std::string& url, const std::string& body,
                 const std::string& contentType, const std::string& authBearer, int timeoutMs,
                 const std::wstring& extraHeaders) {
    Response res;
    std::wstring wurl = Widen(url);

    URL_COMPONENTS uc;
    ZeroMemory(&uc, sizeof(uc));
    uc.dwStructSize = sizeof(uc);
    wchar_t host[256] = L"", path[2048] = L"";
    uc.lpszHostName = host;      uc.dwHostNameLength = 255;
    uc.lpszUrlPath  = path;      uc.dwUrlPathLength  = 2047;
    if (!WinHttpCrackUrl(wurl.c_str(), 0, 0, &uc)) { res.error = "invalid URL"; return res; }

    const bool secure = (uc.nScheme == INTERNET_SCHEME_HTTPS);

    HINTERNET hSession = WinHttpOpen(L"NetLurker/1.0",
                                     WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                     WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        hSession = WinHttpOpen(L"NetLurker/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                               WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    }
    if (!hSession) { res.error = "WinHttpOpen failed"; return res; }
    WinHttpSetTimeouts(hSession, timeoutMs, timeoutMs, timeoutMs, timeoutMs);

    HINTERNET hConnect = WinHttpConnect(hSession, host, uc.nPort, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); res.error = "could not connect to host"; return res; }

    std::wstring wpath = path[0] ? path : L"/";
    HINTERNET hReq = WinHttpOpenRequest(hConnect, Widen(method).c_str(), wpath.c_str(), nullptr,
                                        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                        secure ? WINHTTP_FLAG_SECURE : 0);
    if (!hReq) {
        WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        res.error = "could not build request"; return res;
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

        for (;;) {
            DWORD avail = 0;
            if (!WinHttpQueryDataAvailable(hReq, &avail) || avail == 0) break;
            std::string chunk(avail, '\0');
            DWORD read = 0;
            if (!WinHttpReadData(hReq, &chunk[0], avail, &read) || read == 0) break;
            chunk.resize(read);
            res.body += chunk;
            if (res.body.size() > 4u * 1024 * 1024) break;
        }
        res.ok = (code >= 200 && code < 300);
        if (!res.ok && res.error.empty()) res.error = "HTTP " + std::to_string((int)code);
    }

    WinHttpCloseHandle(hReq);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return res;
}

}}
