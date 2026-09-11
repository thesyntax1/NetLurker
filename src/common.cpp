#include "common.h"
#include "i18n.h"
#include <shlobj.h>
#include <cwchar>
#include <cstdio>

namespace nl {

std::wstring Widen(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring out((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &out[0], n);
    return out;
}

std::string Narrow(const std::wstring& s) {
    if (s.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0, nullptr, nullptr);
    std::string out((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.c_str(), (int)s.size(), &out[0], n, nullptr, nullptr);
    return out;
}

std::wstring ToLower(const std::wstring& s) {
    std::wstring o = s;
    std::transform(o.begin(), o.end(), o.begin(), [](wchar_t c) {
        return (wchar_t)towlower(c);
    });
    return o;
}

bool Contains(const std::wstring& hay, const std::wstring& needle) {
    if (needle.empty()) return true;
    return ToLower(hay).find(ToLower(needle)) != std::wstring::npos;
}

std::wstring Trim(const std::wstring& s) {
    size_t a = s.find_first_not_of(L" \t\r\n");
    if (a == std::wstring::npos) return L"";
    size_t b = s.find_last_not_of(L" \t\r\n");
    return s.substr(a, b - a + 1);
}

std::wstring FormatBytesPerSec(double bps) {
    wchar_t buf[64];
    if (bps <= 0.5) return L"-";
    if (bps < 1024.0)              swprintf(buf, 64, L"%.0f B/s",  bps);
    else if (bps < 1024.0 * 1024)  swprintf(buf, 64, L"%.1f KB/s", bps / 1024.0);
    else                           swprintf(buf, 64, L"%.2f MB/s", bps / (1024.0 * 1024.0));
    return buf;
}

std::wstring FormatBytes(unsigned long long b) {
    wchar_t buf[64];
    if (b < 1024ull)                    swprintf(buf, 64, L"%llu B", b);
    else if (b < 1024ull * 1024)        swprintf(buf, 64, L"%.1f KB", b / 1024.0);
    else if (b < 1024ull * 1024 * 1024) swprintf(buf, 64, L"%.1f MB", b / (1024.0 * 1024.0));
    else                                swprintf(buf, 64, L"%.2f GB", b / (1024.0 * 1024.0 * 1024.0));
    return buf;
}

unsigned long long NowMs() { return (unsigned long long)GetTickCount64(); }

std::wstring FormatDurationShort(unsigned long long s) {
    wchar_t buf[64];
    if (s < 60)         swprintf(buf, 64, Tr(L"%llu s"),  s);
    else if (s < 3600)  swprintf(buf, 64, Tr(L"%llu min"),  s / 60);
    else if (s < 86400) swprintf(buf, 64, Tr(L"%llu h"),  s / 3600);
    else                swprintf(buf, 64, Tr(L"%llu d"), s / 86400);
    return buf;
}

std::wstring FormatDurationLong(unsigned long long s) {
    wchar_t buf[64];
    if (s < 60)        swprintf(buf, 64, Tr(L"%llu s"), s);
    else if (s < 3600) swprintf(buf, 64, Tr(L"%llu min %llu s"), s / 60, s % 60);
    else               swprintf(buf, 64, Tr(L"%llu h %llu min"), s / 3600, (s % 3600) / 60);
    return buf;
}

std::wstring AppDataDir() {
    wchar_t path[MAX_PATH] = {0};
    if (FAILED(SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, path))) return L".";
    std::wstring dir = std::wstring(path) + L"\\NetLurker";
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir;
}

std::wstring ExeDir() {
    wchar_t path[MAX_PATH] = {0};
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    std::wstring full = path;
    size_t p = full.find_last_of(L"\\/");
    if (p != std::wstring::npos) full.resize(p);
    return full.empty() ? L"." : full;
}

bool IsRunAsAdmin() {
    BOOL admin = FALSE;
    PSID grp = nullptr;
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &grp)) {
        if (!CheckTokenMembership(nullptr, grp, &admin)) admin = FALSE;
        FreeSid(grp);
    }
    return admin == TRUE;
}

}
