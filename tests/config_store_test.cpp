#include "config_store.h"
#include "http_url.h"
#include <cassert>
#include <iostream>

static std::wstring Read(const std::wstring& file, const wchar_t* section, const wchar_t* key) {
    wchar_t value[1024]{};
    GetPrivateProfileStringW(section, key, L"", value, 1024, file.c_str());
    return value;
}
int main() {
    wchar_t temp[MAX_PATH]{}, name[MAX_PATH]{};
    assert(GetTempPathW(MAX_PATH, temp));
    assert(GetTempFileNameW(temp, L"nlt", 0, name));
    assert(DeleteFileW(name));
    const std::wstring path = name;
    assert(nl::UpdateIniAtomically(path, {{L"ui", L"lang", L"en"}, {L"other", L"keep", L"yes"}}));
    assert(Read(path, L"ui", L"lang") == L"en");
    assert(nl::UpdateIniAtomically(path, {{L"ui", L"lang", L"tr"}, {L"ai", L"model", L"\u65e5\u672c\u8a9e"}}));
    assert(Read(path, L"ui", L"lang") == L"tr");
    assert(Read(path, L"other", L"keep") == L"yes");
    assert(Read(path, L"ai", L"model") == L"\u65e5\u672c\u8a9e");
    assert(!nl::UpdateIniAtomically(path, {{L"ui", L"lang", L"de"}, {L"ai", L"model", L"bad\n[ui]\nlang=es"}}));
    assert(Read(path, L"ui", L"lang") == L"tr");
    assert(SetFileAttributesW(path.c_str(), FILE_ATTRIBUTE_READONLY));
    assert(!nl::UpdateIniAtomically(path, {{L"ui", L"lang", L"de"}}));
    assert(Read(path, L"ui", L"lang") == L"tr");
    assert(SetFileAttributesW(path.c_str(), FILE_ATTRIBUTE_NORMAL));
    HANDLE locked = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    assert(locked != INVALID_HANDLE_VALUE);
    assert(!nl::UpdateIniAtomically(path, {{L"ui", L"lang", L"de"}}));
    CloseHandle(locked);
    assert(Read(path, L"ui", L"lang") == L"tr");
    assert(DeleteFileW(path.c_str()));
    assert(!nl::UpdateIniAtomically(path + L"\\missing\\config.ini", {{L"ui", L"lang", L"en"}}));

    nl::http::ParsedUrl parsed;
    assert(nl::http::ParseUrl(L"https://example.com/v1/chat?api-version=2026&x=1", parsed));
    assert(parsed.path == L"/v1/chat?api-version=2026&x=1" && parsed.secure && !parsed.Loopback());
    assert(nl::http::ParseUrl(L"http://127.0.0.1:11434/v1", parsed) && parsed.Loopback());
    assert(nl::http::ParseUrl(L"http://[::1]:11434/v1", parsed) && parsed.Loopback());
    assert(nl::http::ParseUrl(L"https://example.com?x=1", parsed) && parsed.path == L"/?x=1");
    for (auto url : {L"file:///tmp", L"https://", L"https://u:p@example.com", L"https://example.com/#secret", L"https://example.com/\r\nx", L"https://example.com:0"})
        assert(!nl::http::ParseUrl(url, parsed));
    assert(nl::http::ParseUrl(L"http://localhost.attacker.example/v1", parsed) && !parsed.Loopback());
    std::cout << "Config: atomic replacement, Unicode, unknown sections, injection/readonly/locked rollback and URL policy passed\n";
}
