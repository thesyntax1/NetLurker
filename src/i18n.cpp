#include "i18n.h"
#include "common.h"
#include <windows.h>
#include <unordered_map>
#include <algorithm>
#include <deque>
#include <mutex>
#include <shared_mutex>
#include <fstream>

namespace nl {

namespace {

std::shared_mutex                                g_mu;
std::deque<std::wstring>                         g_pool;
std::unordered_map<std::wstring, const wchar_t*> g_map;
std::wstring g_code = L"en";
bool g_loaded = false;

std::wstring Lower(const std::wstring& s) {
    std::wstring r = s;
    std::transform(r.begin(), r.end(), r.begin(), ::towlower);
    return r;
}

static void Unescape(std::wstring& s) {
    for (size_t i = 0; i + 1 < s.size(); ++i) {
        if (s[i] == L'\\' && (s[i + 1] == L'n' || s[i + 1] == L't' || s[i + 1] == L'r' || s[i + 1] == L'=')) {
            s[i] = (s[i + 1] == L'n') ? L'\n' : (s[i + 1] == L't') ? L'\t' : (s[i + 1] == L'r') ? L'\r' : L'=';
            s.erase(i + 1, 1);
        }
    }
}

bool ParseLine(const std::wstring& line, std::wstring& key, std::wstring& val) {

    size_t eq = std::wstring::npos;
    for (size_t i = 0; i < line.size(); ++i) {
        if (line[i] == L'=' && (i == 0 || line[i - 1] != L'\\')) { eq = i; break; }
    }
    if (eq == std::wstring::npos) return false;
    key = line.substr(0, eq);
    val = line.substr(eq + 1);
    if (key.empty() || val.empty()) return false;
    Unescape(key);
    Unescape(val);
    return true;
}

using Staging = std::unordered_map<std::wstring, std::wstring>;

std::wstring FormatSignature(const std::wstring& s) {
    std::wstring sig;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] != L'%') continue;
        if (i + 1 < s.size() && s[i + 1] == L'%') { ++i; continue; }
        size_t j = i + 1;
        while (j < s.size() && wcschr(L"-+ #0123456789.*hlLwIz", s[j])) ++j;
        if (j < s.size()) { sig += s[j]; i = j; }
    }
    return sig;
}

void LoadDir(const std::wstring& dir, const std::wstring& code, Staging& out) {
    std::wstring path = dir + L"\\" + code + L".ini";
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    std::string raw;
    char buf[8192];
    DWORD got = 0;
    while (ReadFile(h, buf, sizeof(buf), &got, nullptr) && got) raw.append(buf, got);
    CloseHandle(h);
    if (raw.empty()) return;

    std::wstring text = Widen(raw);
    size_t p = 0;
    while (p < text.size()) {
        size_t e = text.find(L'\n', p);
        if (e == std::wstring::npos) e = text.size();
        std::wstring line = text.substr(p, e - p);
        p = e + 1;
        if (!line.empty() && line.back() == L'\r') line.pop_back();
        if (line.empty() || line[0] == L'#') continue;
        std::wstring key, val;
        if (ParseLine(line, key, val)) out[key] = val;
    }
}
}

void I18nLoadFrom(const std::wstring& dir) {
    std::wstring code;
    {
        std::shared_lock<std::shared_mutex> lk(g_mu);
        code = g_code;
    }

    Staging staging;
    LoadDir(dir, L"en", staging);
    LoadDir(dir, code, staging);
    if (staging.empty()) return;

    for (auto it = staging.begin(); it != staging.end(); ) {
        if (FormatSignature(it->first) != FormatSignature(it->second)) it = staging.erase(it);
        else ++it;
    }

    std::unique_lock<std::shared_mutex> lk(g_mu);
    for (auto& kv : staging) {
        auto ex = g_map.find(kv.first);
        if (ex != g_map.end() && kv.second == ex->second) continue;
        g_pool.push_back(std::move(kv.second));
        g_map[kv.first] = g_pool.back().c_str();
    }
    g_loaded = true;
}

void I18nSetLanguage(const std::wstring& code) {
    std::wstring c = Lower(Trim(code));
    if (c == L"system" || c.empty()) c = I18nSystemLanguage();
    static const std::wstring valid[] = { L"en", L"tr", L"es", L"de", L"fr", L"ja", L"zh", L"pt" };
    bool ok = false;
    for (const auto& v : valid) if (c == v) { ok = true; break; }
    if (!ok) c = L"en";
    std::unique_lock<std::shared_mutex> lk(g_mu);
    if (c == g_code) return;
    g_code = c;
    g_map.clear();
    g_loaded = false;
}

std::wstring I18nLanguage() {
    std::shared_lock<std::shared_mutex> lk(g_mu);
    return g_code;
}

std::vector<std::pair<std::wstring, std::wstring>> I18nLanguages() {
    return {
        { L"system", L"Otomatik / Auto" },
        { L"en", L"English" },
        { L"tr", L"Turkce" },
        { L"es", L"Espanol" },
        { L"de", L"Deutsch" },
        { L"fr", L"Francais" },
        { L"ja", L"Nihongo" },
        { L"zh", L"Zhongwen" },
        { L"pt", L"Portugues" },
    };
}

std::wstring I18nSystemLanguage() {
    LANGID lid = GetUserDefaultUILanguage();
    unsigned short prim = PRIMARYLANGID(lid);
    if (prim == LANG_TURKISH) return L"tr";
    return L"en";
}

const wchar_t* Tr(const wchar_t* s) {
    if (!s || !s[0]) return s;
    std::shared_lock<std::shared_mutex> lk(g_mu);
    if (!g_loaded || g_map.empty()) return s;
    auto it = g_map.find(s);
    if (it != g_map.end()) return it->second;
    return s;
}

}
