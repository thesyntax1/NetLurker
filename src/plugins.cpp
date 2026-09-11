#include "plugins.h"
#include "common.h"
#include "json.h"
#include <windows.h>
#include <vector>
#include <algorithm>

namespace nl {

namespace {
std::vector<PluginDef> g_plugins;

std::wstring Js(const std::string& s) { return Widen(json::Unescape(s)); }

void LoadFile(const std::wstring& path) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    std::string raw;
    char buf[8192];
    DWORD got = 0;
    while (ReadFile(h, buf, sizeof(buf), &got, nullptr) && got) raw.append(buf, got);
    CloseHandle(h);
    if (raw.empty()) return;

    std::string name, exe, args;
    double timeout = 8000.0, dummy = 0.0;
    if (!json::GetString(raw, "name", name) || name.empty()) return;
    if (!json::GetString(raw, "exe",  exe)  || exe.empty())  return;
    if (!json::GetString(raw, "args", args)) args.clear();
    if (json::GetNumber(raw, "timeoutMs", dummy)) timeout = dummy;
    if (timeout < 500) timeout = 500;
    if (timeout > 60000) timeout = 60000;

    PluginDef p;
    p.name = Js(name);
    p.exe  = Js(exe);
    p.args = Js(args);
    p.timeoutMs = (int)timeout;

    for (auto& e : g_plugins) {
        if (e.name == p.name) { e = p; return; }
    }
    g_plugins.push_back(p);
}

std::wstring Expand(const std::wstring& tmpl, const std::wstring& ip) {
    std::wstring r = tmpl;
    size_t at = 0;
    while ((at = r.find(L"{ip}", at)) != std::wstring::npos) {
        r.replace(at, 4, ip);
        at += ip.size();
    }
    return r;
}

PluginResult RunOne(const PluginDef& p, const std::wstring& ip) {
    PluginResult res;
    res.ok = false;
    res.risk = -1;

    std::wstring cmd = L"\"" + p.exe + L"\"";
    if (!p.args.empty()) cmd += L" " + Expand(p.args, ip);

    HANDLE inR = nullptr, inW = nullptr, outR = nullptr, outW = nullptr;
    SECURITY_ATTRIBUTES sa;
    ZeroMemory(&sa, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    if (!CreatePipe(&inR, &inW, &sa, 0)) return res;
    if (!CreatePipe(&outR, &outW, &sa, 0)) { CloseHandle(inR); CloseHandle(inW); return res; }
    SetHandleInformation(outR, HANDLE_FLAG_INHERIT, 0);

    PROCESS_INFORMATION pi;
    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = inR;
    si.hStdOutput = outW;
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);

    BOOL created = CreateProcessW(p.exe.c_str(),
        const_cast<wchar_t*>(cmd.c_str()),
        nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    if (!created) {
        CloseHandle(inR); CloseHandle(inW); CloseHandle(outR); CloseHandle(outW);
        return res;
    }
    CloseHandle(inR);
    CloseHandle(outW);

    std::wstring line = ip + L"\n";
    std::string utf8 = Narrow(line);
    DWORD w1 = 0;
    WriteFile(inW, utf8.data(), (DWORD)utf8.size(), &w1, nullptr);
    CloseHandle(inW);

    std::string out;
    out.reserve(65536);
    char chunk[4096];
    DWORD deadline = GetTickCount() + (DWORD)p.timeoutMs;
    for (;;) {
        DWORD remain = deadline > GetTickCount() ? deadline - GetTickCount() : 0;
        DWORD avail = 0;
        if (PeekNamedPipe(outR, nullptr, 0, nullptr, &avail, nullptr) && avail) {
            DWORD toRead = (DWORD)(std::min)((size_t)avail, sizeof(chunk));
            DWORD got2 = 0;
            if (ReadFile(outR, chunk, toRead, &got2, nullptr) && got2)
                out.append(chunk, got2);
            if (out.size() >= 65536) break;
        } else if (WaitForSingleObject(pi.hProcess, remain ? (DWORD)(std::min)(remain, (DWORD)50) : 0) == WAIT_OBJECT_0) {
            break;
        }
        if (GetTickCount() >= deadline) break;
    }

    for (;;) {
        DWORD avail = 0;
        if (!PeekNamedPipe(outR, nullptr, 0, nullptr, &avail, nullptr) || !avail) break;
        DWORD toRead = (DWORD)(std::min)((size_t)avail, sizeof(chunk));
        DWORD got2 = 0;
        if (!ReadFile(outR, chunk, toRead, &got2, nullptr) || !got2) break;
        out.append(chunk, got2);
        if (out.size() >= 65536) break;
    }
    CloseHandle(outR);

    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    if (code == STILL_ACTIVE) TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    if (code != 0 || out.empty()) return res;

    double risk = -1;
    if (!json::GetNumber(out, "risk", risk)) return res;
    if (risk < 0 || risk > 100) return res;
    res.risk = (int)(risk + 0.5);
    std::string verdict, note;
    if (json::GetString(out, "verdict", verdict)) res.verdict = Js(verdict);
    if (json::GetString(out, "note", note)) res.note = Js(note);
    res.ok = true;
    return res;
}
}

void PluginsLoadFrom(const std::wstring& dir) {
    if (dir.empty()) return;
    std::wstring pattern = dir + L"\\plugins\\*.json";
    WIN32_FIND_DATAW fd;
    HANDLE hf = FindFirstFileW(pattern.c_str(), &fd);
    if (hf == INVALID_HANDLE_VALUE) return;
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            LoadFile(dir + L"\\plugins\\" + fd.cFileName);
    } while (FindNextFileW(hf, &fd));
    FindClose(hf);
}

size_t PluginsCount() { return g_plugins.size(); }

std::vector<PluginResult> PluginsRun(const std::wstring& ip) {
    std::vector<PluginResult> results;
    size_t n = (std::min)(g_plugins.size(), (size_t)4);
    for (size_t i = 0; i < n; ++i) {
        PluginResult r = RunOne(g_plugins[i], ip);
        if (r.ok) results.push_back(r);
    }
    return results;
}

}
