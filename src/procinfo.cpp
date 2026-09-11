#include "procinfo.h"
#include "i18n.h"

#include <winsvc.h>
#include <winternl.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <psapi.h>
#include <sddl.h>
#include <tlhelp32.h>
#include <shellapi.h>
#include <shlobj.h>
#include <sstream>

namespace nl {

typedef NTSTATUS (NTAPI *PFN_NtQueryInformationProcess)(HANDLE, UINT, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *PFN_NtQuerySystemInformation)(UINT, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *PFN_NtSuspendProcess)(HANDLE);
typedef NTSTATUS (NTAPI *PFN_NtResumeProcess)(HANDLE);

struct NtApi {
    PFN_NtQueryInformationProcess QueryProc = nullptr;
    PFN_NtQuerySystemInformation  QuerySys  = nullptr;
    PFN_NtSuspendProcess          Suspend   = nullptr;
    PFN_NtResumeProcess           Resume    = nullptr;
};

static const NtApi& Nt() {
    static NtApi api;
    static bool once = false;
    if (!once) {
        once = true;
        HMODULE nt = GetModuleHandleW(L"ntdll.dll");
        if (nt) {
            api.QueryProc = (PFN_NtQueryInformationProcess)(void*)GetProcAddress(nt, "NtQueryInformationProcess");
            api.QuerySys  = (PFN_NtQuerySystemInformation) (void*)GetProcAddress(nt, "NtQuerySystemInformation");
            api.Suspend   = (PFN_NtSuspendProcess)         (void*)GetProcAddress(nt, "NtSuspendProcess");
            api.Resume    = (PFN_NtResumeProcess)          (void*)GetProcAddress(nt, "NtResumeProcess");
        }
    }
    return api;
}

struct NL_SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime, UserTime, CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    struct { HANDLE UniqueProcess, UniqueThread; } ClientId;
    LONG  Priority, BasePriority;
    ULONG ContextSwitches, ThreadState, WaitReason;
    ULONG Reserved;
};

struct NL_SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime, UserTime, KernelTime;
    UNICODE_STRING ImageName;
    LONG BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize, VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize, WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage, QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage, QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage, PeakPagefileUsage, PrivatePageCount;
    LARGE_INTEGER ReadOperationCount, WriteOperationCount, OtherOperationCount;
    LARGE_INTEGER ReadTransferCount, WriteTransferCount, OtherTransferCount;
    NL_SYSTEM_THREAD_INFORMATION Threads[1];
};

std::wstring ProcDetails::Publisher() const {
    if (!signer.empty())  return signer;
    if (!company.empty()) return company;
    return L"—";
}

const wchar_t* SignStateText(SignState s) {
    switch (s) {
        case SignState::SignedMicrosoft: return Tr(L"Signed by Microsoft");
        case SignState::Signed:          return Tr(L"Signed");
        case SignState::Unsigned:        return Tr(L"Unsigned");
        case SignState::Invalid:         return Tr(L"Invalid signature");
        case SignState::Missing:         return Tr(L"File missing");
        case SignState::Checking:        return Tr(L"Checking");
        default:                         return Tr(L"Unknown");
    }
}

const wchar_t* IntegrityText(Integrity i) {
    switch (i) {
        case Integrity::Untrusted: return Tr(L"Untrusted");
        case Integrity::Low:       return Tr(L"Low (protected)");
        case Integrity::Medium:    return Tr(L"Medium (normal)");
        case Integrity::High:      return Tr(L"High (administrator)");
        case Integrity::System:    return Tr(L"System");
        default:                   return L"—";
    }
}

std::wstring ProcDetails::SignText() const {
    switch (sign) {
        case SignState::SignedMicrosoft: return L"Microsoft";
        case SignState::Signed:          return Tr(L"Signed");
        case SignState::Unsigned:        return Tr(L"UNSIGNED");
        case SignState::Invalid:         return Tr(L"INVALID");
        case SignState::Missing:         return Tr(L"no file");
        case SignState::Checking:        return L"…";
        default:                         return L"—";
    }
}

std::wstring ProcDetails::DisplayName() const {
    if (!services.empty()) return name + L" (" + services + L")";
    return name;
}

std::wstring ProcDetails::AgeText() const {
    if (!startTime) return L"—";
    unsigned long long now = (unsigned long long)time(nullptr) * 1000ull;
    if (now <= startTime) return FormatDurationShort(0);
    return FormatDurationShort((now - startTime) / 1000ull);
}

static SignState VerifyFileSignature(const std::wstring& path, std::wstring& signerOut) {
    if (path.empty()) return SignState::Unknown;
    if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES) return SignState::Missing;

    WINTRUST_FILE_INFO fi;
    ZeroMemory(&fi, sizeof(fi));
    fi.cbStruct = sizeof(fi);
    fi.pcwszFilePath = path.c_str();

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA wd;
    ZeroMemory(&wd, sizeof(wd));
    wd.cbStruct            = sizeof(wd);
    wd.dwUIChoice          = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice       = WTD_CHOICE_FILE;
    wd.pFile               = &fi;
    wd.dwStateAction       = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags         = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL;

    LONG res = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &action, &wd);
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &action, &wd);

    SignState state;
    if (res == ERROR_SUCCESS)                          state = SignState::Signed;
    else if ((DWORD)res == (DWORD)TRUST_E_NOSIGNATURE) state = SignState::Unsigned;
    else if ((DWORD)res == (DWORD)TRUST_E_BAD_DIGEST ||
             (DWORD)res == (DWORD)CERT_E_REVOKED ||
             (DWORD)res == (DWORD)CERT_E_EXPIRED ||
             (DWORD)res == (DWORD)CERT_E_UNTRUSTEDROOT) state = SignState::Invalid;
    else                                               state = SignState::Unsigned;

    if (state == SignState::Signed) {
        HCERTSTORE  store = nullptr;
        HCRYPTMSG   msg   = nullptr;
        DWORD encoding = 0, contentType = 0, formatType = 0;
        if (CryptQueryObject(CERT_QUERY_OBJECT_FILE, path.c_str(),
                             CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                             CERT_QUERY_FORMAT_FLAG_BINARY, 0, &encoding, &contentType,
                             &formatType, &store, &msg, nullptr)) {
            DWORD infoSize = 0;
            if (CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &infoSize) && infoSize) {
                std::vector<BYTE> buf(infoSize);
                if (CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, buf.data(), &infoSize)) {
                    auto* si = reinterpret_cast<CMSG_SIGNER_INFO*>(buf.data());
                    CERT_INFO ci;
                    ZeroMemory(&ci, sizeof(ci));
                    ci.Issuer       = si->Issuer;
                    ci.SerialNumber = si->SerialNumber;
                    PCCERT_CONTEXT cert = CertFindCertificateInStore(
                        store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
                        CERT_FIND_SUBJECT_CERT, &ci, nullptr);
                    if (cert) {
                        DWORD n = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0,
                                                     nullptr, nullptr, 0);
                        if (n > 1) {
                            std::wstring name(n, L'\0');
                            CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr,
                                               &name[0], n);
                            name.resize(wcslen(name.c_str()));
                            signerOut = name;
                        }
                        CertFreeCertificateContext(cert);
                    }
                }
            }
            if (msg)   CryptMsgClose(msg);
            if (store) CertCloseStore(store, 0);
        }
        std::wstring low = ToLower(signerOut);
        if (low.find(L"microsoft") != std::wstring::npos) state = SignState::SignedMicrosoft;
    }
    return state;
}

static void ReadVersionInfo(const std::wstring& path, ProcDetails& d) {
    if (path.empty()) return;
    DWORD dummy = 0;
    DWORD size = GetFileVersionInfoSizeW(path.c_str(), &dummy);
    if (!size) return;
    std::vector<BYTE> buf(size);
    if (!GetFileVersionInfoW(path.c_str(), 0, size, buf.data())) return;

    struct LangCp { WORD lang, cp; } *tr = nullptr;
    UINT trLen = 0;
    if (!VerQueryValueW(buf.data(), L"\\VarFileInfo\\Translation", (LPVOID*)&tr, &trLen) || !tr || trLen < 4)
        return;

    wchar_t sub[128];
    auto q = [&](const wchar_t* field) -> std::wstring {
        swprintf(sub, 128, L"\\StringFileInfo\\%04x%04x\\%s", tr[0].lang, tr[0].cp, field);
        wchar_t* val = nullptr;
        UINT len = 0;
        if (VerQueryValueW(buf.data(), sub, (LPVOID*)&val, &len) && val && len)
            return std::wstring(val, wcsnlen(val, len));
        return L"";
    };
    d.company     = Trim(q(L"CompanyName"));
    d.product     = Trim(q(L"ProductName"));
    d.description = Trim(q(L"FileDescription"));
    d.fileVersion = Trim(q(L"FileVersion"));
}

static void ReadFileStamp(const std::wstring& path, ProcDetails& d) {
    WIN32_FILE_ATTRIBUTE_DATA fa;
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fa)) return;
    ULARGE_INTEGER sz;  sz.LowPart = fa.nFileSizeLow;  sz.HighPart = fa.nFileSizeHigh;
    d.fileSize = sz.QuadPart;
    ULARGE_INTEGER t; t.LowPart = fa.ftLastWriteTime.dwLowDateTime; t.HighPart = fa.ftLastWriteTime.dwHighDateTime;
    d.fileTime = (t.QuadPart > 116444736000000000ULL) ? (t.QuadPart - 116444736000000000ULL) / 10000ULL : 0;
}

static std::wstring ReadCommandLine(HANDLE hProc) {
    auto fn = Nt().QueryProc;
    if (!fn || !hProc) return L"";

    PROCESS_BASIC_INFORMATION pbi;
    ZeroMemory(&pbi, sizeof(pbi));
    ULONG ret = 0;
    if (fn(hProc, 0 , &pbi, sizeof(pbi), &ret) != 0) return L"";
    if (!pbi.PebBaseAddress) return L"";

    SIZE_T rd = 0;
    PVOID paramsPtr = nullptr;
    BYTE* peb = reinterpret_cast<BYTE*>(pbi.PebBaseAddress);
    if (!ReadProcessMemory(hProc, peb + 0x20, &paramsPtr, sizeof(paramsPtr), &rd) || !paramsPtr)
        return L"";

    UNICODE_STRING us;
    ZeroMemory(&us, sizeof(us));
    if (!ReadProcessMemory(hProc, reinterpret_cast<BYTE*>(paramsPtr) + 0x70, &us, sizeof(us), &rd))
        return L"";
    if (!us.Buffer || us.Length == 0 || us.Length > 32768) return L"";

    std::wstring cmd(us.Length / sizeof(wchar_t), L'\0');
    if (!ReadProcessMemory(hProc, us.Buffer, &cmd[0], us.Length, &rd)) return L"";
    cmd.resize(wcsnlen(cmd.c_str(), cmd.size()));
    return cmd;
}

static std::wstring TokenUserName(HANDLE hProc) {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(hProc, TOKEN_QUERY, &tok)) return L"";
    DWORD len = 0;
    GetTokenInformation(tok, TokenUser, nullptr, 0, &len);
    if (!len) { CloseHandle(tok); return L""; }
    std::vector<BYTE> buf(len);
    std::wstring out;
    if (GetTokenInformation(tok, TokenUser, buf.data(), len, &len)) {
        auto* tu = reinterpret_cast<TOKEN_USER*>(buf.data());

        static std::mutex sidMtx;
        static std::unordered_map<std::wstring, std::wstring> sidCache;
        LPWSTR sidStr = nullptr;
        std::wstring key;
        if (ConvertSidToStringSidW(tu->User.Sid, &sidStr) && sidStr) { key = sidStr; LocalFree(sidStr); }
        if (!key.empty()) {
            std::lock_guard<std::mutex> lk(sidMtx);
            auto it = sidCache.find(key);
            if (it != sidCache.end()) { CloseHandle(tok); return it->second; }
        }
        wchar_t name[256] = L"", dom[256] = L"";
        DWORD nl = 256, dl = 256;
        SID_NAME_USE use;
        if (LookupAccountSidW(nullptr, tu->User.Sid, name, &nl, dom, &dl, &use))
            out = (dl > 0) ? (std::wstring(dom) + L"\\" + name) : std::wstring(name);
        else
            out = key;
        if (!key.empty()) {
            std::lock_guard<std::mutex> lk(sidMtx);
            sidCache[key] = out;
        }
    }
    CloseHandle(tok);
    return out;
}

static void ReadTokenTraits(HANDLE hProc, ProcDetails& d) {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(hProc, TOKEN_QUERY, &tok)) return;

    TOKEN_ELEVATION el;
    DWORD len = 0;
    if (GetTokenInformation(tok, TokenElevation, &el, sizeof(el), &len))
        d.elevated = (el.TokenIsElevated != 0);

    len = 0;
    GetTokenInformation(tok, TokenIntegrityLevel, nullptr, 0, &len);
    if (len) {
        std::vector<BYTE> buf(len);
        if (GetTokenInformation(tok, TokenIntegrityLevel, buf.data(), len, &len)) {
            auto* til = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(buf.data());
            PUCHAR cnt = GetSidSubAuthorityCount(til->Label.Sid);
            if (cnt && *cnt > 0) {
                DWORD rid = *GetSidSubAuthority(til->Label.Sid, (DWORD)(*cnt - 1));
                if      (rid >= SECURITY_MANDATORY_SYSTEM_RID)    d.integrity = Integrity::System;
                else if (rid >= SECURITY_MANDATORY_HIGH_RID)      d.integrity = Integrity::High;
                else if (rid >= SECURITY_MANDATORY_MEDIUM_RID)    d.integrity = Integrity::Medium;
                else if (rid >= SECURITY_MANDATORY_LOW_RID)       d.integrity = Integrity::Low;
                else                                              d.integrity = Integrity::Untrusted;
            }
        }
    }
    CloseHandle(tok);
}

static unsigned long long FileTimeToUnixMs(const FILETIME& ft) {
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    if (u.QuadPart < 116444736000000000ULL) return 0;
    return (u.QuadPart - 116444736000000000ULL) / 10000ULL;
}

std::wstring FileSha256(const std::wstring& path) {
    if (path.empty()) return L"";
    HANDLE f = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (f == INVALID_HANDLE_VALUE) return L"";

    HCRYPTPROV prov = 0;
    HCRYPTHASH hash = 0;
    std::wstring out;
    if (CryptAcquireContextW(&prov, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) &&
        CryptCreateHash(prov, CALG_SHA_256, 0, 0, &hash)) {
        std::vector<BYTE> buf(64 * 1024);
        DWORD read = 0;
        bool ok = true;
        while (ReadFile(f, buf.data(), (DWORD)buf.size(), &read, nullptr) && read) {
            if (!CryptHashData(hash, buf.data(), read, 0)) { ok = false; break; }
        }
        if (ok) {
            BYTE digest[32];
            DWORD dl = 32;
            if (CryptGetHashParam(hash, HP_HASHVAL, digest, &dl, 0)) {
                static const wchar_t* hex = L"0123456789abcdef";
                out.reserve(64);
                for (DWORD i = 0; i < dl; ++i) {
                    out += hex[digest[i] >> 4];
                    out += hex[digest[i] & 0xF];
                }
            }
        }
    }
    if (hash) CryptDestroyHash(hash);
    if (prov) CryptReleaseContext(prov, 0);
    CloseHandle(f);
    return out;
}

static bool EnableDebugPrivilege() {
    static bool done = false, result = false;
    if (done) return result;
    done = true;
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) return false;
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
        AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), nullptr, nullptr);
        result = (GetLastError() == ERROR_SUCCESS);
    }
    CloseHandle(tok);
    return result;
}

std::vector<DWORD> ChildProcesses(DWORD pid) {
    std::vector<DWORD> kids;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return kids;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ParentProcessID == pid && pe.th32ProcessID != pid)
                kids.push_back(pe.th32ProcessID);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return kids;
}

static bool TaskkillElevated(DWORD pid, bool tree) {
    wchar_t params[128];
    swprintf(params, 128, tree ? L"/F /T /PID %lu" : L"/F /PID %lu", (unsigned long)pid);
    SHELLEXECUTEINFOW si;
    ZeroMemory(&si, sizeof(si));
    si.cbSize       = sizeof(si);
    si.fMask        = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
    si.lpVerb       = L"runas";
    si.lpFile       = L"taskkill.exe";
    si.lpParameters = params;
    si.nShow        = SW_HIDE;
    if (!ShellExecuteExW(&si)) return false;
    bool ok = false;
    if (si.hProcess) {
        WaitForSingleObject(si.hProcess, 8000);
        DWORD code = 1;
        GetExitCodeProcess(si.hProcess, &code);
        ok = (code == 0);
        CloseHandle(si.hProcess);
    }
    return ok;
}

static bool TerminateOne(DWORD pid, DWORD& errOut) {
    EnableDebugPrivilege();
    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!h) { errOut = GetLastError(); return false; }
    BOOL ok = TerminateProcess(h, 1);
    errOut = ok ? 0 : GetLastError();
    if (ok) WaitForSingleObject(h, 3000);
    CloseHandle(h);
    return ok != FALSE;
}

static std::wstring KillErrorText(DWORD err) {
    switch (err) {
        case ERROR_ACCESS_DENIED:      return Tr(L"access denied (may be a protected/system process)");
        case ERROR_INVALID_PARAMETER:  return Tr(L"process already exited");
        case 0:                        return L"";
        default: {
            wchar_t b[64];
            swprintf(b, 64, Tr(L"Windows error code %lu"), (unsigned long)err);
            return b;
        }
    }
}

KillResult KillProcess(DWORD pid, bool allowElevate) {
    KillResult r;
    if (pid <= 4) { r.message = Tr(L"System processes cannot be terminated."); return r; }
    DWORD err = 0;
    if (TerminateOne(pid, err)) { r.ok = true; r.killed = 1; return r; }
    if (err == ERROR_INVALID_PARAMETER) { r.ok = true; r.killed = 0; r.message = Tr(L"Process had already exited."); return r; }
    if (allowElevate && err == ERROR_ACCESS_DENIED && TaskkillElevated(pid, false)) {
        r.ok = true; r.killed = 1; r.message = Tr(L"Terminated with elevated rights.");
        return r;
    }
    r.message = KillErrorText(err);
    return r;
}

KillResult KillProcessTree(DWORD pid, bool allowElevate) {
    KillResult r;
    if (pid <= 4) { r.message = Tr(L"System processes cannot be terminated."); return r; }

    std::vector<DWORD> order;
    std::unordered_set<DWORD> seen{ pid };
    std::deque<DWORD> queue{ pid };
    while (!queue.empty() && order.size() < 512) {
        DWORD cur = queue.front();
        queue.pop_front();
        order.push_back(cur);
        for (DWORD kid : ChildProcesses(cur))
            if (seen.insert(kid).second) queue.push_back(kid);
    }

    DWORD lastErr = 0;
    for (auto it = order.rbegin(); it != order.rend(); ++it) {
        DWORD err = 0;
        if (TerminateOne(*it, err)) r.killed++;
        else if (err != ERROR_INVALID_PARAMETER) lastErr = err;
    }
    if (r.killed > 0) { r.ok = true; return r; }
    if (allowElevate && lastErr == ERROR_ACCESS_DENIED && TaskkillElevated(pid, true)) {
        r.ok = true; r.killed = 1; r.message = Tr(L"Terminated with elevated rights.");
        return r;
    }
    r.message = KillErrorText(lastErr);
    return r;
}

bool SuspendProcess(DWORD pid, bool suspend) {
    if (pid <= 4) return false;
    EnableDebugPrivilege();
    const auto& nt = Nt();
    if (!nt.Suspend || !nt.Resume) return false;
    HANDLE h = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
    if (!h) return false;
    NTSTATUS st = suspend ? nt.Suspend(h) : nt.Resume(h);
    CloseHandle(h);
    return st >= 0;
}

ProcInfoService::ProcInfoService() {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    m_cpuCount = (int)(si.dwNumberOfProcessors ? si.dwNumberOfProcessors : 1);
}
ProcInfoService::~ProcInfoService() { Stop(); }

void ProcInfoService::Start() {
    if (m_run.exchange(true)) return;
    m_thread = std::thread(&ProcInfoService::Worker, this);
}

void ProcInfoService::Stop() {
    if (!m_run.exchange(false)) return;
    m_cv.notify_all();
    if (m_thread.joinable()) m_thread.join();
}

size_t ProcInfoService::CacheSize() {
    std::lock_guard<std::mutex> lk(m_mtx);
    return m_cache.size();
}

void ProcInfoService::Invalidate(DWORD pid) {
    std::lock_guard<std::mutex> lk(m_mtx);
    m_cache.erase(pid);
}

void ProcInfoService::Prune(const std::unordered_set<DWORD>& live) {
    std::lock_guard<std::mutex> lk(m_mtx);
    for (auto it = m_cache.begin(); it != m_cache.end(); ) {
        if (live.count(it->first) == 0) it = m_cache.erase(it);
        else ++it;
    }
}

static void CollectRunKeyValues(HKEY root, const wchar_t* sub, REGSAM extra,
                                std::unordered_set<std::wstring>& out) {
    HKEY k = nullptr;
    if (RegOpenKeyExW(root, sub, 0, KEY_READ | extra, &k) != ERROR_SUCCESS) return;
    for (DWORD i = 0;; ++i) {
        wchar_t vn[256] = L"", vd[4096] = L"";
        DWORD vnl = 256, vdl = 4096;
        LONG rc = RegEnumValueW(k, i, vn, &vnl, nullptr, nullptr, (LPBYTE)vd, &vdl);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc != ERROR_SUCCESS || !vd[0]) continue;
        wchar_t buf[8192] = L"";
        if (!ExpandEnvironmentStringsW(vd, buf, 8192)) continue;
        std::wstring expanded = buf;
        size_t a = expanded.find_first_not_of(L" \t");
        if (a == std::wstring::npos) continue;
        std::wstring path;
        if (expanded[a] == L'"') {
            size_t b = expanded.find(L'"', a + 1);
            if (b == std::wstring::npos) continue;
            path = expanded.substr(a + 1, b - a - 1);
        } else {
            std::wistringstream ss(expanded.substr(a));
            ss >> path;
        }
        if (path.size() >= 4) out.insert(ToLower(path));
    }
    RegCloseKey(k);
}

static void ScanTaskXmls(std::unordered_set<std::wstring>& out) {
    wchar_t dir[MAX_PATH] = L"";
    GetWindowsDirectoryW(dir, MAX_PATH);
    const std::wstring root = std::wstring(dir) + L"\\System32\\Tasks";

    auto scanDir = [&](const std::wstring& path) {
        WIN32_FIND_DATAW fd;
        HANDLE hf = FindFirstFileW((path + L"\\*").c_str(), &fd);
        if (hf == INVALID_HANDLE_VALUE) return;
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            const std::wstring full = path + L"\\" + fd.cFileName;
            HANDLE h = CreateFileW(full.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (h == INVALID_HANDLE_VALUE) continue;
            std::vector<char> data;
            DWORD sz = GetFileSize(h, nullptr);
            if (sz && sz < 1024 * 1024) {
                data.resize(sz + 2);
                DWORD got = 0;
                if (ReadFile(h, data.data(), sz, &got, nullptr) && got) data.resize(got);
                else data.clear();
            }
            CloseHandle(h);
            if (data.empty()) continue;

            std::wstring xml;
            if (data.size() >= 2 && (unsigned char)data[0] == 0xFF && (unsigned char)data[1] == 0xFE) {

                size_t wlen = (data.size() - 2) / 2;
                xml.resize(wlen);
                memcpy(&xml[0], data.data() + 2, wlen * 2);
            } else {
                xml = Widen(std::string(data.begin(), data.end()));
            }

            size_t p = 0;
            while ((p = xml.find(L"<Command>", p)) != std::wstring::npos) {
                size_t s = p + 9;
                size_t e = xml.find(L"</Command>", s);
                if (e == std::wstring::npos) break;
                std::wstring path = Trim(xml.substr(s, e - s));
                if (path.size() >= 2 && path.front() == L'"') {
                    size_t q = path.find(L'"', 1);
                    if (q != std::wstring::npos) path = path.substr(1, q - 1);
                } else {
                    size_t sp = path.find_first_of(L" \t");
                    if (sp != std::wstring::npos) path = path.substr(0, sp);
                }
                wchar_t expBuf[8192] = L"";
                if (ExpandEnvironmentStringsW(path.c_str(), expBuf, 8192)) path = expBuf;
                if (path.size() >= 4) out.insert(ToLower(path));
                p = e + 10;
            }
        } while (FindNextFileW(hf, &fd));
        FindClose(hf);
    };

    scanDir(root);
    WIN32_FIND_DATAW fd;
    HANDLE hf = FindFirstFileW((root + L"\\*").c_str(), &fd);
    if (hf != INVALID_HANDLE_VALUE) {
        do {
            if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                wcscmp(fd.cFileName, L".") && wcscmp(fd.cFileName, L".."))
                scanDir(root + L"\\" + fd.cFileName);
        } while (FindNextFileW(hf, &fd));
        FindClose(hf);
    }
}

static void ScanServiceBinaries(std::unordered_set<std::wstring>& out) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) return;
    DWORD needed = 0, count = 0, resume = 0;
    EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                          nullptr, 0, &needed, &count, &resume, nullptr);
    if (!needed) { CloseServiceHandle(scm); return; }
    std::vector<BYTE> buf(needed + 1024);
    resume = 0;
    if (!EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                               buf.data(), (DWORD)buf.size(), &needed, &count, &resume, nullptr)) {
        CloseServiceHandle(scm);
        return;
    }
    auto* arr = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buf.data());
    for (DWORD i = 0; i < count; ++i) {
        if (!(arr[i].ServiceStatusProcess.dwServiceType & SERVICE_WIN32_OWN_PROCESS)) continue;
        SC_HANDLE svc = OpenServiceW(scm, arr[i].lpServiceName, SERVICE_QUERY_CONFIG);
        if (!svc) continue;
        std::vector<BYTE> cb(8192);
        DWORD need2 = 0;
        if (QueryServiceConfigW(svc, (QUERY_SERVICE_CONFIGW*)cb.data(), 8192, &need2) && need2 &&
            need2 < 8192) {
            auto* q = (QUERY_SERVICE_CONFIGW*)cb.data();
            if (q->lpBinaryPathName && q->lpBinaryPathName[0]) {
                std::wstring p = q->lpBinaryPathName;
                size_t a = p.find_first_not_of(L" \t");
                if (a != std::wstring::npos) {
                    if (p[a] == L'"') {
                        size_t b = p.find(L'"', a + 1);
                        if (b != std::wstring::npos) p = p.substr(a + 1, b - a - 1);
                    } else {
                        std::wistringstream ss(p.substr(a));
                        ss >> p;
                    }
                }
                if (p.size() >= 4) out.insert(ToLower(p));
            }
        }
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
}

void ProcInfoService::RefreshPersistence() {
    const unsigned long long now = NowMs();
    if (m_lastPersistenceScan && now - m_lastPersistenceScan < 30000) return;
    m_lastPersistenceScan = now;

    std::unordered_set<std::wstring> paths;
    CollectRunKeyValues(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, paths);
    CollectRunKeyValues(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", 0, paths);
    CollectRunKeyValues(HKEY_LOCAL_MACHINE,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, paths);
    CollectRunKeyValues(HKEY_LOCAL_MACHINE,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", 0, paths);
    CollectRunKeyValues(HKEY_LOCAL_MACHINE,
        L"Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", 0, paths);

    HRESULT hrCom = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    const bool comOk = SUCCEEDED(hrCom) || hrCom == RPC_E_CHANGED_MODE;
    for (int csidl : { CSIDL_STARTUP, CSIDL_COMMON_STARTUP }) {
        wchar_t dir[MAX_PATH] = L"";
        if (FAILED(SHGetFolderPathW(nullptr, csidl, nullptr, SHGFP_TYPE_CURRENT, dir)) || !dir[0])
            continue;
        std::wstring mask = std::wstring(dir) + L"\\*.lnk";
        WIN32_FIND_DATAW fd;
        HANDLE hf = FindFirstFileW(mask.c_str(), &fd);
        if (hf == INVALID_HANDLE_VALUE) continue;
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                std::wstring full = std::wstring(dir) + L"\\" + fd.cFileName;
                wchar_t target[MAX_PATH] = L"";
                if (comOk) {
                    IShellLinkW* lnk = nullptr;
                    if (SUCCEEDED(CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER,
                                                   IID_IShellLinkW, (void**)&lnk))) {
                        IPersistFile* pf = nullptr;
                        if (SUCCEEDED(lnk->QueryInterface(IID_IPersistFile, (void**)&pf))) {
                            if (SUCCEEDED(pf->Load(full.c_str(), STGM_READ)) &&
                                SUCCEEDED(lnk->GetPath(target, MAX_PATH, nullptr, 0)) && target[0])
                                paths.insert(ToLower(target));
                            pf->Release();
                        }
                        lnk->Release();
                    }
                }
            }
        } while (FindNextFileW(hf, &fd));
        FindClose(hf);
    }
    if (SUCCEEDED(hrCom)) CoUninitialize();

    if (!m_lastTaskScan || now - m_lastTaskScan >= 300000) {
        m_lastTaskScan = now;
        std::lock_guard<std::mutex> lk(m_mtx);
        if (std::find(m_bgJobs.begin(), m_bgJobs.end(), BgJob::TaskScan) == m_bgJobs.end()) {
            m_bgJobs.push_back(BgJob::TaskScan);
            m_cv.notify_all();
        }
    }
    {
        std::lock_guard<std::mutex> lk(m_mtx);
        paths.insert(m_persistTasks.begin(), m_persistTasks.end());
    }

    if (!m_lastSvcBinScan || now - m_lastSvcBinScan >= 60000) {
        m_lastSvcBinScan = now;
        std::lock_guard<std::mutex> lk(m_mtx);
        if (std::find(m_bgJobs.begin(), m_bgJobs.end(), BgJob::SvcScan) == m_bgJobs.end()) {
            m_bgJobs.push_back(BgJob::SvcScan);
            m_cv.notify_all();
        }
    }
    {
        std::lock_guard<std::mutex> lk(m_mtx);
        paths.insert(m_persistServices.begin(), m_persistServices.end());
    }

    std::lock_guard<std::mutex> lk(m_mtx);
    m_persistPaths.swap(paths);

    for (auto& kv : m_cache)
        kv.second.persistent = !kv.second.path.empty() &&
                               m_persistPaths.count(ToLower(kv.second.path)) != 0;
}

void ProcInfoService::RefreshServiceMap() {
    const unsigned long long now = NowMs();
    if (m_lastServiceScan && now - m_lastServiceScan < 5000) return;
    m_lastServiceScan = now;

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) return;

    DWORD needed = 0, count = 0, resume = 0;
    EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                          nullptr, 0, &needed, &count, &resume, nullptr);
    if (needed == 0) { CloseServiceHandle(scm); return; }

    std::vector<BYTE> buf(needed + 1024);
    resume = 0;
    std::unordered_map<DWORD, std::wstring> map;
    if (EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                              buf.data(), (DWORD)buf.size(), &needed, &count, &resume, nullptr)) {
        auto* arr = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buf.data());
        for (DWORD i = 0; i < count; ++i) {
            DWORD pid = arr[i].ServiceStatusProcess.dwProcessId;
            if (!pid || !arr[i].lpServiceName) continue;
            auto& s = map[pid];
            if (s.size() > 90) continue;
            if (!s.empty()) s += L", ";
            s += arr[i].lpServiceName;
        }
    }
    CloseServiceHandle(scm);

    std::lock_guard<std::mutex> lk(m_mtx);
    m_services.swap(map);
}

void ProcInfoService::SampleRuntime() {
    auto qsi = Nt().QuerySys;
    if (!qsi) return;

    ULONG size = 512 * 1024;
    std::vector<BYTE> buf;
    NTSTATUS st = 0;
    for (int attempt = 0; attempt < 6; ++attempt) {
        buf.resize(size);
        ULONG need = 0;
        st = qsi(5 , buf.data(), size, &need);
        if (st >= 0) break;
        size = (need > size) ? (need + 64 * 1024) : (size * 2);
    }
    if (st < 0) return;

    const unsigned long long now = NowMs();
    double dt = (m_lastRtTick && now > m_lastRtTick) ? (double)(now - m_lastRtTick) / 1000.0 : 0.0;
    if (dt > 30.0) dt = 0.0;

    std::unordered_map<DWORD, ProcRuntime> fresh;
    std::unordered_map<DWORD, RtSample>    samples;
    std::unordered_map<DWORD, std::wstring> names;
    fresh.reserve(400);
    double totalCpu = 0.0;

    const BYTE* p = buf.data();
    for (;;) {
        auto* spi = reinterpret_cast<const NL_SYSTEM_PROCESS_INFORMATION*>(p);
        DWORD pid = (DWORD)(ULONG_PTR)spi->UniqueProcessId;

        ProcRuntime rt;
        rt.pid          = pid;
        rt.workingSet   = (unsigned long long)spi->WorkingSetSize;
        rt.privateBytes = (unsigned long long)spi->PrivatePageCount;
        rt.threads      = spi->NumberOfThreads;
        rt.handles      = spi->HandleCount;
        rt.ioRead       = (unsigned long long)spi->ReadTransferCount.QuadPart;
        rt.ioWrite      = (unsigned long long)spi->WriteTransferCount.QuadPart;
        rt.parentPid    = (DWORD)(ULONG_PTR)spi->InheritedFromUniqueProcessId;
        rt.sessionId    = spi->SessionId;
        rt.valid        = true;

        if (spi->ImageName.Buffer && spi->ImageName.Length)
            names[pid] = std::wstring(spi->ImageName.Buffer, spi->ImageName.Length / sizeof(wchar_t));

        if (spi->NumberOfThreads > 0) {
            bool allSusp = true;
            for (ULONG i = 0; i < spi->NumberOfThreads; ++i) {
                const auto& th = spi->Threads[i];
                if (!(th.ThreadState == 5 && th.WaitReason == 5)) { allSusp = false; break; }
            }
            rt.suspended = allSusp;
        }

        RtSample s;
        s.kernel  = (unsigned long long)spi->KernelTime.QuadPart;
        s.user    = (unsigned long long)spi->UserTime.QuadPart;
        s.t       = now;
        s.ioRead  = rt.ioRead;
        s.ioWrite = rt.ioWrite;

        auto prev = m_rtPrev.find(pid);
        if (prev != m_rtPrev.end() && dt > 0.0) {
            unsigned long long dcpu = 0;
            if (s.kernel + s.user >= prev->second.kernel + prev->second.user)
                dcpu = (s.kernel + s.user) - (prev->second.kernel + prev->second.user);

            double cpuSec = (double)dcpu / 10000000.0;
            rt.cpu = (cpuSec / (dt * (double)m_cpuCount)) * 100.0;
            if (rt.cpu < 0.0)   rt.cpu = 0.0;
            if (rt.cpu > 100.0) rt.cpu = 100.0;
            if (pid != 0) totalCpu += rt.cpu;

            if (s.ioRead  >= prev->second.ioRead)
                rt.ioReadRate  = (double)(s.ioRead  - prev->second.ioRead)  / dt;
            if (s.ioWrite >= prev->second.ioWrite)
                rt.ioWriteRate = (double)(s.ioWrite - prev->second.ioWrite) / dt;
        }

        samples[pid] = s;
        fresh[pid]   = rt;

        if (!spi->NextEntryOffset) break;
        p += spi->NextEntryOffset;
        if ((size_t)(p - buf.data()) >= buf.size()) break;
    }

    if (totalCpu > 100.0) totalCpu = 100.0;

    {
        std::lock_guard<std::mutex> lk(m_rtMtx);
        m_runtime.swap(fresh);
        m_rtPrev.swap(samples);
        if (dt > 0.0) m_totalCpu = totalCpu;
        m_lastRtTick = now;
    }

    std::lock_guard<std::mutex> lk(m_mtx);
    for (auto& kv : m_cache) {
        if (kv.second.parentPid && kv.second.parentName.empty()) {
            auto n = names.find(kv.second.parentPid);
            if (n != names.end()) kv.second.parentName = n->second;
        }
    }
}

ProcRuntime ProcInfoService::Runtime(DWORD pid) {
    std::lock_guard<std::mutex> lk(m_rtMtx);
    auto it = m_runtime.find(pid);
    if (it == m_runtime.end()) return ProcRuntime{};
    return it->second;
}

void ProcInfoService::RequestHash(DWORD pid) {
    std::lock_guard<std::mutex> lk(m_mtx);
    auto it = m_cache.find(pid);
    if (it == m_cache.end() || !it->second.sha256.empty() || it->second.path.empty()) return;
    it->second.sha256 = L"…";
    m_hashQueue.push_back(pid);
    m_cv.notify_all();
}

void ProcInfoService::FillFast(ProcDetails& d) {
    if (d.pid == 0) {
        d.name = L"System Idle";
        d.details = d.extended = true;
        d.sign = SignState::SignedMicrosoft;
        d.user = L"NT AUTHORITY\\SYSTEM";
        return;
    }
    if (d.pid == 4) {
        d.name    = L"System";
        d.path    = L"C:\\Windows\\System32\\ntoskrnl.exe";
        d.company = L"Microsoft Corporation";
        d.signer  = L"Microsoft Windows";
        d.sign    = SignState::SignedMicrosoft;
        d.user    = L"NT AUTHORITY\\SYSTEM";
        d.integrity = Integrity::System;
        d.details = d.extended = true;
        return;
    }

    d.name = L"pid " + std::to_wstring(d.pid);
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, d.pid);
    if (!h) h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, d.pid);
    if (h) {
        wchar_t buf[MAX_PATH * 2] = L"";
        DWORD sz = MAX_PATH * 2;
        if (QueryFullProcessImageNameW(h, 0, buf, &sz) && sz) {
            d.path = buf;
            size_t p = d.path.find_last_of(L'\\');
            d.name = (p == std::wstring::npos) ? d.path : d.path.substr(p + 1);
        }
        FILETIME cr, ex, ke, us;
        if (GetProcessTimes(h, &cr, &ex, &ke, &us)) d.startTime = FileTimeToUnixMs(cr);
        BOOL wow = FALSE;
        if (IsWow64Process(h, &wow)) d.is64 = !wow;
        CloseHandle(h);
    }
    if (d.path.empty()) {

        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe;
            pe.dwSize = sizeof(pe);
            if (Process32FirstW(snap, &pe)) {
                do {
                    if (pe.th32ProcessID == d.pid) {
                        d.name      = pe.szExeFile;
                        d.parentPid = pe.th32ParentProcessID;
                        break;
                    }
                } while (Process32NextW(snap, &pe));
            }
            CloseHandle(snap);
        }
    }
}

void ProcInfoService::FillExtended(ProcDetails& d) {
    if (d.pid <= 4) { d.extended = true; return; }
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, d.pid);
    if (!h) h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, d.pid);
    if (!h) h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, d.pid);
    if (h) {
        d.user    = TokenUserName(h);
        d.cmdline = ReadCommandLine(h);
        ReadTokenTraits(h, d);
        CloseHandle(h);
    }
    if (!d.parentPid) {
        auto rt = Runtime(d.pid);
        if (rt.valid) d.parentPid = rt.parentPid;
    }
    d.extended = true;
}

void ProcInfoService::FillHeavy(ProcDetails& d) {
    if (d.path.empty()) { d.details = true; return; }
    ReadFileStamp(d.path, d);
    ReadVersionInfo(d.path, d);
    std::wstring signer;
    d.sign   = VerifyFileSignature(d.path, signer);
    d.signer = signer;

    if (d.sign == SignState::Signed && d.signer.empty()) {
        std::wstring cl = ToLower(d.company);
        std::wstring pl = ToLower(d.path);
        bool sysPath = pl.find(L"\\windows\\") != std::wstring::npos;
        if (cl.find(L"microsoft") != std::wstring::npos && sysPath) {
            d.sign   = SignState::SignedMicrosoft;
            d.signer = Tr(L"Microsoft Windows (catalog)");
        } else {
            d.signer = d.company.empty() ? Tr(L"(catalog signature)") : (d.company + Tr(L" (catalog)"));
        }
    }
    d.details = true;
}

ProcDetails ProcInfoService::Get(DWORD pid) {
    {
        std::lock_guard<std::mutex> lk(m_mtx);
        auto it = m_cache.find(pid);
        if (it != m_cache.end()) {
            auto sv = m_services.find(pid);
            it->second.services = (sv != m_services.end()) ? sv->second : std::wstring();
            return it->second;
        }
    }

    ProcDetails d;
    d.pid = pid;
    FillFast(d);

    std::lock_guard<std::mutex> lk(m_mtx);
    auto again = m_cache.find(pid);
    if (again != m_cache.end()) return again->second;

    if (!d.path.empty()) {
        ReadFileStamp(d.path, d);
        std::wstring key = d.path + L"|" + std::to_wstring(d.fileSize) + L"|" + std::to_wstring(d.fileTime);
        auto pit = m_byPath.find(key);
        if (pit != m_byPath.end()) {
            d.company     = pit->second.company;
            d.product     = pit->second.product;
            d.description = pit->second.description;
            d.fileVersion = pit->second.fileVersion;
            d.signer      = pit->second.signer;
            d.sign        = pit->second.sign;
            d.sha256      = pit->second.sha256;
            d.details     = true;
        }
    }

    auto sv = m_services.find(pid);
    if (sv != m_services.end()) d.services = sv->second;

    if (!d.path.empty())
        d.persistent = m_persistPaths.count(ToLower(d.path)) != 0;

    if (!d.details) d.sign = SignState::Checking;
    m_queue.push_back(pid);
    m_cv.notify_all();

    m_cache[pid] = d;
    return d;
}

void ProcInfoService::Worker() {
    while (m_run.load()) {
        DWORD pid = 0;
        bool hashJob = false;
        {
            std::unique_lock<std::mutex> lk(m_mtx);
            if (!m_bgJobs.empty()) {
                const BgJob job = m_bgJobs.front();
                m_bgJobs.pop_front();
                lk.unlock();

                if (job == BgJob::TaskScan) {
                    std::unordered_set<std::wstring> tasks;
                    ScanTaskXmls(tasks);
                    std::lock_guard<std::mutex> g(m_mtx);
                    m_persistTasks.swap(tasks);
                } else {
                    std::unordered_set<std::wstring> svc;
                    ScanServiceBinaries(svc);
                    std::lock_guard<std::mutex> g(m_mtx);
                    m_persistServices.swap(svc);
                }
                continue;
            }
            if (!m_hashQueue.empty()) {
                pid = m_hashQueue.front();
                m_hashQueue.pop_front();
                hashJob = true;
            } else if (!m_queue.empty()) {
                pid = m_queue.front();
                m_queue.pop_front();
            } else {
                m_cv.wait_for(lk, std::chrono::milliseconds(250));
                continue;
            }
        }

        ProcDetails snapshot;
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            auto it = m_cache.find(pid);
            if (it == m_cache.end()) continue;
            snapshot = it->second;
        }

        if (hashJob) {
            std::wstring h = FileSha256(snapshot.path);
            std::lock_guard<std::mutex> lk(m_mtx);
            auto it = m_cache.find(pid);
            if (it != m_cache.end()) it->second.sha256 = h.empty() ? L"—" : h;
            m_version++;
            continue;
        }

        if (!snapshot.extended) FillExtended(snapshot);
        if (!snapshot.details) {
            if (snapshot.path.empty()) { snapshot.details = true; snapshot.sign = SignState::Unknown; }
            else                       FillHeavy(snapshot);
        }

        {
            std::lock_guard<std::mutex> lk(m_mtx);
            auto it = m_cache.find(pid);
            if (it != m_cache.end()) {
                it->second.company     = snapshot.company;
                it->second.product     = snapshot.product;
                it->second.description = snapshot.description;
                it->second.fileVersion = snapshot.fileVersion;
                it->second.signer      = snapshot.signer;
                it->second.sign        = snapshot.sign;
                it->second.user        = snapshot.user;
                it->second.cmdline     = snapshot.cmdline;
                it->second.integrity   = snapshot.integrity;
                it->second.elevated    = snapshot.elevated;
                it->second.parentPid   = snapshot.parentPid;
                it->second.fileSize    = snapshot.fileSize;
                it->second.fileTime    = snapshot.fileTime;
                it->second.details     = true;
                it->second.extended    = true;
            }
            if (!snapshot.path.empty()) {
                std::wstring key = snapshot.path + L"|" + std::to_wstring(snapshot.fileSize) +
                                   L"|" + std::to_wstring(snapshot.fileTime);
                m_byPath[key] = snapshot;
                if (m_byPath.size() > 4096) m_byPath.clear();
            }
        }
        m_version++;
    }
}

}
