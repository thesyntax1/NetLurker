#pragma once
#include "common.h"
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <thread>
#include <atomic>
#include <deque>
#include <condition_variable>

namespace nl {

enum class SignState { Unknown = 0, Checking, Signed, SignedMicrosoft, Unsigned, Invalid, Missing };

const wchar_t* SignStateText(SignState s);

enum class Integrity { Unknown = 0, Untrusted, Low, Medium, High, System };
const wchar_t* IntegrityText(Integrity i);

struct ProcDetails {
    DWORD        pid = 0;
    std::wstring name;
    std::wstring path;
    std::wstring cmdline;
    std::wstring user;
    std::wstring services;
    std::wstring company;
    std::wstring product;
    std::wstring description;
    std::wstring fileVersion;
    std::wstring signer;
    std::wstring sha256;
    SignState    sign = SignState::Unknown;
    Integrity    integrity = Integrity::Unknown;
    bool         elevated = false;
    unsigned long long startTime = 0;
    unsigned long long fileSize  = 0;
    unsigned long long fileTime  = 0;
    DWORD        parentPid = 0;
    std::wstring parentName;
    bool         persistent = false;
    bool         details  = false;
    bool         extended = false;
    bool         is64 = true;
    bool         dead = false;

    std::wstring Publisher() const;
    std::wstring SignText() const;
    std::wstring DisplayName() const;
    std::wstring AgeText() const;
};

struct ProcRuntime {
    DWORD  pid = 0;
    double cpu = 0.0;
    unsigned long long workingSet = 0;
    unsigned long long privateBytes = 0;
    unsigned long threads = 0;
    unsigned long handles = 0;
    unsigned long long ioRead = 0;
    unsigned long long ioWrite = 0;
    double ioReadRate = 0.0;
    double ioWriteRate = 0.0;
    DWORD  parentPid = 0;
    DWORD  sessionId = 0;
    bool   suspended = false;
    bool   valid = false;
};

class ProcInfoService {
public:
    ProcInfoService();
    ~ProcInfoService();

    void Start();
    void Stop();

    ProcDetails Get(DWORD pid);
    void        Invalidate(DWORD pid);
    void        RefreshServiceMap();
    void        RefreshPersistence();
    void        Prune(const std::unordered_set<DWORD>& live);
    unsigned long Version() const { return m_version.load(); }
    size_t      CacheSize();

    void        SampleRuntime();
    ProcRuntime Runtime(DWORD pid);
    double      TotalCpu() const { return m_totalCpu; }

    void        RequestHash(DWORD pid);

private:
    void Worker();
    void FillFast(ProcDetails& d);
    void FillExtended(ProcDetails& d);
    void FillHeavy(ProcDetails& d);

    struct RtSample {
        unsigned long long kernel = 0, user = 0, t = 0;
        unsigned long long ioRead = 0, ioWrite = 0;
    };

    std::unordered_map<DWORD, ProcDetails>        m_cache;
    std::unordered_map<std::wstring, ProcDetails> m_byPath;
    std::unordered_map<DWORD, std::wstring>       m_services;
    std::unordered_map<DWORD, ProcRuntime>        m_runtime;
    std::unordered_map<DWORD, RtSample>           m_rtPrev;
    std::unordered_set<std::wstring>              m_persistPaths;
    std::unordered_set<std::wstring>              m_persistTasks;
    std::unordered_set<std::wstring>              m_persistServices;
    std::deque<DWORD>        m_queue;
    std::deque<DWORD>        m_hashQueue;
    enum class BgJob { TaskScan, SvcScan };
    std::deque<BgJob>        m_bgJobs;
    std::mutex               m_mtx;
    std::mutex               m_rtMtx;
    std::condition_variable  m_cv;
    std::thread              m_thread;
    std::atomic<bool>        m_run{false};
    std::atomic<unsigned long> m_version{0};
    unsigned long long       m_lastServiceScan = 0;
    unsigned long long       m_lastPersistenceScan = 0;
    unsigned long long       m_lastTaskScan = 0;
    unsigned long long       m_lastSvcBinScan = 0;
    unsigned long long       m_lastRtTick = 0;
    double                   m_totalCpu = 0.0;
    int                      m_cpuCount = 1;
};

struct KillResult {
    bool ok = false;
    int  killed = 0;
    std::wstring message;
};

KillResult KillProcess(DWORD pid, bool allowElevate);

KillResult KillProcessTree(DWORD pid, bool allowElevate);

bool SuspendProcess(DWORD pid, bool suspend);
bool IsProcessSuspended(DWORD pid);

std::vector<DWORD> ChildProcesses(DWORD pid);

std::wstring FileSha256(const std::wstring& path);

}
