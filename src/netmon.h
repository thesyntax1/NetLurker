#pragma once
#include "common.h"
#include "procinfo.h"
#include <map>
#include <unordered_map>
#include <unordered_set>

namespace nl {

enum class Proto { TCP4, TCP6, UDP4, UDP6 };

enum class Risk { Safe = 0, Info = 1, Warn = 2, Danger = 3 };

struct Conn {
    Proto        proto      = Proto::TCP4;
    std::wstring localIp;
    std::wstring remoteIp;
    unsigned short localPort  = 0;
    unsigned short remotePort = 0;
    DWORD        state      = 0;
    DWORD        pid        = 0;

    std::wstring procName   = L"?";
    std::wstring procPath;
    std::wstring publisher;
    std::wstring services;
    std::wstring user;
    SignState    sign       = SignState::Unknown;

    unsigned long long bytesIn  = 0;
    unsigned long long bytesOut = 0;
    double       rateIn     = 0.0;
    double       rateOut    = 0.0;
    unsigned int rttMs      = 0;
    unsigned int retrans    = 0;

    std::wstring module;

    std::wstring country;
    std::wstring countryCode;
    std::wstring city;
    std::wstring region;
    std::wstring org;
    std::wstring asn;
    std::wstring asname;
    std::wstring host;
    bool         isHosting = false;
    bool         isProxy   = false;
    bool         isMobile  = false;
    bool         geoPending  = false;

    bool         threatIncomplete = true;
    int          threatScore  = -1;
    int          threatReports= 0;
    unsigned long long threatLastReport = 0;
    bool         threatTor    = false;
    std::wstring threatDnsbl;
    bool         threatDnsblIncomplete = true;
    int          pluginRisk = -1;
    std::wstring pluginNote;
    int          threatPdns   = -1;
    std::wstring threatPdnsNames;
    bool         threatPending = false;

    std::wstring rdapName;
    std::wstring rdapOrg;
    std::wstring rdapAbuse;
    std::wstring rdapCidr;
    unsigned long long rdapRegistered = 0;
    int          vtMalicious  = 0;
    int          vtSuspicious = 0;
    int          vtTotal      = 0;
    int          vtReputation = 0;

    std::wstring domain;
    bool         hostsRedirect = false;

    std::wstring banner;
    std::wstring bannerStatus;
    bool         bannerPending = false;

    std::wstring certIssuer;
    std::wstring certSubject;
    std::wstring certSans;
    std::wstring certThumbprint;
    std::wstring certVersion;
    unsigned long long certNotAfter = 0;
    bool         certSelfSigned = false;
    bool         certExpired    = false;
    bool         certNotYetValid= false;
    bool         certMismatch   = false;
    bool         certPending    = false;

    Risk         risk       = Risk::Safe;
    int          riskScore  = 0;
    std::wstring riskReason;

    double       procCpu   = 0.0;
    unsigned long long procRam = 0;
    bool         procSuspended = false;

    bool         isRemotePublic = false;
    bool         isNew          = false;
    unsigned long long firstSeen = 0;
    unsigned long long createTs  = 0;
    unsigned long long ageMs     = 0;
    bool               ageExact  = false;
    unsigned long long geoTs     = 0;
    unsigned long long threatTs  = 0;
    unsigned long long certTs    = 0;
    unsigned long long bannerTs  = 0;
    bool               fwBlocked = false;

    std::wstring Key() const;
    std::wstring ProtoText() const;
    std::wstring StateText() const;
    std::wstring LocalText() const;
    std::wstring RemoteText() const;
    std::wstring RiskText() const;
    std::wstring AgeText() const;
    bool IsTcp() const { return proto == Proto::TCP4 || proto == Proto::TCP6; }
    bool IsListening() const;
};

struct AdapterRow {
    std::wstring name;
    std::wstring desc;
    std::wstring ipv4;
    std::wstring mac;
    std::wstring gateway;
    std::wstring dns;
    unsigned long long speed = 0;
    unsigned long long inBytes = 0, outBytes = 0;
    double inRate = 0, outRate = 0;
    bool   up = false;
    bool   loopback = false;
};

struct LanDevice {
    std::wstring ip;
    std::wstring mac;
    std::wstring vendor;
    std::wstring iface;
    bool         active = false;
};

struct PortScanEvent {
    unsigned long long t = 0;
    unsigned short port = 0;
    int count = 0;
    std::wstring sample;
};

struct ProcAgg {
    DWORD pid = 0;
    std::wstring name;
    double rateIn = 0, rateOut = 0;
    int connCount = 0;
};

struct RiskContext {
    int  distinctRemotes = 0;
    int  listenPorts     = 0;
    bool procIsNew       = false;
    bool suspended       = false;
    bool persistent      = false;
    int  beaconHits      = 0;
    int  beaconPeriodSec = 0;
    unsigned long long nowMs = 0;
};

class NetMonitor {
public:
    NetMonitor();
    ~NetMonitor();

    void Refresh();

    std::vector<Conn>& Connections()             { return m_conns; }
    const std::vector<Conn>& Connections() const { return m_conns; }
    double TotalRateIn()  const { return m_totalIn; }
    double TotalRateOut() const { return m_totalOut; }
    unsigned long long SessionBytesIn()  const { return m_sessionIn; }
    unsigned long long SessionBytesOut() const { return m_sessionOut; }

    double SystemRateIn()  const { return m_sysIn; }
    double SystemRateOut() const { return m_sysOut; }
    unsigned long long SystemBytesIn()  const { return m_sysBytesIn; }
    unsigned long long SystemBytesOut() const { return m_sysBytesOut; }
    const std::vector<AdapterRow>& Adapters() const { return m_adapters; }
    bool   EstatsAvailable() const { return m_estatsOk; }
    ProcInfoService& Procs() { return m_procInfo; }

    const std::vector<LanDevice>& LanDevices() const { return m_lan; }
    size_t LanDevicesActive() const {
        size_t n = 0;
        for (const auto& d : m_lan) if (d.active) n++;
        return n;
    }
    const std::vector<PortScanEvent>& PortScanEvents() const { return m_scanEvents; }
    int    SynRcvdCount() const { return m_synRcvd; }
    void   ClearPortScanEvents() { m_scanEvents.clear(); }

private:
    struct Sample { unsigned long long in = 0, out = 0, t = 0; };

    void SampleInterfaces();
    void CollectTcp4(std::vector<Conn>&);
    void CollectTcp6(std::vector<Conn>&);
    void CollectUdp4(std::vector<Conn>&);
    void CollectUdp6(std::vector<Conn>&);
    void FillProcess(Conn&);
    void ScanArp();
    void ScanPortScans(const std::vector<Conn>& conns);

    std::vector<Conn> m_conns;
    std::unordered_map<std::wstring, Sample>     m_samples;
    std::unordered_map<std::wstring, unsigned long long> m_firstSeen;

    std::unordered_map<std::wstring, std::vector<unsigned long long>> m_beacon;
    ProcInfoService m_procInfo;
    unsigned long long m_lastTick = 0;
    bool               m_firstRefresh = true;
    unsigned long long m_watchedSince = 0;
    double m_totalIn = 0, m_totalOut = 0;
    unsigned long long m_sessionIn = 0, m_sessionOut = 0;
    double m_sysIn = 0, m_sysOut = 0;
    unsigned long long m_sysBytesIn = 0, m_sysBytesOut = 0;
    unsigned long long m_prevIfIn = 0, m_prevIfOut = 0;
    unsigned long long m_lastIfTick = 0;
    std::vector<AdapterRow> m_adapters;
    unsigned long long m_lastAdapterScan = 0;
    std::vector<LanDevice> m_lan;
    unsigned long long m_lastArpScan = 0;
    std::vector<PortScanEvent> m_scanEvents;
    int    m_synRcvd = 0;
    bool   m_estatsOk = false;
    bool   m_isAdmin  = false;
};

void EvaluateRisk(Conn& c, const RiskContext& ctx);
const wchar_t* PortServiceName(unsigned short port);
const wchar_t* PortThreatNote(unsigned short port);

}
