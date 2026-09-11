#include "netmon.h"
#include "dns.h"
#include "banner.h"
#include "i18n.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <tcpestats.h>
#include <psapi.h>
#include <netioapi.h>
#include <tlhelp32.h>
#include <cwchar>
#include <cmath>
#include <cstdio>

namespace nl {

typedef ULONG (WINAPI *PFN_SetPerTcpConnectionEStats)(PMIB_TCPROW, TCP_ESTATS_TYPE, PUCHAR, ULONG, ULONG, ULONG);
typedef ULONG (WINAPI *PFN_GetPerTcpConnectionEStats)(PMIB_TCPROW, TCP_ESTATS_TYPE, PUCHAR, ULONG, ULONG,
                                                      PUCHAR, ULONG, ULONG, PUCHAR, ULONG, ULONG);
typedef ULONG (WINAPI *PFN_SetPerTcp6ConnectionEStats)(PMIB_TCP6ROW, TCP_ESTATS_TYPE, PUCHAR, ULONG, ULONG, ULONG);
typedef ULONG (WINAPI *PFN_GetPerTcp6ConnectionEStats)(PMIB_TCP6ROW, TCP_ESTATS_TYPE, PUCHAR, ULONG, ULONG,
                                                       PUCHAR, ULONG, ULONG, PUCHAR, ULONG, ULONG);

static PFN_SetPerTcpConnectionEStats  g_SetEstats4  = nullptr;
static PFN_GetPerTcpConnectionEStats  g_GetEstats4  = nullptr;
static PFN_SetPerTcp6ConnectionEStats g_SetEstats6  = nullptr;
static PFN_GetPerTcp6ConnectionEStats g_GetEstats6  = nullptr;

typedef ULONG (WINAPI *PFN_GetOwnerModuleFromTcpEntry)(PMIB_TCPROW_OWNER_MODULE,
    TCPIP_OWNER_MODULE_INFO_CLASS, PVOID, ULONG, PULONG);
typedef ULONG (WINAPI *PFN_GetOwnerModuleFromTcp6Entry)(PMIB_TCP6ROW_OWNER_MODULE,
    TCPIP_OWNER_MODULE_INFO_CLASS, PVOID, ULONG, PULONG);
static PFN_GetOwnerModuleFromTcpEntry  g_OwnerMod4 = nullptr;
static PFN_GetOwnerModuleFromTcp6Entry g_OwnerMod6 = nullptr;

struct NL_TCPIP_OWNER_MODULE_BASIC_INFO {
    wchar_t* pModuleName;
    wchar_t* pModulePath;
};

static void LoadEstatsApi() {
    static bool once = false;
    if (once) return;
    once = true;
    HMODULE h = LoadLibraryW(L"iphlpapi.dll");
    if (!h) return;
    g_SetEstats4 = (PFN_SetPerTcpConnectionEStats) (void*)GetProcAddress(h, "SetPerTcpConnectionEStats");
    g_GetEstats4 = (PFN_GetPerTcpConnectionEStats) (void*)GetProcAddress(h, "GetPerTcpConnectionEStats");
    g_SetEstats6 = (PFN_SetPerTcp6ConnectionEStats)(void*)GetProcAddress(h, "SetPerTcp6ConnectionEStats");
    g_GetEstats6 = (PFN_GetPerTcp6ConnectionEStats)(void*)GetProcAddress(h, "GetPerTcp6ConnectionEStats");
    g_OwnerMod4 = (PFN_GetOwnerModuleFromTcpEntry) (void*)GetProcAddress(h, "GetOwnerModuleFromTcpEntry");
    g_OwnerMod6 = (PFN_GetOwnerModuleFromTcp6Entry)(void*)GetProcAddress(h, "GetOwnerModuleFromTcp6Entry");
}

static std::wstring BaseName(const std::wstring& path) {
    size_t p = path.find_last_of(L'\\');
    if (p == std::wstring::npos) p = path.find_last_of(L'/');
    return (p == std::wstring::npos) ? path : path.substr(p + 1);
}

template <typename RowT, typename FnT>
static std::wstring OwnerModuleName(RowT& row, FnT fn) {
    if (!fn) return L"";
    ULONG need = 0;
    if (fn(&row, TCPIP_OWNER_MODULE_INFO_BASIC, nullptr, 0, &need) != ERROR_INSUFFICIENT_BUFFER ||
        need == 0)
        return L"";
    std::vector<BYTE> buf(need + 128);
    if (fn(&row, TCPIP_OWNER_MODULE_INFO_BASIC, buf.data(), (ULONG)buf.size(), &need) != NO_ERROR)
        return L"";
    auto* info = reinterpret_cast<NL_TCPIP_OWNER_MODULE_BASIC_INFO*>(buf.data());
    if (!info->pModuleName || !info->pModuleName[0]) return L"";
    return BaseName(info->pModuleName);
}

static std::wstring Ip4ToStr(DWORD addr) {
    in_addr a; a.S_un.S_addr = addr;
    wchar_t buf[64] = L"";
    InetNtopW(AF_INET, &a, buf, 64);
    return buf;
}

static std::wstring Ip6ToStr(const UCHAR addr[16], DWORD scope) {
    in6_addr a; memcpy(&a, addr, 16);
    wchar_t buf[128] = L"";
    InetNtopW(AF_INET6, &a, buf, 128);
    std::wstring s = buf;
    if (scope) { wchar_t sb[24]; swprintf(sb, 24, L"%%%lu", (unsigned long)scope); s += sb; }
    return s;
}

static unsigned short PortOf(DWORD p) { return (unsigned short)ntohs((u_short)(p & 0xFFFF)); }

static bool IsPublicIPv4(DWORD netOrder) {
    unsigned char b[4];
    memcpy(b, &netOrder, 4);
    if (b[0] == 0 || b[0] == 127) return false;
    if (b[0] == 10) return false;
    if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return false;
    if (b[0] == 192 && b[1] == 168) return false;
    if (b[0] == 169 && b[1] == 254) return false;
    if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return false;
    if (b[0] >= 224) return false;
    return true;
}

static bool IsPublicIPv6(const UCHAR a[16]) {
    static const UCHAR zero[16] = {0};
    if (memcmp(a, zero, 16) == 0) return false;
    if (a[0] == 0xFE && (a[1] & 0xC0) == 0x80) return false;
    if ((a[0] & 0xFE) == 0xFC) return false;
    if (a[0] == 0xFF) return false;
    static const UCHAR loop[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    if (memcmp(a, loop, 16) == 0) return false;
    return true;
}

std::wstring Conn::Key() const {
    wchar_t buf[256];
    swprintf(buf, 256, L"%d|%s:%u|%s:%u|%lu", (int)proto, localIp.c_str(), (unsigned)localPort,
             remoteIp.c_str(), (unsigned)remotePort, (unsigned long)pid);
    return buf;
}

std::wstring Conn::ProtoText() const {
    switch (proto) {
        case Proto::TCP4: return L"TCP";
        case Proto::TCP6: return L"TCP6";
        case Proto::UDP4: return L"UDP";
        default:          return L"UDP6";
    }
}

bool Conn::IsListening() const {
    if (IsTcp()) return state == MIB_TCP_STATE_LISTEN;
    return remotePort == 0;
}

std::wstring Conn::StateText() const {
    if (!IsTcp()) return L"—";
    switch (state) {
        case MIB_TCP_STATE_CLOSED:     return L"CLOSED";
        case MIB_TCP_STATE_LISTEN:     return L"LISTEN";
        case MIB_TCP_STATE_SYN_SENT:   return L"SYN_SENT";
        case MIB_TCP_STATE_SYN_RCVD:   return L"SYN_RCVD";
        case MIB_TCP_STATE_ESTAB:      return L"ESTABLISHED";
        case MIB_TCP_STATE_FIN_WAIT1:  return L"FIN_WAIT1";
        case MIB_TCP_STATE_FIN_WAIT2:  return L"FIN_WAIT2";
        case MIB_TCP_STATE_CLOSE_WAIT: return L"CLOSE_WAIT";
        case MIB_TCP_STATE_CLOSING:    return L"CLOSING";
        case MIB_TCP_STATE_LAST_ACK:   return L"LAST_ACK";
        case MIB_TCP_STATE_TIME_WAIT:  return L"TIME_WAIT";
        case MIB_TCP_STATE_DELETE_TCB: return L"DELETE_TCB";
        default:                       return L"?";
    }
}

std::wstring Conn::LocalText() const {
    wchar_t buf[160];
    swprintf(buf, 160, L"%s:%u", localIp.c_str(), (unsigned)localPort);
    return buf;
}

std::wstring Conn::RemoteText() const {
    if (IsListening()) return L"*:*";
    wchar_t buf[160];
    swprintf(buf, 160, L"%s:%u", remoteIp.c_str(), (unsigned)remotePort);
    return buf;
}

std::wstring Conn::RiskText() const {
    switch (risk) {
        case Risk::Danger: return Tr(L"CRITICAL");
        case Risk::Warn:   return Tr(L"SUSPICIOUS");
        case Risk::Info:   return Tr(L"INFO");
        default:           return Tr(L"NORMAL");
    }
}

std::wstring Conn::AgeText() const {
    const std::wstring d = FormatDurationShort(ageMs / 1000);
    return ageExact ? d : (L"\u2265 " + d);
}

struct PortName { unsigned short port; const wchar_t* name; };
static const PortName kKnownPorts[] = {
    {7,L"ECHO"},{19,L"CHARGEN"},{20,L"FTP-DATA"},{21,L"FTP"},{22,L"SSH"},{23,L"TELNET"},
    {25,L"SMTP"},{37,L"TIME"},{42,L"WINS"},{43,L"WHOIS"},{49,L"TACACS"},{53,L"DNS"},
    {67,L"DHCP"},{68,L"DHCP"},{69,L"TFTP"},{70,L"GOPHER"},{79,L"FINGER"},{80,L"HTTP"},
    {81,L"HTTP-ALT"},{88,L"KERBEROS"},{102,L"MS-EXCHANGE"},{110,L"POP3"},{111,L"RPCBIND"},
    {113,L"IDENT"},{119,L"NNTP"},{123,L"NTP"},{135,L"MS-RPC"},{137,L"NETBIOS-NS"},
    {138,L"NETBIOS-DGM"},{139,L"NETBIOS-SSN"},{143,L"IMAP"},{161,L"SNMP"},{162,L"SNMP-TRAP"},
    {177,L"XDMCP"},{179,L"BGP"},{194,L"IRC"},{389,L"LDAP"},{427,L"SLP"},{443,L"HTTPS"},
    {445,L"SMB"},{464,L"KERBEROS"},{465,L"SMTPS"},{500,L"IKE/IPSEC"},{502,L"MODBUS"},
    {514,L"SYSLOG"},{515,L"LPD"},{520,L"RIP"},{523,L"IBM-DB2"},{548,L"AFP"},{554,L"RTSP"},
    {587,L"SMTP-SUB"},{593,L"RPC-HTTP"},{623,L"IPMI"},{631,L"IPP"},{636,L"LDAPS"},
    {664,L"IPMI"},{853,L"DNS-over-TLS"},{873,L"RSYNC"},{902,L"VMWARE"},{989,L"FTPS"},
    {990,L"FTPS"},{993,L"IMAPS"},{995,L"POP3S"},{1080,L"SOCKS"},{1194,L"OpenVPN"},
    {1234,L"VLC/STREAM"},{1241,L"NESSUS"},{1352,L"LOTUS"},{1433,L"MSSQL"},{1434,L"MSSQL-M"},
    {1521,L"ORACLE"},{1701,L"L2TP"},{1723,L"PPTP"},{1755,L"MMS"},{1812,L"RADIUS"},
    {1883,L"MQTT"},{1900,L"SSDP/UPnP"},{2049,L"NFS"},{2082,L"CPANEL"},{2083,L"CPANEL-SSL"},
    {2086,L"WHM"},{2181,L"ZOOKEEPER"},{2375,L"DOCKER"},{2376,L"DOCKER-TLS"},{2379,L"ETCD"},
    {2483,L"ORACLE"},{2967,L"SYMANTEC-AV"},{3000,L"DEV-HTTP"},{3074,L"XBOX-LIVE"},
    {3128,L"SQUID-PROXY"},{3268,L"GLOBAL-CATALOG"},{3283,L"APPLE-ARD"},{3306,L"MYSQL"},
    {3389,L"RDP"},{3478,L"STUN/TURN"},{3479,L"PSN"},{3690,L"SVN"},{4000,L"ICQ/DEV"},
    {4070,L"SPOTIFY"},{4500,L"IPSEC-NAT"},{4505,L"SALTSTACK"},{4506,L"SALTSTACK"},
    {5000,L"UPnP/DEV"},{5001,L"IPERF"},{5004,L"RTP"},{5060,L"SIP"},{5061,L"SIP-TLS"},
    {5222,L"XMPP"},{5223,L"APPLE-PUSH"},{5228,L"GOOGLE-PLAY"},{5349,L"TURNS"},
    {5353,L"mDNS"},{5355,L"LLMNR"},{5432,L"POSTGRESQL"},{5601,L"KIBANA"},{5672,L"AMQP"},
    {5683,L"CoAP"},{5900,L"VNC"},{5938,L"TeamViewer"},{5985,L"WinRM"},{5986,L"WinRM-SSL"},
    {6000,L"X11"},{6379,L"REDIS"},{6443,L"KUBERNETES"},{6881,L"BITTORRENT"},
    {6882,L"BITTORRENT"},{6969,L"BT-TRACKER"},{7070,L"REALSERVER"},{7680,L"WIN-UPDATE-P2P"},
    {8000,L"HTTP-ALT"},{8006,L"PROXMOX"},{8008,L"HTTP-ALT"},{8080,L"HTTP-PROXY"},
    {8081,L"HTTP-ALT"},{8086,L"INFLUXDB"},{8123,L"HOME-ASSISTANT"},{8443,L"HTTPS-ALT"},
    {8883,L"MQTTS"},{8888,L"HTTP-ALT"},{9000,L"HTTP-ALT"},{9090,L"PROMETHEUS"},
    {9100,L"JETDIRECT"},{9200,L"ELASTICSEARCH"},{9418,L"GIT"},{10000,L"WEBMIN"},
    {11211,L"MEMCACHED"},{15672,L"RABBITMQ"},{19132,L"MINECRAFT-BE"},{25565,L"MINECRAFT"},
    {27015,L"STEAM/SRCDS"},{27017,L"MONGODB"},{27036,L"STEAM-P2P"},{32400,L"PLEX"},
    {33434,L"TRACEROUTE"},{47001,L"WinRM-HTTP"},{49152,L"DYNAMIC-RPC"},{50000,L"SAP"},
    {51820,L"WIREGUARD"},{62078,L"iPHONE-SYNC"},
};

const wchar_t* PortServiceName(unsigned short port) {
    for (const auto& p : kKnownPorts) if (p.port == port) return p.name;
    return nullptr;
}

struct BadPort { unsigned short port; int score; const wchar_t* why; };
static const BadPort kBadPorts[] = {
    {23,   40, L"Telnet - unencrypted remote access"},
    {25,   20, L"Direct SMTP - possible spam/bot indicator"},
    {69,   30, L"TFTP - unauthenticated file transfer (loader malware)"},
    {135,  25, L"MS-RPC exposed to the internet - lateral movement risk"},
    {139,  30, L"NetBIOS exposed to the internet"},
    {445,  45, L"SMB exposed to the internet - EternalBlue/ransomware vector"},
    {1080, 30, L"SOCKS proxy tunnel"},
    {1337, 70, L"1337 - classic backdoor port"},
    {1604, 45, L"1604 - DarkComet RAT"},
    {2222, 15, L"Alternate SSH"},
    {3128, 20, L"Egress through an open proxy"},
    {3389, 35, L"RDP exposed to the internet - brute-force target"},
    {3333, 45, L"3333 - crypto mining pool"},
    {4444, 75, L"4444 - Metasploit/Meterpreter default port"},
    {4445, 65, L"4445 - frequently a reverse shell"},
    {4782, 65, L"4782 - Quasar RAT"},
    {5554, 60, L"5554 - Sasser worm"},
    {5555, 40, L"5555 - ADB / mining / RAT"},
    {5900, 30, L"VNC - possibly unencrypted remote desktop"},
    {6666, 60, L"6666 - IRC botnet command channel"},
    {6667, 60, L"6667 - IRC (botnet C2)"},
    {6668, 60, L"6668 - IRC botnet C2"},
    {6669, 60, L"6669 - IRC botnet C2"},
    {7777, 45, L"7777 - mining pool / RAT"},
    {8333, 25, L"8333 - Bitcoin node"},
    {9001, 45, L"9001 - Tor OR port"},
    {9030, 40, L"9030 - Tor directory port"},
    {9050, 45, L"9050 - Tor SOCKS proxy"},
    {9051, 45, L"9051 - Tor control port"},
    {12345,70, L"12345 - NetBus trojan"},
    {12346,70, L"12346 - NetBus trojan"},
    {14444,45, L"14444 - Monero mining pool"},
    {20034,70, L"20034 - NetBus Pro"},
    {27374,70, L"27374 - SubSeven trojan"},
    {31337,80, L"31337 - Back Orifice / 'elite' backdoor"},
    {45700,45, L"45700 - Monero mining pool"},
    {54321,55, L"54321 - BackOrifice2000 / School Bus"},
};

const wchar_t* PortThreatNote(unsigned short port) {
    for (const auto& b : kBadPorts) if (b.port == port) return Tr(b.why);
    return nullptr;
}

static bool PathLooksSuspicious(const std::wstring& pathLower, std::wstring& where) {
    if (pathLower.empty()) return false;
    struct M { const wchar_t* frag; const wchar_t* label; };
    static const M marks[] = {
        { L"\\appdata\\local\\temp\\", L"%TEMP%" },
        { L"\\windows\\temp\\",        L"Windows\\Temp" },
        { L"\\downloads\\",            L"Downloads" },
        { L"\\appdata\\roaming\\",     L"AppData\\Roaming" },
        { L"\\programdata\\",          L"ProgramData" },
        { L"\\users\\public\\",        L"Public" },
        { L"\\recycle",                L"Recycle Bin" },
        { L"\\music\\",                L"Music folder" },
        { L"\\pictures\\",             L"Pictures folder" },
    };
    for (const auto& m : marks)
        if (pathLower.find(m.frag) != std::wstring::npos) { where = Tr(m.label); return true; }
    return false;
}

static bool IsSystemPath(const std::wstring& pathLower) {
    return pathLower.find(L"\\windows\\system32\\") != std::wstring::npos ||
           pathLower.find(L"\\windows\\syswow64\\") != std::wstring::npos ||
           pathLower.find(L"\\program files")       != std::wstring::npos;
}

void EvaluateRisk(Conn& c, const RiskContext& ctx) {
    int score = 0;
    std::vector<std::wstring> reasons;
    auto add = [&](int pts, const std::wstring& why) {
        score += pts;
        reasons.push_back(why);
    };

    const bool listening = c.IsListening();
    const unsigned short focusPort = listening ? c.localPort : c.remotePort;
    const bool outboundPublic = !listening && c.isRemotePublic;

    if (outboundPublic || listening) {
        for (const auto& bp : kBadPorts) {
            if (bp.port != focusPort) continue;
            bool internetFacing = outboundPublic ||
                (listening && (c.localIp == L"0.0.0.0" || c.localIp == L"::"));
            if ((bp.port == 445 || bp.port == 3389 || bp.port == 135 || bp.port == 139 ||
                 bp.port == 5900) && !internetFacing) break;
            add(bp.score, Tr(bp.why));
            break;
        }
    }

    if (outboundPublic && !PortServiceName(c.remotePort) && !PortThreatNote(c.remotePort)) {
        if (c.remotePort >= 1024) add(10, Tr(L"Destination port does not belong to a known service (T1571)"));
        else                      add(15, Tr(L"Rare privileged destination port (T1571)"));
    }

    const std::wstring pl = ToLower(c.procPath);
    switch (c.sign) {
        case SignState::Unsigned:
            add(c.isRemotePublic ? 30 : 15, Tr(L"Executable is not digitally signed"));
            break;
        case SignState::Invalid:
            add(45, Tr(L"Digital signature invalid/corrupt — file may have been tampered with"));
            break;
        case SignState::Missing:
            add(35, Tr(L"Process file not found on disk (deleted/hidden)"));
            break;
        default: break;
    }

    std::wstring where;
    if (PathLooksSuspicious(pl, where)) {
        if (c.isRemotePublic) add(25, where + Tr(L" process reaching the internet from "));
        else                  add(10, where + Tr(L" process running from "));
    } else if (!pl.empty() && !IsSystemPath(pl) && c.isRemotePublic && c.sign == SignState::Unsigned) {
        add(5, Tr(L"Running outside standard program directories"));
    }

    if (c.isProxy)   add(30, Tr(L"Destination IP flagged as proxy/VPN/Tor exit node (T1090)"));
    if (c.isHosting && c.host.empty() && !c.geoPending && c.sign != SignState::SignedMicrosoft)
        add(10, Tr(L"Destination is a datacenter IP without reverse DNS"));

    if (c.threatScore >= 80) {
        std::wstring r = Tr(L"AbuseIPDB abuse score ") + std::to_wstring(c.threatScore) + Tr(L"/100");
        if (c.threatReports > 0) r += Tr(L" (") + std::to_wstring(c.threatReports) + Tr(L" reports)");
        add(35, r);
    } else if (c.threatScore >= 50) {
        std::wstring r = Tr(L"AbuseIPDB abuse score ") + std::to_wstring(c.threatScore) + Tr(L"/100");
        add(20, r);
    } else if (c.threatScore >= 25) {
        add(8, Tr(L"AbuseIPDB low-medium abuse score (") +
               std::to_wstring(c.threatScore) + Tr(L"/100)"));
    }
    if (!c.threatDnsbl.empty() && c.threatDnsbl != L"—")
        add(30, Tr(L"IP is on DNS blacklists: ") + c.threatDnsbl + Tr(L" (spam/abuse source)"));
    if (c.threatTor && !c.isProxy)
        add(15, Tr(L"Destination flagged as Tor exit node"));

    if (c.certSelfSigned) {
        if (c.isHosting)
            add(22, Tr(L"Self-signed TLS certificate on a datacenter IP (no public CA)"));
        else if (!c.certPending)
            add(8, Tr(L"Remote server uses a self-signed certificate"));
    }
    if (c.certExpired)    add(18, Tr(L"Remote server's TLS certificate has expired"));
    if (c.certNotYetValid) add(12, Tr(L"Remote server's TLS certificate is not yet valid"));
    if (c.certMismatch)   add(12, Tr(L"rDNS name does not match TLS certificate name (possible traffic redirection/spoofing)"));

    if (c.hostsRedirect && outboundPublic)
        add(15, Tr(L"Destination IP is manually redirected in the hosts file (may have been modified by software)"));

    if (c.vtMalicious >= 5) {
        std::wstring r = Tr(L"VirusTotal: ") + std::to_wstring(c.vtMalicious) + L"/" +
                         std::to_wstring(c.vtTotal) + Tr(L" engines flagged it malicious");
        add(35, r);
    } else if (c.vtMalicious >= 2) {
        std::wstring r = Tr(L"VirusTotal: ") + std::to_wstring(c.vtMalicious) + L"/" +
                         std::to_wstring(c.vtTotal) + Tr(L" engines flagged it malicious");
        add(20, r);
    } else if (c.vtSuspicious >= 5) {
        add(10, Tr(L"VirusTotal: ") + std::to_wstring(c.vtSuspicious) + Tr(L" engines flagged it suspicious"));
    }

    if (!c.banner.empty() && !c.bannerPending && BannerIsEol(c.banner))
        add(8, Tr(L"Server software is an end-of-life version: ") + c.banner + Tr(L" (EOL infrastructure)"));

    if (listening && (c.localIp == L"0.0.0.0" || c.localIp == L"::")) {
        if (!PortServiceName(c.localPort) && c.localPort >= 1024)
            add(15, Tr(L"Non-standard port listening on all interfaces"));
        if (c.sign == SignState::Unsigned)
            add(15, Tr(L"Unsigned process is accepting external connections"));
    }

    if (c.rateOut > 200 * 1024 && c.rateOut > c.rateIn * 6 && c.isRemotePublic)
        add(20, Tr(L"High outbound/inbound ratio — possible data exfiltration (T1041)"));
    if (c.retrans > 50 && c.rttMs > 0)
        add(5, Tr(L"High packet retransmission — unstable/remote connection"));

    if (ctx.distinctRemotes > 60)
        add(15, Tr(L"Process talks to many different public IPs (possible scanning/botnet)"));
    else if (ctx.distinctRemotes > 25)
        add(5, Tr(L"Process connects to many different destinations"));
    if (ctx.procIsNew && c.isRemotePublic)
        add(5, Tr(L"Newly started process immediately connected outbound"));
    if (ctx.beaconHits >= 4 && ctx.beaconPeriodSec > 0) {
        wchar_t b[160];
        swprintf(b, 160, Tr(L"Repeated connections to the same target every ~%d s (C2 beacon pattern, T1071)"),
                 ctx.beaconPeriodSec);
        add(ctx.beaconPeriodSec <= 120 ? 25 : 12, b);
    }
    if (ctx.suspended && c.isRemotePublic)
        add(10, Tr(L"Suspended process still has an open outbound connection"));
    if (ctx.persistent) {
        if (c.sign == SignState::Unsigned || c.sign == SignState::Invalid ||
            c.sign == SignState::Missing)
            add(18, Tr(L"Unsigned process is registered to auto-start (persistence, T1547)"));
        else if (c.isRemotePublic)
            add(6, Tr(L"Process is registered to auto-start (persistence)"));
    }

    if (c.sign == SignState::SignedMicrosoft) score -= 15;
    else if (c.sign == SignState::Signed)     score -= 10;
    if (!c.isRemotePublic)                    score -= 10;
    if (c.remotePort == 443 || c.remotePort == 80) score -= 5;

    if (score < 0) score = 0;
    if (score > 100) score = 100;

    c.riskScore = score;
    if (score >= 70)      c.risk = Risk::Danger;
    else if (score >= 45) c.risk = Risk::Warn;
    else if (score >= 20) c.risk = Risk::Info;
    else                  c.risk = Risk::Safe;

    if (reasons.empty()) {
        c.riskReason = Tr(L"No notable anomaly");
    } else {
        c.riskReason.clear();
        for (size_t i = 0; i < reasons.size(); ++i) {
            if (i) c.riskReason += L" • ";
            c.riskReason += reasons[i];
        }
    }
}

NetMonitor::NetMonitor() {
    LoadEstatsApi();
    m_isAdmin = IsRunAsAdmin();
    m_lastTick = NowMs();
    m_procInfo.Start();
}
NetMonitor::~NetMonitor() { m_procInfo.Stop(); }

void NetMonitor::FillProcess(Conn& c) {
    ProcDetails d = m_procInfo.Get(c.pid);
    c.procName  = d.name;
    c.procPath  = d.path;
    c.publisher = d.Publisher();
    c.services  = d.services;
    c.user      = d.user;
    c.sign      = d.sign;
}

template <typename RowT, typename GetFn, typename SetFn>
static void ReadEstats(RowT& row, GetFn getFn, SetFn setFn, Conn& c, bool& okFlag) {
    TCP_ESTATS_DATA_ROD_v0 rod;
    ZeroMemory(&rod, sizeof(rod));
    if (getFn(&row, TcpConnectionEstatsData, nullptr, 0, 0, nullptr, 0, 0,
              (PUCHAR)&rod, 0, sizeof(rod)) == NO_ERROR) {
        c.bytesIn  = rod.DataBytesIn;
        c.bytesOut = rod.DataBytesOut;
        okFlag = true;
    } else {
        TCP_ESTATS_DATA_RW_v0 rw;
        ZeroMemory(&rw, sizeof(rw));
        rw.EnableCollection = TRUE;
        setFn(&row, TcpConnectionEstatsData, (PUCHAR)&rw, 0, sizeof(rw), 0);
    }

    TCP_ESTATS_PATH_ROD_v0 prod;
    ZeroMemory(&prod, sizeof(prod));
    if (getFn(&row, TcpConnectionEstatsPath, nullptr, 0, 0, nullptr, 0, 0,
              (PUCHAR)&prod, 0, sizeof(prod)) == NO_ERROR) {
        if (prod.SmoothedRtt < 100000) c.rttMs = (unsigned)prod.SmoothedRtt;
        c.retrans = (unsigned)prod.PktsRetrans;
    } else {
        TCP_ESTATS_PATH_RW_v0 prw;
        ZeroMemory(&prw, sizeof(prw));
        prw.EnableCollection = TRUE;
        setFn(&row, TcpConnectionEstatsPath, (PUCHAR)&prw, 0, sizeof(prw), 0);
    }
}

static unsigned long long FileTimeToUnixMs(const LARGE_INTEGER& li) {
    if (li.QuadPart <= 116444736000000000LL) return 0;
    return (unsigned long long)((li.QuadPart - 116444736000000000LL) / 10000LL);
}

void NetMonitor::CollectTcp4(std::vector<Conn>& out) {
    ULONG size = 0;
    if (GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_MODULE_ALL, 0) != ERROR_INSUFFICIENT_BUFFER)
        return;
    std::vector<char> buf(size);
    if (GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_MODULE_ALL, 0) != NO_ERROR) return;
    auto* t = reinterpret_cast<MIB_TCPTABLE_OWNER_MODULE*>(buf.data());
    for (DWORD i = 0; i < t->dwNumEntries; ++i) {
        auto& r = t->table[i];
        Conn c;
        c.proto      = Proto::TCP4;
        c.localIp    = Ip4ToStr(r.dwLocalAddr);
        c.localPort  = PortOf(r.dwLocalPort);
        c.remoteIp   = Ip4ToStr(r.dwRemoteAddr);
        c.remotePort = PortOf(r.dwRemotePort);
        c.state      = r.dwState;
        c.pid        = r.dwOwningPid;
        c.createTs   = FileTimeToUnixMs(r.liCreateTimestamp);
        c.isRemotePublic = (c.state != MIB_TCP_STATE_LISTEN) && IsPublicIPv4(r.dwRemoteAddr);

        if (m_isAdmin && g_GetEstats4 && g_SetEstats4 && c.state == MIB_TCP_STATE_ESTAB) {
            MIB_TCPROW row;
            ZeroMemory(&row, sizeof(row));
            row.dwState      = r.dwState;
            row.dwLocalAddr  = r.dwLocalAddr;
            row.dwLocalPort  = r.dwLocalPort;
            row.dwRemoteAddr = r.dwRemoteAddr;
            row.dwRemotePort = r.dwRemotePort;
            ReadEstats(row, g_GetEstats4, g_SetEstats4, c, m_estatsOk);
        }
        if (m_isAdmin && c.pid && (c.state == MIB_TCP_STATE_ESTAB || c.state == MIB_TCP_STATE_LISTEN))
            c.module = OwnerModuleName(r, g_OwnerMod4);
        out.push_back(std::move(c));
    }
}

void NetMonitor::CollectTcp6(std::vector<Conn>& out) {
    ULONG size = 0;
    if (GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET6, TCP_TABLE_OWNER_MODULE_ALL, 0) != ERROR_INSUFFICIENT_BUFFER)
        return;
    std::vector<char> buf(size);
    if (GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET6, TCP_TABLE_OWNER_MODULE_ALL, 0) != NO_ERROR) return;
    auto* t = reinterpret_cast<MIB_TCP6TABLE_OWNER_MODULE*>(buf.data());
    for (DWORD i = 0; i < t->dwNumEntries; ++i) {
        auto& r = t->table[i];
        Conn c;
        c.proto      = Proto::TCP6;
        c.localIp    = Ip6ToStr(r.ucLocalAddr, r.dwLocalScopeId);
        c.localPort  = PortOf(r.dwLocalPort);
        c.remoteIp   = Ip6ToStr(r.ucRemoteAddr, r.dwRemoteScopeId);
        c.remotePort = PortOf(r.dwRemotePort);
        c.state      = r.dwState;
        c.pid        = r.dwOwningPid;
        c.createTs   = FileTimeToUnixMs(r.liCreateTimestamp);
        c.isRemotePublic = (c.state != MIB_TCP_STATE_LISTEN) && IsPublicIPv6(r.ucRemoteAddr);

        if (m_isAdmin && g_GetEstats6 && g_SetEstats6 && c.state == MIB_TCP_STATE_ESTAB) {
            MIB_TCP6ROW row;
            ZeroMemory(&row, sizeof(row));
            row.State = (MIB_TCP_STATE)r.dwState;
            memcpy(&row.LocalAddr,  r.ucLocalAddr, 16);
            memcpy(&row.RemoteAddr, r.ucRemoteAddr, 16);
            row.dwLocalScopeId  = r.dwLocalScopeId;
            row.dwLocalPort     = r.dwLocalPort;
            row.dwRemoteScopeId = r.dwRemoteScopeId;
            row.dwRemotePort    = r.dwRemotePort;
            ReadEstats(row, g_GetEstats6, g_SetEstats6, c, m_estatsOk);
        }
        if (m_isAdmin && c.pid && (c.state == MIB_TCP_STATE_ESTAB || c.state == MIB_TCP_STATE_LISTEN))
            c.module = OwnerModuleName(r, g_OwnerMod6);
        out.push_back(std::move(c));
    }
}

void NetMonitor::CollectUdp4(std::vector<Conn>& out) {
    ULONG size = 0;
    if (GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET, UDP_TABLE_OWNER_MODULE, 0) != ERROR_INSUFFICIENT_BUFFER)
        return;
    std::vector<char> buf(size);
    if (GetExtendedUdpTable(buf.data(), &size, FALSE, AF_INET, UDP_TABLE_OWNER_MODULE, 0) != NO_ERROR) return;
    auto* t = reinterpret_cast<MIB_UDPTABLE_OWNER_MODULE*>(buf.data());
    for (DWORD i = 0; i < t->dwNumEntries; ++i) {
        const auto& r = t->table[i];
        Conn c;
        c.proto     = Proto::UDP4;
        c.localIp   = Ip4ToStr(r.dwLocalAddr);
        c.localPort = PortOf(r.dwLocalPort);
        c.remoteIp  = L"0.0.0.0";
        c.pid       = r.dwOwningPid;
        c.createTs  = FileTimeToUnixMs(r.liCreateTimestamp);
        out.push_back(std::move(c));
    }
}

void NetMonitor::CollectUdp6(std::vector<Conn>& out) {
    ULONG size = 0;
    if (GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET6, UDP_TABLE_OWNER_MODULE, 0) != ERROR_INSUFFICIENT_BUFFER)
        return;
    std::vector<char> buf(size);
    if (GetExtendedUdpTable(buf.data(), &size, FALSE, AF_INET6, UDP_TABLE_OWNER_MODULE, 0) != NO_ERROR) return;
    auto* t = reinterpret_cast<MIB_UDP6TABLE_OWNER_MODULE*>(buf.data());
    for (DWORD i = 0; i < t->dwNumEntries; ++i) {
        const auto& r = t->table[i];
        Conn c;
        c.proto     = Proto::UDP6;
        c.localIp   = Ip6ToStr(r.ucLocalAddr, r.dwLocalScopeId);
        c.localPort = PortOf(r.dwLocalPort);
        c.remoteIp  = L"::";
        c.pid       = r.dwOwningPid;
        c.createTs  = FileTimeToUnixMs(r.liCreateTimestamp);
        out.push_back(std::move(c));
    }
}

static void FillAdapterGateways(std::vector<AdapterRow>& rows);

void NetMonitor::SampleInterfaces() {
    typedef NETIO_STATUS (WINAPI *PFN_GetIfTable2)(PMIB_IF_TABLE2*);
    typedef VOID (WINAPI *PFN_FreeMibTable)(PVOID);
    static PFN_GetIfTable2 pGetIfTable2 = nullptr;
    static PFN_FreeMibTable pFreeMibTable = nullptr;
    static bool loaded = false;
    if (!loaded) {
        loaded = true;
        HMODULE h = GetModuleHandleW(L"iphlpapi.dll");
        if (!h) h = LoadLibraryW(L"iphlpapi.dll");
        if (h) {
            pGetIfTable2  = (PFN_GetIfTable2) (void*)GetProcAddress(h, "GetIfTable2");
            pFreeMibTable = (PFN_FreeMibTable)(void*)GetProcAddress(h, "FreeMibTable");
        }
    }
    if (!pGetIfTable2 || !pFreeMibTable) return;

    PMIB_IF_TABLE2 table = nullptr;
    if (pGetIfTable2(&table) != NO_ERROR || !table) return;

    unsigned long long totIn = 0, totOut = 0;
    const unsigned long long now = NowMs();
    const bool refreshList = (m_lastAdapterScan == 0 || now - m_lastAdapterScan > 4000);
    std::vector<AdapterRow> rows;

    for (ULONG i = 0; i < table->NumEntries; ++i) {
        const MIB_IF_ROW2& r = table->Table[i];
        const bool loopback = (r.Type == IF_TYPE_SOFTWARE_LOOPBACK);
        const bool up = (r.OperStatus == IfOperStatusUp);
        if (!loopback && r.InterfaceAndOperStatusFlags.FilterInterface == 0) {
            totIn  += r.InOctets;
            totOut += r.OutOctets;
        }
        if (refreshList && !loopback && (up || r.InOctets || r.OutOctets)) {
            AdapterRow a;
            a.name     = r.Alias;
            a.desc     = r.Description;
            a.speed    = (r.ReceiveLinkSpeed > r.TransmitLinkSpeed) ? r.ReceiveLinkSpeed : r.TransmitLinkSpeed;
            a.inBytes  = r.InOctets;
            a.outBytes = r.OutOctets;
            a.up       = up;
            a.loopback = loopback;
            if (r.PhysicalAddressLength >= 6) {
                wchar_t mac[32];
                swprintf(mac, 32, L"%02X:%02X:%02X:%02X:%02X:%02X",
                         r.PhysicalAddress[0], r.PhysicalAddress[1], r.PhysicalAddress[2],
                         r.PhysicalAddress[3], r.PhysicalAddress[4], r.PhysicalAddress[5]);
                a.mac = mac;
            }
            rows.push_back(std::move(a));
        }
    }
    pFreeMibTable(table);

    if (m_lastIfTick && now > m_lastIfTick) {
        double dt = (double)(now - m_lastIfTick) / 1000.0;
        if (dt >= 0.05 && dt <= 30.0) {
            if (totIn  >= m_prevIfIn)  {
                unsigned long long d = totIn - m_prevIfIn;
                m_sysIn = (double)d / dt;
                m_sysBytesIn += d;
            }
            if (totOut >= m_prevIfOut) {
                unsigned long long d = totOut - m_prevIfOut;
                m_sysOut = (double)d / dt;
                m_sysBytesOut += d;
            }
        }
    }
    m_prevIfIn   = totIn;
    m_prevIfOut  = totOut;
    m_lastIfTick = now;

    if (refreshList) {
        FillAdapterGateways(rows);
        m_lastAdapterScan = now;
        m_adapters.swap(rows);
    }
}

static void FillAdapterGateways(std::vector<AdapterRow>& rows) {
    ULONG size = 0;
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                             nullptr, nullptr, &size) != ERROR_BUFFER_OVERFLOW)
        return;
    std::vector<BYTE> buf(size);
    auto* head = (IP_ADAPTER_ADDRESSES*)buf.data();
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                             nullptr, head, &size) != NO_ERROR)
        return;

    auto sockText = [](const SOCKADDR* sa) -> std::wstring {
        wchar_t ip[64] = L"";
        if (sa->sa_family == AF_INET)
            InetNtopW(AF_INET, &((const sockaddr_in*)sa)->sin_addr, ip, 64);
        else if (sa->sa_family == AF_INET6)
            InetNtopW(AF_INET6, &((const sockaddr_in6*)sa)->sin6_addr, ip, 64);
        return ip;
    };

    for (auto* a = head; a; a = a->Next) {
        AdapterRow* target = nullptr;
        for (auto& row : rows)
            if (row.desc == a->Description) { target = &row; break; }
        if (!target) continue;

        std::wstring gw;
        for (auto* g = a->FirstGatewayAddress; g; g = g->Next) {
            std::wstring ip = sockText(g->Address.lpSockaddr);
            if (ip.empty()) continue;
            if (!gw.empty()) gw += L", ";
            gw += ip;
            if (gw.size() > 90) break;
        }
        target->gateway = gw;

        std::wstring dns;
        for (auto* d = a->FirstDnsServerAddress; d; d = d->Next) {
            std::wstring ip = sockText(d->Address.lpSockaddr);
            if (ip.empty()) continue;
            if (!dns.empty()) dns += L", ";
            dns += ip;
            if (dns.size() > 130) break;
        }
        target->dns = dns;
    }
}

void NetMonitor::ScanArp() {
    const unsigned long long now = NowMs();
    if (m_lastArpScan && now - m_lastArpScan < 10000) return;
    m_lastArpScan = now;

    typedef NETIO_STATUS (WINAPI* PFN_GetIpNetTable2)(ADDRESS_FAMILY, PMIB_IPNET_TABLE2*);
    typedef VOID (WINAPI* PFN_FreeMibTable)(PVOID);
    static PFN_GetIpNetTable2 pGetIpNetTable2 = nullptr;
    static PFN_FreeMibTable pFree = nullptr;
    static bool loaded = false;
    if (!loaded) {
        loaded = true;
        HMODULE h = GetModuleHandleW(L"iphlpapi.dll");
        if (!h) h = LoadLibraryW(L"iphlpapi.dll");
        if (h) {
            pGetIpNetTable2 = (PFN_GetIpNetTable2)(void*)GetProcAddress(h, "GetIpNetTable2");
            pFree = (PFN_FreeMibTable)(void*)GetProcAddress(h, "FreeMibTable");
        }
    }
    if (!pGetIpNetTable2 || !pFree) return;

    std::vector<LanDevice> devs;
    for (ADDRESS_FAMILY fam : { (ADDRESS_FAMILY)AF_INET, (ADDRESS_FAMILY)AF_INET6 }) {
        PMIB_IPNET_TABLE2 t = nullptr;
        if (pGetIpNetTable2(fam, &t) != NO_ERROR || !t) continue;
        for (ULONG i = 0; i < t->NumEntries; ++i) {
            const MIB_IPNET_ROW2& r = t->Table[i];
            if (r.State == NlnsUnreachable || r.State == NlnsIncomplete) continue;
            if (r.PhysicalAddressLength < 6) continue;
            bool zero = true;
            for (ULONG b = 0; b < r.PhysicalAddressLength; ++b)
                if (r.PhysicalAddress[b]) { zero = false; break; }
            if (zero) continue;
            wchar_t ip[64] = L"";
            if (fam == AF_INET)
                InetNtopW(AF_INET, &r.Address.Ipv4.sin_addr, ip, 64);
            else
                InetNtopW(AF_INET6, &r.Address.Ipv6.sin6_addr, ip, 64);
            if (!ip[0]) continue;
            LanDevice d;
            d.ip = ip;
            wchar_t mac[24];
            swprintf(mac, 24, L"%02X:%02X:%02X:%02X:%02X:%02X",
                     r.PhysicalAddress[0], r.PhysicalAddress[1], r.PhysicalAddress[2],
                     r.PhysicalAddress[3], r.PhysicalAddress[4], r.PhysicalAddress[5]);
            d.mac = mac;
            d.vendor = MacVendor(d.mac);
            d.active = (r.State == NlnsReachable || r.State == NlnsDelay || r.State == NlnsProbe);
            devs.push_back(std::move(d));
        }
        pFree(t);
    }
    std::sort(devs.begin(), devs.end(), [](const LanDevice& a, const LanDevice& b) {
        return a.ip < b.ip;
    });
    m_lan.swap(devs);
}

void NetMonitor::ScanPortScans(const std::vector<Conn>& conns) {
    const unsigned long long now = NowMs();
    std::unordered_map<unsigned short, std::unordered_set<std::wstring>> byPort;
    int synCount = 0;
    for (const auto& c : conns) {
        if (!c.IsTcp() || c.state != MIB_TCP_STATE_SYN_RCVD) continue;
        synCount++;
        byPort[c.localPort].insert(c.remoteIp);
    }
    m_synRcvd = synCount;

    for (const auto& kv : byPort) {
        if (kv.second.size() < 6) continue;
        bool dup = false;
        for (const auto& ev : m_scanEvents)
            if (ev.port == kv.first && now - ev.t < 10000) { dup = true; break; }
        if (dup) continue;
        PortScanEvent ev;
        ev.t = now;
        ev.port = kv.first;
        ev.count = (int)kv.second.size();
        int n = 0;
        for (const auto& ip : kv.second) {
            if (n++) ev.sample += L" ";
            ev.sample += ip;
            if (n >= 4) break;
        }
        m_scanEvents.push_back(ev);
        if (m_scanEvents.size() > 8) m_scanEvents.erase(m_scanEvents.begin());
    }
}

void NetMonitor::Refresh() {
    m_procInfo.RefreshServiceMap();
    m_procInfo.RefreshPersistence();
    m_procInfo.SampleRuntime();
    SampleInterfaces();
    ScanArp();

    std::vector<Conn> fresh;
    fresh.reserve(512);
    CollectTcp4(fresh);
    CollectTcp6(fresh);
    CollectUdp4(fresh);
    CollectUdp6(fresh);
    ScanPortScans(fresh);

    const unsigned long long now = NowMs();
    const unsigned long long wallNow = (unsigned long long)time(nullptr) * 1000ull;
    if (m_firstRefresh) m_watchedSince = now;
    double dtSec = (now > m_lastTick) ? (double)(now - m_lastTick) / 1000.0 : 0.0;
    if (dtSec < 0.05 || dtSec > 30.0) dtSec = 0.0;

    m_totalIn = m_totalOut = 0;

    std::unordered_map<std::wstring, Sample> newSamples;
    newSamples.reserve(fresh.size() * 2);
    std::unordered_map<std::wstring, unsigned long long> newFirst;
    newFirst.reserve(fresh.size() * 2);

    std::unordered_map<DWORD, ProcDetails> procCache;
    std::unordered_map<DWORD, ProcRuntime>  rtCache;
    std::unordered_set<DWORD> livePids;

    for (auto& c : fresh) {
        auto pit = procCache.find(c.pid);
        if (pit == procCache.end()) {
            pit = procCache.emplace(c.pid, m_procInfo.Get(c.pid)).first;
            rtCache[c.pid] = m_procInfo.Runtime(c.pid);
            livePids.insert(c.pid);
        }
        const ProcDetails& d = pit->second;
        c.procName  = d.name;
        c.procPath  = d.path;
        c.publisher = d.Publisher();
        c.services  = d.services;
        c.user      = d.user;
        c.sign      = d.sign;
        const ProcRuntime& rt = rtCache[c.pid];
        c.procCpu       = rt.cpu;
        c.procRam       = rt.workingSet;
        c.procSuspended = rt.suspended;

        const std::wstring key = c.Key();

        auto fs = m_firstSeen.find(key);

        if (fs == m_firstSeen.end()) { c.firstSeen = now; c.isNew = !m_firstRefresh; }
        else                         { c.firstSeen = fs->second; c.isNew = false; }
        newFirst[key] = c.firstSeen;

        if (c.createTs && wallNow > c.createTs) {
            c.ageMs    = wallNow - c.createTs;
            c.ageExact = true;
        } else {
            c.ageMs    = now - c.firstSeen;
            c.ageExact = (m_watchedSince != 0 && c.firstSeen > m_watchedSince);
        }

        if (c.bytesIn || c.bytesOut) {
            auto prev = m_samples.find(key);
            if (prev != m_samples.end() && dtSec > 0.0) {
                if (c.bytesIn  >= prev->second.in) {
                    unsigned long long d = c.bytesIn - prev->second.in;
                    c.rateIn = (double)d / dtSec;
                    m_sessionIn += d;
                }
                if (c.bytesOut >= prev->second.out) {
                    unsigned long long d = c.bytesOut - prev->second.out;
                    c.rateOut = (double)d / dtSec;
                    m_sessionOut += d;
                }
            }
            Sample s; s.in = c.bytesIn; s.out = c.bytesOut; s.t = now;
            newSamples[key] = s;
        }
        m_totalIn  += c.rateIn;
        m_totalOut += c.rateOut;
    }

    for (const auto& c : fresh) {
        if (!c.isNew || !c.isRemotePublic || !c.IsTcp()) continue;
        std::wstring bk = c.procName + L"|" + c.remoteIp;
        auto& v = m_beacon[bk];
        v.push_back(now);
        if (v.size() > 24) v.erase(v.begin(), v.begin() + (v.size() - 24));
    }

    for (auto it = m_beacon.begin(); it != m_beacon.end(); ) {
        auto& v = it->second;
        while (!v.empty() && now - v.front() > 1800000ull) v.erase(v.begin());
        if (v.empty()) it = m_beacon.erase(it); else ++it;
    }

    auto beaconOf = [&](const Conn& c, int& hits, int& periodSec) {
        hits = periodSec = 0;
        auto it = m_beacon.find(c.procName + L"|" + c.remoteIp);
        if (it == m_beacon.end() || it->second.size() < 4) return;
        const auto& v = it->second;
        hits = (int)v.size();
        std::vector<double> gaps;
        for (size_t i = 1; i < v.size(); ++i) gaps.push_back((double)(v[i] - v[i-1]) / 1000.0);
        double mean = 0;
        for (double g : gaps) mean += g;
        mean /= (double)gaps.size();
        if (mean < 2.0 || mean > 900.0) return;
        double var = 0;
        for (double g : gaps) var += (g - mean) * (g - mean);
        double sd = sqrt(var / (double)gaps.size());
        if (sd / mean < 0.25) periodSec = (int)(mean + 0.5);
    };

    std::unordered_map<DWORD, std::unordered_set<std::wstring>> remotesByPid;
    std::unordered_map<DWORD, int> listensByPid;
    for (const auto& c : fresh) {
        if (c.isRemotePublic) remotesByPid[c.pid].insert(c.remoteIp);
        if (c.IsListening())  listensByPid[c.pid]++;
    }

    for (auto& c : fresh) {
        RiskContext ctx;
        ctx.nowMs = now;
        auto it = remotesByPid.find(c.pid);
        ctx.distinctRemotes = (it == remotesByPid.end()) ? 0 : (int)it->second.size();
        auto lt = listensByPid.find(c.pid);
        ctx.listenPorts = (lt == listensByPid.end()) ? 0 : lt->second;
        ctx.procIsNew = false;
        auto pd = procCache.find(c.pid);
        if (pd != procCache.end() && pd->second.startTime) {
            unsigned long long unixNow = (unsigned long long)time(nullptr) * 1000ull;
            if (unixNow > pd->second.startTime && unixNow - pd->second.startTime < 60000ull)
                ctx.procIsNew = true;
        }
        ctx.suspended = c.procSuspended;
        if (pd != procCache.end()) ctx.persistent = pd->second.persistent;
        beaconOf(c, ctx.beaconHits, ctx.beaconPeriodSec);
        EvaluateRisk(c, ctx);
    }

    static unsigned long long lastPrune = 0;
    if (now - lastPrune > 15000) {
        lastPrune = now;
        std::unordered_set<DWORD> alive;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe;
            pe.dwSize = sizeof(pe);
            if (Process32FirstW(snap, &pe)) {
                do { alive.insert(pe.th32ProcessID); } while (Process32NextW(snap, &pe));
            }
            CloseHandle(snap);
            if (!alive.empty()) m_procInfo.Prune(alive);
        }
    }

    m_samples.swap(newSamples);
    m_firstSeen.swap(newFirst);
    m_lastTick = now;
    m_firstRefresh = false;
    m_conns.swap(fresh);
}

}
