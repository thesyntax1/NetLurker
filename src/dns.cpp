#include "dns.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <cmath>
#include <sstream>

using namespace nl;

namespace {

struct NL_DNS_CACHE_ENTRY {
    void*          pNext;
    wchar_t*       pName;
    unsigned short wType;
    unsigned short wDataLength;
    unsigned long  dwFlags;
    unsigned long  TimeToLive;
};

typedef unsigned long (WINAPI* PFN_DnsGetCacheDataTable)(NL_DNS_CACHE_ENTRY**);
typedef void (WINAPI* PFN_DnsRecordListFree)(void*, unsigned long);

struct DnsApi {
    PFN_DnsGetCacheDataTable GetCache = nullptr;
    PFN_DnsRecordListFree    FreeList = nullptr;
};

const DnsApi& Dns() {
    static DnsApi api = [] {
        DnsApi a;
        HMODULE h = LoadLibraryW(L"dnsapi.dll");
        if (h) {
            a.GetCache = (PFN_DnsGetCacheDataTable)(void*)GetProcAddress(h, "DnsGetCacheDataTable");
            a.FreeList = (PFN_DnsRecordListFree)(void*)GetProcAddress(h, "DnsRecordListFree");
        }
        return a;
    }();
    return api;
}

std::wstring Ip4ToStr(DWORD addr) {
    wchar_t b[64];
    swprintf(b, 64, L"%u.%u.%u.%u",
             (unsigned)(addr & 0xFF), (unsigned)((addr >> 8) & 0xFF),
             (unsigned)((addr >> 16) & 0xFF), (unsigned)((addr >> 24) & 0xFF));
    return b;
}

std::wstring Ip6ToStr(const unsigned char* p) {
    wchar_t b[64];
    swprintf(b, 64, L"%x:%x:%x:%x:%x:%x:%x:%x",
             (unsigned)(p[0] << 8 | p[1]), (unsigned)(p[2] << 8 | p[3]),
             (unsigned)(p[4] << 8 | p[5]), (unsigned)(p[6] << 8 | p[7]),
             (unsigned)(p[8] << 8 | p[9]), (unsigned)(p[10] << 8 | p[11]),
             (unsigned)(p[12] << 8 | p[13]), (unsigned)(p[14] << 8 | p[15]));
    return b;
}

bool SuspectDomain(const std::wstring& d) {
    if (d.size() > 40) return true;
    int freq[256] = {0};
    int digits = 0, letters = 0;
    for (wchar_t ch : d) {
        if ((unsigned)ch < 256) freq[(unsigned char)ch]++;
        if (ch >= L'0' && ch <= L'9') digits++;
        if ((ch >= L'a' && ch <= L'z') || (ch >= L'A' && ch <= L'Z')) letters++;
    }
    double total = (double)(d.size());
    if (total < 8) return false;
    double H = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (!freq[i]) continue;
        double p = freq[i] / total;
        H -= p * log2(p);
    }
    const double lettersOnly = (double)letters / std::max(1.0, total - (double)digits);
    if (H > 3.5) return true;
    if (digits > 0 && (double)digits / total > 0.35) return true;
    (void)lettersOnly;
    return false;
}

std::wstring HostsPath() {
    wchar_t dir[MAX_PATH] = L"";
    GetWindowsDirectoryW(dir, MAX_PATH);
    return std::wstring(dir) + L"\\System32\\drivers\\etc\\hosts";
}

}

void DnsCacheService::Refresh() {
    const unsigned long long now = NowMs();
    const auto& api = Dns();
    if (api.GetCache && (!m_lastDns || now - m_lastDns >= 10000)) {
        m_lastDns = now;
        NL_DNS_CACHE_ENTRY* head = nullptr;
        if (api.GetCache(&head) == 0 && head) {
            std::unordered_map<std::wstring, std::vector<std::pair<std::wstring, unsigned long>>> fresh;
            for (auto* e = head; e; e = (NL_DNS_CACHE_ENTRY*)e->pNext) {
                if (!e->pName || !e->pName[0] || e->wDataLength == 0) continue;
                std::wstring name = e->pName;
                while (!name.empty() && name.back() == L'.') name.pop_back();
                if (name.empty()) continue;
                const unsigned char* data =
                    (const unsigned char*)e + sizeof(NL_DNS_CACHE_ENTRY);
                std::wstring ip;
                if (e->wType == 1  && e->wDataLength >= 4)
                    ip = Ip4ToStr(*(const DWORD*)data);
                else if (e->wType == 28  && e->wDataLength >= 16)
                    ip = Ip6ToStr(data);
                if (ip.empty() || ip == L"0.0.0.0" || ip == L"::") continue;
                auto& v = fresh[ip];
                v.push_back({ name, e->TimeToLive });
            }

            for (auto& kv : fresh) {
                std::sort(kv.second.begin(), kv.second.end(),
                          [](const auto& a, const auto& b) { return a.second > b.second; });
                if (kv.second.size() > 3) kv.second.resize(3);
            }
            std::lock_guard<std::mutex> lk(m_mtx);
            m_byIp.swap(fresh);
            api.FreeList(head, 0 );
        }
    }
    if (!m_lastHosts || now - m_lastHosts >= 60000) LoadHosts();
}

std::wstring DnsCacheService::DomainFor(const std::wstring& ip) const {
    std::lock_guard<std::mutex> lk(m_mtx);
    auto it = m_byIp.find(ip);
    if (it == m_byIp.end() || it->second.empty()) return L"";
    return it->second[0].first;
}

bool DnsCacheService::IsHostsRedirect(const std::wstring& ip) const {
    std::lock_guard<std::mutex> lk(m_mtx);
    return m_hostsIps.count(ip) != 0;
}

int DnsCacheService::HostsEntryCount() const {
    std::lock_guard<std::mutex> lk(m_mtx);
    return m_hostsEntries;
}

std::vector<DnsCacheRow> DnsCacheService::TopDomains() const {
    std::vector<DnsCacheRow> rows;
    std::lock_guard<std::mutex> lk(m_mtx);
    for (const auto& kv : m_byIp) {
        for (const auto& p : kv.second) {
            rows.push_back({ p.first, kv.first, SuspectDomain(p.first) });
            if (rows.size() >= 240) goto done;
        }
    }
done:
    std::sort(rows.begin(), rows.end(), [](const DnsCacheRow& a, const DnsCacheRow& b) {
        if (a.suspect != b.suspect) return a.suspect > b.suspect;
        return ToLower(a.domain) < ToLower(b.domain);
    });
    if (rows.size() > 8) rows.resize(8);
    return rows;
}

size_t DnsCacheService::CacheSize() const {
    std::lock_guard<std::mutex> lk(m_mtx);
    return m_byIp.size();
}

void DnsCacheService::LoadHosts() {
    m_lastHosts = NowMs();
    std::unordered_set<std::wstring> ips;
    int entries = 0;

    HANDLE h = CreateFileW(HostsPath().c_str(), GENERIC_READ, FILE_SHARE_READ |
                           FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        std::string data;
        data.resize(1024 * 1024);
        DWORD got = 0;
        if (ReadFile(h, &data[0], (DWORD)data.size(), &got, nullptr)) data.resize(got);
        else data.clear();
        CloseHandle(h);

        size_t p = 0;
        while (p < data.size()) {
            size_t e = data.find('\n', p);
            if (e == std::string::npos) e = data.size();
            std::string line = data.substr(p, e - p);
            p = e + 1;
            while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
            size_t c = line.find('#');
            if (c != std::string::npos) line = line.substr(0, c);
            std::wistringstream ss(Widen(line));
            std::wstring ip;
            ss >> ip;
            if (ip.empty()) continue;
            bool isLocal = ip == L"127.0.0.1" || ip == L"::1" || ip == L"localhost";
            std::wstring name;
            while (ss >> name) {
                if (name.empty()) continue;
                if (!isLocal) {
                    ips.insert(ip);
                    entries++;
                }
                break;
            }
        }
    }

    std::lock_guard<std::mutex> lk(m_mtx);
    m_hostsIps.swap(ips);
    m_hostsEntries = entries;
}

namespace {

struct Oui { const wchar_t* oui; const wchar_t* vendor; };

const Oui kOui[] = {
    { L"000A27", L"Apple" }, { L"000393", L"Apple" }, { L"0010FA", L"Apple" },
    { L"001451", L"Apple" }, { L"0017F2", L"Apple" }, { L"001B63", L"Apple" },
    { L"001E52", L"Apple" }, { L"001F5B", L"Apple" }, { L"00254B", L"Apple" },
    { L"003065", L"Apple" }, { L"00CDFE", L"Apple" }, { L"0C3021", L"Apple" },
    { L"143DB6", L"Apple" }, { L"14BD61", L"Apple" }, { L"1C1AC0", L"Apple" },
    { L"286ABA", L"Apple" }, { L"28CFE9", L"Apple" }, { L"2851EB", L"Apple" },
    { L"289A4B", L"Apple" }, { L"34C059", L"Apple" }, { L"380F4A", L"Apple" },
    { L"3C15C2", L"Apple" }, { L"40831D", L"Apple" }, { L"448CE3", L"Apple" },
    { L"4C3275", L"Apple" }, { L"58B035", L"Apple" }, { L"5C97F3", L"Apple" },
    { L"60FEC5", L"Apple" }, { L"685B35", L"Apple" }, { L"70A2B3", L"Apple" },
    { L"7C04D0", L"Apple" }, { L"84B153", L"Apple" }, { L"84FCAC", L"Apple" },
    { L"8C8590", L"Apple" }, { L"90B21F", L"Apple" }, { L"98FE94", L"Apple" },
    { L"A4D1D2", L"Apple" }, { L"ACCF5C", L"Apple" }, { L"B0B28F", L"Apple" },
    { L"F01898", L"Apple" }, { L"F0D1A9", L"Apple" }, { L"F40F24", L"Apple" },
    { L"F82DD8", L"Apple" }, { L"FCA3B4", L"Apple" }, { L"FCB668", L"Apple" },
    { L"B42A0E", L"Apple" }, { L"BC926B", L"Apple" }, { L"C86F1D", L"Apple" },
    { L"DC2B2A", L"Apple" }, { L"7C6D62", L"Apple" }, { L"F0DCE2", L"Apple" },
    { L"8C7C92", L"Apple" }, { L"3C22FB", L"Apple" }, { L"2C3361", L"Apple" },
    { L"6C7E67", L"Apple" }, { L"E0ACCB", L"Apple" }, { L"50EAD6", L"Apple" },
    { L"001124", L"Apple" }, { L"68A86D", L"Apple" }, { L"F09FD8", L"Apple" },
    { L"002241", L"Samsung" }, { L"0023D6", L"Samsung" }, { L"0050F3", L"Samsung" },
    { L"00EBD5", L"Samsung" }, { L"04B3B6", L"Samsung" }, { L"08389E", L"Samsung" },
    { L"0C8910", L"Samsung" }, { L"107B44", L"Samsung" }, { L"141330", L"Samsung" },
    { L"18A905", L"Samsung" }, { L"20D390", L"Samsung" }, { L"2426F0", L"Samsung" },
    { L"245BF0", L"Samsung" }, { L"2C4401", L"Samsung" }, { L"306CBE", L"Samsung" },
    { L"38D40B", L"Samsung" }, { L"3C6200", L"Samsung" }, { L"402E28", L"Samsung" },
    { L"441319", L"Samsung" }, { L"4C0FC7", L"Samsung" }, { L"5C0A5B", L"Samsung" },
    { L"641666", L"Samsung" }, { L"64CB4E", L"Samsung" }, { L"687F74", L"Samsung" },
    { L"709E29", L"Samsung" }, { L"787F62", L"Samsung" }, { L"7C2F80", L"Samsung" },
    { L"8482F4", L"Samsung" }, { L"8809AF", L"Samsung" }, { L"8CE117", L"Samsung" },
    { L"94350A", L"Samsung" }, { L"9810E8", L"Samsung" }, { L"98D3B1", L"Samsung" },
    { L"A04041", L"Samsung" }, { L"B0C5CA", L"Samsung" }, { L"C4731E", L"Samsung" },
    { L"CC05E8", L"Samsung" }, { L"CC07AB", L"Samsung" }, { L"D0034B", L"Samsung" },
    { L"E4B0E8", L"Samsung" }, { L"E83A97", L"Samsung" }, { L"F07B62", L"Samsung" },
    { L"F0EE10", L"Samsung" }, { L"8C04BA", L"Samsung" }, { L"2805FC", L"Samsung" },
    { L"0013E0", L"Xiaomi" }, { L"0C1DAF", L"Xiaomi" }, { L"141E0A", L"Xiaomi" },
    { L"18F643", L"Xiaomi" }, { L"20A6CD", L"Xiaomi" }, { L"28E31F", L"Xiaomi" },
    { L"3478D7", L"Xiaomi" }, { L"38A4ED", L"Xiaomi" }, { L"3C35C2", L"Xiaomi" },
    { L"443355", L"Xiaomi" }, { L"50E666", L"Xiaomi" }, { L"64CC2E", L"Xiaomi" },
    { L"68DFDD", L"Xiaomi" }, { L"78324F", L"Xiaomi" }, { L"78A2A0", L"Xiaomi" },
    { L"7C1DD9", L"Xiaomi" }, { L"8CBE57", L"Xiaomi" }, { L"986D35", L"Xiaomi" },
    { L"A40A7C", L"Xiaomi" }, { L"D4970B", L"Xiaomi" }, { L"F80B31", L"Xiaomi" },
    { L"F862AA", L"Xiaomi" }, { L"281FB8", L"Xiaomi" }, { L"38295A", L"Xiaomi" },
    { L"001CDF", L"Huawei" }, { L"00259E", L"Huawei" }, { L"04BD70", L"Huawei" },
    { L"101B54", L"Huawei" }, { L"1C96F2", L"Huawei" }, { L"20689D", L"Huawei" },
    { L"241C04", L"Huawei" }, { L"28FD80", L"Huawei" }, { L"3071B2", L"Huawei" },
    { L"342EBD", L"Huawei" }, { L"3859F9", L"Huawei" }, { L"485D60", L"Huawei" },
    { L"48F8B3", L"Huawei" }, { L"5804CB", L"Huawei" }, { L"58696C", L"Huawei" },
    { L"6857ED", L"Huawei" }, { L"706D15", L"Huawei" }, { L"74A528", L"Huawei" },
    { L"7C8900", L"Huawei" }, { L"8430E5", L"Huawei" }, { L"98A7B0", L"Huawei" },
    { L"AC85D2", L"Huawei" }, { L"F80B41", L"Huawei" }, { L"FC48EF", L"Huawei" },
    { L"0013F7", L"Intel" }, { L"001500", L"Intel" }, { L"0017C4", L"Intel" },
    { L"001B77", L"Intel" }, { L"0024D7", L"Intel" }, { L"4C3488", L"Intel" },
    { L"505AF1", L"Intel" }, { L"5CF286", L"Intel" }, { L"60F189", L"Intel" },
    { L"7C5CF8", L"Intel" }, { L"84A6C8", L"Intel" }, { L"88B111", L"Intel" },
    { L"8C7365", L"Intel" }, { L"9017C8", L"Intel" }, { L"94B86C", L"Intel" },
    { L"981636", L"Intel" }, { L"A0A8CD", L"Intel" }, { L"B4A5EF", L"Intel" },
    { L"D89695", L"Intel" }, { L"DCB5B6", L"Intel" }, { L"E4A4E7", L"Intel" },
    { L"F07959", L"Intel" }, { L"00000C", L"Cisco" }, { L"000142", L"Cisco" },
    { L"000C41", L"Cisco" }, { L"0011BB", L"Cisco" }, { L"0017DF", L"Cisco" },
    { L"0022BD", L"Cisco" }, { L"0C2724", L"Cisco" }, { L"1C1D67", L"Cisco" },
    { L"24E9B3", L"Cisco" }, { L"3037A6", L"Cisco" }, { L"3C08F6", L"Cisco" },
    { L"5C5EAB", L"Cisco" }, { L"68BDAB", L"Cisco" }, { L"70DBA6", L"Cisco" },
    { L"78BAF9", L"Cisco" }, { L"88295F", L"Cisco" }, { L"B06EBF", L"Cisco" },
    { L"00E04C", L"Realtek" }, { L"001D0F", L"Realtek" }, { L"001FC6", L"Realtek" },
    { L"08A95A", L"Realtek" }, { L"0CFEE6", L"Realtek" }, { L"10D561", L"Realtek" },
    { L"18D6C7", L"Realtek" }, { L"1CB72C", L"Realtek" }, { L"246C84", L"Realtek" },
    { L"2C56DC", L"Realtek" }, { L"48E7DA", L"Realtek" }, { L"508ACB", L"Realtek" },
    { L"5254B5", L"Realtek" }, { L"52AF10", L"Realtek" }, { L"74B2C0", L"Realtek" },
    { L"84A8E4", L"Realtek" }, { L"8CB06A", L"Realtek" }, { L"A09E1A", L"Realtek" },
    { L"B8D7AF", L"Realtek" }, { L"BC7A4C", L"Realtek" }, { L"C82A14", L"Realtek" },
    { L"CC8CE3", L"Realtek" }, { L"F09838", L"Realtek" }, { L"00137B", L"TP-Link" },
    { L"142D87", L"TP-Link" }, { L"1863A9", L"TP-Link" }, { L"3C84DD", L"TP-Link" },
    { L"3C9142", L"TP-Link" }, { L"50C7BF", L"TP-Link" }, { L"5CD9F4", L"TP-Link" },
    { L"5CBF57", L"TP-Link" }, { L"60A44C", L"TP-Link" }, { L"6831F8", L"TP-Link" },
    { L"90F652", L"TP-Link" }, { L"98484C", L"TP-Link" }, { L"A0423F", L"TP-Link" },
    { L"AC8430", L"TP-Link" }, { L"B0A737", L"TP-Link" }, { L"C46E1F", L"TP-Link" },
    { L"F49447", L"TP-Link" }, { L"000625", L"TP-Link" }, { L"000FB3", L"Asus" },
    { L"0011D8", L"Asus" }, { L"001E8C", L"Asus" }, { L"0023B2", L"Asus" },
    { L"00E018", L"Asus" }, { L"044BED", L"Asus" }, { L"089E01", L"Asus" },
    { L"0C9D92", L"Asus" }, { L"18D60F", L"Asus" }, { L"1C872C", L"Asus" },
    { L"20780B", L"Asus" }, { L"2C5631", L"Asus" }, { L"3C9F81", L"Asus" },
    { L"40B076", L"Asus" }, { L"54A050", L"Asus" }, { L"609217", L"Asus" },
    { L"704D7B", L"Asus" }, { L"E0CB4E", L"Asus" }, { L"F07960", L"Asus" },
    { L"FCA0F8", L"Asus" }, { L"000FB5", L"Netgear" }, { L"00146C", L"Netgear" },
    { L"001B2F", L"Netgear" }, { L"0023EB", L"Netgear" }, { L"0CB556", L"Netgear" },
    { L"14171C", L"Netgear" }, { L"204E7F", L"Netgear" }, { L"28107B", L"Netgear" },
    { L"283152", L"Netgear" }, { L"2C30E9", L"Netgear" }, { L"305266", L"Netgear" },
    { L"44A56E", L"Netgear" }, { L"60427F", L"Netgear" }, { L"9C3DCF", L"Netgear" },
    { L"A021B7", L"Netgear" }, { L"C0FFD4", L"Netgear" }, { L"E0EB62", L"Netgear" },
    { L"001F3B", L"D-Link" }, { L"00E0B4", L"D-Link" }, { L"1CBDB9", L"D-Link" },
    { L"28EDE0", L"D-Link" }, { L"3C1E04", L"D-Link" }, { L"40CD7A", L"D-Link" },
    { L"48D705", L"D-Link" }, { L"7858F3", L"D-Link" }, { L"7898E8", L"D-Link" },
    { L"7CB73B", L"D-Link" }, { L"8CE748", L"D-Link" }, { L"9006DF", L"D-Link" },
    { L"B0C554", L"D-Link" }, { L"C83A35", L"D-Link" }, { L"D8357B", L"D-Link" },
    { L"F07D68", L"D-Link" }, { L"001F33", L"Netgear" },
    { L"1C6F65", L"Xiaomi" }, { L"503237", L"Xiaomi" }, { L"8CE117", L"Xiaomi" },
    { L"247703", L"Espressif (IoT)" }, { L"24A160", L"Espressif (IoT)" },
    { L"30AEA4", L"Espressif (IoT)" }, { L"5CCF7F", L"Espressif (IoT)" },
    { L"68C63A", L"Espressif (IoT)" }, { L"840D8E", L"Espressif (IoT)" },
    { L"BCDDC2", L"Espressif (IoT)" }, { L"CC50E3", L"Espressif (IoT)" },
    { L"D8A01D", L"Espressif (IoT)" }, { L"DC4F22", L"Espressif (IoT)" },
    { L"ECFA00", L"Espressif (IoT)" }, { L"08B61F", L"Espressif (IoT)" },
    { L"B4E62D", L"Espressif (IoT)" }, { L"FCF5C4", L"Espressif (IoT)" },
    { L"AC67B2", L"Espressif (IoT)" }, { L"8052DF", L"Espressif (IoT)" },
    { L"E839DF", L"Espressif (IoT)" }, { L"C40B31", L"Espressif (IoT)" },
    { L"081EFD", L"Espressif (IoT)" }, { L"F4519B", L"Espressif (IoT)" },
    { L"5C5176", L"Espressif (IoT)" }, { L"94B97E", L"Espressif (IoT)" },
    { L"00045A", L"Linksys" }, { L"000C41", L"Cisco" }, { L"0022D1", L"Roku" },
    { L"0023A7", L"Roku" }, { L"08184C", L"Roku" }, { L"8C496D", L"Roku" },
    { L"B0A737", L"Roku" }, { L"BC4902", L"Roku" }, { L"CC6DA0", L"Roku" },
    { L"D0D0FD", L"Roku" }, { L"D403F5", L"Roku" }, { L"B8B7F1", L"Roku" },
    { L"08353F", L"Roku" }, { L"001217", L"Cisco" }, { L"00B0D0", L"Dell" },
    { L"0018B0", L"Dell" }, { L"0022D8", L"Dell" }, { L"142D7B", L"Dell" },
    { L"189DB1", L"Dell" }, { L"1C15CD", L"Dell" }, { L"341A2C", L"Dell" },
    { L"B8CF64", L"Dell" }, { L"BC305B", L"Dell" }, { L"D47BA2", L"Dell" },
    { L"E0DB55", L"Dell" }, { L"F8B156", L"Dell" }, { L"F8CA84", L"Dell" },
    { L"70A25E", L"Dell" }, { L"10657B", L"Dell" }, { L"001B78", L"HP" },
    { L"0022A4", L"HP" }, { L"10604B", L"HP" }, { L"1C6590", L"HP" },
    { L"281878", L"HP" }, { L"2C76A1", L"HP" }, { L"34B8EE", L"HP" },
    { L"3CD92B", L"HP" }, { L"48BA4E", L"HP" }, { L"6493B4", L"HP" },
    { L"7099D1", L"HP" }, { L"80516E", L"HP" }, { L"9CB654", L"HP" },
    { L"B4B52F", L"HP" }, { L"C8D3FF", L"HP" }, { L"D8489E", L"HP" },
    { L"E4115B", L"HP" }, { L"EC8EB5", L"HP" }, { L"F0921C", L"HP" },
    { L"00155D", L"Lenovo" }, { L"0023FA", L"Lenovo" }, { L"089A91", L"Lenovo" },
    { L"14A0F8", L"Lenovo" }, { L"1C662A", L"Lenovo" }, { L"281878", L"Lenovo" },
    { L"38F98C", L"Lenovo" }, { L"40A8F0", L"Lenovo" }, { L"54F0F8", L"Lenovo" },
    { L"58B035", L"Lenovo" }, { L"6C2C59", L"Lenovo" }, { L"8062CA", L"Lenovo" },
    { L"8484ED", L"Lenovo" }, { L"8C2F39", L"Lenovo" }, { L"946A77", L"Lenovo" },
    { L"98EECB", L"Lenovo" }, { L"B0B2DC", L"Lenovo" }, { L"C8FF77", L"Lenovo" },
    { L"D0C2BF", L"Lenovo" }, { L"E8B1FC", L"Lenovo" }, { L"F0DEF1", L"Lenovo" },
    { L"001320", L"Intel" }, { L"000D65", L"Cisco" }, { L"002673", L"Microsoft" },
    { L"0050F2", L"Microsoft" }, { L"3038A2", L"Microsoft" }, { L"449C93", L"Microsoft" },
    { L"505BD0", L"Microsoft" }, { L"70F395", L"Microsoft" }, { L"8C28A3", L"Microsoft" },
    { L"B4A45D", L"Microsoft" }, { L"C07EBC", L"Microsoft" }, { L"D48AF5", L"Microsoft" },
    { L"F4F5D8", L"Microsoft" }, { L"7C3548", L"Microsoft" }, { L"003F10", L"Microsoft" },
    { L"001E3E", L"ZTE" }, { L"002232", L"ZTE" }, { L"0023C0", L"ZTE" },
    { L"00D0D0", L"ZTE" }, { L"10532C", L"ZTE" }, { L"185D9A", L"ZTE" },
    { L"20A39F", L"ZTE" }, { L"3CAC9D", L"ZTE" }, { L"645E10", L"ZTE" },
    { L"7C71C4", L"ZTE" }, { L"8CA3DD", L"ZTE" }, { L"98C1C2", L"ZTE" },
    { L"BCC6DB", L"ZTE" }, { L"C8AA83", L"ZTE" }, { L"E4A32F", L"ZTE" },
    { L"F0836C", L"ZTE" }, { L"00198F", L"LG" }, { L"001B10", L"LG" },
    { L"002313", L"LG" }, { L"04294B", L"LG" }, { L"0CF893", L"LG" },
    { L"182666", L"LG" }, { L"20F59D", L"LG" }, { L"2426F7", L"LG" },
    { L"30551E", L"LG" }, { L"3C5C60", L"LG" }, { L"4808BC", L"LG" },
    { L"5065F3", L"LG" }, { L"5CCBCA", L"LG" }, { L"64B8F0", L"LG" },
    { L"6C5E14", L"LG" }, { L"747A89", L"LG" }, { L"7C859B", L"LG" },
    { L"8C8BF2", L"LG" }, { L"948D50", L"LG" }, { L"A09F10", L"LG" },
    { L"B42A39", L"LG" }, { L"C04301", L"LG" }, { L"CC1E8E", L"LG" },
    { L"D86CE9", L"LG" }, { L"E03E44", L"LG" }, { L"F04493", L"LG" },
    { L"F48E38", L"LG" }, { L"0013A9", L"Sony" }, { L"0024BE", L"Sony" },
    { L"0C3CC7", L"Sony" }, { L"104FA8", L"Sony" }, { L"1CDD88", L"Sony" },
    { L"20D5BF", L"Sony" }, { L"2C98A6", L"Sony" }, { L"30119B", L"Sony" },
    { L"343D98", L"Sony" }, { L"405D82", L"Sony" }, { L"485A3F", L"Sony" },
    { L"4C0BEC", L"Sony" }, { L"544249", L"Sony" }, { L"588D64", L"Sony" },
    { L"6C0B4B", L"Sony" }, { L"70C354", L"Sony" }, { L"78D75F", L"Sony" },
    { L"8CC84B", L"Sony" }, { L"9097F3", L"Sony" }, { L"98D88C", L"Sony" },
    { L"AC294B", L"Sony" }, { L"B8A175", L"Sony" }, { L"C85BB2", L"Sony" },
    { L"D4D897", L"Sony" }, { L"E88D28", L"Sony" }, { L"F05D89", L"Sony" },
    { L"F4BC20", L"Sony" }, { L"001CBE", L"Nintendo" }, { L"002409", L"Nintendo" },
    { L"00F7C5", L"Nintendo" }, { L"04AC44", L"Nintendo" }, { L"181EB0", L"Nintendo" },
    { L"1C1CB4", L"Nintendo" }, { L"2C1075", L"Nintendo" }, { L"308D99", L"Nintendo" },
    { L"3C384F", L"Nintendo" }, { L"4063C8", L"Nintendo" }, { L"44C398", L"Nintendo" },
    { L"487A54", L"Nintendo" }, { L"4C1FCC", L"Nintendo" }, { L"581208", L"Nintendo" },
    { L"5CBF90", L"Nintendo" }, { L"602E20", L"Nintendo" }, { L"64F69D", L"Nintendo" },
    { L"6C1638", L"Nintendo" }, { L"7007CB", L"Nintendo" }, { L"78E8B6", L"Nintendo" },
    { L"7CBB8A", L"Nintendo" }, { L"8C7A0B", L"Nintendo" }, { L"98B6E9", L"Nintendo" },
    { L"98E8FA", L"Nintendo" }, { L"9C87F1", L"Nintendo" }, { L"A4C0E1", L"Nintendo" },
    { L"B89BED", L"Nintendo" }, { L"CCFB65", L"Nintendo" }, { L"D82A7E", L"Nintendo" },
    { L"E0F6B5", L"Nintendo" }, { L"E8B748", L"Nintendo" }, { L"F0E5C3", L"Nintendo" },
    { L"0009FA", L"Arris" }, { L"001F2C", L"Arris" }, { L"00D097", L"Arris" },
    { L"083A88", L"Arris" }, { L"0C0E76", L"Arris" }, { L"14C089", L"Arris" },
    { L"1C7EE5", L"Arris" }, { L"201385", L"Arris" }, { L"2C1B7C", L"Arris" },
    { L"3039F2", L"Arris" }, { L"347368", L"Arris" }, { L"3C6256", L"Arris" },
    { L"442713", L"Arris" }, { L"4803C2", L"Arris" }, { L"50383C", L"Arris" },
    { L"54A23D", L"Arris" }, { L"5C4A1E", L"Arris" }, { L"603E7D", L"Arris" },
    { L"6809E7", L"Arris" }, { L"6C2F8C", L"Arris" }, { L"74A956", L"Arris" },
    { L"783867", L"Arris" }, { L"7CA69E", L"Arris" }, { L"8C2D8E", L"Arris" },
    { L"904CE5", L"Arris" }, { L"98E29C", L"Arris" }, { L"A8BD1A", L"Arris" },
    { L"AC3C0B", L"Arris" }, { L"B019C6", L"Arris" }, { L"B8A331", L"Arris" },
    { L"C4618B", L"Arris" }, { L"CCB11A", L"Arris" }, { L"D09C7A", L"Arris" },
    { L"D4B110", L"Arris" }, { L"E057A6", L"Arris" }, { L"E8BFD5", L"Arris" },
    { L"F0369F", L"Arris" }, { L"F4A4D6", L"Arris" }, { L"F893F3", L"Arris" },
    { L"FC5FA2", L"Arris" }, { L"002622", L"Technicolor" }, { L"0C5491", L"Technicolor" },
    { L"1C0B5C", L"Technicolor" }, { L"202B20", L"Technicolor" }, { L"28BE03", L"Technicolor" },
    { L"2C90DC", L"Technicolor" }, { L"303FDC", L"Technicolor" }, { L"386088", L"Technicolor" },
    { L"3C0E4B", L"Technicolor" }, { L"4440E8", L"Technicolor" }, { L"4CB58A", L"Technicolor" },
    { L"50C8A4", L"Technicolor" }, { L"5886B5", L"Technicolor" }, { L"5C81EE", L"Technicolor" },
    { L"6040B5", L"Technicolor" }, { L"647520", L"Technicolor" }, { L"687340", L"Technicolor" },
    { L"703018", L"Technicolor" }, { L"78AC5B", L"Technicolor" }, { L"7C00C3", L"Technicolor" },
    { L"802AB7", L"Technicolor" }, { L"848CC7", L"Technicolor" }, { L"88D821", L"Technicolor" },
    { L"8C45C6", L"Technicolor" }, { L"906726", L"Technicolor" }, { L"948478", L"Technicolor" },
    { L"9C1EB9", L"Technicolor" }, { L"A0CC2F", L"Technicolor" }, { L"A4B733", L"Technicolor" },
    { L"AC1645", L"Technicolor" }, { L"B0335A", L"Technicolor" }, { L"B445F0", L"Technicolor" },
    { L"B86CB2", L"Technicolor" }, { L"BCAD58", L"Technicolor" }, { L"C03355", L"Technicolor" },
    { L"C45CBC", L"Technicolor" }, { L"C87CBC", L"Technicolor" }, { L"CC0B1E", L"Technicolor" },
    { L"D02443", L"Technicolor" }, { L"D45CF5", L"Technicolor" }, { L"D8E59C", L"Technicolor" },
    { L"DC3553", L"Technicolor" }, { L"E0AA96", L"Technicolor" }, { L"E46449", L"Technicolor" },
    { L"E8C201", L"Technicolor" }, { L"ECAD22", L"Technicolor" }, { L"F07959", L"Technicolor" },
    { L"F473DF", L"Technicolor" }, { L"F8A823", L"Technicolor" }, { L"FC023E", L"Technicolor" },
    { L"F44EFD", L"Google" }, { L"001A11", L"Google" }, { L"38F23E", L"Google" },
    { L"3C5A37", L"Google" }, { L"54A51B", L"Google" }, { L"5C95AE", L"Google" },
    { L"6CFDB9", L"Google" }, { L"9C2D52", L"Google" }, { L"A44CC8", L"Google" },
    { L"B8C1A2", L"Google" }, { L"C03EBA", L"Google" }, { L"CCF8F0", L"Google" },
    { L"D0EED2", L"Google" }, { L"E8FEDF", L"Google" }, { L"F48C50", L"Google" },
    { L"70B3D5", L"Amazon" }, { L"001DC2", L"Amazon" }, { L"0400C0", L"Amazon" },
    { L"20E3A1", L"Amazon" }, { L"34172D", L"Amazon" }, { L"3C7DB1", L"Amazon" },
    { L"44A842", L"Amazon" }, { L"4CABCD", L"Amazon" }, { L"5073CB", L"Amazon" },
    { L"542A9C", L"Amazon" }, { L"5C0E8B", L"Amazon" }, { L"601EDB", L"Amazon" },
    { L"687898", L"Amazon" }, { L"6CBF58", L"Amazon" }, { L"78E103", L"Amazon" },
    { L"8C1ABF", L"Amazon" }, { L"987F08", L"Amazon" }, { L"A09BA2", L"Amazon" },
    { L"B0A82B", L"Amazon" }, { L"B805F1", L"Amazon" }, { L"C0C520", L"Amazon" },
    { L"D021F9", L"Amazon" }, { L"D84DD9", L"Amazon" }, { L"E09B31", L"Amazon" },
    { L"E4A1E6", L"Amazon" }, { L"E8B48C", L"Amazon" }, { L"F0D5BF", L"Amazon" },
    { L"FC6514", L"Amazon" }, { L"00223B", L"Tenda" }, { L"14CF92", L"Tenda" },
    { L"1CBFCE", L"Tenda" }, { L"24DFA7", L"Tenda" }, { L"285FDB", L"Tenda" },
    { L"30B49E", L"Tenda" }, { L"3895BD", L"Tenda" }, { L"3CD16E", L"Tenda" },
    { L"50FA84", L"Tenda" }, { L"5C4B22", L"Tenda" }, { L"64E2BB", L"Tenda" },
    { L"680ABE", L"Tenda" }, { L"7C5787", L"Tenda" }, { L"84B5A0", L"Tenda" },
    { L"94D771", L"Tenda" }, { L"983F0B", L"Tenda" }, { L"A0F459", L"Tenda" },
    { L"ACF49D", L"Tenda" }, { L"B0B4D5", L"Tenda" }, { L"C83A35", L"Tenda" },
    { L"CC87F3", L"Tenda" }, { L"D8534B", L"Tenda" }, { L"E0AAB6", L"Tenda" },
    { L"E46BC2", L"Tenda" }, { L"E85D2B", L"Tenda" }, { L"F4F26D", L"Tenda" },
    { L"6C2995", L"Ubiquiti" }, { L"24A43C", L"Ubiquiti" }, { L"04C5A4", L"Ubiquiti" },
    { L"788A20", L"Ubiquiti" }, { L"80AFCA", L"Ubiquiti" }, { L"AC5C14", L"Ubiquiti" },
    { L"B45059", L"Ubiquiti" }, { L"DC9FDB", L"Ubiquiti" }, { L"E063DA", L"Ubiquiti" },
    { L"FCECD3", L"Ubiquiti" }, { L"003072", L"Arduino/IoT" }, { L"98190C", L"Raspberry Pi" },
    { L"B827EB", L"Raspberry Pi" }, { L"DC3BCC", L"Raspberry Pi" }, { L"D8F0F2", L"Raspberry Pi" },
    { L"28CD5A", L"Raspberry Pi" }, { L"E45F01", L"Raspberry Pi" }, { L"2CCFA7", L"Raspberry Pi" },
    { L"00904C", L"Epigram" }, { L"00177C", L"SmartRG" }, { L"00A0E9", L"EnGenius" },
    { L"F84E58", L"Brother" }, { L"001BA9", L"Brother" }, { L"301F57", L"Brother" },
    { L"80A85D", L"Brother" }, { L"C03DFD", L"Netgear" }, { L"0C8096", L"Motorola" },
    { L"001C59", L"Motorola" }, { L"1C5CF2", L"Motorola" }, { L"30D1B7", L"Motorola" },
    { L"34967F", L"Motorola" }, { L"40FC89", L"Motorola" }, { L"48BA4E", L"Motorola" },
    { L"5C2443", L"Motorola" }, { L"6CB7F4", L"Motorola" }, { L"74E810", L"Motorola" },
    { L"80544C", L"Motorola" }, { L"8C11CB", L"Motorola" }, { L"902B34", L"Motorola" },
    { L"A419B2", L"Motorola" }, { L"B8B1C7", L"Motorola" }, { L"C0D5E5", L"Motorola" },
    { L"CC38F1", L"Motorola" }, { L"D0E2B0", L"Motorola" }, { L"D805E2", L"Motorola" },
    { L"E40CF0", L"Motorola" }, { L"E8D0B0", L"Motorola" }, { L"F0B6EB", L"Motorola" },
    { L"F430B9", L"Motorola" }, { L"F86778", L"Motorola" }, { L"FC8426", L"Motorola" },
    { L"001BA2", L"Fritz (AVM)" }, { L"0023D5", L"Fritz (AVM)" }, { L"00308E", L"Fritz (AVM)" },
    { L"00A057", L"Fritz (AVM)" }, { L"00D058", L"Fritz (AVM)" }, { L"08F958", L"Fritz (AVM)" },
    { L"14C850", L"Fritz (AVM)" }, { L"1C8071", L"Fritz (AVM)" }, { L"20D09F", L"Fritz (AVM)" },
    { L"244C07", L"Fritz (AVM)" }, { L"28A89D", L"Fritz (AVM)" }, { L"2C91AB", L"Fritz (AVM)" },
    { L"30A8DB", L"Fritz (AVM)" }, { L"343F0A", L"Fritz (AVM)" }, { L"383188", L"Fritz (AVM)" },
    { L"3C2EFF", L"Fritz (AVM)" }, { L"3C9A77", L"Fritz (AVM)" }, { L"408B07", L"Fritz (AVM)" },
    { L"40E263", L"Fritz (AVM)" }, { L"48D3FF", L"Fritz (AVM)" }, { L"4CCB78", L"Fritz (AVM)" },
    { L"50B6D8", L"Fritz (AVM)" }, { L"54477E", L"Fritz (AVM)" }, { L"584FDF", L"Fritz (AVM)" },
    { L"588BF8", L"Fritz (AVM)" }, { L"5C4979", L"Fritz (AVM)" }, { L"5CE0CA", L"Fritz (AVM)" },
    { L"60BE9E", L"Fritz (AVM)" }, { L"64FEC8", L"Fritz (AVM)" }, { L"6854F5", L"Fritz (AVM)" },
    { L"68F0BC", L"Fritz (AVM)" }, { L"6C6F18", L"Fritz (AVM)" }, { L"70B0DF", L"Fritz (AVM)" },
    { L"70F1E5", L"Fritz (AVM)" }, { L"74A2E6", L"Fritz (AVM)" }, { L"74F737", L"Fritz (AVM)" },
    { L"78FFCA", L"Fritz (AVM)" }, { L"7CFF4D", L"Fritz (AVM)" }, { L"80BAE6", L"Fritz (AVM)" },
    { L"841A8A", L"Fritz (AVM)" }, { L"8443D2", L"Fritz (AVM)" }, { L"889A21", L"Fritz (AVM)" },
    { L"8C01B7", L"Fritz (AVM)" }, { L"8CBB1F", L"Fritz (AVM)" }, { L"905C44", L"Fritz (AVM)" },
    { L"94267A", L"Fritz (AVM)" }, { L"9864C7", L"Fritz (AVM)" }, { L"9C144A", L"Fritz (AVM)" },
    { L"9CABD0", L"Fritz (AVM)" }, { L"A0481C", L"Fritz (AVM)" }, { L"A48201", L"Fritz (AVM)" },
    { L"A80CE3", L"Fritz (AVM)" }, { L"AC4C8A", L"Fritz (AVM)" }, { L"B07C6F", L"Fritz (AVM)" },
    { L"B4D5BD", L"Fritz (AVM)" }, { L"B85F5F", L"Fritz (AVM)" }, { L"BC4CA3", L"Fritz (AVM)" },
    { L"C049EF", L"Fritz (AVM)" }, { L"C42014", L"Fritz (AVM)" }, { L"C4F361", L"Fritz (AVM)" },
    { L"CC5B14", L"Fritz (AVM)" }, { L"D01CBB", L"Fritz (AVM)" }, { L"D46B40", L"Fritz (AVM)" },
    { L"DC9B09", L"Fritz (AVM)" }, { L"E0FAEC", L"Fritz (AVM)" }, { L"E48429", L"Fritz (AVM)" },
    { L"E8A386", L"Fritz (AVM)" }, { L"ECB5FA", L"Fritz (AVM)" }, { L"F08984", L"Fritz (AVM)" },
    { L"F4C714", L"Fritz (AVM)" }, { L"F86C8E", L"Fritz (AVM)" }, { L"FC51A4", L"Fritz (AVM)" },
    { L"000B82", L"Grandstream" }, { L"001E37", L"Universal" }, { L"000E8F", L"Sercomm" },
    { L"002386", L"LG" }, { L"002490", L"Sagemcom" }, { L"00301D", L"Sagemcom" },
    { L"00A065", L"Sagemcom" }, { L"0C8973", L"Sagemcom" }, { L"14B0F0", L"Sagemcom" },
    { L"1C9963", L"Sagemcom" }, { L"2081D1", L"Sagemcom" }, { L"24BE18", L"Sagemcom" },
    { L"2856C6", L"Sagemcom" }, { L"2C5A13", L"Sagemcom" }, { L"2C8DA1", L"Sagemcom" },
    { L"3010B3", L"Sagemcom" }, { L"307641", L"Sagemcom" }, { L"34262A", L"Sagemcom" },
    { L"3476C5", L"Sagemcom" }, { L"38CEC6", L"Sagemcom" }, { L"3C1400", L"Sagemcom" },
    { L"3C434B", L"Sagemcom" }, { L"403247", L"Sagemcom" }, { L"44D9E7", L"Sagemcom" },
    { L"44F040", L"Sagemcom" }, { L"486849", L"Sagemcom" }, { L"4C0172", L"Sagemcom" },
    { L"4C5DD2", L"Sagemcom" }, { L"50465D", L"Sagemcom" }, { L"50AE8B", L"Sagemcom" },
    { L"50D59C", L"Sagemcom" }, { L"543AF8", L"Sagemcom" }, { L"54D97F", L"Sagemcom" },
    { L"585508", L"Sagemcom" }, { L"5CC9D3", L"Sagemcom" }, { L"5CDD70", L"Sagemcom" },
    { L"6052D0", L"Sagemcom" }, { L"6063F9", L"Sagemcom" }, { L"6457D8", L"Sagemcom" },
    { L"64642A", L"Sagemcom" }, { L"6872DC", L"Sagemcom" }, { L"68CE4E", L"Sagemcom" },
    { L"6CA75F", L"Sagemcom" }, { L"70485C", L"Sagemcom" }, { L"70B14E", L"Sagemcom" },
    { L"70D931", L"Sagemcom" }, { L"743F4C", L"Sagemcom" }, { L"749DDC", L"Sagemcom" },
    { L"7839E4", L"Sagemcom" }, { L"7C1E52", L"Sagemcom" }, { L"7C97C3", L"Sagemcom" },
    { L"7CB219", L"Sagemcom" }, { L"8017D7", L"Sagemcom" }, { L"8090BC", L"Sagemcom" },
    { L"80C063", L"Sagemcom" }, { L"843F4E", L"Sagemcom" }, { L"84C478", L"Sagemcom" },
    { L"88092C", L"Sagemcom" }, { L"883B15", L"Sagemcom" }, { L"88B469", L"Sagemcom" },
    { L"8C9361", L"Sagemcom" }, { L"90AF49", L"Sagemcom" }, { L"941EEC", L"Sagemcom" },
    { L"947B2C", L"Sagemcom" }, { L"94CDA9", L"Sagemcom" }, { L"9823F0", L"Sagemcom" },
    { L"9858F8", L"Sagemcom" }, { L"98B6D3", L"Sagemcom" }, { L"9C3104", L"Sagemcom" },
    { L"9C6D44", L"Sagemcom" }, { L"A05026", L"Sagemcom" }, { L"A42257", L"Sagemcom" },
    { L"A457A3", L"Sagemcom" }, { L"A8F274", L"Sagemcom" }, { L"ACB8C1", L"Sagemcom" },
    { L"B0E76A", L"Sagemcom" }, { L"B4B15A", L"Sagemcom" }, { L"B81B0A", L"Sagemcom" },
    { L"BCA8A6", L"Sagemcom" }, { L"C0C6A3", L"Sagemcom" }, { L"C402C8", L"Sagemcom" },
    { L"C40FA1", L"Sagemcom" }, { L"C83F26", L"Sagemcom" }, { L"C85B76", L"Sagemcom" },
    { L"CC35DA", L"Sagemcom" }, { L"D08C5D", L"Sagemcom" }, { L"D45157", L"Sagemcom" },
    { L"D8B4C7", L"Sagemcom" }, { L"DC5338", L"Sagemcom" }, { L"E05F45", L"Sagemcom" },
    { L"E48984", L"Sagemcom" }, { L"E89778", L"Sagemcom" }, { L"E8DF6E", L"Sagemcom" },
    { L"ECB1D7", L"Sagemcom" }, { L"F06E32", L"Sagemcom" }, { L"F0C54C", L"Sagemcom" },
    { L"F40F9B", L"Sagemcom" }, { L"F48969", L"Sagemcom" }, { L"F85C69", L"Sagemcom" },
    { L"FC0B34", L"Sagemcom" }, { L"FC71FA", L"Sagemcom" },
};

}

namespace nl {
std::wstring MacVendor(const std::wstring& mac) {
    std::wstring n;
    for (wchar_t ch : mac) {
        if ((ch >= L'0' && ch <= L'9') || (ch >= L'A' && ch <= L'F')) n += ch;
        else if (ch >= L'a' && ch <= L'f') n += (wchar_t)(ch - L'a' + L'A');
    }
    if (n.size() < 6) return L"";
    std::wstring oui = n.substr(0, 6);
    for (const auto& o : kOui)
        if (oui == o.oui) return o.vendor;
    return L"";
}
}
