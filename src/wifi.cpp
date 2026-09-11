#include "wifi.h"
#include "i18n.h"
#include <cstdio>

using namespace nl;

namespace {

#pragma pack(push, 4)
struct NL_GUID { unsigned long d1; unsigned short d2, d3; unsigned char d4[8]; };

struct NL_WLAN_INTERFACE_INFO {
    NL_GUID guid;
    wchar_t desc[256];
    unsigned long isState;
};

struct NL_WLAN_INTERFACE_INFO_LIST {
    unsigned long dwNumberOfItems;
    unsigned long dwIndex;
    NL_WLAN_INTERFACE_INFO items[1];
};

struct NL_DOT11_SSID {
    unsigned long len;
    unsigned char ssid[32];
};

struct NL_DOT11_MAC {
    unsigned char mac[6];
};

struct NL_WLAN_ASSOCIATION_ATTRIBUTES {
    NL_DOT11_SSID ssid;
    unsigned long bssType;
    NL_DOT11_MAC bssid;
    unsigned long phyType;
    unsigned long phyIndex;
    unsigned long signal;
    unsigned long rxRate;
    unsigned long txRate;
};

struct NL_WLAN_SECURITY_ATTRIBUTES {
    long securityEnabled;
    long oneXEnabled;
    unsigned long authAlg;
    unsigned long cipherAlg;
};

struct NL_WLAN_CONNECTION_ATTRIBUTES {
    unsigned long isState;
    unsigned long connMode;
    wchar_t profile[256];
    NL_WLAN_ASSOCIATION_ATTRIBUTES assoc;
    NL_WLAN_SECURITY_ATTRIBUTES sec;
};
#pragma pack(pop)

typedef unsigned long (WINAPI* PFN_WlanOpenHandle)(unsigned long, void*, unsigned long*, void**);
typedef unsigned long (WINAPI* PFN_WlanCloseHandle)(void*, void*);
typedef unsigned long (WINAPI* PFN_WlanEnumInterfaces)(void*, void*, NL_WLAN_INTERFACE_INFO_LIST**);
typedef unsigned long (WINAPI* PFN_WlanQueryInterface)(void*, const NL_GUID*, unsigned long, void*,
                                                       unsigned long*, void**, unsigned long*);
typedef void (WINAPI* PFN_WlanFreeMemory)(void*);

struct WlanApi {
    PFN_WlanOpenHandle      Open = nullptr;
    PFN_WlanCloseHandle     Close = nullptr;
    PFN_WlanEnumInterfaces  Enum = nullptr;
    PFN_WlanQueryInterface  Query = nullptr;
    PFN_WlanFreeMemory      Free = nullptr;
};

const WlanApi& Wlan() {
    static WlanApi api = [] {
        WlanApi a;
        HMODULE h = LoadLibraryW(L"wlanapi.dll");
        if (h) {
            a.Open  = (PFN_WlanOpenHandle)(void*)GetProcAddress(h, "WlanOpenHandle");
            a.Close = (PFN_WlanCloseHandle)(void*)GetProcAddress(h, "WlanCloseHandle");
            a.Enum  = (PFN_WlanEnumInterfaces)(void*)GetProcAddress(h, "WlanEnumInterfaces");
            a.Query = (PFN_WlanQueryInterface)(void*)GetProcAddress(h, "WlanQueryInterface");
            a.Free  = (PFN_WlanFreeMemory)(void*)GetProcAddress(h, "WlanFreeMemory");
        }
        return a;
    }();
    return api;
}

std::wstring AuthName(unsigned long alg) {
    switch (alg) {
        case 1:  return Tr(L"Open (unencrypted!)");
        case 2:  return Tr(L"WEP (weak!)");
        case 3:  return L"WPA";
        case 4:  return L"WPA-PSK";
        case 5:  return L"WPA-None";
        case 6:  return L"WPA2-EAP";
        case 7:  return L"WPA2-PSK";
        case 8:  return L"WPA3";
        case 9:  return L"WPA3-SAE";
        default: return Tr(L"Unknown");
    }
}

std::wstring CipherName(unsigned long alg) {
    switch (alg) {
        case 0:   return Tr(L"none (unencrypted!)");
        case 1:   return Tr(L"WEP40 (weak!)");
        case 2:   return Tr(L"TKIP (weak)");
        case 4:   return L"AES";
        case 5:   return Tr(L"WEP104 (weak!)");
        case 6:   return L"BIP";
        case 256: return Tr(L"group");
        default:  return Tr(L"unknown");
    }
}

std::wstring MacText(const unsigned char* m) {
    wchar_t b[24];
    swprintf(b, 24, L"%02X:%02X:%02X:%02X:%02X:%02X",
             m[0], m[1], m[2], m[3], m[4], m[5]);
    return b;
}

}

namespace nl {

WifiInfo QueryWifi() {
    WifiInfo w;
    const WlanApi& api = Wlan();
    if (!api.Open || !api.Enum || !api.Query) return w;

    void* h = nullptr;
    unsigned long neg = 0;
    if (api.Open(2, nullptr, &neg, &h) != 0 || !h) return w;

    NL_WLAN_INTERFACE_INFO_LIST* list = nullptr;
    if (api.Enum(h, nullptr, &list) != 0 || !list || list->dwNumberOfItems == 0) {
        api.Close(h, nullptr);
        if (list) api.Free(list);
        return w;
    }

    int idx = -1;
    for (unsigned long i = 0; i < list->dwNumberOfItems; ++i) {
        if (list->items[i].isState == 1 ) { idx = (int)i; break; }
    }
    if (idx < 0) {
        api.Free(list);
        api.Close(h, nullptr);
        return w;
    }

    const NL_GUID guid = list->items[idx].guid;
    void* data = nullptr;
    unsigned long size = 0, type = 0;

    if (api.Query(h, &guid, 7, nullptr, &size, &data, &type) == 0 && data && size >= sizeof(NL_WLAN_CONNECTION_ATTRIBUTES)) {
        const auto* ca = (const NL_WLAN_CONNECTION_ATTRIBUTES*)data;
        const auto& a = ca->assoc;
        const auto& s = ca->sec;

        w.ok = true;
        const unsigned long len = (std::min)(a.ssid.len, 32ul);
        w.ssid.assign((const char*)a.ssid.ssid, (const char*)a.ssid.ssid + len);
        w.bssid = MacText(a.bssid.mac);
        w.signal = (int)a.signal;
        w.rxRate = a.rxRate;
        w.txRate = a.txRate;

        if (s.securityEnabled) {
            w.security = AuthName(s.authAlg) + L" (" + CipherName(s.cipherAlg) + L")";
        } else {
            w.security = Tr(L"Open network (NO encryption!)");
        }
        switch (ca->isState) {
            case 1:  w.state = Tr(L"Connected"); break;
            case 2:  w.state = Tr(L"Associating"); break;
            case 3:  w.state = Tr(L"Authentication failed"); break;
            default: w.state = Tr(L"Unknown"); break;
        }
    }
    if (data) api.Free(data);
    api.Free(list);
    api.Close(h, nullptr);
    return w;
}

}
