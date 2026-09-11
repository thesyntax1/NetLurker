#pragma once
#include "common.h"
#include <string>

namespace nl {

struct WifiInfo {
    bool   ok = false;
    std::wstring ssid;
    std::wstring bssid;
    std::wstring security;
    std::wstring state;
    int    signal = 0;
    unsigned long txRate = 0;
    unsigned long rxRate = 0;
};

WifiInfo QueryWifi();

}
