#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <string>
#include <vector>
#include <cstdint>
#include <algorithm>

namespace nl {

std::wstring Widen(const std::string& s);
std::string  Narrow(const std::wstring& s);
std::wstring ToLower(const std::wstring& s);
bool         Contains(const std::wstring& hay, const std::wstring& needle);
std::wstring Trim(const std::wstring& s);
std::wstring FormatBytesPerSec(double bytesPerSec);
std::wstring FormatBytes(unsigned long long bytes);

std::wstring FormatDurationShort(unsigned long long seconds);
std::wstring FormatDurationLong(unsigned long long seconds);

unsigned long long NowMs();

std::wstring AppDataDir();
std::wstring ExeDir();
bool         IsRunAsAdmin();

}
