#pragma once
#include "common.h"
#include <mutex>

namespace nl {
struct IniValue { std::wstring section, key, value; };

// One same-directory replacement, not a sequence of partially committed settings.
// Unknown sections are preserved. Failure leaves the original file untouched.
inline bool UpdateIniAtomically(const std::wstring& path, const std::vector<IniValue>& values) {
    static std::mutex mutex;
    std::lock_guard<std::mutex> lock(mutex);
    const auto separator = path.find_last_of(L"\\/");
    if (separator == std::wstring::npos) return false;
    const std::wstring dir = path.substr(0, separator + 1);
    wchar_t temporary[MAX_PATH]{};
    if (!GetTempFileNameW(dir.c_str(), L"nls", 0, temporary)) return false;
    struct Cleanup {
        const wchar_t* path;
        ~Cleanup() { DeleteFileW(path); }
    } cleanup{temporary};

    const DWORD attrs = GetFileAttributesW(path.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES) {
        if (attrs & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_READONLY)) return false;
        WritePrivateProfileStringW(nullptr, nullptr, nullptr, path.c_str());
        if (!CopyFileW(path.c_str(), temporary, FALSE)) return false;
    } else {
        if (GetLastError() != ERROR_FILE_NOT_FOUND) return false;
        // A Unicode INI also preserves non-ASCII endpoint/model values on first save.
        HANDLE f = CreateFileW(temporary, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (f == INVALID_HANDLE_VALUE) return false;
        const unsigned char bom[] = {0xff, 0xfe};
        DWORD written = 0;
        const bool ok = WriteFile(f, bom, sizeof(bom), &written, nullptr) && written == sizeof(bom);
        CloseHandle(f);
        if (!ok) return false;
    }
    for (const auto& entry : values) {
        // INI has no escaping for line breaks. Reject rather than permit section injection.
        if (entry.value.find_first_of(L"\r\n") != std::wstring::npos) return false;
        if (!WritePrivateProfileStringW(entry.section.c_str(), entry.key.c_str(), entry.value.c_str(), temporary))
            return false;
    }
    WritePrivateProfileStringW(nullptr, nullptr, nullptr, temporary);
    HANDLE f = CreateFileW(temporary, GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;
    const bool flushed = FlushFileBuffers(f) != FALSE;
    CloseHandle(f);
    if (!flushed || !MoveFileExW(temporary, path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) return false;
    WritePrivateProfileStringW(nullptr, nullptr, nullptr, path.c_str());
    return true;
}
} // namespace nl
