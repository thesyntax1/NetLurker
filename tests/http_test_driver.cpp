#include "http.h"
#include <windows.h>
#include <iostream>

// Only the UTF-8 boundary is supplied here; the actual production transport is linked.
namespace nl {
std::wstring Widen(const std::string& s) {
    if (s.empty()) return L"";
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring out(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &out[0], n);
    return out;
}
}
int main(int argc, char** argv) {
    if (argc < 2) return 2;
    auto response = nl::http::Request("POST", argv[1], "fixture-body", "application/json",
                                      argc > 2 ? argv[2] : "fixture-key", 1500, L"X-Fixture: test");
    std::cout << response.ok << '\n' << response.status << '\n' << response.body.size() << '\n'
              << response.error << '\n' << response.body.substr(0, 200);
}
