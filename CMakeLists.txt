cmake_minimum_required(VERSION 3.15)
project(NetLurker LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT WIN32)
    message(FATAL_ERROR "NetLurker builds on Windows only.")
endif()

enable_language(RC)

add_executable(NetLurker WIN32
    src/main.cpp
    src/common.cpp
    src/netmon.cpp
    src/threat.cpp
    src/cert.cpp
    src/banner.cpp
    src/dns.cpp
    src/wifi.cpp
    src/geo.cpp
    src/procinfo.cpp
    src/history.cpp
    src/http.cpp
    src/json.cpp
    src/ai.cpp
    src/ui_draw.cpp
    res/netlurker.rc
)

target_include_directories(NetLurker PRIVATE src)

target_compile_definitions(NetLurker PRIVATE
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0601
)

target_link_libraries(NetLurker PRIVATE
    iphlpapi ws2_32 winhttp gdiplus comctl32 shlwapi dwmapi
    comdlg32 shell32 ole32 user32 gdi32 advapi32 psapi
    wintrust crypt32 version wtsapi32
)

if(MSVC)
    target_compile_options(NetLurker PRIVATE /W4 /permissive- /utf-8 /EHsc)
    set_target_properties(NetLurker PROPERTIES LINK_FLAGS "/SUBSYSTEM:WINDOWS /ENTRY:wWinMainCRTStartup")
else()
    target_compile_options(NetLurker PRIVATE -Wall -Wextra -Wno-unused-parameter -municode)
    target_link_options(NetLurker PRIVATE -municode -mwindows -static -static-libgcc -static-libstdc++)
endif()

set_target_properties(NetLurker PROPERTIES OUTPUT_NAME "NetLurker")
