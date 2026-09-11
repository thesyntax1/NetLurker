@echo off
setlocal

where cl >nul 2>nul
if errorlevel 1 (
  echo [ERROR] cl.exe not found. Run this script from the "x64 Native Tools Command Prompt for VS".
  exit /b 1
)

if not exist build mkdir build

echo [1/3] Compiling sources...
rc /nologo /fo build\netlurker.res res\netlurker.rc
if errorlevel 1 goto :fail

cl /nologo /std:c++17 /EHsc /O2 /MT /W3 /utf-8 /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /DNOMINMAX ^
   /D_WIN32_WINNT=0x0601 /Isrc ^
   src\main.cpp src\common.cpp src\netmon.cpp src\geo.cpp src\procinfo.cpp src\history.cpp ^
   src\http.cpp src\json.cpp src\ai.cpp src\ui_draw.cpp src\i18n.cpp ^
   src\threat.cpp src\plugins.cpp src\cert.cpp src\banner.cpp src\dns.cpp src\wifi.cpp src\firewall.cpp ^
   build\netlurker.res ^
   /Fo:build\ /Fe:build\NetLurker.exe ^
   /link /SUBSYSTEM:WINDOWS /ENTRY:wWinMainCRTStartup ^
   iphlpapi.lib ws2_32.lib winhttp.lib gdiplus.lib comctl32.lib shlwapi.lib dwmapi.lib ^
   comdlg32.lib shell32.lib ole32.lib user32.lib gdi32.lib advapi32.lib psapi.lib ^
   wintrust.lib crypt32.lib version.lib wtsapi32.lib oleaut32.lib
if errorlevel 1 goto :fail

echo.
if exist lang\*.ini (
  if not exist build\lang mkdir build\lang
  copy /Y lang\*.ini build\lang\ >nul
  echo [3/3] Language files copied -> build\lang\
)
echo.
echo done -> build\NetLurker.exe
exit /b 0

:fail
echo.
echo [ERROR] Build failed.
exit /b 1
