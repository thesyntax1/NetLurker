@echo off
setlocal

where g++ >nul 2>nul
if errorlevel 1 (
  echo [ERROR] g++ not found. Install MSYS2/MinGW-w64 and add it to PATH.
  exit /b 1
)

if not exist build mkdir build

echo [1/3] Compiling sources...
windres -I src -O coff res\netlurker.rc build\netlurker.res.o
if errorlevel 1 goto :fail

g++ -std=c++17 -O2 -municode -mwindows -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN -DNOMINMAX ^
    -D_WIN32_WINNT=0x0601 -Isrc ^
    src\main.cpp src\common.cpp src\netmon.cpp src\geo.cpp src\procinfo.cpp src\history.cpp ^
    src\http.cpp src\json.cpp src\ai.cpp src\ui_draw.cpp src\i18n.cpp ^
    src\threat.cpp src\plugins.cpp src\cert.cpp src\banner.cpp src\dns.cpp src\wifi.cpp ^
    build\netlurker.res.o -o build\NetLurker.exe ^
    -static -static-libgcc -static-libstdc++ ^
    -liphlpapi -lws2_32 -lwinhttp -lgdiplus -lcomctl32 -lshlwapi -ldwmapi ^
    -lcomdlg32 -lshell32 -lole32 -luser32 -lgdi32 -ladvapi32 -lpsapi ^
    -lwintrust -lcrypt32 -lversion -lwtsapi32
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
