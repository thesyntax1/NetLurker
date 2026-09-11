#!/usr/bin/env bash
set -euo pipefail

ZIG="${ZIG:-zig}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/build"
mkdir -p "$OUT"

SRC=(main common netmon geo procinfo history http json ai ui_draw i18n threat plugins cert banner dns wifi firewall)
OBJ=()
for f in "${SRC[@]}"; do
  echo "  CXX  src/$f.cpp"
  "$ZIG" c++ -target x86_64-windows-gnu -std=c++17 -O2 -w \
      -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN -DNOMINMAX -D_WIN32_WINNT=0x0601 \
      -I"$ROOT/src" -c "$ROOT/src/$f.cpp" -o "$OUT/$f.o"
  OBJ+=("$OUT/$f.o")
done

echo "  RC   res/netlurker.rc"
"$ZIG" rc /c 65001 /fo "$OUT/netlurker.res" "$ROOT/res/netlurker.rc" >/dev/null

echo "  LINK build/NetLurker.exe"
"$ZIG" c++ -target x86_64-windows-gnu -municode -w -o "$OUT/NetLurker.exe" \
    "${OBJ[@]}" "$OUT/netlurker.res" -Wl,--subsystem,windows \
    -liphlpapi -lws2_32 -lwinhttp -lgdiplus -lcomctl32 -lshlwapi -ldwmapi \
    -lcomdlg32 -lshell32 -lole32 -luser32 -lgdi32 -ladvapi32 -lpsapi -lwintrust -lcrypt32 -lversion -lwtsapi32 -loleaut32

if [ -d "$ROOT/lang" ] && compgen -G "$ROOT/lang/*.ini" > /dev/null; then
  mkdir -p "$OUT/lang"
  cp "$ROOT"/lang/*.ini "$OUT/lang/"
  echo "language files copied -> $OUT/lang/"
fi
echo "done -> $OUT/NetLurker.exe"
