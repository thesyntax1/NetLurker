#!/usr/bin/env python3
"""Fail closed when a candidate has no successful launch/UI-test evidence."""
from pathlib import Path
import sys


def verify(root: Path) -> None:
    if (root / "ui-tests-exit.txt").read_text().strip() != "0":
        raise ValueError("instrumented UI tests did not pass")
    steps = dict(line.split("=", 1) for line in (root / "smoke-steps.txt").read_text().splitlines() if "=" in line)
    for name in ("wait_for_device", "install", "am_start", "dumpsys", "logcat", "screencap", "chmod", "gradle"):
        if steps.get(name) != "0":
            raise ValueError(f"missing/failed emulator step: {name}")
    activities = (root / "activities.txt").read_text(errors="replace")
    if not any("ResumedActivity" in line and "dev.netlurker.android" in line for line in activities.splitlines()):
        raise ValueError("NetLurker was not the resumed activity")
    log = (root / "logcat.txt").read_text(errors="replace")
    if "FATAL EXCEPTION" in log or "ANR in dev.netlurker.android" in log:
        raise ValueError("crash/ANR marker found; inspect logcat before releasing")
    if not (root / "screen.png").read_bytes().startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("missing/invalid emulator screenshot")


if __name__ == "__main__":
    verify(Path(sys.argv[1] if len(sys.argv) > 1 else "."))
    print("Launch, screenshot, crash and instrumented-test evidence passed")
