param([string]$Version = "6.0.0-rc.1")
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Push-Location $Root
try {
    $dirty = git status --porcelain
    if ($LASTEXITCODE -ne 0 -or $dirty) { throw "Package a committed, clean source tree so the recorded revision is meaningful." }
    $revision = git rev-parse HEAD
    if ($LASTEXITCODE -ne 0) { throw "Cannot determine source revision." }
    python tools\gen_lang.py --check
    if ($LASTEXITCODE -ne 0) { throw "Language catalog check failed." }
    # Never fall back to an executable left behind by an earlier build.
    Remove-Item build\NetLurker.exe -ErrorAction SilentlyContinue
    cmd /c build.bat
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path build\NetLurker.exe)) { throw "Fresh build failed." }
    $revision | Set-Content build\build-revision.txt -Encoding ascii
    python tools\package_release.py --input build --output dist --version $Version --revision $revision
    if ($LASTEXITCODE -ne 0) { throw "Packaging validation failed." }
    Write-Host "Candidate packaged in dist/. Not signed, tagged, or published by this script."
    Write-Host "Complete docs/RELEASE-CHECKLIST.md before distribution."
} finally {
    Pop-Location
}
