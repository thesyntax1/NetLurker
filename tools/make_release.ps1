param([string]$Version = "")
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Push-Location $Root
try {
    $shared = Get-Content version.json -Raw | ConvertFrom-Json
    if (-not $Version) { $Version = $shared.version }
    if ($Version -ne $shared.version) { throw "Run python tools/release_version.py --version $Version and commit the version bump first, or use the Actions dry run." }
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
    Copy-Item version.json build\build-version.json
    python tools\package_release.py --input build --output dist --version $Version --revision $revision
    if ($LASTEXITCODE -ne 0) { throw "Packaging validation failed." }
    Write-Host "Candidate packaged in dist/. Not signed, tagged, or published by this script."
    Write-Host "Complete docs/RELEASE-CHECKLIST.md before distribution."
} finally {
    Pop-Location
}
