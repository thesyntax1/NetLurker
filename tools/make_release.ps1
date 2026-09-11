param(
    [string]$Version = ""
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot

if (-not $Version) {
    $rc = Get-Content "$Root\res\netlurker.rc" -Raw
    if ($rc -match 'VERSION (\d+),(\d+),(\d+),(\d+)') {
        $Version = "$($Matches[1]).$($Matches[2]).$($Matches[3])"
    } else {
        $Version = (Get-Date -Format "yyyy.MM.dd")
    }
}

Write-Host "== packaging NetLurker v$Version =="

if (-not (Test-Path "$Root\build\NetLurker.exe")) {
    Write-Host "[1/3] Building: running build.bat..."
    Push-Location $Root
    cmd /c build.bat
    Pop-Location
} else {
    Write-Host "[1/3] Reusing existing build\NetLurker.exe (delete it to rebuild)."
}

Write-Host "[2/3] Copying language files..."
$dst = "$Root\build\lang"
if (-not (Test-Path $dst)) { New-Item -ItemType Directory -Path $dst | Out-Null }
Copy-Item "$Root\lang\*.ini" $dst -Force

Write-Host "[3/3] Creating zip + SHA256SUMS..."
$zip = Join-Path $Root "NetLurker-v$Version-win64.zip"
if (Test-Path $zip) { Remove-Item $zip }
Compress-Archive -Path "$Root\build\NetLurker.exe", "$Root\build\lang" -DestinationPath $zip

$sums = @()
foreach ($f in @($zip, "$Root\build\NetLurker.exe")) {
    $h = (Get-FileHash $f -Algorithm SHA256).Hash.ToLower()
    $sums += "$h  $(Split-Path -Leaf $f)"
}
$sums | Out-File "$Root\SHA256SUMS" -Encoding ascii

Write-Host ""
Write-Host "Ready:"
Write-Host "  $zip"
Write-Host "  $Root\SHA256SUMS"
Write-Host ""
Write-Host "Publish:"
Write-Host "  gh release create v$Version $zip SHA256SUMS --title `"NetLurker v$Version`" --generate-notes"
