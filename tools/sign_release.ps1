param(
    [Parameter(Mandatory=$true)][string]$File,
    [string]$Thumbprint = "",
    [string]$Cert = "",
    [string]$Password = "",
    [string]$TimestampUrl = "http://timestamp.digicert.com",
    [string]$Description = "NetLurker - Real-time Windows Network Intelligence",
    [switch]$Verify
)

$ErrorActionPreference = "Stop"
$sign = Get-Command signtool.exe -ErrorAction SilentlyContinue
if (-not $sign) {
    throw "signtool.exe not found. Install the Windows SDK and add it to PATH."
}
if (-not (Test-Path $File)) { throw "File not found: $File" }
$File = (Resolve-Path $File).Path

if ($Verify) {
    Write-Host "== Verifying: $File =="
    & signtool.exe verify /pa /v $File
    if ($LASTEXITCODE -ne 0) { throw "Signature verification FAILED." }
    Write-Host "Signature verified." -ForegroundColor Green
    exit 0
}

$common = @("sign", "/fd", "SHA256", "/tr", $TimestampUrl, "/td", "SHA256",
            "/d", "`"$Description`"")

if ($Cert -ne "") {
    if ($Password -eq "") { throw "-Password is required for a PFX file." }
    & signtool.exe @common /f $Cert /p $Password $File
} elseif ($Thumbprint -ne "") {
    & signtool.exe @common /sha1 $Thumbprint $File
} else {
    throw "Specify a signing source: -Thumbprint or -Cert (or -Verify)."
}
if ($LASTEXITCODE -ne 0) { throw "Signing failed." }

Write-Host "Signed; verifying..." -ForegroundColor Green
& signtool.exe verify /pa /v $File
if ($LASTEXITCODE -ne 0) { throw "Signature verification FAILED." }

$sig = Get-AuthenticodeSignature $File
Write-Host ""
Write-Host "Summary:" -ForegroundColor Green
Write-Host "  File     : $File"
Write-Host "  Status   : $($sig.Status)"
Write-Host "  Signer   : $($sig.SignerCertificate.Subject)"
Write-Host "  SHA-256  : $((Get-FileHash $File -Algorithm SHA256).Hash.ToLower())"
