# Z2LS v0.32.1 deployment script.
# Run on Z2LS via:  powershell -ExecutionPolicy Bypass -File deploy-z2ls-v032-1.ps1
# Assumes new binary staged at C:\TRS_Tools\ztlp\ztlp.exe.new (uploaded via scp).
#
# v0.32.1 changes vs v0.32:
#   - PUNCH_REPORT candidates now carry the QUIC listener port (23095)
#     instead of the keepalive socket's ephemeral port. Multi-candidate
#     dial actually works LAN-direct.
#   - QuicDialer binds family-matched per dial — IPv6 candidates work.
#   - Loopback classified at priority 0; cosmetic.
#   - Regression test pinning that `ns register` CBOR includes node_id.

$ErrorActionPreference = 'Stop'
$ZtlpDir = 'C:\TRS_Tools\ztlp'
$NssmExe = "$ZtlpDir\nssm.exe"
$LiveBin = "$ZtlpDir\ztlp.exe"
$NewBin  = "$ZtlpDir\ztlp.exe.new"
$BackupBin = "$ZtlpDir\ztlp.exe.backup-pre-v0.32.1"

# Same params we set on v0.32 deploy (--advertise-all-interfaces stays on).
# Rewriting from clean ASCII source-of-truth here instead of doing string-append
# on `nssm get` output because nssm stores parameters as UTF-16 internally and
# `get` echoes the raw bytes (including NULs), which corrupts naive string append.
$V032Params = 'listen --key C:\ProgramData\ZTLP\identity.json --bind 0.0.0.0:23095 --policy C:\ProgramData\ZTLP\policy.toml --forward ssh:127.0.0.1:22 --ns-server 16.147.41.195:23096 --gateway --relay 34.218.240.106:23095 --service-name z2ls-desktop-lrc8dkh-dcc1e2 --max-sessions 100 --advertise-all-interfaces'

function Write-Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "  [!!] $msg" -ForegroundColor Yellow }

Write-Step 'Pre-flight'
if (-not (Test-Path $NewBin))  { throw "v0.32.1 binary not staged at $NewBin" }
if (-not (Test-Path $LiveBin)) { throw "current ztlp.exe missing at $LiveBin" }
if (-not (Test-Path $NssmExe)) { throw "nssm.exe missing at $NssmExe" }

$newVer = (& $NewBin --version 2>&1) -join ' '
$oldVer = (& $LiveBin --version 2>&1) -join ' '
Write-Host "  current binary: $oldVer"
Write-Host "  new binary:     $newVer"

Write-Step 'Stopping ztlp_listener'
$svc = Get-Service ztlp_listener
if ($svc.Status -eq 'Running') {
    Stop-Service ztlp_listener -Force
    Start-Sleep -Seconds 2
    $svc.Refresh()
    if ($svc.Status -ne 'Stopped') { throw "service did not stop (state=$($svc.Status))" }
    Write-Ok 'stopped'
} else {
    Write-Warn "was not running (state=$($svc.Status))"
}

Write-Step 'Backing up current binary'
if (-not (Test-Path $BackupBin)) {
    Copy-Item $LiveBin $BackupBin -Force
    Write-Ok "backup at $BackupBin"
} else {
    Write-Warn "backup already exists at $BackupBin (preserving)"
}

Write-Step 'Installing v0.32.1 binary'
Copy-Item $NewBin $LiveBin -Force
$liveLen = (Get-Item $LiveBin).Length
$newLen  = (Get-Item $NewBin).Length
if ($liveLen -ne $newLen) { throw "size mismatch after copy: live=$liveLen new=$newLen" }
Write-Ok "live binary now $liveLen bytes"

Write-Step 'Setting NSSM AppParameters (clean rewrite)'
& $NssmExe set ztlp_listener AppParameters $V032Params | Out-Null
Write-Ok 'params updated'

Write-Step 'Starting ztlp_listener'
Start-Service ztlp_listener
# Loop up to 15s for the service to reach Running
$deadline = (Get-Date).AddSeconds(15)
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 500
    $svc.Refresh()
    if ($svc.Status -eq 'Running') { break }
}
if ($svc.Status -ne 'Running') { throw "service did not reach Running (state=$($svc.Status))" }
Write-Ok "started (state=$($svc.Status))"

Write-Step 'Post-flight'
Start-Sleep -Seconds 3
$verifyVer = (& $LiveBin --version 2>&1) -join ' '
Write-Host "  live binary now reports: $verifyVer"
$listening = netstat -an | Select-String '0.0.0.0:23095\s.*UDP'
if ($listening) {
    Write-Ok "UDP 23095 is listening"
} else {
    Write-Warn "UDP 23095 not visible in netstat (may still be binding)"
}

Write-Host ''
Write-Host '=== v0.32.1 DEPLOY COMPLETE ===' -ForegroundColor Green
