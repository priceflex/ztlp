# Z2LS v0.32 deployment script — v2 (UTF-16 NSSM-get workaround).
# Run on Z2LS via:  powershell -ExecutionPolicy Bypass -File deploy-z2ls-v032.ps1
# Assumes ztlp-v032.exe is staged at $env:USERPROFILE\ztlp-v032.exe
# (uploaded via scp before this runs).

$ErrorActionPreference = 'Stop'
$ZtlpDir = 'C:\TRS_Tools\ztlp'
$NssmExe = "$ZtlpDir\nssm.exe"
$LiveBin = "$ZtlpDir\ztlp.exe"
$NewBin  = "$env:USERPROFILE\Downloads\ztlp-v032.exe"
$BackupBin = "$ZtlpDir\ztlp.exe.backup-pre-v0.32"

# Original known-good params (captured from rollback). We rewrite from a clean
# ASCII source-of-truth here instead of doing string-append on `nssm get` output
# because nssm stores parameters as UTF-16 internally and `get` echoes the raw
# bytes (including NULs), which corrupts naive string append.
$BaseParams = 'listen --key C:\ProgramData\ZTLP\identity.json --bind 0.0.0.0:23095 --policy C:\ProgramData\ZTLP\policy.toml --forward ssh:127.0.0.1:22 --ns-server 16.147.41.195:23096 --gateway --relay 34.218.240.106:23095 --service-name z2ls-desktop-lrc8dkh-dcc1e2 --max-sessions 100'
$V032Params = "$BaseParams --advertise-all-interfaces"

function Write-Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "  [!!] $msg" -ForegroundColor Yellow }

Write-Step 'Pre-flight'
if (-not (Test-Path $NewBin)) { throw "v0.32 binary not staged at $NewBin" }
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
    Write-Warn "backup already exists, not overwriting: $BackupBin"
}

Write-Step 'Installing v0.32 binary'
Copy-Item $NewBin $LiveBin -Force
$installedVer = (& $LiveBin --version 2>&1) -join ' '
Write-Ok "installed: $installedVer"

Write-Step 'Verifying v0.32 CLI surface'
$listenHelp = & $LiveBin listen --help 2>&1 | Out-String
$gwHelp     = & $LiveBin gateway --help 2>&1 | Out-String
$missing = @()
if ($listenHelp -notmatch '--advertise-interface')      { $missing += '--advertise-interface' }
if ($listenHelp -notmatch '--advertise-all-interfaces') { $missing += '--advertise-all-interfaces' }
if ($gwHelp -notmatch 'candidates')                     { $missing += 'gateway candidates' }
if ($missing.Count -gt 0) {
    Write-Warn "v0.32 surface MISSING: $($missing -join ', ')"
    Write-Warn 'rolling back binary...'
    Copy-Item $BackupBin $LiveBin -Force
    Start-Service ztlp_listener
    throw "v0.32 surface check failed; binary rolled back"
}
Write-Ok 'flags + subcommands present'

Write-Step 'Setting NSSM AppParameters from clean source'
# Write from clean ASCII source instead of round-tripping nssm get output
& $NssmExe set ztlp_listener AppParameters $V032Params 2>&1 | Out-Null
Write-Ok "set AppParameters length=$($V032Params.Length)"

Write-Step 'Starting ztlp_listener'
Start-Service ztlp_listener
$tries = 0
while ($svc.Status -ne 'Running' -and $tries -lt 15) {
    Start-Sleep -Seconds 1
    $svc.Refresh()
    $tries++
}
if ($svc.Status -ne 'Running') {
    Write-Warn "service did NOT start after 15s (status=$($svc.Status))"
    Write-Warn 'rolling back AppParameters AND binary...'
    Stop-Service ztlp_listener -Force -ErrorAction SilentlyContinue
    & $NssmExe set ztlp_listener AppParameters $BaseParams 2>&1 | Out-Null
    Copy-Item $BackupBin $LiveBin -Force
    Start-Service ztlp_listener
    throw "v0.32 service failed to start; full rollback applied"
}
Write-Ok "service running (took $tries sec)"

Write-Step 'Tail of ztlp-listener.out.log'
Start-Sleep -Seconds 3
$logPath = 'C:\TRS_Tools\ztlp\logs\ztlp-listener.out.log'
if (Test-Path $logPath) {
    Get-Content $logPath -Tail 30
} else {
    Write-Warn "log not found at $logPath"
}

Write-Step 'UDP listener check'
Get-NetUDPEndpoint -LocalPort 23095 -ErrorAction SilentlyContinue | Format-Table -AutoSize

Write-Host ''
Write-Host '*** DEPLOY COMPLETE ***' -ForegroundColor Green
Write-Host "  binary:       $LiveBin (v0.32)"
Write-Host "  backup:       $BackupBin (v0.31)"
Write-Host "  rollback cmd: powershell -File rollback-z2ls.ps1"
