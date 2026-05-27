# Emergency rollback for Z2LS ztlp_listener service
# Restores original AppParameters and original binary, then starts service
$ErrorActionPreference = 'Stop'
$Nssm = 'C:\TRS_Tools\ztlp\nssm.exe'
$LiveBin = 'C:\TRS_Tools\ztlp\ztlp.exe'
$BackupBin = 'C:\TRS_Tools\ztlp\ztlp.exe.backup-pre-v0.32'

# Original known-good AppParameters captured from the deploy run
$origParams = 'listen --key C:\ProgramData\ZTLP\identity.json --bind 0.0.0.0:23095 --policy C:\ProgramData\ZTLP\policy.toml --forward ssh:127.0.0.1:22 --ns-server 16.147.41.195:23096 --gateway --relay 34.218.240.106:23095 --service-name z2ls-desktop-lrc8dkh-dcc1e2 --max-sessions 100'

Write-Host "==> Stopping service if running"
$svc = Get-Service ztlp_listener
if ($svc.Status -ne 'Stopped') { Stop-Service ztlp_listener -Force; Start-Sleep 2 }

Write-Host "==> Restoring original AppParameters"
& $Nssm set ztlp_listener AppParameters $origParams 2>&1 | Out-Null
Write-Host "    set OK"

Write-Host "==> Verifying AppParameters readback"
$readback = (& $Nssm get ztlp_listener AppParameters 2>&1) -join ' '
Write-Host "    readback length=$($readback.Length)"

Write-Host "==> Restoring pre-v0.32 binary"
Copy-Item -Path $BackupBin -Destination $LiveBin -Force
Write-Host "    restored from $BackupBin"

Write-Host "==> Starting service"
Start-Service ztlp_listener
Start-Sleep 3
$svc.Refresh()
Write-Host "    status: $($svc.Status)"

Write-Host "==> Final binary version"
& $LiveBin --version 2>&1

Write-Host "==> UDP listener"
Get-NetUDPEndpoint -LocalPort 23095 -ErrorAction SilentlyContinue | Format-Table -AutoSize
