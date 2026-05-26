# D2.T5 -- Windows-bench smoke for the D2 service host.
#
# Verifies that ztlp-service.exe (cross-compiled from Linux/MinGW for this
# smoke; CI build identical from MSVC) can:
#   1. Install as a Windows service named "ZtlpAgent"
#   2. Create C:\ProgramData\ZTLP\agent.token with the right ACL
#       (SYSTEM:F, BUILTIN\Administrators:R, current-user:R)
#   3. Register with the SCM as LocalSystem, auto-start, correct binPath
#   4. Start cleanly and stay Running for at least 5 seconds
#   5. Stop cleanly
#   6. Uninstall cleanly (no lingering SCM entry)
#
# Leaves the bench in the same state we found it in (token file removed,
# service unregistered, ProgramData\ZTLP\ untouched aside from token file).
#
# Designed to be re-runnable: if a prior run left a ZtlpAgent service
# behind, we tear it down at the top before re-installing.

$ErrorActionPreference = 'Stop'
$failures = @()
function Pass($msg) { Write-Host "  [OK] $msg" -ForegroundColor Green }
function Fail($msg) { Write-Host "  [X] $msg" -ForegroundColor Red; $script:failures += $msg }
function Section($msg) { Write-Host ""; Write-Host "=== $msg ===" -ForegroundColor Cyan }

$ServicePath = 'C:\Users\trs\Desktop\ztlp-service.exe'
$TokenPath = 'C:\ProgramData\ZTLP\agent.token'

# --- Pre-flight cleanup -----------------------------------------------
Section "Pre-flight: tear down any prior smoke run"
$existing = Get-Service -Name ZtlpAgent -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "  Found existing ZtlpAgent service; stopping and uninstalling..."
    if ($existing.Status -ne 'Stopped') {
        Stop-Service ZtlpAgent -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }
    & $ServicePath uninstall 2>&1 | ForEach-Object { Write-Host "    $_" }
    Start-Sleep -Seconds 1
}
# Remove the token file too so we can verify install creates it from scratch
if (Test-Path $TokenPath) {
    Write-Host "  Removing pre-existing $TokenPath"
    Remove-Item -Force $TokenPath -ErrorAction SilentlyContinue
}
Pass "bench state reset"

# --- 1. Install -------------------------------------------------------
Section "Step 1: ztlp-service.exe install"
$installOutput = & $ServicePath install 2>&1
$installExit = $LASTEXITCODE
$installOutput | ForEach-Object { Write-Host "    $_" }
if ($installExit -eq 0) { Pass "install exited 0" } else { Fail "install exited $installExit" }

# --- 2. Token file with correct ACL -----------------------------------
Section "Step 2: token file + ACL"
if (Test-Path $TokenPath) {
    Pass "$TokenPath exists"
} else {
    Fail "$TokenPath was NOT created"
}

if (Test-Path $TokenPath) {
    $acl = Get-Acl $TokenPath
    $acesByIdentity = @{}
    foreach ($ace in $acl.Access) {
        $key = $ace.IdentityReference.Value
        if (-not $acesByIdentity.ContainsKey($key)) { $acesByIdentity[$key] = @() }
        $acesByIdentity[$key] += $ace
    }
    Write-Host "  ACL entries:"
    foreach ($id in $acesByIdentity.Keys) {
        foreach ($a in $acesByIdentity[$id]) {
            Write-Host "    $id  $($a.AccessControlType)  $($a.FileSystemRights)"
        }
    }
    # D2.T4 contract: SYSTEM:F, BUILTIN\Administrators:R, current-user:R
    $hasSystemFull = $acl.Access | Where-Object {
        $_.IdentityReference.Value -eq 'NT AUTHORITY\SYSTEM' -and
        $_.FileSystemRights -eq 'FullControl'
    }
    $hasAdminRead = $acl.Access | Where-Object {
        $_.IdentityReference.Value -eq 'BUILTIN\Administrators' -and
        ($_.FileSystemRights.ToString() -match 'Read|FullControl')
    }
    # The installer grants the current user as <computername>\<user>
    # (whoami output), NOT $USERDOMAIN\$USERNAME which would be
    # WORKGROUP\trs on a non-domain host. So compute the expected
    # identity the same way the installer did.
    $computerName = $env:COMPUTERNAME
    $expectedUser = "$computerName\$env:USERNAME"
    $hasUserRead = $acl.Access | Where-Object {
        $_.IdentityReference.Value -ieq $expectedUser -and
        ($_.FileSystemRights.ToString() -match 'Read|FullControl')
    }
    if ($hasSystemFull) { Pass "SYSTEM has FullControl" } else { Fail "SYSTEM does NOT have FullControl" }
    if ($hasAdminRead) { Pass "BUILTIN\Administrators has Read" } else { Fail "BUILTIN\Administrators does NOT have Read" }
    if ($hasUserRead) { Pass "$expectedUser has Read" } else { Fail "$expectedUser does NOT have Read" }
}

# --- 3. SCM entry -----------------------------------------------------
Section "Step 3: SCM entry"
$svc = Get-Service -Name ZtlpAgent -ErrorAction SilentlyContinue
if (-not $svc) {
    Fail "ZtlpAgent service NOT registered in SCM"
} else {
    Pass "ZtlpAgent registered"
    $wmi = Get-CimInstance Win32_Service -Filter "Name = 'ZtlpAgent'"
    Write-Host "  PathName : $($wmi.PathName)"
    Write-Host "  StartName: $($wmi.StartName)"
    Write-Host "  StartMode: $($wmi.StartMode)"
    Write-Host "  State    : $($wmi.State)"
    Write-Host "  Description: $($wmi.Description)"
    if ($wmi.StartName -eq 'LocalSystem') { Pass "StartName=LocalSystem" } else { Fail "StartName=$($wmi.StartName), expected LocalSystem" }
    if ($wmi.StartMode -eq 'Auto') { Pass "StartMode=Auto" } else { Fail "StartMode=$($wmi.StartMode), expected Auto" }
    if ($wmi.PathName -match '"') { Pass "binPath is quoted (no unquoted-path CVE)" } else { Fail "binPath is NOT quoted, exposes unquoted-service-path attack: $($wmi.PathName)" }
}

# --- 4. Start the service ---------------------------------------------
Section "Step 4: start service"
Start-Service ZtlpAgent -ErrorAction SilentlyContinue
Start-Sleep -Seconds 3
$svc = Get-Service -Name ZtlpAgent
Write-Host "  Status after start: $($svc.Status)"
if ($svc.Status -eq 'Running') {
    Pass "service is Running"
    # Hold for 5 seconds to ensure it doesn't crash-loop immediately
    Start-Sleep -Seconds 5
    $svc.Refresh()
    if ($svc.Status -eq 'Running') {
        Pass "service still Running after 5s (no immediate crash)"
    } else {
        Fail "service transitioned out of Running within 5s: $($svc.Status)"
    }
} else {
    Fail "service did NOT reach Running state; got $($svc.Status)"
    # Pull the most recent System log entries for ZtlpAgent for debug
    Write-Host "  Recent System log entries:"
    Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Service Control Manager'} -MaxEvents 5 -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match 'ZtlpAgent' } |
        Format-List TimeCreated, Id, LevelDisplayName, Message
}

# --- 5. Stop the service ----------------------------------------------
Section "Step 5: stop service"
Stop-Service ZtlpAgent -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
$svc = Get-Service -Name ZtlpAgent
if ($svc.Status -eq 'Stopped') { Pass "service Stopped cleanly" } else { Fail "service didn't stop; status=$($svc.Status)" }

# --- 6. Uninstall -----------------------------------------------------
Section "Step 6: ztlp-service.exe uninstall"
$uninstallOutput = & $ServicePath uninstall 2>&1
$uninstallExit = $LASTEXITCODE
$uninstallOutput | ForEach-Object { Write-Host "    $_" }
if ($uninstallExit -eq 0) { Pass "uninstall exited 0" } else { Fail "uninstall exited $uninstallExit" }

Start-Sleep -Seconds 2
$svc = Get-Service -Name ZtlpAgent -ErrorAction SilentlyContinue
if ($svc) { Fail "ZtlpAgent service STILL registered after uninstall" } else { Pass "ZtlpAgent no longer registered" }

# --- Cleanup ----------------------------------------------------------
Section "Cleanup"
if (Test-Path $TokenPath) {
    Remove-Item -Force $TokenPath -ErrorAction SilentlyContinue
    Pass "removed leftover token file"
}

# --- Summary ----------------------------------------------------------
Section "SUMMARY"
if ($failures.Count -eq 0) {
    Write-Host "[PASS] D2.T5 SMOKE PASSED -- all checks green" -ForegroundColor Green
    exit 0
} else {
    Write-Host "[FAIL] D2.T5 SMOKE FAILED -- $($failures.Count) check(s) failed:" -ForegroundColor Red
    $failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    exit 1
}
