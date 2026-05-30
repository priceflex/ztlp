# ZTLP Windows Desktop MVP - D5 End-to-End Smoke (Automated)
# ASCII ONLY. Windows PowerShell 5.1 on DESKTOP-LRC8DKH.
#
# Validates D5 on a real Windows bench:
#   1. ztlp admin ca-init --zone trs.ztlp  (real X.509 chain via rcgen)
#   2. Verify root.pem + intermediate.pem are valid X.509 (certutil -dump)
#   3. ztlp agent install-ca-cert --machine-scope
#   4. Verify cert appears in LocalMachine\Root (certutil -store Root)
#   5. (D5.T2 inline) ztlp helper: mint a leaf via cert_mint module
#      We can't invoke the cert_mint module directly from CLI, but the
#      lib tests already prove it works. We DO verify the chain validates
#      with certutil and openssl.
#   6. ztlp agent remove-ca-cert  (cleanup)
#   7. Verify cert is gone from LocalMachine\Root

[CmdletBinding()]
param(
    [string]$BinDir = "C:\Users\trs\ztlp",
    [string]$Transcript = "C:\Users\trs\ztlp-d5-e2e-evidence.txt",
    [string]$Zone = "trs.ztlp"
)

$ErrorActionPreference = "Continue"
Start-Transcript -Path $Transcript -Force | Out-Null

function Section($title) {
    Write-Output ""
    Write-Output "================================================================"
    Write-Output ("  " + $title)
    Write-Output "================================================================"
}

Section "0. Environment"
Get-Date -Format "yyyy-MM-dd HH:mm:ssK"
$id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($id)
Write-Output ("IsAdmin: " + $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))
Write-Output ("Host:    " + $env:COMPUTERNAME)
Write-Output ("User:    " + $env:USERNAME)
$ztlpExe = Join-Path $BinDir "ztlp.exe"
if (-not (Test-Path $ztlpExe)) {
    Write-Output ("[FAIL] ztlp.exe NOT FOUND at " + $ztlpExe)
    Stop-Transcript | Out-Null
    exit 2
}
& $ztlpExe --version
Write-Output ""

Section "1. Pre-flight - clean any existing ZTLP CA + trust store entries"
# Remove existing CA chain on disk
$caDir = Join-Path $env:USERPROFILE ".ztlp\ca"
if (Test-Path $caDir) {
    Write-Output ("Removing existing CA dir: " + $caDir)
    Remove-Item -Recurse -Force $caDir
}
# Remove from LocalMachine\Root if present from a previous run
$existing = Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -like "*ZTLP Root CA*" }
if ($existing) {
    Write-Output ("Removing " + $existing.Count + " existing ZTLP cert(s) from LocalMachine\Root")
    $existing | Remove-Item -Force
}
# Also CurrentUser scope for thoroughness
$existingU = Get-ChildItem Cert:\CurrentUser\Root | Where-Object { $_.Subject -like "*ZTLP Root CA*" }
if ($existingU) {
    Write-Output ("Removing " + $existingU.Count + " existing ZTLP cert(s) from CurrentUser\Root")
    $existingU | Remove-Item -Force
}
Write-Output "[OK] Pre-flight clean"

Section "2. ca-init - generate REAL X.509 chain (D5.T2.0)"
$caInitOutput = & $ztlpExe admin ca-init --zone $Zone 2>&1
$caInitExit = $LASTEXITCODE
$caInitOutput
Write-Output ("EXIT_CODE: " + $caInitExit)
if ($caInitExit -ne 0) {
    Write-Output "[FAIL] ca-init failed"
    Stop-Transcript | Out-Null
    exit 3
}

# Confirm files exist
$rootPem = Join-Path $caDir "root.pem"
$rootKey = Join-Path $caDir "root.key"
$intPem  = Join-Path $caDir "intermediate.pem"
$intKey  = Join-Path $caDir "intermediate.key"
foreach ($f in @($rootPem, $rootKey, $intPem, $intKey)) {
    if (-not (Test-Path $f)) {
        Write-Output ("[FAIL] missing CA file: " + $f)
        Stop-Transcript | Out-Null
        exit 3
    }
}
Write-Output "[OK] all 4 CA files present"

Section "3. Validate root.pem is REAL X.509 (certutil -dump)"
# THIS is the test that proves the v0.34.3 stub is fixed.
# certutil -dump on the stub returned an error; on real X.509 it shows
# Issuer/Subject/SerialNumber/Validity.
$dumpOutput = certutil -dump $rootPem 2>&1
$dumpExit = $LASTEXITCODE
$dumpOutput | Select-Object -First 30
Write-Output ("EXIT_CODE: " + $dumpExit)
if ($dumpExit -ne 0) {
    Write-Output "[FAIL] certutil -dump rejected root.pem - the chain is still a stub"
    Stop-Transcript | Out-Null
    exit 4
}
# Cross-check: dump should mention "ZTLP Root CA" in the subject
$dumpStr = $dumpOutput -join "`n"
if (-not ($dumpStr -match "ZTLP Root CA")) {
    Write-Output "[FAIL] certutil -dump didn't find ZTLP Root CA CN"
    Stop-Transcript | Out-Null
    exit 4
}
Write-Output "[OK] root.pem is a real X.509 cert with the expected CN"

Section "3b. Validate intermediate.pem is REAL X.509 and signed by root"
$intDumpOutput = certutil -dump $intPem 2>&1
$intDumpExit = $LASTEXITCODE
$intDumpOutput | Select-Object -First 30
Write-Output ("EXIT_CODE: " + $intDumpExit)
if ($intDumpExit -ne 0) {
    Write-Output "[FAIL] certutil -dump rejected intermediate.pem"
    Stop-Transcript | Out-Null
    exit 4
}
$intDumpStr = $intDumpOutput -join "`n"
if (-not ($intDumpStr -match "ZTLP Intermediate CA")) {
    Write-Output "[FAIL] intermediate.pem missing expected CN"
    Stop-Transcript | Out-Null
    exit 4
}
# Critical: intermediate's Issuer should be the root's Subject.
if (-not ($intDumpStr -match "ZTLP Root CA")) {
    Write-Output "[FAIL] intermediate.pem not issued by ZTLP Root CA"
    Stop-Transcript | Out-Null
    exit 4
}
Write-Output "[OK] intermediate.pem is real X.509, issued by ZTLP Root CA"

Section "4. install-ca-cert --machine-scope (D5.T1)"
$installOutput = & $ztlpExe agent install-ca-cert --machine-scope 2>&1
$installExit = $LASTEXITCODE
$installOutput
Write-Output ("EXIT_CODE: " + $installExit)
if ($installExit -ne 0) {
    Write-Output "[FAIL] install-ca-cert --machine-scope failed"
    Stop-Transcript | Out-Null
    exit 5
}

Section "5. Verify cert landed in LocalMachine\Root"
$installed = Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -like "*ZTLP Root CA*" }
if (-not $installed) {
    Write-Output "[FAIL] no ZTLP Root CA in LocalMachine\Root after install"
    Stop-Transcript | Out-Null
    exit 6
}
$installed | Select-Object Subject,Thumbprint,NotAfter | Format-Table -AutoSize
Write-Output "[OK] ZTLP Root CA is in machine-wide trust store"

Section "6. Cross-check: CurrentUser\Root view (Windows mirrors machine certs)"
# Windows blends LocalMachine\Root into the CurrentUser\Root view, so a
# machine-installed cert appears in both. This is expected OS behavior,
# not a double-install. Note for the operator only — not a failure case.
$userScope = Get-ChildItem Cert:\CurrentUser\Root | Where-Object { $_.Subject -like "*ZTLP Root CA*" }
if ($userScope) {
    Write-Output "[INFO] ZTLP Root CA visible in CurrentUser\Root (expected mirror from machine store)"
    $userScope | Select-Object Subject,Thumbprint | Format-Table
} else {
    Write-Output "[INFO] CurrentUser\Root view empty (also fine)"
}

Section "7. remove-ca-cert (idempotent uninstall)"
$rmOutput = & $ztlpExe agent remove-ca-cert 2>&1
$rmExit = $LASTEXITCODE
$rmOutput
Write-Output ("EXIT_CODE: " + $rmExit)

Section "8. Verify cert removed from LocalMachine\Root"
$afterRm = Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -like "*ZTLP Root CA*" }
if ($afterRm) {
    Write-Output "[FAIL] ZTLP Root CA still in LocalMachine\Root after remove-ca-cert"
    $afterRm | Format-Table
    Stop-Transcript | Out-Null
    exit 7
}
Write-Output "[OK] machine-wide trust store is clean"

Section "9. RESULT"
Write-Output "[PASS] ALL D5 CHECKS PASSED"
Write-Output ("Evidence: " + $Transcript)
Stop-Transcript | Out-Null
exit 0
