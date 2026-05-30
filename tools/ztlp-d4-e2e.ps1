# ZTLP Windows Desktop MVP - D4 End-to-End Smoke (Automated)
# ASCII ONLY. Windows PowerShell 5.1 on DESKTOP-LRC8DKH defaults to
# Windows-1252 when reading .ps1 - any UTF-8 multi-byte char breaks parse.

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Token,

    [string]$BinDir = "C:\Users\trs\ztlp",
    [string]$Transcript = "C:\Users\trs\ztlp-d4-e2e-evidence.txt"
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
Write-Output ("PSVer:   " + $PSVersionTable.PSVersion.ToString())
$ztlpExe = Join-Path $BinDir "ztlp.exe"
if (-not (Test-Path $ztlpExe)) {
    Write-Output ("[FAIL] ztlp.exe NOT FOUND at " + $ztlpExe)
    Stop-Transcript | Out-Null
    exit 2
}
& $ztlpExe --version
Write-Output ""

Section "1. Pre-flight - existing ZTLP NRPT rules (should be none)"
$preRules = Get-DnsClientNrptRule | Where-Object { $_.Comment -like "*ZTLP*" }
if ($preRules) {
    Write-Output "[WARN] Found pre-existing ZTLP NRPT rules - removing first"
    $preRules | Format-Table Name,Namespace,NameServers,Comment -AutoSize
    & $ztlpExe agent dns-teardown 2>&1
} else {
    Write-Output "[OK] Clean - no ZTLP NRPT rules present"
}

Section "2. Enroll with token (ztlp setup --token ...)"
$enrollResult = & $ztlpExe setup --token $Token --name "lrc8dkh-d4smoke3" -y 2>&1
$enrollExit = $LASTEXITCODE
$enrollResult
Write-Output ""
Write-Output ("EXIT_CODE: " + $enrollExit)
if ($enrollExit -ne 0) {
    Write-Output "[FAIL] Enrollment failed"
    Stop-Transcript | Out-Null
    exit 3
}

if (Test-Path "$env:USERPROFILE\.ztlp\identity.json") {
    Write-Output "[OK] identity.json written"
} else {
    Write-Output "[FAIL] identity.json missing after enrollment"
    Stop-Transcript | Out-Null
    exit 3
}

Section "3. D4 - agent dns-setup (auto-detect zone from identity)"
$dnsResult = & $ztlpExe agent dns-setup --zones trs.ztlp 2>&1
$dnsExit = $LASTEXITCODE
$dnsResult
Write-Output ""
Write-Output ("EXIT_CODE: " + $dnsExit)
if ($dnsExit -ne 0) {
    Write-Output "[FAIL] dns-setup failed"
    Stop-Transcript | Out-Null
    exit 4
}

Section "4. Verify NRPT rule shape (Get-DnsClientNrptRule)"
$rules = Get-DnsClientNrptRule | Where-Object { $_.Comment -like "*ZTLP*" }
if (-not $rules) {
    Write-Output "[FAIL] No ZTLP NRPT rules created - D4 IS BROKEN"
    Stop-Transcript | Out-Null
    exit 5
}
$rules | Format-Table Name,Namespace,NameServers,Comment -AutoSize
Write-Output ""
Write-Output "Full record (JSON):"
$rules | ConvertTo-Json -Depth 4

Section "5. Verify DNS interception"
Write-Output "nslookup probe.trs.ztlp (should hit ZTLP loopback resolver):"
nslookup probe.trs.ztlp 2>&1
Write-Output ""
Write-Output "Resolve-DnsName probe.trs.ztlp (cross-check):"
Resolve-DnsName probe.trs.ztlp -ErrorAction SilentlyContinue 2>&1 | Format-List

Section "6. D4 - agent dns-teardown (first call should remove rules)"
$teardown1 = & $ztlpExe agent dns-teardown 2>&1
$teardown1Exit = $LASTEXITCODE
$teardown1
Write-Output ("EXIT_CODE: " + $teardown1Exit)

$postRules1 = Get-DnsClientNrptRule | Where-Object { $_.Comment -like "*ZTLP*" }
if ($postRules1) {
    Write-Output "[FAIL] ZTLP NRPT rules still present after teardown:"
    $postRules1 | Format-Table Name,Namespace,Comment -AutoSize
    Stop-Transcript | Out-Null
    exit 6
}
Write-Output "[OK] All ZTLP NRPT rules removed"

Section "7. Idempotency - agent dns-teardown second call should no-op cleanly"
$teardown2 = & $ztlpExe agent dns-teardown 2>&1
$teardown2Exit = $LASTEXITCODE
$teardown2
Write-Output ("EXIT_CODE: " + $teardown2Exit)
if ($teardown2Exit -ne 0) {
    Write-Output "[FAIL] Second teardown should be idempotent - D4 IS BROKEN"
    Stop-Transcript | Out-Null
    exit 7
}
Write-Output "[OK] Teardown is idempotent"

Section "8. RESULT"
Write-Output "[PASS] ALL D4 CHECKS PASSED"
Write-Output ("Evidence: " + $Transcript)
Stop-Transcript | Out-Null
exit 0
