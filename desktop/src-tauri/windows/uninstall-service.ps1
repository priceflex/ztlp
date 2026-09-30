# Called by the NSIS uninstaller hook (hooks.nsh) with the install dir as $args[0].
# Removes the ZtlpAgent service AND everything enrollment put on this PC:
#   service + C:\ProgramData\ZTLP (via `ztlp.exe agent uninstall`),
#   the NRPT rule pointing at ZTLP's DNS listener (127.0.0.55),
#   THIS device's root CA in LocalMachine\Root (by thumbprint of its own root.pem),
#   the attestation record the app wrote under %USERPROFILE%\.ztlp.
# Self-elevates (one UAC prompt) and returns the elevated run's exit code.
# Exit codes: 0 = clean, 2 = UAC declined / could not launch, otherwise the failing step's code.
param(
  [Parameter(Mandatory = $true)][string]$InstallDir,
  [switch]$Elevated
)
$ztlp = Join-Path $InstallDir 'ztlp.exe'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $Elevated -and -not $isAdmin) {
  try {
    $self = $MyInvocation.MyCommand.Path
    $args2 = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$self`"", '-InstallDir', "`"$InstallDir`"", '-Elevated')
    $p = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList $args2 `
          -Verb RunAs -WindowStyle Hidden -Wait -PassThru -ErrorAction Stop
    exit $p.ExitCode
  } catch { exit 2 }
}

$rc = 0
$userHome = $env:USERPROFILE
$rootPem = 'C:\ProgramData\ZTLP\.ztlp\ca\root.pem'

# 1. remember this device's CA thumbprint BEFORE the state dir is deleted
$thumb = $null
if (Test-Path -LiteralPath $rootPem) {
  try { $thumb = (New-Object Security.Cryptography.X509Certificates.X509Certificate2 $rootPem).Thumbprint } catch {}
}

# 2. service + ProgramData
if (Test-Path -LiteralPath $ztlp) {
  & $ztlp agent uninstall *> $null
  if ($LASTEXITCODE -ne 0) { $rc = $LASTEXITCODE }
}

# 3. DNS rule(s) that route to ZTLP's resolver only (never other NRPT rules)
Get-DnsClientNrptRule -ErrorAction SilentlyContinue |
  Where-Object { $_.NameServers -contains '127.0.0.55' } |
  ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force -ErrorAction SilentlyContinue }

# 4. this device's root CA (LocalMachine + the installing user's store)
if ($thumb) {
  foreach ($loc in 'LocalMachine', 'CurrentUser') {
    try {
      $store = New-Object Security.Cryptography.X509Certificates.X509Store('Root', $loc)
      $store.Open('ReadWrite')
      foreach ($c in @($store.Certificates | Where-Object { $_.Thumbprint -eq $thumb })) { $store.Remove($c) }
      $store.Close()
    } catch {}
  }
}

# 5. app-written record in the user profile (only ours; remove the dir only if empty)
$att = Join-Path $userHome '.ztlp\attestation.json'
if (Test-Path -LiteralPath $att) { Remove-Item -LiteralPath $att -Force -ErrorAction SilentlyContinue }
$ud = Join-Path $userHome '.ztlp'
if ((Test-Path -LiteralPath $ud) -and -not (Get-ChildItem -LiteralPath $ud -Force -ErrorAction SilentlyContinue)) {
  Remove-Item -LiteralPath $ud -Force -ErrorAction SilentlyContinue
}
exit $rc
