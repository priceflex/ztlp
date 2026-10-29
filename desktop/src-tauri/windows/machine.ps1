# Called by the NSIS installer hooks (hooks.nsh) and safe to run by hand.
# Runs `ztlp.exe agent machine-setup` or `machine-teardown` ELEVATED (one UAC
# prompt) and returns that command's exit code.
#   setup    = DNS rule .ztlp -> 127.0.0.55, machine CA in
#              C:\ProgramData\ZTLP\ca trusted in LocalMachine\Root, removal of
#              the old ZtlpAgent service. Idempotent.
#   teardown = undo the above (uninstall).
# Exit codes: 0 = done, 2 = UAC declined / could not launch, otherwise the
# ztlp.exe exit code. Output goes to %ProgramData%\ZTLP-machine-<action>.log.
param(
  [Parameter(Mandatory = $true)][string]$InstallDir,
  [ValidateSet('setup', 'teardown')][string]$Action = 'setup',
  [switch]$Elevated
)
$ztlp = Join-Path $InstallDir 'ztlp.exe'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $Elevated -and -not $isAdmin) {
  try {
    $self = $MyInvocation.MyCommand.Path
    $args2 = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$self`"", '-InstallDir', "`"$InstallDir`"", '-Action', $Action, '-Elevated')
    $p = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList $args2 `
          -Verb RunAs -WindowStyle Hidden -Wait -PassThru -ErrorAction Stop
    exit $p.ExitCode
  } catch { exit 2 }
}

if (-not (Test-Path $ztlp)) { exit 3 }
$log = Join-Path $env:ProgramData "ZTLP-machine-$Action.log"
& $ztlp agent "machine-$Action" *> $log
$rc = $LASTEXITCODE
if ($Action -eq 'setup') {
  # A negative answer cached before the rule existed would hide .ztlp names.
  try { Clear-DnsClientCache } catch { }
}
exit $rc
