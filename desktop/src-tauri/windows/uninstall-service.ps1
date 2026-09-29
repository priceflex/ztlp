# Called by the NSIS uninstaller hook (hooks.nsh) with the install dir as $args[0].
# Runs `ztlp.exe agent uninstall` ELEVATED and returns ITS exit code (not
# powershell's). Exit codes: 0 = service removed (or was never installed),
# 2 = UAC declined / could not launch, otherwise ztlp's own non-zero code.
param([Parameter(Mandatory = $true)][string]$InstallDir)
$ztlp = Join-Path $InstallDir 'ztlp.exe'
if (-not (Test-Path -LiteralPath $ztlp)) { exit 0 }
try {
  $p = Start-Process -FilePath $ztlp -ArgumentList 'agent', 'uninstall' `
        -Verb RunAs -WindowStyle Hidden -Wait -PassThru -ErrorAction Stop
  exit $p.ExitCode
} catch {
  # UAC declined or elevation failed
  exit 2
}
