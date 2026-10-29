; ZTLP NSIS installer hooks (Tauri `bundle.windows.nsis.installerHooks`).
;
; Windows per-user agent (docs/plans/2026-10-29-windows-agent-per-user-unelevated.md):
; there is no ZtlpAgent service any more. The app runs the agent as the
; signed-in user. Everything that needs admin happens here, once, behind ONE
; UAC prompt: `ztlp.exe agent machine-setup` (DNS rule for .ztlp, machine CA
; + LocalMachine\Root trust, removal of the old ZtlpAgent service). It runs
; through machine.ps1, which self-elevates and returns the command's exit
; code, so there is no nested-quote command line to get wrong in NSIS.
;
; Uninstall: `machine-teardown` (one UAC prompt) removes what setup added.
; Skipped during an in-place update (Tauri runs the old uninstaller with
; /UPDATE), so updating keeps DNS + the CA and asks for admin only once.

!macro ZTLP_STOP_RUNNING
  ; Stop this user's app + agent so their files can be replaced/removed.
  ; Unelevated taskkill only reaches the current user's processes; the
  ; USERNAME filter keeps it off anyone else's ztlp.exe.
  nsExec::Exec 'taskkill /F /T /IM ztlp-desktop.exe'
  Pop $0
  ReadEnvStr $1 USERNAME
  nsExec::Exec 'taskkill /F /FI "USERNAME eq $1" /IM ztlp.exe'
  Pop $0
!macroend

!macro NSIS_HOOK_PREINSTALL
  !insertmacro ZTLP_STOP_RUNNING
!macroend

!macro NSIS_HOOK_POSTINSTALL
  DetailPrint "Setting up DNS and certificates for ZTLP (administrator permission needed once)..."
  nsExec::ExecToLog '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\machine.ps1" -InstallDir "$INSTDIR" -Action setup'
  Pop $0
  DetailPrint "Machine setup finished (exit $0)"
  StrCmp $0 "0" ztlp_setup_ok
    IfSilent ztlp_setup_ok
    MessageBox MB_OK|MB_ICONEXCLAMATION "ZTLP could not finish the one-time DNS and certificate setup (exit code $0).$\r$\n$\r$\nOpen ZTLP and click Fix on the DNS or HTTPS check to try again."
  ztlp_setup_ok:
  ; Start the app (tray) at every logon; it runs this user's agent.
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "ZTLP" '"$INSTDIR\ztlp-desktop.exe" --autostart'
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  !insertmacro ZTLP_STOP_RUNNING
  StrCmp $UpdateMode 1 ztlp_skip_teardown
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "ZTLP"
  IfFileExists "$INSTDIR\machine.ps1" 0 ztlp_skip_teardown
    DetailPrint "Removing ZTLP DNS rule and certificates..."
    nsExec::ExecToLog '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\machine.ps1" -InstallDir "$INSTDIR" -Action teardown'
    Pop $0
    DetailPrint "Machine teardown finished (exit $0)"
  ztlp_skip_teardown:
!macroend
