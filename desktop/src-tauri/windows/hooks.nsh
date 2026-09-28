; ZTLP NSIS installer hooks (Tauri `bundle.windows.nsis.installerHooks`).
;
; PR #112 review fix: uninstalling the desktop app left the ZtlpAgent
; LocalSystem service registered and C:\ProgramData\ZTLP (identity, CA key,
; agent.token) on disk. Before the app files are removed, run the bundled
; `ztlp.exe agent uninstall`, which stops + deletes the service and removes
; the ProgramData state dir.
;
; The uninstaller must be elevated for the SCM delete. Tauri's per-user NSIS
; uninstaller is not, so this goes through `powershell Start-Process -Verb
; RunAs -Wait` (one UAC prompt). If the service was never installed, the
; command is a harmless no-op.

!macro NSIS_HOOK_PREUNINSTALL
  IfFileExists "$INSTDIR\ztlp.exe" 0 ztlp_skip_service_uninstall
    DetailPrint "Removing ZTLP background service and its state..."
    nsExec::ExecToLog 'powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "Start-Process -FilePath ''$INSTDIR\ztlp.exe'' -ArgumentList ''agent'',''uninstall'' -Verb RunAs -WindowStyle Hidden -Wait"'
    Pop $0
    DetailPrint "ztlp agent uninstall finished (exit $0)"
  ztlp_skip_service_uninstall:
!macroend
