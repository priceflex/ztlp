; ZTLP NSIS installer hooks (Tauri `bundle.windows.nsis.installerHooks`).
;
; Uninstalling the desktop app used to leave the ZtlpAgent LocalSystem service
; registered and C:\ProgramData\ZTLP (identity, CA key, agent.token) on disk.
; Before the app files are removed, run the bundled `ztlp.exe agent uninstall`
; (elevated) through uninstall-service.ps1, which returns that command's own
; exit code. The script is a separate file so there is NO nested-quote
; command line to get wrong in NSIS. It ships as a bundle resource, so it is
; installed next to ztlp.exe in $INSTDIR.
;
; If the service cannot be removed (UAC declined / uninstall failed) the user
; is asked whether to continue; declining aborts the uninstall so the service
; and its state are not silently orphaned.

!macro NSIS_HOOK_PREUNINSTALL
  IfFileExists "$INSTDIR\ztlp.exe" 0 ztlp_skip_service_uninstall
    DetailPrint "Removing ZTLP background service and its state..."
    IfFileExists "$INSTDIR\uninstall-service.ps1" ztlp_have_script 0
      MessageBox MB_OK|MB_ICONEXCLAMATION "uninstall-service.ps1 is missing from the install folder; the ZTLP background service cannot be removed automatically. Run 'ztlp.exe agent uninstall' from an administrator prompt afterwards."
      Goto ztlp_skip_service_uninstall
    ztlp_have_script:
    nsExec::ExecToLog '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\uninstall-service.ps1" -InstallDir "$INSTDIR"'
    Pop $0
    DetailPrint "Service removal finished (exit $0)"
    StrCmp $0 "0" ztlp_skip_service_uninstall
      MessageBox MB_YESNO|MB_ICONEXCLAMATION "The ZTLP background service could not be removed (exit code $0). Its identity and certificate state will be left on this PC.$\r$\n$\r$\nContinue uninstalling anyway?" IDYES ztlp_skip_service_uninstall
      Abort "Uninstall cancelled: the ZTLP background service was not removed."
  ztlp_skip_service_uninstall:
!macroend
