@echo off

:# Kill Processes
taskkill /im "msedge.exe" /f /t >nul 2>&1
taskkill /im "crashhelper.exe" /f /t >nul 2>&1
taskkill /im "dllhost.exe" /f /t >nul 2>&1
taskkill /im "WmiApSrv.exe" /f /t >nul 2>&1
taskkill /im "WmiPrvSE.exe" /f /t >nul 2>&1
taskkill /im "CompPkgSrv.exe" /f /t >nul 2>&1
taskkill /im "wlanext.exe" /f >nul 2>&1
taskkill /im "net.exe" /f /t >nul 2>&1
taskkill /im "net.exe" /f >nul 2>&1
taskkill /im "OSPPSVC.EXE" /f >nul 2>&1
taskkill /im "OSPPSVC.EXE" /f >nul 2>&1
taskkill /im "HelpPane.exe" /f >nul 2>&1
taskkill /im "crashpad_handler.exe" /f >nul 2>&1
taskkill /im "PING.exe" /f >nul 2>&1
taskkill /im "MicrosoftEdgeUpdate.exe" /f >nul 2>&1
taskkill /im "msedgewebview2.exe" /f >nul 2>&1



:List Processes
del "%tmp%\1.txt" >nul 2>&1
del "%tmp%\2.txt" >nul 2>&1
del "%tmp%\3.txt" >nul 2>&1

WMIC /OUTPUT:"%tmp%\1.txt" path win32_process get Caption /format:csv
for /f "tokens=1,* delims=," %%A in ('type "%tmp%\1.txt"') do echo %%~nxB|find "."|find /v "svchost.exe">>"%tmp%\3.txt"

sort "%tmp%\3.txt" /O "%tmp%\3.txt"
setlocal enabledelayedexpansion
for /f "tokens=*" %%a in ('type "%tmp%\3.txt"') do (
 if "%%a" neq "!last!" (
  echo %%a>>"%tmp%\2.txt"
  set "last=%%a"
 )
)
endlocal
)


:List Processes
for /f "skip=1 tokens=*" %%a in ('type "%tmp%\2.txt"') do (
if not "%%a"=="audiodg.exe" (
if not "%%a"=="GoogleChromePortable.exe" (
if not "%%a"=="chrome.exe" (
if not "%%a"=="Cloud Sticky Notes.exe" (
if not "%%a"=="cmd.exe" (
if not "%%a"=="conhost.exe" (
if not "%%a"=="csrss.exe" (
if not "%%a"=="ctfmon.exe" (
if not "%%a"=="CxUtilSvc.exe" (
if not "%%a"=="devmonsrv.exe" (
if not "%%a"=="DFSSvc.exe" (
if not "%%a"=="dllhost.exe" (
if not "%%a"=="dwm.exe" (
if not "%%a"=="explorer.exe" (
if not "%%a"=="firefox.exe" (
if not "%%a"=="fontdrvhost.exe" (
if not "%%a"=="lsass.exe" (
if not "%%a"=="lsm.exe" (
if not "%%a"=="MDLCSvc.exe" (
if not "%%a"=="MsMpEng.exe" (
if not "%%a"=="NisSrv.exe" (
if not "%%a"=="openvpn-gui.exe" (
if not "%%a"=="PRSvc.exe" (
if not "%%a"=="putty.exe" (
if not "%%a"=="RuntimeBroker.exe" (
if not "%%a"=="SearchApp.exe" (
if not "%%a"=="SearchUI.exe" (
if not "%%a"=="SecurityHealthService.exe" (
if not "%%a"=="services.exe" (
if not "%%a"=="SgrmBroker.exe" (
if not "%%a"=="ShellExperienceHost.exe" (
if not "%%a"=="sihost.exe" (
if not "%%a"=="smss.exe" (
if not "%%a"=="sppsvc.exe" (
if not "%%a"=="StartMenu.exe" (
if not "%%a"=="StartMenuExperienceHost.exe" (
if not "%%a"=="taskhost.exe" (
if not "%%a"=="taskhostw.exe" (
if not "%%a"=="Taskmgr.exe" (
if not "%%a"=="TextInputHost.exe" (
if not "%%a"=="VGAuthService.exe" (
if not "%%a"=="vm3dservice.exe" (
if not "%%a"=="vmnat.exe" (
if not "%%a"=="vmnetdhcp.exe" (
if not "%%a"=="vmtoolsd.exe" (
if not "%%a"=="vmware-authd.exe" (
if not "%%a"=="vmware.exe" (
if not "%%a"=="vmware-usbarbitrator64.exe" (
if not "%%a"=="vmware-vmx.exe" (
if not "%%a"=="wininit.exe" (
if not "%%a"=="winlogon.exe" (
if not "%%a"=="WMIC.exe" (
if not "%%a"=="WmiPrvSE.exe" (
if not "%%a"=="WUDFHost.exe" (
if not "%%a"=="duckhunt 0.9.exe" (
if not "%%a"=="SearchHost.exe" (
if not "%%a"=="mksSandbox.exe" (
if not "%%a"=="nvWmi64.exe" (
if not "%%a"=="TiWorker.exe" (
if not "%%a"=="NumLocker.exe" (
if not "%%a"=="OfficeClickToRun.exe" (
if not "%%a"=="ApplicationFrameHost.exe" (
if not "%%a"=="MoUsoCoreWorker.exe" (
if not "%%a"=="notepad++.exe" (
if not "%%a"=="SearchFilterHost.exe" (
if not "%%a"=="SearchIndexer.exe" (
if not "%%a"=="SearchProtocolHost.exe" (
if not "%%a"=="spoolsv.exe" (
if not "%%a"=="msiexec.exe" (

echo %%a
))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))

echo.
echo.
echo.
pause
