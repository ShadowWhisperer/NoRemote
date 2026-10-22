@echo off
echo Building config
setlocal enabledelayedexpansion
net session >nul 2>&1 || (echo Run as administrator & pause & exit /b 1)

:: =============================================

:: AnyDesk, ConnectWise / ScreenConnect, Splashtop, TeamViewer

set PUBLISHERS="philandro Software GmbH" "AnyDesk" "CONNECTWISE" "ELSINORE TECHNOLOGIES" "TeamViewer" "Splashtop"

set FILES="AnyDesk" "ScreenConnect" "ConnectWiseControl" "TeamViewer" "Splashtop" "UltraViewer"

:: =============================================

set "XML=%TEMP%\applocker_block.xml"
> "%XML%" echo ^<AppLockerPolicy Version="1"^>

for %%C in (Exe Msi) do (
  >> "%XML%" echo ^<RuleCollection Type="%%C" EnforcementMode="Enabled"^>
  call :guid
  >> "%XML%" echo ^<FilePathRule Id="!G!" Name="Allow all" Description="" UserOrGroupSid="S-1-1-0" Action="Allow"^>^<Conditions^>^<FilePathCondition Path="*"/^>^</Conditions^>^</FilePathRule^>
  for %%P in (%PUBLISHERS%) do (
    call :guid
    >> "%XML%" echo ^<FilePublisherRule Id="!G!" Name="Deny %%~P" Description="" UserOrGroupSid="S-1-1-0" Action="Deny"^>^<Conditions^>^<FilePublisherCondition PublisherName="O=%%~P*" ProductName="*" BinaryName="*"^>^<BinaryVersionRange LowSection="*" HighSection="*"/^>^</FilePublisherCondition^>^</Conditions^>^</FilePublisherRule^>
  )
  for %%F in (%FILES%) do (
    call :guid
    >> "%XML%" echo ^<FilePathRule Id="!G!" Name="Deny file %%~F" Description="" UserOrGroupSid="S-1-1-0" Action="Deny"^>^<Conditions^>^<FilePathCondition Path="*\%%~F*"/^>^</Conditions^>^</FilePathRule^>
  )
  >> "%XML%" echo ^</RuleCollection^>
)
>> "%XML%" echo ^</AppLockerPolicy^>

echo Applying
powershell -NoProfile -ExecutionPolicy Bypass -Command "Set-AppLockerPolicy -XmlPolicy '%XML%'"
if errorlevel 1 (echo Policy import failed & exit /b 1)

sc config appidsvc start= auto >nul 2>&1
sc start appidsvc >nul 2>&1

:: ---- Firewall: block inbound + outbound, all profiles ----
call :fw "%SystemRoot%\System32\quickassist.exe"
call :fw "%SystemRoot%\System32\msra.exe"
call :fw "%SystemRoot%\SysWOW64\msra.exe"

echo Done.
exit /b 0

:guid
for /f %%G in ('powershell -NoProfile -Command "[guid]::NewGuid().ToString()"') do set G=%%G
exit /b

:fw
echo Firewall: %~1
netsh advfirewall firewall delete rule name="BlockRemote %~1" >nul 2>&1
netsh advfirewall firewall add rule name="BlockRemote %~1" dir=in action=block program="%~1" enable=yes profile=any >nul 2>&1
netsh advfirewall firewall add rule name="BlockRemote %~1" dir=out action=block program="%~1" enable=yes profile=any >nul 2>&1
exit /b
