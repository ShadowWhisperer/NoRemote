@echo off
net session >nul 2>&1 || (echo Run as administrator. & pause & exit /b 1)

reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2" /f

netsh advfirewall firewall delete rule name="BlockRemote %SystemRoot%\System32\quickassist.exe"
netsh advfirewall firewall delete rule name="BlockRemote %SystemRoot%\System32\msra.exe"
netsh advfirewall firewall delete rule name="BlockRemote %SystemRoot%\SysWOW64\msra.exe"

sc config appidsvc start= demand >nul 2>&1

gpupdate /force

echo Done. Reboot.
pause
