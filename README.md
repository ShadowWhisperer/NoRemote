Prevent common (what I've seen) remote software from installing or running. It uses Windows' built in [AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/applocker-overview).  

Only works on Windows 10/11 Pro, Enterprise, Education.  
Run as Admin.  

Blocks:
- AnyDesk
- ScreenConnect
- Splashtop
- TeamViewer
- Quick Assist (Windows Firewall)
- Windows Remote Assistance (Windows Firewall)

<img width="719" height="235" alt="Capture" src="https://github.com/user-attachments/assets/983df5d0-e6bb-4998-8511-b006bb71b7cb" />
<br/><br>

**Rules:** `secpol.msc` > Application Control Policies > AppLocker  
**Logs:** `eventvwr.msc` (Event Viewer) > Applications and Services Logs > Microsoft > Windows > AppLocker. (Event ID: 8004) / Level: Error)  


## Notes
- Script replaces the whole AppLocker policy. All existing rules get removed.  
- This does not a block every remote program. Just the ones listed above. 
