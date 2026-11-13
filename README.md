Prevent remote software from installing. It uses Windows' built in [AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/applocker-overview).  

If the remote program is already installed, AppLocker only prevents a few of them from running.

[Download](https://github.com/ShadowWhisperer/NoRemote/releases/latest/download/NoRemote.exe)  


<img width="1063" height="629" alt="new" src="https://github.com/user-attachments/assets/1abec3dd-d563-41e1-b7f5-1f7262d67ff8" />
<br/><br>


## Requirements
- Only works on Windows 10/11 Pro, Enterprise, Education.  
- Run as Admin.  

## Features
- Highlights running remotes, moves them to the top of the list  
- Right click any of the running remotes to stop them all  
- Right click ScreenConnect > Remove > Will kill it, run the uninstaller, then delete the folder that is was running in.  
- Common: Select remote software that is commonly used in remote scams. (From what I've seen)  

**Rules:** `secpol.msc` > Application Control Policies > AppLocker  
**Logs:** `eventvwr.msc` (Event Viewer) > Applications and Services Logs > Microsoft > Windows > AppLocker. (Event ID: 8004) / Level: Error)  

## Notes
- Script replaces the whole AppLocker policy. All existing rules get removed.  
- This does not block every remote program.
