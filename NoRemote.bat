@echo off
setlocal
net session >nul 2>&1 || (echo Run as administrator. & pause & exit /b 1)


:: =============================================

:: AnyDesk, ConnectWise / ScreenConnect, Splashtop, TeamViewer
set PUBLISHERS="philandro Software GmbH" "AnyDesk" "CONNECTWISE" "ELSINORE TECHNOLOGIES" "TeamViewer" "Splashtop"
set FILES="AnyDesk" "ScreenConnect" "ConnectWiseControl" "TeamViewer" "Splashtop" "UltraViewer"
set FIREWALL="%SystemRoot%\System32\quickassist.exe" "%SystemRoot%\System32\msra.exe" "%SystemRoot%\SysWOW64\msra.exe"

:: =============================================



set "PS1=%TEMP%\NoRemote.ps1"

sc config appidsvc start= auto >nul 2>&1
sc start appidsvc >nul 2>&1

netsh advfirewall set allprofiles state on >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v EnableFirewall /t REG_DWORD /d 1 /f >nul 2>&1

powershell -NoProfile -ExecutionPolicy Bypass -Command "(Get-Content -LiteralPath '%~f0' -Raw) -replace '(?s)^.*\r?\n#PS#\r?\n','' | Set-Content -LiteralPath '%PS1%' -Encoding UTF8"
powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%"
set "RC=%errorlevel%"
del "%PS1%" >nul 2>&1

pause
exit /b %RC%
#PS#
$ErrorActionPreference = 'Stop'

function Get-List([string]$Name) {
    $raw = [string][Environment]::GetEnvironmentVariable($Name)
    foreach ($m in [regex]::Matches($raw, '"([^"]+)"')) { $m.Groups[1].Value.Trim() }
}

function Add-PathRule($Doc, $Col, $Name, $Action, $Path) {
    $r = $Col.AppendChild($Doc.CreateElement('FilePathRule'))
    $r.SetAttribute('Id', [guid]::NewGuid().ToString())
    $r.SetAttribute('Name', $Name)
    $r.SetAttribute('Description', '')
    $r.SetAttribute('UserOrGroupSid', 'S-1-1-0')
    $r.SetAttribute('Action', $Action)
    $cond = $r.AppendChild($Doc.CreateElement('Conditions')).AppendChild($Doc.CreateElement('FilePathCondition'))
    $cond.SetAttribute('Path', $Path)
}

function Add-PublisherRule($Doc, $Col, $Name, $Publisher, $Action = 'Deny') {
    $r = $Col.AppendChild($Doc.CreateElement('FilePublisherRule'))
    $r.SetAttribute('Id', [guid]::NewGuid().ToString())
    $r.SetAttribute('Name', $Name)
    $r.SetAttribute('Description', '')
    $r.SetAttribute('UserOrGroupSid', 'S-1-1-0')
    $r.SetAttribute('Action', $Action)
    $cond = $r.AppendChild($Doc.CreateElement('Conditions')).AppendChild($Doc.CreateElement('FilePublisherCondition'))
    $cond.SetAttribute('PublisherName', $Publisher)
    $cond.SetAttribute('ProductName', '*')
    $cond.SetAttribute('BinaryName', '*')
    $range = $cond.AppendChild($Doc.CreateElement('BinaryVersionRange'))
    $range.SetAttribute('LowSection', '*')
    $range.SetAttribute('HighSection', '*')
}

# Exe + Msi: allow everything, then deny the listed publishers and file names (deny wins).
function New-PolicyFile([string]$File, [string[]]$Publishers, [string[]]$Names) {
    $doc = New-Object System.Xml.XmlDocument
    $root = $doc.AppendChild($doc.CreateElement('AppLockerPolicy'))
    $root.SetAttribute('Version', '1')
    foreach ($type in 'Exe', 'Msi') {
        $col = $root.AppendChild($doc.CreateElement('RuleCollection'))
        $col.SetAttribute('Type', $type)
        $col.SetAttribute('EnforcementMode', 'Enabled')
        Add-PathRule $doc $col 'Allow all' 'Allow' '*'
        foreach ($p in $Publishers) {
            Add-PublisherRule $doc $col ('Block publisher: ' + $p) ($p.ToUpperInvariant())
        }
        foreach ($n in $Names) {
            Add-PathRule $doc $col ('Block file name: ' + $n) 'Deny' ('*\' + $n + '*')
        }
    }
    # Packaged (Store) apps: with Exe rules enforced and no Appx rules, Windows blocks ALL packaged
    # apps (Start menu, Settings, ...; event 8027). Allow signed packaged apps.
    $appx = $root.AppendChild($doc.CreateElement('RuleCollection'))
    $appx.SetAttribute('Type', 'Appx')
    $appx.SetAttribute('EnforcementMode', 'Enabled')
    Add-PublisherRule $doc $appx 'Allow all signed packaged apps' '*' 'Allow'
    $doc.Save($File)
}

function Get-Decision($XmlFile, $File) {
    $r = @(Test-AppLockerPolicy -XmlPolicy $XmlFile -Path $File -User Everyone)[0]
    if ($r) { [string]$r.PolicyDecision } else { 'NoResult' }
}

function Show-Result($Label, $Want, $Got) {
    $ok = ($Got -eq $Want)
    $tag = if ($ok) { 'PASS' } else { 'FAIL' }
    $color = if ($ok) { 'Green' } else { 'Red' }
    Write-Host ('  {0}  {1,-42} {2}' -f $tag, $Label, $Got) -ForegroundColor $color
    return $ok
}

function Remove-BlockRules([string[]]$Programs) {
    foreach ($prog in $Programs) {
        Get-NetFirewallRule -DisplayName ('BlockRemote ' + $prog) -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    }
}

function Set-BlockRules([string[]]$Programs) {
    Remove-BlockRules $Programs
    foreach ($prog in $Programs) {
        foreach ($dir in 'Inbound', 'Outbound') {
            New-NetFirewallRule -DisplayName ('BlockRemote ' + $prog) -Direction $dir -Action Block -Program $prog -Profile Any | Out-Null
        }
    }
}

try {
    Import-Module AppLocker
    $cap = (Get-CimInstance Win32_OperatingSystem).Caption
    if ($cap -match 'Home') { throw ($cap + ' does not support AppLocker.') }

    # ---- publishers: exact signer strings ----
    $pubs = @(Get-List 'PUBLISHERS')
    $pubs = @($pubs | ForEach-Object { $_.ToUpperInvariant() } | Select-Object -Unique)
    $names = @(Get-List 'FILES')
    if (($pubs.Count + $names.Count) -eq 0) { throw 'PUBLISHERS and FILES are both empty.' }
    Write-Host ('Publishers: {0}   File names: {1}' -f $pubs.Count, $names.Count)

    $policy = Join-Path $env:TEMP 'NoRemote_policy.xml'
    New-PolicyFile $policy $pubs $names

    # A real, signed Windows exe used for the tests (renamed copies are only copied, never run).
    $testExe = foreach ($f in 'whoami.exe', 'cmd.exe', 'notepad.exe') {
        $p = Join-Path $env:windir ('System32\' + $f)
        if (Test-Path -LiteralPath $p) { $p; break }
    }
    $work = Join-Path $env:TEMP 'NoRemote_test'
    New-Item -ItemType Directory -Force -Path $work | Out-Null
    $failed = 0
    $pubWarn = 0

    # 1. Every file-name rule must deny a renamed copy.
    foreach ($n in $names) {
        $copy = Join-Path $work ($n + '.exe')
        Copy-Item -LiteralPath $testExe -Destination $copy -Force
        if (-not (Show-Result ($n + '.exe (renamed copy)') 'Denied' (Get-Decision $policy $copy))) { $failed++ }
    }

    # 2. Core Windows files must stay allowed.
    $controls = @(
        (Join-Path $env:windir 'explorer.exe'),
        (Join-Path $env:windir 'System32\cmd.exe'),
        (Join-Path $env:windir 'System32\notepad.exe'),
        (Join-Path $env:windir 'ImmersiveControlPanel\SystemSettings.exe')
    )
    $startHost = Get-ChildItem -Path (Join-Path $env:windir 'SystemApps') -Filter 'StartMenuExperienceHost.exe' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($startHost) { $controls += $startHost.FullName }
    foreach ($c in $controls) {
        if (Test-Path -LiteralPath $c) {
            if (-not (Show-Result (Split-Path $c -Leaf) 'Allowed' (Get-Decision $policy $c))) { $failed++ }
        }
    }

    # 3. Does an exact publisher rule match on this system? (warning only)
    try {
        $seen = [string](Get-AppLockerFileInformation -Path $testExe).Publisher.PublisherName
        if ($seen) {
            $probeFile = Join-Path $env:TEMP 'NoRemote_probe.xml'
            New-PolicyFile $probeFile @($seen) @()
            if (-not (Show-Result 'publisher rule (exact signer string)' 'Denied' (Get-Decision $probeFile $testExe))) { $pubWarn++ }
        } else {
            Write-Host '  SKIP  publisher rule test (could not read the signer)'
        }
    } catch {
        Write-Host ('  SKIP  publisher rule test: ' + $_.Exception.Message)
    }

    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    if ($failed -gt 0) { throw ([string]$failed + ' test(s) failed. Policy was NOT applied.') }
    if ($pubWarn -gt 0) { Write-Host '  WARN  Some publisher rules did not match. Those signers are NOT blocked (file-name rules still apply).' -ForegroundColor Yellow }

    $applyTime = (Get-Date).AddSeconds(-2)
    Set-AppLockerPolicy -XmlPolicy $policy

    # The local policy updates at once. The effective policy and enforcement follow a little later.
    $expected = 2 * ($pubs.Count + $names.Count)
    $saved = 0
    foreach ($c in (Get-AppLockerPolicy -Local).RuleCollections) {
        foreach ($r in $c) { if ([string]$r.Action -eq 'Deny') { $saved++ } }
    }
    Write-Host ('Saved deny rules: {0} (expected {1})' -f $saved, $expected)

    $active = $false
    for ($i = 0; $i -lt 15 -and -not $active; $i++) {
        $deny = 0
        foreach ($c in (Get-AppLockerPolicy -Effective).RuleCollections) {
            foreach ($r in $c) { if ([string]$r.Action -eq 'Deny') { $deny++ } }
        }
        $ev = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-AppLocker/EXE and DLL'; Id = 8001; StartTime = $applyTime } -ErrorAction SilentlyContinue
        if (($deny -eq $expected) -or $ev) { $active = $true } else { Start-Sleep -Seconds 3 }
    }
    if ($active) {
        Write-Host 'New policy active.' -ForegroundColor Green
    } else {
        Write-Host 'WARN  New policy is not active yet (policy shows old rules). Check later: Get-AppLockerPolicy -Effective' -ForegroundColor Yellow
    }
    $fw = @(Get-List 'FIREWALL')
    if ($fw.Count -gt 0) { Set-BlockRules $fw }
    Write-Host 'Done.'
}
catch {
    Write-Host ('ERROR: ' + $_.Exception.Message) -ForegroundColor Red
    exit 1
}
