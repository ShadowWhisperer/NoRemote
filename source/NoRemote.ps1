#Requires -RunAsAdministrator
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Must run elevated (the compiled exe also asks for it through its manifest)
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    [void][System.Windows.Forms.MessageBox]::Show('NoRemote must be run as administrator.' + "`n`n" + 'Right-click it and choose Run as administrator.','NoRemote','OK','Warning')
    exit 1
}
$ErrorActionPreference = 'Stop'

# =====================================================================
#  PROGRAM LIST - loaded from programs.txt (same folder as this script)
#  Edit that file to add, change or remove programs.
# =====================================================================
$ScriptDir = $PSScriptRoot
if (-not $ScriptDir) { $ScriptDir = Split-Path -Parent ([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName) }
$ProgramFile = Join-Path $ScriptDir 'programs.txt'
# Build.ps1 puts a copy of programs.txt here. A programs.txt next to the exe/script takes priority.
$EmbeddedList = @'
#EMBEDDED-LIST
'@
$ListLines = $null
if (Test-Path -LiteralPath $ProgramFile) {
    $ListLines = Get-Content -LiteralPath $ProgramFile -Encoding UTF8
} elseif ($EmbeddedList.Trim() -ne ('#EMBEDDED' + '-LIST')) {
    $ListLines = [regex]::Replace($EmbeddedList, '\\u([0-9A-Fa-f]{4})', { param($m) [string][char][Convert]::ToInt32($m.Groups[1].Value, 16) }) -split "`r?`n"
} else {
    [void][System.Windows.Forms.MessageBox]::Show("programs.txt not found:`n$ProgramFile",'NoRemote','OK','Error')
    exit 1
}

function Split-Items([string]$Text, [switch]$Expand) {
    foreach ($i in ($Text -split ';')) {
        $i = $i.Trim()
        if (-not $i) { continue }
        if ($Expand) { $i = [Environment]::ExpandEnvironmentVariables($i) }
        $i
    }
}

$Programs = @()
$cur = $null
foreach ($raw in $ListLines) {
    $line = $raw.Trim()
    if (-not $line -or $line.StartsWith('#')) { continue }
    if ($line -match '^\[(.+)\]$') {
        $cur = @{ Name = $Matches[1].Trim(); Common = $false; Pub = @(); File = @(); Proc = @(); Fw = @(); Svc = @() }
        $Programs += $cur
        continue
    }
    if ($cur -and $line -match '^([A-Za-z]+)\s*=\s*(.*)$') {
        $v = $Matches[2]
        switch ($Matches[1].ToLower()) {
            'common'     { $cur.Common = ($v.Trim() -match '^(yes|y|true|1)$') }
            'publishers' { $cur.Pub  = @(Split-Items $v) }
            'files'      { $cur.File = @(Split-Items $v) }
            'processes'  { $cur.Proc = @(Split-Items $v) }
            'services'   { $cur.Svc  = @(Split-Items $v) }
            'firewall'   { $cur.Fw   = @(Split-Items $v -Expand) }
        }
    }
}
$Programs = @($Programs | Sort-Object { $_.Name })
$Common = @($Programs | Where-Object { $_.Common } | ForEach-Object { $_.Name })

# ---- Policy helpers (same logic as NoRemote.bat) ----
function Add-PathRule($Doc,$Col,$Name,$Action,$Path) {
    $r = $Col.AppendChild($Doc.CreateElement('FilePathRule'))
    $r.SetAttribute('Id',[guid]::NewGuid().ToString()); $r.SetAttribute('Name',$Name)
    $r.SetAttribute('Description',''); $r.SetAttribute('UserOrGroupSid','S-1-1-0'); $r.SetAttribute('Action',$Action)
    $c = $r.AppendChild($Doc.CreateElement('Conditions')).AppendChild($Doc.CreateElement('FilePathCondition'))
    $c.SetAttribute('Path',$Path)
}
function Add-PublisherRule($Doc,$Col,$Name,$Publisher,$Action='Deny') {
    $r = $Col.AppendChild($Doc.CreateElement('FilePublisherRule'))
    $r.SetAttribute('Id',[guid]::NewGuid().ToString()); $r.SetAttribute('Name',$Name)
    $r.SetAttribute('Description',''); $r.SetAttribute('UserOrGroupSid','S-1-1-0'); $r.SetAttribute('Action',$Action)
    $c = $r.AppendChild($Doc.CreateElement('Conditions')).AppendChild($Doc.CreateElement('FilePublisherCondition'))
    $c.SetAttribute('PublisherName',$Publisher); $c.SetAttribute('ProductName','*'); $c.SetAttribute('BinaryName','*')
    $g = $c.AppendChild($Doc.CreateElement('BinaryVersionRange'))
    $g.SetAttribute('LowSection','*'); $g.SetAttribute('HighSection','*')
}
# Publisher entries must be the full AppLocker publisher string (O=..., L=..., S=..., C=...),
# as shown by (Get-AppLockerFileInformation -Path file.exe).Publisher.PublisherName.
# Entries that do not start with O= are ignored (AppLocker cannot match a bare name).
function Format-Publisher([string]$Name) {
    if ($Name -like 'O=*') { return $Name.ToUpperInvariant() }
    return $null
}
function New-PolicyFile([string]$File,[string[]]$Pubs,[string[]]$Names) {
    $doc = New-Object System.Xml.XmlDocument
    $root = $doc.AppendChild($doc.CreateElement('AppLockerPolicy')); $root.SetAttribute('Version','1')
    foreach ($t in 'Exe','Msi') {
        $col = $root.AppendChild($doc.CreateElement('RuleCollection'))
        $col.SetAttribute('Type',$t); $col.SetAttribute('EnforcementMode','Enabled')
        Add-PathRule $doc $col 'Allow all' 'Allow' '*'
        foreach ($p in $Pubs)  { $fp = Format-Publisher $p; if ($fp) { Add-PublisherRule $doc $col ('Block publisher: ' + $p) $fp } }
        foreach ($n in $Names) { Add-PathRule $doc $col ('Block file name: ' + $n) 'Deny' ('*\' + $n + '*') }
    }
    $ax = $root.AppendChild($doc.CreateElement('RuleCollection'))
    $ax.SetAttribute('Type','Appx'); $ax.SetAttribute('EnforcementMode','Enabled')
    Add-PublisherRule $doc $ax 'Allow all signed packaged apps' '*' 'Allow'
    $doc.Save($File)
}
function New-EmptyPolicyFile([string]$File) {
    $x = '<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="NotConfigured" /><RuleCollection Type="Msi" EnforcementMode="NotConfigured" /><RuleCollection Type="Appx" EnforcementMode="NotConfigured" /></AppLockerPolicy>'
    Set-Content -LiteralPath $File -Value $x -Encoding UTF8
}
function Remove-AllBlockRules {
    Get-NetFirewallRule -DisplayName 'BlockRemote *' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
}
function Set-BlockRules([string[]]$Paths) {
    Remove-AllBlockRules
    foreach ($p in $Paths) {
        foreach ($d in 'Inbound','Outbound') {
            New-NetFirewallRule -DisplayName ('BlockRemote ' + $p) -Direction $d -Action Block -Program $p -Profile Any | Out-Null
        }
    }
}

# ---- Read current state ----
function Get-CurrentState {
    $names = @()
    foreach ($scope in @{Local=$true}, @{Effective=$true}) {
        try {
            foreach ($c in (Get-AppLockerPolicy @scope).RuleCollections) {
                foreach ($r in $c) { if ([string]$r.Action -eq 'Deny') { $names += [string]$r.Name } }
            }
        } catch {}
    }
    $fw = @(Get-NetFirewallRule -DisplayName 'BlockRemote *' -ErrorAction SilentlyContinue | ForEach-Object { $_.DisplayName })
    $set = @{}
    foreach ($p in $Programs) {
        $on = $false
        foreach ($x in $p.Pub)  { if ($names -contains ('Block publisher: ' + $x.ToUpperInvariant())) { $on = $true } }
        foreach ($x in $p.File) { if ($names -contains ('Block file name: ' + $x)) { $on = $true } }
        foreach ($x in $p.Fw)   { if ($fw -contains ('BlockRemote ' + $x)) { $on = $true } }
        $set[$p.Name] = $on
    }
    $set
}

# ---- Detect running remote software (processes + running services) ----
$script:Running = @{}
$script:Matched = @{}      # program name -> process image names that matched
$script:MatchedPids = @{}  # program name -> process IDs that matched
function Get-RunningMap {
    $ErrorActionPreference = 'SilentlyContinue'
    $procs = @(Get-CimInstance Win32_Process | ForEach-Object { [pscustomobject]@{ N = [string]$_.Name; P = [string]$_.ExecutablePath; ID = [int]$_.ProcessId } })
    $svc = @(Get-CimInstance Win32_Service -Filter "State='Running'" | ForEach-Object { [pscustomobject]@{ P = [string]$_.PathName; ID = [int]$_.ProcessId } })
    $map = @{}
    $script:Matched = @{}
    $script:MatchedPids = @{}
    foreach ($p in $Programs) {
        $names = @(); $ids = @()
        foreach ($f in $p.File) {
            foreach ($x in $procs) { if ($x.N -like ($f + '*') -or $x.P -like ('*\' + $f + '*')) { $names += $x.N; $ids += $x.ID } }
            foreach ($v in $svc) {
                if ($v.P -like ('*\' + $f + '*')) {
                    if ($v.ID -gt 0) { $ids += $v.ID }
                    if ($v.P -match '^\s*"?([^"]*?\.exe)') { $names += [System.IO.Path]::GetFileName($Matches[1]) }
                }
            }
        }
        foreach ($pn in $p.Proc) {
            foreach ($x in $procs) { if ($x.N -ieq $pn) { $names += $x.N; $ids += $x.ID } }
        }
        foreach ($w in $p.Fw) {
            $leaf = [System.IO.Path]::GetFileName($w)
            foreach ($x in $procs) { if ($x.N -ieq $leaf) { $names += $x.N; $ids += $x.ID } }
        }
        $names = @($names | Where-Object { $_ } | Sort-Object -Unique)
        $ids = @($ids | Where-Object { $_ } | Sort-Object -Unique)
        $script:Matched[$p.Name] = $names
        $script:MatchedPids[$p.Name] = $ids
        $map[$p.Name] = (($names.Count + $ids.Count) -gt 0)
    }
    $map
}

function Show-Info([string]$Text,[string]$Icon='Information') {
    [void][System.Windows.Forms.MessageBox]::Show($Text,'NoRemote','OK',$Icon)
}

# ---- GUI ----
$script:Loading = $true
$script:SavedChecks = @{}
$form = New-Object System.Windows.Forms.Form
$form.Text = 'NoRemote v1'; $form.StartPosition = 'CenterScreen'
$form.ClientSize = New-Object System.Drawing.Size(360,560)
$form.FormBorderStyle = 'Sizable'; $form.MaximizeBox = $false; $form.ShowIcon = $false
# Height resizable, width fixed
$form.MinimumSize = New-Object System.Drawing.Size($form.Width, ($form.Height - 105))
$form.MaximumSize = New-Object System.Drawing.Size($form.Width, [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea.Height)

$list = New-Object System.Windows.Forms.ListView
$list.Location = New-Object System.Drawing.Point(10,10); $list.Size = New-Object System.Drawing.Size(340,390)
$list.Anchor = 'Top,Bottom,Left,Right'
$list.View = 'Details'; $list.CheckBoxes = $true; $list.HeaderStyle = 'None'
$list.FullRowSelect = $true; $list.MultiSelect = $false; $list.HideSelection = $true
[void]$list.Columns.Add('Program', 250)
[void]$list.Columns.Add('Status', 80)
foreach ($p in $Programs) {
    $it = New-Object System.Windows.Forms.ListViewItem($p.Name)
    [void]$it.SubItems.Add('')
    [void]$list.Items.Add($it)
}
$list.Add_Resize({ $list.Columns[0].Width = [Math]::Max(60, $list.ClientSize.Width - 90); $list.Columns[1].Width = 85 })
$list.Add_SelectedIndexChanged({ foreach ($i in @($list.SelectedItems)) { $i.Selected = $false } })
$list.Add_MouseClick({
    param($s, $e)
    $h = $s.HitTest($e.Location)
    if ($e.Button -eq 'Left' -and $h.Item -and $h.Location -ne [System.Windows.Forms.ListViewHitTestLocations]::StateImage) { $h.Item.Checked = -not $h.Item.Checked }
})
$form.Controls.Add($list)

# Shown in place of the list while the startup scan runs
$lblScan = New-Object System.Windows.Forms.Label
$lblScan.Text = 'Scanning for remotes'
$lblScan.TextAlign = 'MiddleCenter'
$lblScan.Font = New-Object System.Drawing.Font('Segoe UI', 11)
$lblScan.Location = $list.Location; $lblScan.Size = $list.Size
$lblScan.Anchor = 'Top,Bottom,Left,Right'
$lblScan.Visible = $false
$form.Controls.Add($lblScan)

function Set-Checks([scriptblock]$Rule) {
    foreach ($it in $list.Items) { $it.Checked = [bool](& $Rule $it.Text) }
}
$script:Detected = @{}   # programs that were killed and no longer run
function Update-Highlights {
    $i = 0
    foreach ($it in $list.Items) {
        if ($null -eq $it.Tag) { $it.Tag = $i }
        $i++
        if ($script:Running[$it.Text]) {
            $it.BackColor = [System.Drawing.Color]::Firebrick; $it.ForeColor = [System.Drawing.Color]::White
            $it.SubItems[1].Text = 'RUNNING'
        } elseif ($script:Detected[$it.Text]) {
            $it.BackColor = [System.Drawing.Color]::Firebrick; $it.ForeColor = [System.Drawing.Color]::White
            $it.SubItems[1].Text = 'Detected'
        } else {
            $it.BackColor = [System.Drawing.SystemColors]::Window; $it.ForeColor = [System.Drawing.SystemColors]::WindowText
            $it.SubItems[1].Text = ''
        }
    }
    # running first, then detected, then the rest (original order within each group)
    $sorted = @($list.Items | Sort-Object @{ Expression = { if ($script:Running[$_.Text]) { 0 } elseif ($script:Detected[$_.Text]) { 1 } else { 2 } } }, @{ Expression = { [int]$_.Tag } })
    $wasLoading = $script:Loading
    $script:Loading = $true          # no Save-button checks while the list is rebuilt
    $list.BeginUpdate()
    $list.Items.Clear()
    $list.Items.AddRange([System.Windows.Forms.ListViewItem[]]$sorted)
    $list.EndUpdate()
    $script:Loading = $wasLoading
    Update-SaveButton
}
function Invoke-Hidden([string]$File, [string]$Arguments) {
    # run a console program with no window and wait for it
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $File; $psi.Arguments = $Arguments
        $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
        [System.Diagnostics.Process]::Start($psi).WaitForExit()
    } catch {}
}
function Invoke-TaskKill([string[]]$TkArgs) {
    # .NET process start: PowerShell error preference cannot abort this
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = 'taskkill.exe'; $psi.Arguments = ($TkArgs -join ' ')
        $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
        $pr = [System.Diagnostics.Process]::Start($psi)
        $pr.WaitForExit()
    } catch {}
}

# ---- Right-click menu (rows that are running or detected) ----
$menu = New-Object System.Windows.Forms.ContextMenuStrip
$miKill  = $menu.Items.Add('Kill All')
$miPurge = $menu.Items.Add('Purge')   # ConnectWise / ScreenConnect only
$list.Add_MouseUp({
    param($s, $e)
    if ($e.Button -ne 'Right') { return }
    $h = $s.HitTest($e.Location)
    if ($h.Item -and ($script:Running[$h.Item.Text] -or $script:Detected[$h.Item.Text])) {
        $miPurge.Visible = ($h.Item.Text -eq 'ConnectWise / ScreenConnect')
        $menu.Show($s, $e.Location)
    }
})
function Stop-ProgramServices($Progs) {
    # fire and forget: send "net stop" for every listed service (name or display name) and do not wait
    foreach ($p in $Progs) {
        foreach ($sn in @($p.Svc)) {
            try {
                $psi = New-Object System.Diagnostics.ProcessStartInfo
                $psi.FileName = 'net.exe'; $psi.Arguments = 'stop "' + $sn + '" /y'
                $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
                [void][System.Diagnostics.Process]::Start($psi)
            } catch {}
        }
    }
}
function Stop-ProgramProcesses($Progs) {
    foreach ($p in $Progs) {
        foreach ($n in @($script:Matched[$p.Name] | Where-Object { $_ })) { Invoke-TaskKill @('/IM', ('"' + $n + '"'), '/F') }
        foreach ($id in @($script:MatchedPids[$p.Name] | Where-Object { $_ })) {
            if (Get-Process -Id $id -ErrorAction SilentlyContinue) { Invoke-TaskKill @('/PID', [string]$id, '/F') }
        }
    }
}
$miKill.Add_Click({
    $ErrorActionPreference = 'Continue'   # native stderr must not become a terminating error
    $form.Cursor = 'WaitCursor'
    try {
        $script:Running = Get-RunningMap
        $hit = @($Programs | Where-Object { $script:Running[$_.Name] })
        # two passes: services, process names, then again (a service may respawn a process)
        foreach ($pass in 1..2) {
            Stop-ProgramServices $Programs           # services first
            Stop-ProgramProcesses $Programs          # all matched process names
            Start-Sleep -Milliseconds 700
            $script:Running = Get-RunningMap         # refresh names/PIDs for the next pass
        }
        foreach ($p in $hit) { $script:Detected[$p.Name] = $true }
        Update-Highlights
    } catch {}
    $form.Cursor = 'Default'
})

# ---- Purge: ConnectWise / ScreenConnect ----
# Finds every install from the running processes (and service paths), stops services and processes (twice), then deletes the install folders.
# Folders are deleted only when the folder name itself starts with ScreenConnect / ConnectWise Control.
# Anything else is listed as "not deleted" so it can be checked by hand.
$script:ScPattern = 'ScreenConnect|ConnectWise ?Control'
$script:ScLeaf = '^(ScreenConnect|ConnectWise ?Control)'

function Get-SafePurgeRoot([string]$Dir) {
    # walk up from an exe folder to the nearest folder whose own name looks like ScreenConnect / ConnectWise Control
    $d = $Dir.TrimEnd('\')
    # Common Files is off limits, except <Common Files>\Remote\*screenconnect*
    foreach ($cf in @($env:CommonProgramFiles, ${env:CommonProgramFiles(x86)}, $env:CommonProgramW6432 | Where-Object { $_ } | Sort-Object -Unique)) {
        if ($d.Equals($cf, [System.StringComparison]::OrdinalIgnoreCase) -or $d.StartsWith($cf + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
            if ($d -match ('(?i)^' + [regex]::Escape($cf) + '\\Remote\\[^\\]*screenconnect[^\\]*')) {
                $root = $Matches[0]
                $item = Get-Item -LiteralPath $root -Force -ErrorAction SilentlyContinue
                if ($item -and -not ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) { return $root }
            }
            return $null
        }
    }
    while ($d -and $d.Length -gt 3) {
        if ((Split-Path -Leaf $d) -match $script:ScLeaf) {
            if (($d -split '\\').Count -lt 3) { return $null }                                   # too shallow
            $item = Get-Item -LiteralPath $d -Force -ErrorAction SilentlyContinue
            if (-not $item -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) { return $null }   # missing or junction/symlink
            return $d
        }
        $d = Split-Path -Parent $d
    }
    return $null
}

function Get-ScreenConnectTargets {
    $ErrorActionPreference = 'SilentlyContinue'
    $svc = @(); $exeDirs = @()
    foreach ($s in @(Get-CimInstance Win32_Service)) {
        if ([string]$s.PathName -match $script:ScPattern) {
            $svc += $s.Name
            if ($s.PathName -match '^\s*"?([^"]*?\.exe)') { $exeDirs += (Split-Path -Parent $Matches[1]) }
        }
    }
    foreach ($p in @(Get-CimInstance Win32_Process)) {
        if ([string]$p.ExecutablePath -match $script:ScPattern) { $exeDirs += (Split-Path -Parent $p.ExecutablePath) }
    }
    $delete = @(); $skipped = @()
    foreach ($d in ($exeDirs | Where-Object { $_ } | Sort-Object -Unique)) {
        $root = Get-SafePurgeRoot $d
        if ($root) { $delete += $root } else { $skipped += $d }
    }
    # drop folders that sit inside another folder already on the list
    $delete = @($delete | Sort-Object -Unique)
    $delete = @($delete | Where-Object { $x = $_; -not ($delete | Where-Object { $_ -ne $x -and $x.StartsWith($_ + '\', [System.StringComparison]::OrdinalIgnoreCase) }) })
    [pscustomobject]@{ Services = @($svc | Sort-Object -Unique); Delete = $delete; Skipped = @($skipped | Sort-Object -Unique) }
}

function Stop-ScreenConnect($Targets) {
    foreach ($sn in $Targets.Services) {      # services: send stop, do not wait
        try {
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = 'net.exe'; $psi.Arguments = 'stop "' + $sn + '" /y'
            $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
            [void][System.Diagnostics.Process]::Start($psi)
        } catch {}
    }
    $script:Running = Get-RunningMap
    $prog = @($Programs | Where-Object { $_.Name -eq 'ConnectWise / ScreenConnect' })
    Stop-ProgramProcesses $prog               # process names/PIDs from the program table
    # anything running from a ScreenConnect path or from a folder about to be deleted
    foreach ($p in @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)) {
        $path = [string]$p.ExecutablePath
        if (-not $path) { continue }
        $hit = ($path -match $script:ScPattern)
        foreach ($d in $Targets.Delete) { if ($path.StartsWith($d + '\', [System.StringComparison]::OrdinalIgnoreCase)) { $hit = $true } }
        if ($hit) { Invoke-TaskKill @('/PID', [string]$p.ProcessId, '/F') }
    }
}

$miPurge.Add_Click({
    $ErrorActionPreference = 'Continue'
    $form.Cursor = 'WaitCursor'
    $failed = @()
    try {
        $t = Get-ScreenConnectTargets
        if ($t.Delete.Count -gt 0 -or $t.Skipped.Count -gt 0) {
            $msg = "Purge ConnectWise / ScreenConnect?`n`nServices: " + ($(if ($t.Services.Count) { $t.Services -join ', ' } else { '(none)' }))
            $msg += "`n`nFolders that will be DELETED:`n - " + ($(if ($t.Delete.Count) { $t.Delete -join "`n - " } else { '(none)' }))
            if ($t.Skipped.Count -gt 0) { $msg += "`n`nUnrecognized locations (NOT deleted):`n - " + ($t.Skipped -join "`n - ") }
            $ans = [System.Windows.Forms.MessageBox]::Show($msg + "`n`nContinue?", 'NoRemote - Purge', 'YesNo', 'Warning')
            if ($ans -ne 'Yes') { return }
        }
        foreach ($pass in 1..2) {                 # stop services and processes, then again
            Stop-ScreenConnect $t
            Start-Sleep -Milliseconds 1500
        }
        foreach ($d in $t.Delete) {
            foreach ($try in 1..2) {
                try { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction Stop; break }
                catch { if ($try -eq 1) { Stop-ScreenConnect $t; Start-Sleep -Milliseconds 1500 } else { $failed += ($d + ' : ' + $_.Exception.Message) } }
            }
        }
        $script:Running = Get-RunningMap
        $script:Detected['ConnectWise / ScreenConnect'] = $true
        Update-Highlights
    } catch { $failed += ('Error: ' + $_.Exception.Message) }
    finally { $form.Cursor = 'Default' }
    $notes = @()
    if ($t -and $t.Skipped.Count -gt 0) { $notes += ("Not deleted (unrecognized location):`n - " + ($t.Skipped -join "`n - ")) }
    if ($failed.Count -gt 0) { $notes += ("Could not delete:`n - " + ($failed -join "`n - ")) }
    if ($notes.Count -gt 0) { Show-Info ($notes -join "`n`n") 'Warning' }
})

# ---- Save button state: green = unapplied changes, red = last save failed ----
function Set-SaveButtonColor([string]$State) {
    $b = $script:btnSave
    if (-not $b) { return }
    switch ($State) {
        'green' { $b.BackColor = [System.Drawing.Color]::SeaGreen;  $b.ForeColor = [System.Drawing.Color]::White }
        'red'   { $b.BackColor = [System.Drawing.Color]::Firebrick; $b.ForeColor = [System.Drawing.Color]::White }
        default { $b.BackColor = [System.Drawing.SystemColors]::Control; $b.ForeColor = [System.Drawing.SystemColors]::ControlText }
    }
}
function Update-SaveButton {
    if ($script:Loading) { return }
    $dirty = $false
    try {
        foreach ($it in @($list.Items)) {
            if (-not $it -or [string]::IsNullOrEmpty($it.Text)) { continue }
            if ([bool]$it.Checked -ne [bool]$script:SavedChecks[[string]$it.Text]) { $dirty = $true; break }
        }
    } catch { return }
    if ($dirty) { Set-SaveButtonColor 'green' } else { Set-SaveButtonColor 'none' }
}

function New-Btn($Text,$Y,$Click) {
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $Text; $b.Location = New-Object System.Drawing.Point(10,$Y); $b.Size = New-Object System.Drawing.Size(340,30)
    $b.Anchor = 'Bottom,Left,Right'
    $b.Add_Click($Click); $form.Controls.Add($b)
    $script:LastBtn = $b
}

New-Btn 'Check All' 410 { Set-Checks { $true } }
New-Btn 'Common'    445 { Set-Checks { param($n) $Common -contains $n } }
New-Btn 'None'      480 { Set-Checks { $false } }
New-Btn 'Save'      520 {
    $script:btnSave.Enabled = $false
    $script:btnSave.Text = 'Saving...'
    $script:btnSave.BackColor = [System.Drawing.Color]::LightGray
    $script:btnSave.ForeColor = [System.Drawing.Color]::DimGray
    $form.Refresh()
    try {
        $pubs = @(); $files = @(); $fw = @()
        $checkedNames = @($list.CheckedItems | ForEach-Object { $_.Text })
        foreach ($p in $Programs) {
            if ($checkedNames -contains $p.Name) { $pubs += $p.Pub; $files += $p.File; $fw += $p.Fw }
        }
        $f = Join-Path $env:TEMP 'NoRemote_policy.xml'
        # sc config is denied on newer Windows builds (protected service); set Automatic start in the registry
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\AppIDSvc' -Name Start -Value 2 -ErrorAction SilentlyContinue
        Invoke-Hidden 'sc.exe' 'config appidsvc start= auto'
        Invoke-Hidden 'sc.exe' 'start appidsvc'
        if (($pubs.Count + $files.Count) -eq 0) { New-EmptyPolicyFile $f } else { New-PolicyFile $f $pubs $files }
        Set-AppLockerPolicy -XmlPolicy $f
        if ($fw.Count -gt 0) { Set-BlockRules $fw } else { Remove-AllBlockRules }

        # success: remember what is applied and clear the green
        $script:SavedChecks = @{}
        foreach ($it in $list.Items) { $script:SavedChecks[$it.Text] = [bool]$it.Checked }
        Update-SaveButton
    } catch {
        Set-SaveButtonColor 'red'
        Show-Info ('ERROR: ' + $_.Exception.Message) 'Error'
    } finally {
        $script:btnSave.Text = 'Save'
        $script:btnSave.Enabled = $true
    }
}
$script:btnSave = $script:LastBtn
$script:btnSave.FlatStyle = 'Flat'
Set-SaveButtonColor 'none'
$list.Add_ItemChecked({ Update-SaveButton })

# One scan at launch: show "Scanning for remotes", then the list
$form.Add_Shown({
    $list.Visible = $false
    $lblScan.Visible = $true
    $form.Refresh()
    try { $script:Running = Get-RunningMap } catch { Show-Info ('Scan failed: ' + $_.Exception.Message) 'Warning' }
    try {
        Import-Module AppLocker
        $st = Get-CurrentState
        Set-Checks { param($n) $st[$n] }
    } catch { Show-Info ('Could not read current state: ' + $_.Exception.Message) 'Warning' }
    foreach ($it in $list.Items) { $script:SavedChecks[$it.Text] = [bool]$it.Checked }
    $script:Loading = $false
    Update-SaveButton
    Update-Highlights
    $lblScan.Visible = $false
    $list.Visible = $true
})

[void]$form.ShowDialog()