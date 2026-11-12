
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
Import-Module ps2exe
$dir = $PSScriptRoot
$list = Get-Content -LiteralPath (Join-Path $dir 'programs.txt') -Raw -Encoding UTF8
# non-ASCII -> \uXXXX so the compiled script stays plain ASCII (the script converts it back)
$list = [regex]::Replace($list, '[^\x00-\x7F]', { param($m) '\u{0:X4}' -f [int][char]$m.Value })
$src = Get-Content -LiteralPath (Join-Path $dir 'NoRemote.ps1') -Raw
$src = [regex]::Replace($src, "(?s)(\`$EmbeddedList = @')\r?\n#EMBEDDED-LIST\r?\n'@", { param($m) $m.Groups[1].Value + "`r`n" + $list.TrimEnd() + "`r`n'@" })
$src = $src -replace '(?m)^#Requires -RunAsAdministrator\r?\n', ''     # -requireAdmin does this in the exe
$tmp = Join-Path $dir 'NoRemote.build.ps1'
Set-Content -LiteralPath $tmp -Value $src -Encoding ASCII
$args2 = @{ inputFile = $tmp; outputFile = (Join-Path $dir 'NoRemote.exe'); noConsole = $true; requireAdmin = $true; STA = $true }
$ico = Join-Path $dir 'NoRemote.ico'
if (Test-Path -LiteralPath $ico) { $args2.iconFile = $ico }
Invoke-ps2exe @args2
Remove-Item -LiteralPath $tmp -Force
