param([switch]$ValidateOnly)
$ErrorActionPreference='Stop'
$app=[IO.Path]::GetFullPath($PSScriptRoot)
$expected=[IO.Path]::GetFullPath((Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Programs\GoodGoodStudy'))
if (-not [string]::Equals($app,$expected,[StringComparison]::OrdinalIgnoreCase)) { throw 'Uninstall directory is outside the expected per-user installation' }
for($ancestor=$app; $ancestor; $ancestor=Split-Path $ancestor -Parent) {
    if (((Get-Item -LiteralPath $ancestor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Uninstall parent contains a reparse point' }
}
# Refuse reparse points before any recursive deletion.
$pending=New-Object 'System.Collections.Generic.Stack[string]'
$pending.Push($app)
while($pending.Count -gt 0) {
    $path=$pending.Pop()
    $item=Get-Item -LiteralPath $path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Refusing to remove an installation containing a reparse point' }
    if ($item.PSIsContainer) { foreach($child in Get-ChildItem -LiteralPath $path -Force) { $pending.Push($child.FullName) } }
}
if ($ValidateOnly) { Write-Output 'Per-user uninstall path validated; nothing removed.'; exit 0 }
. (Join-Path $app 'tools\Autostart.ps1')
Invoke-AutostartCommand 'Disable' (Join-Path $app 'GoodGoodStudy.exe') 'https://yifan.im/tools/goodgoodstudy/config.json'
& (Join-Path $app 'GoodGoodStudy.exe') --stop-instance
if ($LASTEXITCODE -ne 0) { throw 'Application did not exit; close it and retry uninstall' }
$menu=Join-Path ([Environment]::GetFolderPath('Programs')) 'GoodGoodStudy'
foreach($name in @('GoodGoodStudy - Status.lnk','GoodGoodStudy - Disable.lnk','GoodGoodStudy - Enable.lnk','Uninstall GoodGoodStudy.lnk')) {
    $file=Join-Path $menu $name
    if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file }
}
if ((Test-Path -LiteralPath $menu) -and @(Get-ChildItem -LiteralPath $menu -Force).Count -eq 0) { Remove-Item -LiteralPath $menu }
Remove-Item -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\GoodGoodStudy' -ErrorAction SilentlyContinue
Set-Location ([Environment]::GetFolderPath('LocalApplicationData'))
# app was verified above to equal this user's exact Programs/GoodGoodStudy directory.
Remove-Item -LiteralPath $app -Recurse -Force
Write-Output 'GoodGoodStudy uninstalled. Captures, logs and DPAPI device credential were retained.'
