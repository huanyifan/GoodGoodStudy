param(
    [ValidateSet('Prepare','Finish')][string]$Mode,
    [Parameter(Mandatory=$true)][string]$InstallDirectory
)
$ErrorActionPreference='Stop'
$integrationMode=$Mode
$local=[Environment]::GetFolderPath('LocalApplicationData')
$expected=[IO.Path]::GetFullPath((Join-Path $local 'Programs\GoodGoodStudy'))
$actual=[IO.Path]::GetFullPath($InstallDirectory)
if (-not [string]::Equals($actual,$expected,[StringComparison]::OrdinalIgnoreCase)) { throw 'Unexpected installation directory' }
$state=Join-Path $local 'GoodGoodStudy'
[IO.Directory]::CreateDirectory($state) | Out-Null
function Setup-Log([string]$Text) {
    [IO.File]::AppendAllText((Join-Path $state 'setup.log'),[DateTime]::UtcNow.ToString('O')+' '+$Text+[Environment]::NewLine)
}
try {
    . (Join-Path $PSScriptRoot 'Autostart.ps1')
    $exe=Join-Path $actual 'GoodGoodStudy.exe'
    if ($integrationMode -eq 'Prepare') {
        Invoke-AutostartCommand 'Disable' $exe 'https://yifan.im/tools/goodgoodstudy/config.json'
        Setup-Log 'Previous scheduled watchdog disabled.'
        exit 0
    }
    $menu=Join-Path ([Environment]::GetFolderPath('Programs')) 'GoodGoodStudy'
    New-Item -ItemType Directory -Path $menu -Force | Out-Null
    $shell=New-Object -ComObject WScript.Shell
    try {
        foreach($item in @(
            @{Name='GoodGoodStudy - Status'; File='Autostart-Status.cmd'},
            @{Name='GoodGoodStudy - Disable'; File='Disable-Autostart.cmd'},
            @{Name='GoodGoodStudy - Enable'; File='Enable-Autostart.cmd'}
        )) {
            $shortcut=$shell.CreateShortcut((Join-Path $menu ($item.Name+'.lnk')))
            $shortcut.TargetPath=Join-Path $actual $item.File
            $shortcut.WorkingDirectory=$actual
            $shortcut.IconLocation=$exe+',0'
            $shortcut.Save()
        }
        $shortcut=$shell.CreateShortcut((Join-Path $menu 'Uninstall GoodGoodStudy.lnk'))
        $shortcut.TargetPath=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $shortcut.Arguments='-NoProfile -ExecutionPolicy Bypass -File "'+(Join-Path $actual 'Uninstall.ps1')+'"'
        $shortcut.WorkingDirectory=$local
        $shortcut.Save()
    } finally { [Runtime.InteropServices.Marshal]::ReleaseComObject($shell) | Out-Null }
    $registry='HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\GoodGoodStudy'
    New-Item -Path $registry -Force | Out-Null
    $powershell=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $uninstall='"'+$powershell+'" -NoProfile -ExecutionPolicy Bypass -File "'+(Join-Path $actual 'Uninstall.ps1')+'"'
    foreach($property in @{
        DisplayName='GoodGoodStudy Rust'; DisplayVersion='3.2.1'; Publisher='GoodGoodStudy';
        InstallLocation=$actual; DisplayIcon=$exe; UninstallString=$uninstall;
        InstallDate=(Get-Date).ToString('yyyyMMdd')
    }.GetEnumerator()) {
        New-ItemProperty -Path $registry -Name $property.Key -Value $property.Value -PropertyType String -Force | Out-Null
    }
    New-ItemProperty -Path $registry -Name NoModify -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $registry -Name NoRepair -Value 1 -PropertyType DWord -Force | Out-Null
    $DeferConfigCheck=$true
    Invoke-AutostartCommand 'Enable' $exe 'https://yifan.im/tools/goodgoodstudy/config.json'
    Setup-Log 'Shortcuts, uninstall entry and watchdog installed.'
} catch {
    Setup-Log ('Integration failed: '+$_.Exception.GetType().Name)
    exit 1
}
