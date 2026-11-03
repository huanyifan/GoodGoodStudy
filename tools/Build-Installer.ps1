param(
    [Parameter(Mandatory=$true)][string]$ProfilePath,
    [string]$OutputDirectory=(Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'GoodGoodStudyBuilds\3.2.0')
)
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$output=[IO.Path]::GetFullPath($OutputDirectory)
if ($output.StartsWith('\\') -or $output -eq [IO.Path]::GetPathRoot($output)) { throw 'A dedicated local private output directory is required' }
foreach($ancestor in @($output,(Split-Path $output -Parent))) {
    if ((Test-Path -LiteralPath $ancestor) -and ((Get-Item -LiteralPath $ancestor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Reparse output directory refused' }
}
$acl=New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true,$false)
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
$acl.SetOwner($sid)
$rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
$acl.AddAccessRule($rule)
if (-not (Test-Path -LiteralPath $output)) { [IO.Directory]::CreateDirectory($output) | Out-Null }
$currentAcl=Get-Acl -LiteralPath $output
$rules=@($currentAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
$alreadyPrivate=$currentAcl.AreAccessRulesProtected -and $rules.Count -eq 1 -and
    $rules[0].IdentityReference.Value -eq $sid.Value -and
    $rules[0].AccessControlType -eq 'Allow' -and
    ($rules[0].FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq [Security.AccessControl.FileSystemRights]::FullControl
if (-not $alreadyPrivate) { Set-Acl -LiteralPath $output -AclObject $acl }
$cargo=if($env:CARGO_HOME){Join-Path $env:CARGO_HOME 'bin\cargo.exe'}else{'cargo.exe'}
$env:CARGO_TARGET_DIR=Join-Path $output 'target'
function Cargo {
    param([Parameter(ValueFromRemainingArguments=$true)][string[]]$Arguments)
    & $cargo @Arguments
    if ($LASTEXITCODE -ne 0) { throw 'Rust build/check failed' }
}
Push-Location (Join-Path $root 'clients\rust')
try { Cargo @('test','--locked'); Cargo @('clippy','--locked','--all-targets','--','-D','warnings'); Cargo @('build','--release','--locked') } finally { Pop-Location }
$files=[ordered]@{
    'GoodGoodStudy.exe'=(Join-Path $env:CARGO_TARGET_DIR 'release\goodgoodstudy.exe')
    'README.md'=(Join-Path $root 'README.md')
    'LICENSE'=(Join-Path $root 'LICENSE')
    'config.example.json'=(Join-Path $root 'config.example.json')
    'Import-Profile.cmd'=(Join-Path $root 'Import-Profile.cmd')
    'Enable-Autostart.cmd'=(Join-Path $root 'Enable-Autostart.cmd')
    'Disable-Autostart.cmd'=(Join-Path $root 'Disable-Autostart.cmd')
    'Autostart-Status.cmd'=(Join-Path $root 'Autostart-Status.cmd')
    'tools/Autostart.ps1'=(Join-Path $root 'tools\Autostart.ps1')
    'tools/Convert-Ini.ps1'=(Join-Path $root 'tools\Convert-Ini.ps1')
    'tools/Install-Integration.ps1'=(Join-Path $root 'tools\Install-Integration.ps1')
    'Uninstall.ps1'=(Join-Path $root 'installer\resources\Uninstall.ps1')
    'provisioning/device-profile.json'=[IO.Path]::GetFullPath($ProfilePath)
}
if ((Get-Item -LiteralPath $ProfilePath).Length -gt 4096) { throw 'Profile too large' }
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$payload=Join-Path $output 'installer.payload.zip'
$hashes=[ordered]@{}
$stream=[IO.File]::Open($payload,[IO.FileMode]::Create,[IO.FileAccess]::Write,[IO.FileShare]::None)
$zip=New-Object IO.Compression.ZipArchive($stream,[IO.Compression.ZipArchiveMode]::Create,$false)
try {
    foreach($entry in $files.GetEnumerator()) {
        $hashes[$entry.Key]=(Get-FileHash -LiteralPath $entry.Value -Algorithm SHA256).Hash.ToLowerInvariant()
        [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip,$entry.Value,$entry.Key,[IO.Compression.CompressionLevel]::Optimal) | Out-Null
    }
    $manifest=$zip.CreateEntry('manifest.json').Open()
    try {
        $bytes=[Text.Encoding]::UTF8.GetBytes((@{version='3.2.0';sha256=$hashes}|ConvertTo-Json -Depth 4 -Compress))
        $manifest.Write($bytes,0,$bytes.Length)
    } finally { $manifest.Dispose() }
} finally { $zip.Dispose(); $stream.Dispose() }
Push-Location (Join-Path $root 'installer')
try {
    Remove-Item Env:GGS_INSTALL_PAYLOAD -ErrorAction SilentlyContinue
    Cargo @('test','--lib','--locked')
    $env:GGS_INSTALL_PAYLOAD=$payload
    Cargo @('clippy','--locked','--all-targets','--','-D','warnings')
    Cargo @('build','--release','--locked')
} finally { Pop-Location; Remove-Item Env:GGS_INSTALL_PAYLOAD -ErrorAction SilentlyContinue }
$exe=Join-Path $output 'GoodGoodStudy-Rust-Setup-3.2.0.personal.exe'
Copy-Item -LiteralPath (Join-Path $env:CARGO_TARGET_DIR 'release\goodgoodstudy-setup.exe') -Destination $exe -Force
$report=Join-Path $output ('verification-'+[Guid]::NewGuid().ToString('N')+'.json')
$process=Start-Process -FilePath $exe -ArgumentList @('--verify-online',('"'+$report+'"')) -WindowStyle Hidden -Wait -PassThru
if ($process.ExitCode -ne 0) { throw 'Installer online credential verification failed' }
Get-Content -LiteralPath $report
$hash=(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
[IO.File]::WriteAllText((Join-Path $output 'SHA256SUMS.txt'),$hash+'  '+[IO.Path]::GetFileName($exe)+[Environment]::NewLine)
Write-Output ('Personal installer: '+$exe)
