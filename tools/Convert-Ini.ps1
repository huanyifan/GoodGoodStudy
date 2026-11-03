param(
    [Parameter(Mandatory=$true)][string]$InputPath,
    [Parameter(Mandatory=$true)][string]$OutputPath,
    [string]$ExecutablePath = (Join-Path $PSScriptRoot '..\bin\Release\GoodGoodStudy.exe')
)
$ErrorActionPreference = 'Stop'
try {
    Add-Type -AssemblyName System.Web.Extensions
    [Reflection.Assembly]::LoadFrom((Resolve-Path -LiteralPath $ExecutablePath).Path) | Out-Null
    if ((Get-Item -LiteralPath $InputPath).Length -gt 65536) { throw 'INI too large' }
    if ([IO.Path]::GetFullPath($InputPath) -eq [IO.Path]::GetFullPath($OutputPath)) { throw 'Input and output must differ' }
    $values = @{}
    foreach ($line in Get-Content -LiteralPath $InputPath) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith(';') -or $trimmed.StartsWith('#') -or $trimmed.StartsWith('[')) { continue }
        $parts = $trimmed -split '=', 2
        if ($parts.Count -ne 2) { throw 'Invalid INI line' }
        $value = $parts[1].Trim()
        if (($value.StartsWith('"') -and $value.EndsWith('"')) -or ($value.StartsWith("'") -and $value.EndsWith("'"))) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        $values[$parts[0].Trim()] = $value
    }
    foreach ($required in @('senderMail','smtpServer','tokenCode','toMail','timeInterval')) {
        if (-not $values.ContainsKey($required) -or [string]::IsNullOrWhiteSpace($values[$required])) { throw 'Required INI value missing' }
    }
    $settings = New-Object GoodGoodStudy.AppConfig
    $settings.intervalSeconds = [int]::Parse($values['timeInterval'], [Globalization.CultureInfo]::InvariantCulture) * 60
    $settings.mail.enabled = $true
    $settings.mail.sender = $values['senderMail']
    $settings.mail.recipient = $values['toMail']
    $settings.mail.username = $values['senderMail']
    $settings.mail.password = $values['tokenCode']
    $settings.mail.host = $values['smtpServer']
    $settings.Validate()
    $serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    $stateDirectory = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'GoodGoodStudy'
    $key = [GoodGoodStudy.ConfigCrypto]::LoadKey($stateDirectory)
    $encrypted = [GoodGoodStudy.ConfigCrypto]::Encrypt($serializer.Serialize($settings), $key)
    [GoodGoodStudy.AtomicFile]::WriteBytes([IO.Path]::GetFullPath($OutputPath), [Text.Encoding]::UTF8.GetBytes($encrypted))
    Write-Output 'INI converted and encrypted; no plaintext JSON was written. SMTP uses STARTTLS on port 587.'
} catch {
    Write-Error ('INI encryption failed (' + $_.Exception.GetType().Name + '). Check the input, key and README; secrets are not printed.')
    exit 1
}
