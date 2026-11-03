param(
    [Parameter(Mandatory=$true)][string]$InputPath,
    [Parameter(Mandatory=$true)][string]$OutputPath,
    [string]$ExecutablePath = (Join-Path $PSScriptRoot '..\GoodGoodStudy.exe')
)
$ErrorActionPreference = 'Stop'
try {
    $exe = (Resolve-Path -LiteralPath $ExecutablePath).Path
    & $exe --convert-ini $InputPath $OutputPath
    if ($LASTEXITCODE -ne 0) { throw 'Native INI conversion failed' }
} catch {
    Write-Error ('INI conversion failed (' + $_.Exception.GetType().Name + '). Secrets are not printed.')
    exit 1
}
