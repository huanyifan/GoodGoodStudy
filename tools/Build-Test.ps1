param([string]$PackagesDirectory = (Join-Path $PSScriptRoot '..\..\build-packages'))
$ErrorActionPreference = 'Stop'
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$msbuild = & $vswhere -latest -products '*' -find 'MSBuild\**\Bin\MSBuild.exe' | Select-Object -First 1
if (-not $msbuild) { throw 'Install Visual Studio Build Tools with MSBuild and Visual Basic.' }
Push-Location (Join-Path $PSScriptRoot '..')
try {
    & $msbuild 'Tests\GoodGoodStudy.Tests.vbproj' /restore /p:Configuration=Release "/p:RestorePackagesPath=$PackagesDirectory" /nologo /verbosity:minimal
    if ($LASTEXITCODE -ne 0) { throw 'Build failed' }
    & '.\Tests\bin\Release\GoodGoodStudy.Tests.exe'
    if ($LASTEXITCODE -ne 0) { throw 'Regression checks failed' }
} finally {
    Pop-Location
}
