param([switch]$SkipRust,[switch]$SkipGo)
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
$output=Join-Path $root 'artifacts'
function Run-Checked([string]$Command,[string[]]$Arguments){
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) { throw ('Native build step failed: ' + $Command) }
}
if (-not $SkipGo) {
    $go=(Get-Command go -ErrorAction Stop).Source
    Push-Location (Join-Path $root 'clients\go')
    try {
        $env:CGO_ENABLED='0'
        Run-Checked $go @('test','./...')
        Run-Checked $go @('vet','./...')
        $destination=Join-Path $output 'Go\GoodGoodStudy.exe'
        New-Item -ItemType Directory -Path (Split-Path $destination -Parent) -Force | Out-Null
        Run-Checked $go @('build','-trimpath','-ldflags','-s -w','-o',$destination,'.')
    } finally { Pop-Location }
}
if (-not $SkipRust) {
    $cargo=Get-Command cargo -ErrorAction SilentlyContinue
    if ($cargo) { $cargo=$cargo.Source }
    elseif ($env:CARGO_HOME) { $cargo=Join-Path $env:CARGO_HOME 'bin\cargo.exe' }
    else { throw 'Install Rust MSVC toolchain and C++ Build Tools first.' }
    Push-Location (Join-Path $root 'clients\rust')
    try {
        Run-Checked $cargo @('fmt','--','--check')
        Run-Checked $cargo @('clippy','--locked','--all-targets','--','-D','warnings')
        Run-Checked $cargo @('test','--locked')
        Run-Checked $cargo @('build','--release','--locked')
        $target=if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path (Get-Location).Path 'target' }
        $destination=Join-Path $output 'Rust'
        New-Item -ItemType Directory -Path $destination -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $target 'release\goodgoodstudy.exe') -Destination (Join-Path $destination 'GoodGoodStudy.exe')
    } finally { Pop-Location }
}
Write-Output ('Native outputs: ' + $output)
