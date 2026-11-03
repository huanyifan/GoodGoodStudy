param([switch]$ValidateWithScheduler)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\tools\Autostart.ps1')
$script:checks = 0
function Assert-Check([bool]$Condition,[string]$Description) {
    if (-not $Condition) { throw ('FAIL: ' + $Description) }
    $script:checks++
}
function Assert-Rejected([scriptblock]$Action,[string]$Description) {
    try { & $Action } catch { $script:checks++; return }
    throw ('FAIL: expected rejection: ' + $Description)
}
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$exe = 'C:\Apps\Study & Tools\GoodGoodStudy.exe'
$scriptPath = 'C:\Apps\Study & Tools\tools\Autostart.ps1'
$url = 'https://yifan.im/tools/goodgoodstudy/config.json?one=1&two=2'
$xmlText = New-WatchdogTaskXml $exe $scriptPath $url $sid
[xml]$xml = $xmlText
$ns = New-Object Xml.XmlNamespaceManager($xml.NameTable)
$ns.AddNamespace('t','http://schemas.microsoft.com/windows/2004/02/mit/task')
function NodeText([string]$Xpath) { return $xml.SelectSingleNode($Xpath,$ns).InnerText }
Assert-Check ((NodeText '//t:Principals/t:Principal/t:UserId') -eq $sid) 'current-user task principal'
Assert-Check ((NodeText '//t:LogonType') -eq 'InteractiveToken') 'interactive user only'
Assert-Check ((NodeText '//t:RunLevel') -eq 'LeastPrivilege') 'no elevated task'
Assert-Check ((NodeText '//t:LogonTrigger/t:UserId') -eq $sid) 'logon filter bound to user'
Assert-Check ((NodeText '//t:LogonTrigger/t:Delay') -eq 'PT15S') 'logon delay'
Assert-Check ((NodeText '//t:TimeTrigger/t:Repetition/t:Interval') -eq 'PT1M') 'one-minute checks'
Assert-Check ($null -eq $xml.SelectSingleNode('//t:TimeTrigger/t:Repetition/t:Duration',$ns)) 'indefinite repetition'
Assert-Check ((NodeText '//t:MultipleInstancesPolicy') -eq 'IgnoreNew') 'no overlapping watchdogs'
Assert-Check ((NodeText '//t:Hidden') -eq 'false') 'visible task registration'
Assert-Check ((NodeText '//t:DisallowStartIfOnBatteries') -eq 'false') 'watchdog works on battery'
Assert-Check ((NodeText '//t:ExecutionTimeLimit') -eq 'PT45S') 'watchdog timeout'
Assert-Check ((NodeText '//t:Exec/t:Arguments').Contains('"' + $exe + '"')) 'quoted executable path'
Assert-Check ((NodeText '//t:Exec/t:Arguments').Contains('"' + $scriptPath + '"')) 'quoted script path'
Assert-Check ((NodeText '//t:Exec/t:Arguments').Contains('&two=2')) 'URL XML round trip'
Assert-Rejected { Assert-ConfigUrl 'http://yifan.im/config.json' } 'HTTP rejected'
Assert-Rejected { Assert-ConfigUrl 'https://user:secret@yifan.im/config.json' } 'credentials in URL rejected'
Assert-Rejected { New-WatchdogTaskXml '\\server\share\GoodGoodStudy.exe' $scriptPath $url $sid } 'network executable rejected'
Assert-Rejected { New-WatchdogTaskXml 'relative.exe' $scriptPath $url $sid } 'relative executable rejected'
Assert-Rejected { Assert-ConfigUrl ('https://yifan.im/' + [char]34 + 'bad') } 'quote rejected'
$now = Get-Date
$session = [Diagnostics.Process]::GetCurrentProcess().SessionId
$process = [pscustomobject]@{ Id=100; Path=$exe; StartTime=$now; SessionId=$session }
$record = [pscustomobject]@{ Id=100; ExecutablePath=$exe; StartTimeUtcTicks=$now.ToUniversalTime().Ticks }
Assert-Check (Test-ManagedProcessIdentity $process $record $exe) 'matching process identity'
$record.StartTimeUtcTicks--
Assert-Check (-not (Test-ManagedProcessIdentity $process $record $exe)) 'reused PID rejected'
$record.StartTimeUtcTicks = $now.ToUniversalTime().Ticks
$record.Id = 101
Assert-Check (-not (Test-ManagedProcessIdentity $process $record $exe)) 'different process ID rejected'
$record.Id = 100
Assert-Check (-not (Test-ManagedProcessIdentity $process $record 'C:\Other\GoodGoodStudy.exe')) 'different executable rejected'
Assert-Check (-not (Test-ManagedProcessIdentity $null $record $exe)) 'exited process ignored'
$state = Join-Path $env:TEMP ('GoodGoodStudy-autostart-test-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $state | Out-Null
try {
    [IO.File]::WriteAllText((Join-Path $state 'autostart-disabled'),'disabled')
    Invoke-CaptureWatchdog 'C:\DoesNotExist.exe' $url $state
    Assert-Check (-not (Test-Path -LiteralPath (Join-Path $state 'autostart-process.json'))) 'disabled flag prevents launch'
} finally {
    # Only the unique directory created above, containing a single test flag.
    Remove-Item -LiteralPath (Join-Path $state 'autostart-disabled')
    Remove-Item -LiteralPath $state
}
if ($ValidateWithScheduler) {
    $service = New-Object -ComObject 'Schedule.Service'
    $service.Connect()
    $folder = $service.GetFolder('\')
    $testName = 'GoodGoodStudy-ValidateOnly-' + [Guid]::NewGuid().ToString('N')
    # TASK_VALIDATE_ONLY=1 checks schema without registering or executing a task.
    $folder.RegisterTask($testName,$xmlText,1,$null,$null,3,$null) | Out-Null
    $exists = $false
    try { $folder.GetTask($testName) | Out-Null; $exists=$true } catch {}
    Assert-Check (-not $exists) 'native scheduler validation did not install a task'
}
Write-Output ('PASS: ' + $script:checks + ' autostart checks; no capture or startup task enabled.')
