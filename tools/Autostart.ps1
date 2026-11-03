param(
    [ValidateSet('Enable','Disable','Status','Watchdog')][string]$Mode = 'Status',
    [string]$ExecutablePath,
    [string]$ConfigUrl = 'https://yifan.im/tools/goodgoodstudy/config.json',
    [switch]$DeferConfigCheck
)
$ErrorActionPreference = 'Stop'
$script:WatchdogScriptPath = $PSCommandPath

function Get-AutostartStateDirectory {
    return Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'GoodGoodStudy'
}
function Get-AutostartTaskName {
    return 'GoodGoodStudy-Watchdog-' + [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
}
function Assert-ConfigUrl([string]$Url) {
    $uri = $null
    if (-not [Uri]::TryCreate($Url, [UriKind]::Absolute, [ref]$uri) -or
        $uri.Scheme -ne 'https' -or $uri.UserInfo -or $uri.Fragment -or $Url.Contains('"') -or ($Url.IndexOfAny([char[]]"`r`n") -ge 0)) {
        throw 'A plain HTTPS configuration URL is required.'
    }
    return $uri.AbsoluteUri
}
function New-WatchdogTaskXml([string]$Exe, [string]$Script, [string]$Url, [string]$Sid) {
    $urlValue = Assert-ConfigUrl $Url
    foreach ($path in @($Exe,$Script)) {
        if (-not [IO.Path]::IsPathRooted($path) -or $path.StartsWith('\\') -or $path.Contains('"')) {
            throw 'Autostart requires absolute local file paths.'
        }
    }
    $escape = { param($value) [Security.SecurityElement]::Escape([string]$value) }
    $arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -Mode Watchdog -ExecutablePath "{1}" -ConfigUrl "{2}"' -f $Script,$Exe,$urlValue
    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $start = (Get-Date).AddMinutes(1).ToString('yyyy-MM-ddTHH:mm:ss')
    return @"
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>GoodGoodStudy: start at user logon and check the capture process every minute.</Description></RegistrationInfo>
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled><UserId>$(& $escape $Sid)</UserId><Delay>PT15S</Delay></LogonTrigger>
    <TimeTrigger><Repetition><Interval>PT1M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition><StartBoundary>$start</StartBoundary><Enabled>true</Enabled></TimeTrigger>
  </Triggers>
  <Principals><Principal id="CurrentUser"><UserId>$(& $escape $Sid)</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden>
    <WakeToRun>false</WakeToRun><ExecutionTimeLimit>PT45S</ExecutionTimeLimit>
  </Settings>
  <Actions Context="CurrentUser"><Exec><Command>$(& $escape $powershell)</Command><Arguments>$(& $escape $arguments)</Arguments><WorkingDirectory>$(& $escape ([IO.Path]::GetDirectoryName($Exe)))</WorkingDirectory></Exec></Actions>
</Task>
"@
}
function Test-CaptureRunning {
    $name = 'Local\GoodGoodStudy-' + [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $mutex = $null
    $acquired = $false
    try {
        try { $mutex = [Threading.Mutex]::OpenExisting($name) }
        catch [Threading.WaitHandleCannotBeOpenedException] { return $false }
        try { $acquired = $mutex.WaitOne(0) }
        catch [Threading.AbandonedMutexException] { $acquired = $true }
        return -not $acquired
    } finally {
        if ($mutex) {
            if ($acquired) { $mutex.ReleaseMutex() }
            $mutex.Dispose()
        }
    }
}
function Test-ManagedProcessIdentity($Process, $Record, [string]$ExpectedExe) {
    return $Process -and
        [string]::Equals([string]$Record.ExecutablePath,$ExpectedExe,[StringComparison]::OrdinalIgnoreCase) -and
        [string]::Equals([string]$Process.Path,$ExpectedExe,[StringComparison]::OrdinalIgnoreCase) -and
        [int]$Record.Id -eq $Process.Id -and
        [long]$Record.StartTimeUtcTicks -eq $Process.StartTime.ToUniversalTime().Ticks -and
        $Process.SessionId -eq [Diagnostics.Process]::GetCurrentProcess().SessionId
}
function Write-WatchdogLog([string]$Directory, [string]$Message) {
    try {
        [IO.Directory]::CreateDirectory($Directory) | Out-Null
        $path = Join-Path $Directory 'watchdog.log'
        if ((Test-Path -LiteralPath $path) -and (Get-Item -LiteralPath $path).Length -gt 262144) {
            Move-Item -LiteralPath $path -Destination ($path + '.1') -Force
        }
        [IO.File]::AppendAllText($path, [DateTime]::UtcNow.ToString('O') + ' ' + $Message + [Environment]::NewLine)
    } catch {}
}
function Invoke-CaptureWatchdog([string]$Exe, [string]$Url, [string]$Directory) {
    if (Test-Path -LiteralPath (Join-Path $Directory 'autostart-disabled')) { return }
    [IO.Directory]::CreateDirectory($Directory) | Out-Null
    $gate = New-Object Threading.Mutex($false,('Local\GoodGoodStudyWatchdog-' + [Security.Principal.WindowsIdentity]::GetCurrent().User.Value))
    $acquired = $false
    try {
        try { $acquired = $gate.WaitOne(0) } catch [Threading.AbandonedMutexException] { $acquired = $true }
        if (-not $acquired -or (Test-CaptureRunning)) { return }
        if (Test-Path -LiteralPath (Join-Path $Directory 'autostart-disabled')) { return }
        $normalized = Assert-ConfigUrl $Url
        # Start-Process starts a separate program, never a thread inside explorer.exe.
        $process = Start-Process -FilePath $Exe -ArgumentList @('--config-url',('"' + $normalized + '"')) -WorkingDirectory ([IO.Path]::GetDirectoryName($Exe)) -WindowStyle Hidden -PassThru
        $record = @{ Id=$process.Id; ExecutablePath=$Exe; StartTimeUtcTicks=$process.StartTime.ToUniversalTime().Ticks }
        if (Test-Path -LiteralPath (Join-Path $Directory 'autostart-disabled')) {
            $process.Kill()
            return
        }
        try {
            $record | ConvertTo-Json -Compress | Set-Content -LiteralPath (Join-Path $Directory 'autostart-process.json') -Encoding utf8
        } catch {
            if (-not $process.HasExited) { $process.Kill() }
            throw
        }
        Write-WatchdogLog $Directory 'Capture process started.'
    } finally {
        if ($acquired) { $gate.ReleaseMutex() }
        $gate.Dispose()
    }
}
function Stop-ManagedCapture([string]$Exe, [string]$Directory) {
    $recordPath = Join-Path $Directory 'autostart-process.json'
    if (-not (Test-Path -LiteralPath $recordPath)) { return }
    try {
        $record = Get-Content -LiteralPath $recordPath -Raw | ConvertFrom-Json
        $process = Get-Process -Id ([int]$record.Id) -ErrorAction SilentlyContinue
        if (Test-ManagedProcessIdentity $process $record $Exe) {
            $stopSignal = $null
            try {
                try {
                    $stopSignal = [Threading.EventWaitHandle]::OpenExisting('Local\GoodGoodStudyStop-' + [Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
                    $stopSignal.Set() | Out-Null
                } catch [Threading.WaitHandleCannotBeOpenedException] {}
                if (-not $process.WaitForExit(20000)) { Stop-Process -Id $process.Id -ErrorAction Stop }
            } finally {
                if ($stopSignal) { $stopSignal.Dispose() }
            }
        }
    } finally {
        Remove-Item -LiteralPath $recordPath -ErrorAction SilentlyContinue
    }
}
function Invoke-AutostartCommand([string]$Action, [string]$Exe, [string]$Url) {
    $directory = Get-AutostartStateDirectory
    $taskName = Get-AutostartTaskName
    if ($Action -eq 'Watchdog') {
        Invoke-CaptureWatchdog $Exe $Url $directory
        return
    }
    $existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    switch ($Action) {
        'Enable' {
            if (-not (Test-Path -LiteralPath $Exe -PathType Leaf)) { throw 'GoodGoodStudy.exe not found.' }
            $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            $xml = New-WatchdogTaskXml $Exe $script:WatchdogScriptPath $Url $sid
            if (-not $DeferConfigCheck) {
                & $Exe --check-config $Url
                if ($LASTEXITCODE -ne 0) { throw 'Import the device profile and validate remote configuration first.' }
            }
            Register-ScheduledTask -TaskName $taskName -Xml $xml -Force | Out-Null
            $flag = Join-Path $directory 'autostart-disabled'
            if (Test-Path -LiteralPath $flag) { Remove-Item -LiteralPath $flag }
            Start-ScheduledTask -TaskName $taskName
            Write-Output 'Enabled: logon startup and one-minute process checks. Capture starts now.'
        }
        'Disable' {
            [IO.Directory]::CreateDirectory($directory) | Out-Null
            [IO.File]::WriteAllText((Join-Path $directory 'autostart-disabled'),'disabled')
            if ($existing) { Disable-ScheduledTask -TaskName $taskName | Out-Null }
            $gate = New-Object Threading.Mutex($false,('Local\GoodGoodStudyWatchdog-' + [Security.Principal.WindowsIdentity]::GetCurrent().User.Value))
            $acquired = $false
            try {
                try { $acquired = $gate.WaitOne(15000) } catch [Threading.AbandonedMutexException] { $acquired = $true }
                if (-not $acquired) { throw 'Watchdog is busy; task disabled. Retry Disable to stop the managed process.' }
                if ($existing) {
                    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
                    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
                }
                Stop-ManagedCapture $Exe $directory
            } finally {
                if ($acquired) { $gate.ReleaseMutex() }
                $gate.Dispose()
            }
            Write-Output 'Disabled: task removed; capture started by this watchdog stopped.'
        }
        'Status' {
            if ($existing) {
                $info = Get-ScheduledTaskInfo -TaskName $taskName
                Write-Output ('Task: ' + $taskName + '; state=' + $existing.State + '; last result=' + $info.LastTaskResult)
            } else { Write-Output 'Autostart is not registered.' }
            Write-Output ('Capture running in this session: ' + (Test-CaptureRunning))
            Write-Output ('Logs: ' + (Join-Path $directory 'watchdog.log'))
        }
    }
}
# Dot-sourcing exposes pure helpers to regression tests without installing or starting anything.
if ($MyInvocation.InvocationName -ne '.') {
    try {
        if (-not $ExecutablePath) {
            $ExecutablePath = Join-Path $PSScriptRoot '..\GoodGoodStudy.exe'
            if (-not (Test-Path -LiteralPath $ExecutablePath)) {
                $ExecutablePath = Join-Path $PSScriptRoot '..\bin\Release\GoodGoodStudy.exe'
            }
        }
        $ExecutablePath = [IO.Path]::GetFullPath($ExecutablePath)
        $ConfigUrl = Assert-ConfigUrl $ConfigUrl
        Invoke-AutostartCommand $Mode $ExecutablePath $ConfigUrl
    } catch {
        Write-WatchdogLog (Get-AutostartStateDirectory) ('Watchdog command failed: ' + $_.Exception.GetType().Name)
        Write-Error ('Autostart command failed (' + $_.Exception.GetType().Name + '). See README; configuration secrets are not printed.')
        exit 1
    }
}
