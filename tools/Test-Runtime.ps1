param([Parameter(Mandatory=$true)][string]$ExecutablePath)
$ErrorActionPreference='Stop'
$build=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'GoodGoodStudyBuilds\3.2.1'
$testBase=Join-Path $build ('runtime-tests\'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'))
$testState=Join-Path $testBase 'GoodGoodStudy'
[IO.Directory]::CreateDirectory($testState)|Out-Null
Copy-Item -LiteralPath (Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'GoodGoodStudy\device-profile.dpapi') -Destination (Join-Path $testState 'device-profile.dpapi')
$info=New-Object Diagnostics.ProcessStartInfo
$info.FileName=[IO.Path]::GetFullPath($ExecutablePath)
$info.UseShellExecute=$false
$info.CreateNoWindow=$true
$info.WindowStyle=[Diagnostics.ProcessWindowStyle]::Hidden
$info.RedirectStandardOutput=$true
$info.RedirectStandardError=$true
$info.EnvironmentVariables['LOCALAPPDATA']=$testBase
# This integration test deliberately exercises one capture, never a mail batch.
$info.Arguments='--debug-config'
$preflight=[Diagnostics.Process]::Start($info)
try {
 $preOut=$preflight.StandardOutput.ReadToEndAsync()
 $preErr=$preflight.StandardError.ReadToEndAsync()
 if(-not $preflight.WaitForExit(60000)){$preflight.Kill();throw 'Configuration preflight timed out'}
 if($preflight.ExitCode -ne 0){throw 'Configuration preflight failed; runtime test not started'}
 $configEvent=@($preOut.GetAwaiter().GetResult() -split '\r?\n' | Where-Object {$_ -like '{*'} | ForEach-Object {$_|ConvertFrom-Json} | Where-Object step -eq '09.aes_decrypt_and_validate')
 if($configEvent.Count -ne 1){throw 'Preflight configuration summary missing'}
 $config=$configEvent[0].details
 if($config.intervalSeconds -ne 120 -or $config.batchSize -lt 2 -or -not $config.usesDefaultScreenshotDirectory){throw 'Runtime test requires a 120-second interval, batch size >=2 and the default isolated capture directory'}
}finally{$preflight.Dispose()}
$info.Arguments=''
$process=New-Object Diagnostics.Process
$process.StartInfo=$info
$started=[DateTime]::UtcNow
$summary=[ordered]@{startedUtc=$started.ToString('O');executable=$info.FileName;testDirectory=$testBase;normalRuntime=$true;isolatedState=$true;screenshotValidated=$false;duplicateInstanceRejected=$false;gracefulExit=$false;mailQueueFiles=0}
try {
 if(-not $process.Start()){throw 'Rust process did not start'}
 $stdout=$process.StandardOutput.ReadToEndAsync()
 $stderr=$process.StandardError.ReadToEndAsync()
 Write-Output ('Rust runtime started: PID='+$process.Id+'; test directory='+$testBase)
 Start-Sleep -Seconds 4
 if($process.HasExited){throw ('Rust exited early: '+$process.ExitCode)}
 $second=New-Object Diagnostics.Process
 $second.StartInfo=$info
 try {
  $second.Start()|Out-Null
  $secondOut=$second.StandardOutput.ReadToEndAsync()
  $secondErr=$second.StandardError.ReadToEndAsync()
  if(-not $second.WaitForExit(5000)){ $second.Kill();throw 'Duplicate instance was not rejected' }
  if($second.ExitCode -ne 1){throw 'Unexpected duplicate instance exit code'}
  $summary.duplicateInstanceRejected=$true
  Write-Output 'Duplicate-instance protection passed; waiting for first scheduled screenshot (120-second interval).'
 } finally { $second.Dispose() }
 $captures=Join-Path $testState 'captures'
 $limit=$started.AddSeconds(190)
 $image=$null
 while([DateTime]::UtcNow -lt $limit){
  if($process.HasExited){throw ('Rust stopped before capture: '+$process.ExitCode)}
  if(Test-Path -LiteralPath $captures){$image=Get-ChildItem -LiteralPath $captures -File -Filter '*.png'|Select-Object -First 1}
  if($image){break}
  Start-Sleep -Seconds 2
 }
 if(-not $image){throw 'No screenshot arrived within 190 seconds'}
 Start-Sleep -Seconds 1
 $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
 $event=[Threading.EventWaitHandle]::OpenExisting('Local\GoodGoodStudyStop-'+$sid)
 try {$event.Set()|Out-Null}finally{$event.Dispose()}
 if(-not $process.WaitForExit(20000)){throw 'Graceful stop timed out'}
 if($process.ExitCode -ne 0){throw 'Rust runtime failed during shutdown'}
 $summary.gracefulExit=$true
 $summary.exitCode=$process.ExitCode
 Add-Type -AssemblyName System.Drawing
 $bitmap=[Drawing.Bitmap]::new($image.FullName)
 try {
  $pixel=$bitmap.GetPixel([int]($bitmap.Width/2),[int]($bitmap.Height/2))
  if($bitmap.Width -le 0 -or $bitmap.Height -le 0){throw 'PNG dimensions invalid'}
  $summary.screenshot=[ordered]@{file=$image.FullName;width=$bitmap.Width;height=$bitmap.Height;bytes=$image.Length;decoded=$true}
 }finally{$bitmap.Dispose()}
 $summary.screenshotValidated=$true
 $summary.mailQueueFiles=@(Get-ChildItem -LiteralPath (Join-Path $testState 'pending') -File).Count
 if($summary.mailQueueFiles -ne 0){throw 'Unexpected mail queue file during runtime test'}
 $summary.passed=$true
} catch {
 $summary.passed=$false
 $summary.failure=$_.Exception.Message
 throw
} finally {
 if($process.Id -and -not $process.HasExited){
  $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  try { $stop=[Threading.EventWaitHandle]::OpenExisting('Local\GoodGoodStudyStop-'+$sid);try{$stop.Set()|Out-Null}finally{$stop.Dispose()} }catch{}
  if(-not $process.WaitForExit(20000)){$process.Kill();$process.WaitForExit(5000)|Out-Null}
 }
 if($stdout){[IO.File]::WriteAllText((Join-Path $testBase 'stdout.log'),$stdout.GetAwaiter().GetResult())}
 if($stderr){[IO.File]::WriteAllText((Join-Path $testBase 'stderr.log'),$stderr.GetAwaiter().GetResult())}
 $summary.durationSeconds=[math]::Round(([DateTime]::UtcNow-$started).TotalSeconds,1)
 $summary.finishedUtc=[DateTime]::UtcNow.ToString('O')
 $summary|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $testBase 'runtime-test.json') -Encoding utf8
 $summary|ConvertTo-Json -Depth 5
 $process.Dispose()
}
