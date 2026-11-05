param(
 [Parameter(Mandatory=$true)][string]$ExecutablePath,
 [ValidateRange(1,30)][int]$Attempts=20
)
$ErrorActionPreference='Stop'
$build=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'GoodGoodStudyBuilds\3.2.2'
$base=Join-Path $build ('stability-tests\'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'))
[IO.Directory]::CreateDirectory($base)|Out-Null
$results=@()
for($i=1;$i -le $Attempts;$i++){
 $run=Join-Path $base ('run-'+$i)
 $state=Join-Path $run 'GoodGoodStudy'
 [IO.Directory]::CreateDirectory($state)|Out-Null
 Copy-Item -LiteralPath (Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'GoodGoodStudy\device-profile.dpapi') -Destination (Join-Path $state 'device-profile.dpapi')
 $info=New-Object Diagnostics.ProcessStartInfo
 $info.FileName=[IO.Path]::GetFullPath($ExecutablePath)
 $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
 $info.EnvironmentVariables['LOCALAPPDATA']=$run
 $p=[Diagnostics.Process]::Start($info)
 $out=$p.StandardOutput.ReadToEndAsync();$err=$p.StandardError.ReadToEndAsync()
 $running=$false
 $failure=$null
 try {
  $deadline=[DateTime]::UtcNow.AddSeconds(60)
  while([DateTime]::UtcNow -lt $deadline -and -not $p.HasExited){
   $log=Join-Path $state 'runtime.log'
   if((Test-Path -LiteralPath $log) -and (Get-Content -LiteralPath $log -Raw).Contains('Rust capture started.')){$running=$true;break}
   Start-Sleep -Milliseconds 200
  }
  if(-not $running){throw 'Did not reach ready state'}
 }catch{$failure=$_.Exception.Message}
 finally{
  if(-not $p.HasExited){
   if($running){
    $event=[Threading.EventWaitHandle]::OpenExisting('Local\GoodGoodStudyStop-'+[Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
    try{$event.Set()|Out-Null}finally{$event.Dispose()}
   }
   if(-not $p.WaitForExit(20000)){$p.Kill();$p.WaitForExit();$failure='Stop timed out'}
  }
  $text=$err.GetAwaiter().GetResult()
  [IO.File]::WriteAllText((Join-Path $run 'stderr.log'),$text)
  [IO.File]::WriteAllText((Join-Path $run 'stdout.log'),$out.GetAwaiter().GetResult())
  $record=[pscustomobject]@{attempt=$i;ready=$running;exitCode=$p.ExitCode;failure=$failure;retryMessages=([regex]::Matches($text,'Configuration retry:')).Count}
  $results+=$record
  $record|ConvertTo-Json -Compress
  $p.Dispose()
 }
 Start-Sleep -Seconds 1
}
$summary=[ordered]@{attempts=$Attempts;passed=@($results|Where-Object {$_.ready -and $_.exitCode -eq 0 -and -not $_.failure}).Count;results=$results;directory=$base}
$summary|ConvertTo-Json -Depth 5|Set-Content (Join-Path $base 'startup-test.json') -Encoding utf8
Write-Output ('Startup report: '+(Join-Path $base 'startup-test.json'))
if($summary.passed -ne $Attempts){throw 'Some startup attempts failed; see report'}
