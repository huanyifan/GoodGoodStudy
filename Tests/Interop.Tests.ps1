$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Web.Extensions
[Reflection.Assembly]::LoadFrom((Join-Path $PSScriptRoot '..\bin\Release\GoodGoodStudy.exe')) | Out-Null
$serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
$utf8 = New-Object Text.UTF8Encoding($false)
$root = Join-Path $env:TEMP ('GoodGoodStudy-interop-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
$python = $null
$script:checks = 0
function Check([bool]$Condition,[string]$Description) {
    if (-not $Condition) { throw ('FAIL: ' + $Description) }
    $script:checks++
}
function Request-Json([string]$Method, [string]$Url, [string]$Body, [string]$Token) {
    [Console]::WriteLine('Interop HTTP: ' + $Method + '; credential present=' + [bool]$Token)
    $request = [Net.HttpWebRequest]::Create($Url)
    $request.Method = $Method
    $request.Timeout = 2000
    $request.ReadWriteTimeout = 2000
    $request.Proxy = $null
    $request.ServicePoint.Expect100Continue = $false
    if ($Token) { $request.Headers['Authorization'] = 'Bearer ' + $Token }
    if ($Body) {
        $bytes = $utf8.GetBytes($Body)
        $request.ContentType = 'application/json'
        $request.ContentLength = $bytes.Length
        $output = $request.GetRequestStream()
        try { $output.Write($bytes,0,$bytes.Length) } finally { $output.Dispose() }
    }
    $response = $request.GetResponse()
    try {
        $reader = New-Object IO.StreamReader($response.GetResponseStream())
        try { return $reader.ReadToEnd() } finally { $reader.Dispose() }
    } finally { $response.Dispose() }
}
function Check-Unauthorized([string]$Method,[string]$Url,[string]$Body,[string]$Token) {
    try { Request-Json $Method $Url $Body $Token | Out-Null }
    catch {
        if ($_.Exception.InnerException -and $_.Exception.InnerException.Response) { $response = $_.Exception.InnerException.Response }
        elseif ($_.Exception.Response) { $response = $_.Exception.Response } else { throw }
        try { Check ([int]$response.StatusCode -eq 401) 'unauthorized request rejected'; return }
        finally { $response.Dispose() }
    }
    throw 'FAIL: expected HTTP 401'
}
try {
    $credential = [GoodGoodStudy.ClientProfile]::Create()
    $profilePath = Join-Path $root 'test-profile.json'
    [IO.File]::WriteAllText($profilePath,$serializer.Serialize($credential),$utf8)
    [IO.File]::WriteAllText((Join-Path $root 'config.json'),'{"intervalSeconds":42,"mail":{"enabled":false}}',$utf8)
    & python -B (Join-Path $PSScriptRoot '..\server\config_admin.py') --profile $profilePath --devices (Join-Path $root 'devices.json')
    if ($LASTEXITCODE -ne 0) { throw 'Test enrollment failed' }
    $listener = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback,0)
    $listener.Start()
    $port = $listener.LocalEndpoint.Port
    $listener.Stop()
    $server = (Resolve-Path (Join-Path $PSScriptRoot '..\server\config_server.py')).Path
    $python = Start-Process -FilePath (Get-Command python).Source -ArgumentList @('-B',('"' + $server + '"'),'--bind','127.0.0.1','--port',$port,'--data-dir',('"' + $root + '"')) -WindowStyle Hidden -PassThru -RedirectStandardError (Join-Path $root 'stderr.log')
    $url = 'http://127.0.0.1:' + $port + '/tools/goodgoodstudy/config.json'
    $ready = $false
    for ($i=0; $i -lt 40; $i++) {
        $probe = New-Object Net.Sockets.TcpClient
        try { $probe.Connect('127.0.0.1',$port); $ready=$true; break }
        catch { Start-Sleep -Milliseconds 150 }
        finally { $probe.Dispose() }
    }
    if (-not $ready) { throw 'Test server did not start' }
    Write-Output 'Interop: testing unauthenticated GET/POST.'
    Check-Unauthorized 'GET' $url $null $null
    Check-Unauthorized 'POST' $url '{}' $null
    $session = New-Object GoodGoodStudy.ConfigSession($credential.deviceId)
    $other = New-Object GoodGoodStudy.ConfigSession($credential.deviceId)
    try {
        $body = $serializer.Serialize($session.Request)
        Check-Unauthorized 'POST' $url $body ([Convert]::ToBase64String((New-Object byte[] 32)))
        Write-Output 'Interop: testing authenticated ECDH response.'
        $replyText = Request-Json 'POST' $url $body $credential.accessToken
        $response = $serializer.Deserialize($replyText,[GoodGoodStudy.SessionResponse])
        Check ($session.Decrypt($response).intervalSeconds -eq 42) '.NET CNG and Python ECDH/HKDF/AES interoperability'
        $next = $serializer.Deserialize((Request-Json 'POST' $url $body $credential.accessToken),[GoodGoodStudy.SessionResponse])
        Check ($next.serverPublicKey -ne $response.serverPublicKey) 'fresh ephemeral server public key'
        Check ($next.serverNonce -ne $response.serverNonce) 'fresh server nonce'
        Check ($next.payload.ciphertext -ne $response.payload.ciphertext) 'fresh ciphertext for same configuration'
        Check (-not $replyText.Contains('intervalSeconds')) 'configuration not plaintext on wire'
        Check (-not $replyText.Contains($credential.accessToken)) 'access credential not echoed'
        $rejected = $false
        try { $other.Decrypt($response) | Out-Null } catch { $rejected=$true }
        Check $rejected 'cross-session replay rejected'
        $tag = [Convert]::FromBase64String($response.payload.mac)
        $tag[0] = $tag[0] -bxor 1
        $response.payload.mac = [Convert]::ToBase64String($tag)
        $rejected = $false
        try { $session.Decrypt($response) | Out-Null } catch { $rejected=$true }
        Check $rejected 'tampered response rejected'
        Check (-not [IO.File]::ReadAllText((Join-Path $root 'devices.json')).Contains($credential.accessToken)) 'server stores credential hash only'
        [IO.File]::WriteAllText((Join-Path $root 'devices.json'),'{}',$utf8)
        Check-Unauthorized 'POST' $url $body $credential.accessToken
    } finally { $session.Dispose(); $other.Dispose() }
    Write-Output ('PASS: ' + $script:checks + ' Python/.NET protocol checks; test-only data and loopback server.')
} catch {
    [Console]::WriteLine($_.Exception.GetBaseException().ToString())
    if ($python -and -not $python.HasExited) { Stop-Process -Id $python.Id; $python.WaitForExit() }
    $diagnostic = Join-Path $root 'stderr.log'
    if (Test-Path -LiteralPath $diagnostic) {
        Get-Content -LiteralPath $diagnostic | Write-Output
    }
    throw
} finally {
    if ($python -and -not $python.HasExited) { Stop-Process -Id $python.Id -ErrorAction SilentlyContinue; $python.WaitForExit() }
    $absolute = [IO.Path]::GetFullPath($root)
    $prefix = [IO.Path]::GetFullPath((Join-Path $env:TEMP 'GoodGoodStudy-interop-'))
    if (-not $absolute.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) { throw 'Unexpected test cleanup path' }
    Remove-Item -LiteralPath $absolute -Recurse -Force
}
