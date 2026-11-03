Option Strict On
Imports System.IO
Imports System.IO.Compression
Imports System.Linq
Imports System.Security.Cryptography
Imports System.Text
Imports System.Web.Script.Serialization
Imports GoodGoodStudy

Module TestMain
    Private count As Integer
    Sub Main()
        Dim root = Path.Combine(Path.GetTempPath(), "GoodGoodStudy-tests-" & Guid.NewGuid().ToString("N"))
        Directory.CreateDirectory(root)
        Try
            Dim key = ConfigCrypto.GenerateKey()
            Dim json = "{""intervalSeconds"":1,""batchSize"":10}"
            Dim encrypted = ConfigCrypto.Encrypt(json, key)
            Check(ConfigCrypto.Decrypt(encrypted, key) = json, "encrypted round trip")
            Check(ConfigCrypto.Encrypt(json, key) <> encrypted, "fresh random IV")
            Reject(Sub() ConfigCrypto.Decrypt(encrypted, ConfigCrypto.GenerateKey()), "wrong key")
            For Each field In New String() {"iv", "ciphertext", "mac"}
                Dim envelope = New JavaScriptSerializer().Deserialize(Of Dictionary(Of String, Object))(encrypted)
                Dim bytes = Convert.FromBase64String(CStr(envelope(field)))
                bytes(0) = bytes(0) Xor CByte(1)
                envelope(field) = Convert.ToBase64String(bytes)
                Dim tampered = New JavaScriptSerializer().Serialize(envelope)
                Reject(Sub() ConfigCrypto.Decrypt(tampered, key), "reject modified " & field)
            Next
            Reject(Sub() AppConfig.Parse("{""batchSize"":0}"), "reject zero batch size")
            Reject(Sub() AppConfig.Parse("{""intervalSeconds"":0}"), "reject zero interval")
            Reject(Sub() AppConfig.Parse("{""mail"":null}"), "reject null mail")
            Reject(Sub() AppConfig.Parse("{""mail"":{""enabled"":true}}"), "reject incomplete SMTP")
            Reject(Sub() AppConfig.Parse("{""screenshotDirectory"":""relative""}"), "reject relative screenshot path")
            Check(AppConfig.Parse("{}").screenshotDirectory = "", "empty path uses runner fallback")
            Reject(Sub() RemoteConfig.ValidateUrl("http://yifan.im/config.json"), "reject HTTP")
            Reject(Sub() RemoteConfig.ValidateUrl("https://user:password@yifan.im/config.json"), "reject URL credentials")
            Dim profile = ClientProfile.Create()
            Dim messages As New List(Of String)
            Dim loader As New RemoteConfig(profile, Sub(value) messages.Add(value))
            Check(loader.Load(RemoteConfig.DefaultUrl, Function(uri, request, credential) SessionReply(request, json)).intervalSeconds = 1, "authenticated ECDH remote config")
            Reject(Sub() loader.Load(RemoteConfig.DefaultUrl, Function(uri, request, credential) Nothing), "invalid handshake rejected without fallback")
            Check(Directory.GetFiles(root, "*.encrypted.json").Length = 0, "no configuration cache written")
            Using session As New ConfigSession(profile.deviceId), other As New ConfigSession(profile.deviceId)
                Dim first = SessionReply(session.Request, json)
                Dim second = SessionReply(session.Request, json)
                Check(first.serverPublicKey <> second.serverPublicKey AndAlso first.serverNonce <> second.serverNonce, "fresh server handshake")
                Check(session.Decrypt(first).intervalSeconds = 1, "session round trip")
                Reject(Sub() other.Decrypt(first), "response replayed into a different session")
                first.serverNonce = Convert.ToBase64String(New Byte(31) {})
                Reject(Sub() session.Decrypt(first), "handshake nonce tampering")
            End Using
            Dim store As New CaptureStore(Path.Combine(root, "captures"), Path.Combine(root, "pending"))
            For cycle = 1 To 2
                For index = 1 To 9
                    File.WriteAllText(Path.Combine(store.captureDirectory, CaptureStore.UniqueName(".png")), "fake image")
                Next
                Check(store.ArchiveReadyBatches(10) = 0, "no early archive")
                File.WriteAllText(Path.Combine(store.captureDirectory, CaptureStore.UniqueName(".png")), "tenth fake image")
                Check(store.ArchiveReadyBatches(10) = 1, "archive exactly tenth image")
                Check(store.Images().Length = 0, "source removed after durable archive")
            Next
            Dim archives = Directory.GetFiles(store.queueDirectory, "*.zip")
            Check(archives.Length = 2, "unique archive names across batches")
            For Each archive In archives
                Using zip = ZipFile.OpenRead(archive)
                    Check(zip.Entries.Count = 10, "all images preserved in ZIP")
                End Using
            Next
            Dim survivor = Path.Combine(store.captureDirectory, CaptureStore.UniqueName(".png"))
            File.WriteAllText(survivor, "keep me")
            Reject(Sub() store.Archive(New String() {survivor, Path.Combine(root, "missing.png")}), "reject incomplete batch")
            Check(File.Exists(survivor), "failed archive preserves originals")
            Dim keyRoot = Path.Combine(root, "key")
            profile.Save(keyRoot)
            Check(ClientProfile.Load(keyRoot).accessToken = profile.accessToken, "DPAPI credential round trip")
            Check(Not File.ReadAllText(Path.Combine(keyRoot, "device-profile.dpapi")).Contains(profile.accessToken), "credential not stored in plaintext")
            Check(Not File.Exists(Path.Combine(keyRoot, "config-key.dpapi")), "no persistent AES key")
            Console.WriteLine("PASS: " & count.ToString() & " regression checks; no screenshots or email.")
        Finally
            ' This directory is freshly created by this test, never a configured screenshot path.
            Directory.Delete(root, True)
        End Try
    End Sub

    Private Function SessionReply(request As SessionRequest, json As String) As SessionResponse
        Using server As New ECDiffieHellmanCng(256)
            server.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash
            server.HashAlgorithm = CngAlgorithm.Sha256
            Dim point = ConfigSession.ExportPoint(server)
            Dim nonce(31) As Byte
            Using rng = RandomNumberGenerator.Create()
                rng.GetBytes(nonce)
            End Using
            Dim key = ConfigSession.Derive(server, Convert.FromBase64String(request.clientPublicKey), request, point, nonce)
            Try
                Return New SessionResponse With {.version = 2, .keyAgreement = ConfigSession.Protocol,
                    .serverPublicKey = Convert.ToBase64String(point), .serverNonce = Convert.ToBase64String(nonce),
                    .payload = New JavaScriptSerializer().Deserialize(Of EncryptedConfig)(ConfigCrypto.Encrypt(json, key))}
            Finally
                ConfigSession.Wipe(key)
            End Try
        End Using
    End Function

    Private Sub Check(condition As Boolean, description As String)
        If Not condition Then Throw New Exception("FAIL: " & description)
        count += 1
    End Sub

    Private Sub Reject(action As Action, description As String)
        Try
            action()
        Catch ex As Exception
            count += 1
            Return
        End Try
        Throw New Exception("FAIL: expected rejection: " & description)
    End Sub
End Module
