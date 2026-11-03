Option Strict On
Imports System.IO
Imports System.Security.Cryptography
Imports System.Text

Public Class SessionRequest
    Public Property version As Integer = 2
    Public Property deviceId As String
    Public Property clientPublicKey As String
    Public Property clientNonce As String
End Class

Public Class SessionResponse
    Public Property version As Integer
    Public Property keyAgreement As String
    Public Property serverPublicKey As String
    Public Property serverNonce As String
    Public Property payload As EncryptedConfig
End Class

Public NotInheritable Class ConfigSession
    Implements IDisposable
    Public Const Protocol As String = "GoodGoodStudy.Config.ECDH-P256.HKDF-SHA256.v2"
    Public ReadOnly Request As SessionRequest
    Private ReadOnly exchange As ECDiffieHellmanCng

    Public Sub New(deviceId As String)
        exchange = New ECDiffieHellmanCng(256)
        If Not exchange.Key.IsEphemeral Then Throw New CryptographicException("Ephemeral ECDH key required.")
        exchange.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash
        exchange.HashAlgorithm = CngAlgorithm.Sha256
        Dim nonce(31) As Byte
        Using rng = RandomNumberGenerator.Create()
            rng.GetBytes(nonce)
        End Using
        Request = New SessionRequest With {.deviceId = deviceId,
            .clientPublicKey = Convert.ToBase64String(ExportPoint(exchange)),
            .clientNonce = Convert.ToBase64String(nonce)}
    End Sub

    Public Shared Function ExportPoint(value As ECDiffieHellmanCng) As Byte()
        Dim blob = value.Key.Export(CngKeyBlobFormat.EccPublicBlob)
        If blob.Length <> 72 OrElse BitConverter.ToUInt32(blob, 0) <> &H314B4345UI Then Throw New CryptographicException("Unexpected curve.")
        Dim point(64) As Byte
        point(0) = 4
        Buffer.BlockCopy(blob, 8, point, 1, 64)
        Return point
    End Function

    Public Shared Function ImportPoint(point As Byte()) As CngKey
        If point.Length <> 65 OrElse point(0) <> 4 Then Throw New CryptographicException("Invalid P-256 point.")
        Dim blob(71) As Byte
        Buffer.BlockCopy(BitConverter.GetBytes(&H314B4345UI), 0, blob, 0, 4)
        Buffer.BlockCopy(BitConverter.GetBytes(32), 0, blob, 4, 4)
        Buffer.BlockCopy(point, 1, blob, 8, 64)
        Return CngKey.Import(blob, CngKeyBlobFormat.EccPublicBlob)
    End Function

    Public Shared Function Derive(exchange As ECDiffieHellmanCng, otherPublic As Byte(), request As SessionRequest, serverPublic As Byte(), serverNonce As Byte()) As Byte()
        Dim clientNonce = Convert.FromBase64String(request.clientNonce)
        Dim clientPublic = Convert.FromBase64String(request.clientPublicKey)
        If clientNonce.Length <> 32 OrElse serverNonce.Length <> 32 OrElse clientPublic.Length <> 65 Then Throw New CryptographicException("Invalid handshake.")
        Dim hashedSecret As Byte() = Nothing
        Dim prk As Byte() = Nothing
        Dim first As Byte() = Nothing
        Dim second As Byte() = Nothing
        Try
            Using other = ImportPoint(otherPublic)
                hashedSecret = exchange.DeriveKeyMaterial(other)
            End Using
            Using salt As New MemoryStream(), info As New MemoryStream()
                salt.Write(clientNonce, 0, clientNonce.Length)
                salt.Write(serverNonce, 0, serverNonce.Length)
                Dim context = Encoding.UTF8.GetBytes(Protocol & "|" & request.deviceId & "|")
                info.Write(context, 0, context.Length)
                info.Write(clientPublic, 0, clientPublic.Length)
                info.Write(serverPublic, 0, serverPublic.Length)
                info.Write(clientNonce, 0, clientNonce.Length)
                info.Write(serverNonce, 0, serverNonce.Length)
                Using extract As New HMACSHA256(salt.ToArray())
                    prk = extract.ComputeHash(hashedSecret)
                End Using
                Using expand As New HMACSHA256(prk)
                    Dim contextBytes = info.ToArray()
                    first = expand.ComputeHash(JoinBytes(contextBytes, New Byte() {1}))
                    second = expand.ComputeHash(JoinBytes(first, contextBytes, New Byte() {2}))
                    Return JoinBytes(first, second)
                End Using
            End Using
        Finally
            Wipe(hashedSecret)
            Wipe(prk)
            Wipe(first)
            Wipe(second)
        End Try
    End Function

    Private Shared Function JoinBytes(ParamArray arrays As Byte()()) As Byte()
        Using output As New MemoryStream()
            For Each bytes In arrays
                output.Write(bytes, 0, bytes.Length)
            Next
            Return output.ToArray()
        End Using
    End Function

    Public Function Decrypt(response As SessionResponse) As AppConfig
        If response Is Nothing OrElse response.version <> 2 OrElse response.keyAgreement <> Protocol OrElse response.payload Is Nothing Then Throw New CryptographicException("Invalid handshake response.")
        Dim serverPublic = Convert.FromBase64String(response.serverPublicKey)
        Dim serverNonce = Convert.FromBase64String(response.serverNonce)
        Dim key = Derive(exchange, serverPublic, Request, serverPublic, serverNonce)
        Try
            Dim envelope = New System.Web.Script.Serialization.JavaScriptSerializer().Serialize(response.payload)
            Return AppConfig.Parse(ConfigCrypto.Decrypt(envelope, key))
        Finally
            Wipe(key)
        End Try
    End Function

    Public Shared Sub Wipe(bytes As Byte())
        If bytes IsNot Nothing Then Array.Clear(bytes, 0, bytes.Length)
    End Sub

    Public Sub Dispose() Implements IDisposable.Dispose
        exchange.Dispose()
    End Sub
End Class
