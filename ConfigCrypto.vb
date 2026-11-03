Option Strict On
Imports System.IO
Imports System.Security.Cryptography
Imports System.Text
Imports System.Web.Script.Serialization

Public Class EncryptedConfig
    Public Property version As Integer
    Public Property algorithm As String
    Public Property iv As String
    Public Property ciphertext As String
    Public Property mac As String
End Class

Public NotInheritable Class ConfigCrypto
    Public Const Algorithm As String = "AES-256-CBC+HMAC-SHA256"

    Public Shared Function GenerateKey() As Byte()
        Dim result(63) As Byte
        Using rng = RandomNumberGenerator.Create()
            rng.GetBytes(result)
        End Using
        Return result
    End Function

    Private Shared Sub ValidateKey(key As Byte())
        If key Is Nothing OrElse key.Length <> 64 Then Throw New CryptographicException("A 64-byte key is required.")
    End Sub

    Private Shared Function Part(key As Byte(), offset As Integer) As Byte()
        Dim result(31) As Byte
        Buffer.BlockCopy(key, offset, result, 0, 32)
        Return result
    End Function

    Private Shared Function Authenticate(key As Byte(), iv As Byte(), ciphertext As Byte()) As Byte()
        Using data As New MemoryStream()
            Dim prefix = Encoding.ASCII.GetBytes("GoodGoodStudy.Config.v1|" & Algorithm & "|")
            data.Write(prefix, 0, prefix.Length)
            data.Write(iv, 0, iv.Length)
            data.Write(ciphertext, 0, ciphertext.Length)
            Using hmac As New HMACSHA256(Part(key, 32))
                Return hmac.ComputeHash(data.ToArray())
            End Using
        End Using
    End Function

    Public Shared Function Encrypt(json As String, key As Byte()) As String
        ValidateKey(key)
        AppConfig.Parse(json)
        Using aes = System.Security.Cryptography.Aes.Create()
            aes.Key = Part(key, 0)
            aes.Mode = CipherMode.CBC
            aes.Padding = PaddingMode.PKCS7
            aes.GenerateIV()
            Dim plain = Encoding.UTF8.GetBytes(json)
            Dim ciphertext As Byte()
            Using transform = aes.CreateEncryptor()
                ciphertext = transform.TransformFinalBlock(plain, 0, plain.Length)
            End Using
            Return New JavaScriptSerializer().Serialize(New EncryptedConfig With {
                .version = 1, .algorithm = Algorithm, .iv = Convert.ToBase64String(aes.IV),
                .ciphertext = Convert.ToBase64String(ciphertext),
                .mac = Convert.ToBase64String(Authenticate(key, aes.IV, ciphertext))})
        End Using
    End Function

    Public Shared Function Decrypt(encrypted As String, key As Byte()) As String
        ValidateKey(key)
        If String.IsNullOrWhiteSpace(encrypted) OrElse encrypted.Length > 131072 Then Throw New CryptographicException("Invalid envelope size.")
        Dim envelope = New JavaScriptSerializer().Deserialize(Of EncryptedConfig)(encrypted)
        If envelope Is Nothing OrElse envelope.version <> 1 OrElse envelope.algorithm <> Algorithm Then Throw New CryptographicException("Unsupported envelope.")
        Dim iv = Convert.FromBase64String(envelope.iv)
        Dim ciphertext = Convert.FromBase64String(envelope.ciphertext)
        Dim mac = Convert.FromBase64String(envelope.mac)
        If iv.Length <> 16 OrElse mac.Length <> 32 OrElse ciphertext.Length = 0 OrElse ciphertext.Length Mod 16 <> 0 Then Throw New CryptographicException("Invalid envelope.")
        Dim expected = Authenticate(key, iv, ciphertext)
        Dim difference As Integer = 0
        For index = 0 To expected.Length - 1
            difference = difference Or (CInt(expected(index)) Xor CInt(mac(index)))
        Next
        If difference <> 0 Then Throw New CryptographicException("Authentication failed.")
        Using aes = System.Security.Cryptography.Aes.Create()
            aes.Key = Part(key, 0)
            aes.IV = iv
            aes.Mode = CipherMode.CBC
            aes.Padding = PaddingMode.PKCS7
            Using transform = aes.CreateDecryptor()
                Return New UTF8Encoding(False, True).GetString(transform.TransformFinalBlock(ciphertext, 0, ciphertext.Length))
            End Using
        End Using
    End Function

End Class

Public NotInheritable Class AtomicFile
    Public Shared Sub WriteBytes(path As String, content As Byte())
        Dim temporary = path & "." & Guid.NewGuid().ToString("N") & ".tmp"
        Try
            File.WriteAllBytes(temporary, content)
            If File.Exists(path) Then
                File.Replace(temporary, path, Nothing)
            Else
                File.Move(temporary, path)
            End If
        Finally
            If File.Exists(temporary) Then File.Delete(temporary)
        End Try
    End Sub
End Class
