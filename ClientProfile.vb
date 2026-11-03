Option Strict On
Imports System.IO
Imports System.Security.AccessControl
Imports System.Security.Cryptography
Imports System.Security.Principal
Imports System.Text
Imports System.Web.Script.Serialization

Public Class ClientProfile
    Public Property deviceId As String
    Public Property accessToken As String
    Private Shared ReadOnly Entropy As Byte() = Encoding.UTF8.GetBytes("GoodGoodStudy.DeviceCredential.v2")

    Public Sub Validate()
        Dim id As Guid
        If Not Guid.TryParseExact(deviceId, "D", id) Then Throw New InvalidDataException("Invalid device ID.")
        Dim token = Convert.FromBase64String(accessToken)
        Try
            If token.Length <> 32 OrElse Convert.ToBase64String(token) <> accessToken Then Throw New InvalidDataException("Invalid device credential.")
        Finally
            ConfigSession.Wipe(token)
        End Try
    End Sub

    Public Shared Function Create() As ClientProfile
        Dim token(31) As Byte
        Using rng = RandomNumberGenerator.Create()
            rng.GetBytes(token)
        End Using
        Try
            Return New ClientProfile With {.deviceId = Guid.NewGuid().ToString("D"), .accessToken = Convert.ToBase64String(token)}
        Finally
            ConfigSession.Wipe(token)
        End Try
    End Function

    Public Shared Function Parse(json As String) As ClientProfile
        If json Is Nothing OrElse json.Length > 4096 Then Throw New InvalidDataException("Invalid profile size.")
        Dim result = New JavaScriptSerializer().Deserialize(Of ClientProfile)(json)
        If result Is Nothing Then Throw New InvalidDataException("Missing profile.")
        result.Validate()
        Return result
    End Function

    Public Shared Function Load(directory As String) As ClientProfile
        Dim bytes = ProtectedData.Unprotect(File.ReadAllBytes(Path.Combine(directory, "device-profile.dpapi")), Entropy, DataProtectionScope.CurrentUser)
        Try
            Return Parse(Encoding.UTF8.GetString(bytes))
        Finally
            ConfigSession.Wipe(bytes)
        End Try
    End Function

    Public Sub Save(directory As String)
        Validate()
        System.IO.Directory.CreateDirectory(directory)
        Dim bytes = Encoding.UTF8.GetBytes(New JavaScriptSerializer().Serialize(Me))
        Try
            AtomicFile.WriteBytes(Path.Combine(directory, "device-profile.dpapi"), ProtectedData.Protect(bytes, Entropy, DataProtectionScope.CurrentUser))
        Finally
            ConfigSession.Wipe(bytes)
        End Try
    End Sub

    Public Shared Sub WritePrivateFile(path As String, content As String)
        Dim security As New FileSecurity()
        security.SetAccessRuleProtection(True, False)
        security.AddAccessRule(New FileSystemAccessRule(WindowsIdentity.GetCurrent().User, FileSystemRights.FullControl, AccessControlType.Allow))
        Using output As New FileStream(path, FileMode.CreateNew, FileSystemRights.Write, FileShare.None, 4096, FileOptions.None, security)
            Dim bytes = Encoding.UTF8.GetBytes(content)
            Try
                output.Write(bytes, 0, bytes.Length)
            Finally
                ConfigSession.Wipe(bytes)
            End Try
        End Using
    End Sub
End Class
