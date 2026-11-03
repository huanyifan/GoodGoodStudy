Option Strict On
Imports System.IO
Imports System.Net
Imports System.Security
Imports System.Text
Imports System.Threading
Imports System.Web.Script.Serialization

Public Class RemoteConfig
    Public Const DefaultUrl As String = "https://yifan.im/tools/goodgoodstudy/config.json"
    Private ReadOnly profile As ClientProfile
    Private ReadOnly log As Action(Of String)

    Public Sub New(credential As ClientProfile, logger As Action(Of String))
        credential.Validate()
        profile = credential
        log = logger
    End Sub

    Public Shared Function ValidateUrl(url As String) As Uri
        Dim result As Uri = Nothing
        If Not Uri.TryCreate(url, UriKind.Absolute, result) OrElse result.Scheme <> Uri.UriSchemeHttps OrElse result.UserInfo <> "" OrElse result.Fragment <> "" Then Throw New ArgumentException("An HTTPS URL without credentials or fragment is required.")
        Return result
    End Function

    Public Function Load(url As String, Optional fetch As Func(Of Uri, SessionRequest, ClientProfile, SessionResponse) = Nothing) As AppConfig
        Dim endpoint = ValidateUrl(url)
        If fetch Is Nothing Then fetch = AddressOf Download
        Using session As New ConfigSession(profile.deviceId)
            Dim result = session.Decrypt(fetch(endpoint, session.Request, profile))
            log("Authenticated HTTPS/ECDH configuration loaded; session keys discarded.")
            Return result
        End Using
    End Function

    Private Shared Function Download(endpoint As Uri, handshake As SessionRequest, profile As ClientProfile) As SessionResponse
        ServicePointManager.SecurityProtocol = ServicePointManager.SecurityProtocol Or SecurityProtocolType.Tls12
        Dim serializer As New JavaScriptSerializer()
        Dim body = Encoding.UTF8.GetBytes(serializer.Serialize(handshake))
        Dim request = DirectCast(WebRequest.Create(endpoint), HttpWebRequest)
        request.Method = "POST"
        request.ServicePoint.Expect100Continue = False
        request.AllowAutoRedirect = False
        request.Timeout = 15000
        request.ReadWriteTimeout = 15000
        request.UserAgent = "GoodGoodStudy/3"
        request.ContentType = "application/json"
        request.Headers(HttpRequestHeader.Authorization) = "Bearer " & profile.accessToken
        request.ContentLength = body.Length
        request.AutomaticDecompression = DecompressionMethods.None
        Try
            Using deadline As New Timer(Sub(state) request.Abort(), Nothing, 15000, Timeout.Infinite)
                Using output = request.GetRequestStream()
                    output.Write(body, 0, body.Length)
                End Using
                Using response = DirectCast(request.GetResponse(), HttpWebResponse)
                    If response.StatusCode <> HttpStatusCode.OK OrElse response.ContentLength > 131072 Then Throw New InvalidDataException("Invalid HTTP response.")
                    Using input = response.GetResponseStream(), output As New MemoryStream()
                        Dim buffer(4095) As Byte
                        Do
                            Dim count = input.Read(buffer, 0, buffer.Length)
                            If count = 0 Then Exit Do
                            If output.Length + count > 131072 Then Throw New InvalidDataException("Configuration too large.")
                            output.Write(buffer, 0, count)
                        Loop
                        Return serializer.Deserialize(Of SessionResponse)(New UTF8Encoding(False, True).GetString(output.ToArray()))
                    End Using
                End Using
            End Using
        Catch ex As WebException
            Dim response = TryCast(ex.Response, HttpWebResponse)
            If response IsNot Nothing Then
                Dim denied = response.StatusCode = HttpStatusCode.Unauthorized OrElse response.StatusCode = HttpStatusCode.Forbidden
                response.Dispose()
                If denied Then Throw New SecurityException("Device access denied.")
            End If
            Throw
        End Try
    End Function
End Class
