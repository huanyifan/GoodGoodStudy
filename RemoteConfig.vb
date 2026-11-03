Option Strict On
Imports System.IO
Imports System.Net
Imports System.Security.Cryptography
Imports System.Text
Imports System.Threading

Public Class RemoteConfig
    Public Const DefaultUrl As String = "https://yifan.im/tools/goodgoodstudy/config.json"
    Private ReadOnly stateDirectory As String
    Private ReadOnly key As Byte()
    Private ReadOnly log As Action(Of String)

    Public Sub New(directory As String, masterKey As Byte(), logger As Action(Of String))
        stateDirectory = directory
        key = masterKey
        log = logger
    End Sub

    Public Shared Function ValidateUrl(url As String) As Uri
        Dim result As Uri = Nothing
        If Not Uri.TryCreate(url, UriKind.Absolute, result) OrElse result.Scheme <> Uri.UriSchemeHttps OrElse result.UserInfo <> "" OrElse result.Fragment <> "" Then Throw New ArgumentException("An HTTPS URL without credentials or fragment is required.")
        Return result
    End Function

    Public Function Load(url As String, Optional fetch As Func(Of Uri, String) = Nothing) As AppConfig
        Dim endpoint = ValidateUrl(url)
        Directory.CreateDirectory(stateDirectory)
        Dim cacheName As String
        Using hash = SHA256.Create()
            cacheName = BitConverter.ToString(hash.ComputeHash(Encoding.UTF8.GetBytes(endpoint.AbsoluteUri))).Replace("-", "") & ".encrypted.json"
        End Using
        Dim cachePath = Path.Combine(stateDirectory, cacheName)
        If fetch Is Nothing Then fetch = AddressOf Download
        Try
            Dim encrypted = fetch(endpoint)
            Dim config = AppConfig.Parse(ConfigCrypto.Decrypt(encrypted, key))
            Try
                AtomicFile.WriteBytes(cachePath, Encoding.UTF8.GetBytes(encrypted))
            Catch ex As Exception
                log("Configuration loaded; cache write failed: " & ex.GetType().Name)
            End Try
            log("Validated HTTPS configuration loaded.")
            Return config
        Catch ex As Exception
            log("Remote configuration unavailable or invalid: " & ex.GetType().Name)
        End Try
        If Not File.Exists(cachePath) OrElse New FileInfo(cachePath).Length > 131072 Then Throw New InvalidDataException("No valid cached configuration.")
        Dim cached = AppConfig.Parse(ConfigCrypto.Decrypt(File.ReadAllText(cachePath, Encoding.UTF8), key))
        log("Using last validated encrypted configuration cache.")
        Return cached
    End Function

    Private Shared Function Download(endpoint As Uri) As String
        ServicePointManager.SecurityProtocol = ServicePointManager.SecurityProtocol Or SecurityProtocolType.Tls12
        Dim request = DirectCast(WebRequest.Create(endpoint), HttpWebRequest)
        request.AllowAutoRedirect = False
        request.Timeout = 15000
        request.ReadWriteTimeout = 15000
        request.UserAgent = "GoodGoodStudy/2"
        request.AutomaticDecompression = DecompressionMethods.None
        ' Abort bounds the whole download, including a server that slowly drips bytes.
        Using deadline As New Timer(Sub(state) request.Abort(), Nothing, 15000, Timeout.Infinite),
              response = DirectCast(request.GetResponse(), HttpWebResponse)
            If response.StatusCode <> HttpStatusCode.OK OrElse response.ContentLength > 131072 Then Throw New InvalidDataException("Invalid HTTP response.")
            Using input = response.GetResponseStream(), output As New MemoryStream()
                Dim buffer(4095) As Byte
                Do
                    Dim count = input.Read(buffer, 0, buffer.Length)
                    If count = 0 Then Exit Do
                    If output.Length + count > 131072 Then Throw New InvalidDataException("Configuration too large.")
                    output.Write(buffer, 0, count)
                Loop
                Return New UTF8Encoding(False, True).GetString(output.ToArray())
            End Using
        End Using
    End Function
End Class
