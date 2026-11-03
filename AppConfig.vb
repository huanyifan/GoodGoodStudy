Option Strict On
Imports System.IO
Imports System.Net.Mail
Imports System.Web.Script.Serialization

Public Class AppConfig
    Public Property intervalSeconds As Integer = 180
    Public Property batchSize As Integer = 10
    Public Property screenshotDirectory As String = ""
    Public Property retentionDays As Integer = 7
    Public Property maxStorageMB As Integer = 512
    Public Property mail As New MailConfig()

    Public Shared Function Parse(json As String) As AppConfig
        If String.IsNullOrWhiteSpace(json) OrElse json.Length > 65536 OrElse Not json.TrimStart().StartsWith("{", StringComparison.Ordinal) Then Throw New InvalidDataException("Invalid configuration.")
        Dim result = New JavaScriptSerializer().Deserialize(Of AppConfig)(json)
        If result Is Nothing Then Throw New InvalidDataException("Missing configuration.")
        result.Validate()
        Return result
    End Function

    Public Sub Validate()
        If intervalSeconds < 1 OrElse intervalSeconds > 86400 Then Throw New InvalidDataException("intervalSeconds must be 1..86400.")
        If batchSize < 1 OrElse batchSize > 100 Then Throw New InvalidDataException("batchSize must be 1..100.")
        If retentionDays < 1 OrElse retentionDays > 365 Then Throw New InvalidDataException("Invalid retentionDays.")
        If maxStorageMB < 16 OrElse maxStorageMB > 8192 Then Throw New InvalidDataException("Invalid maxStorageMB.")
        If mail Is Nothing Then Throw New InvalidDataException("Missing mail configuration.")
        If Not String.IsNullOrWhiteSpace(screenshotDirectory) AndAlso Not Path.IsPathRooted(screenshotDirectory) Then Throw New InvalidDataException("Screenshot directory must be absolute.")
        If mail.enabled Then
            If String.IsNullOrWhiteSpace(mail.host) OrElse mail.port < 1 OrElse mail.port > 65535 Then Throw New InvalidDataException("Invalid SMTP server.")
            If Not mail.enableSsl Then Throw New InvalidDataException("SMTP TLS is required.")
            Dim sender As New MailAddress(mail.sender)
            Dim recipient As New MailAddress(mail.recipient)
            If String.IsNullOrWhiteSpace(mail.username) OrElse String.IsNullOrWhiteSpace(mail.password) Then Throw New InvalidDataException("SMTP credentials required.")
        End If
    End Sub
End Class

Public Class MailConfig
    Public Property enabled As Boolean = False
    Public Property host As String = ""
    Public Property port As Integer = 587
    Public Property enableSsl As Boolean = True
    Public Property sender As String = ""
    Public Property recipient As String = ""
    Public Property username As String = ""
    Public Property password As String = ""
End Class
