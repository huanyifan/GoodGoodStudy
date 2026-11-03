Option Strict On
Imports System.Diagnostics
Imports System.Drawing
Imports System.IO
Imports System.Linq
Imports System.Net
Imports System.Net.Mail
Imports System.Threading
Imports System.Windows.Forms

Public Class CaptureRunner
    Private ReadOnly config As AppConfig
    Private ReadOnly store As CaptureStore
    Private ReadOnly log As Action(Of String)

    Public Sub New(settings As AppConfig, stateDirectory As String, logger As Action(Of String))
        config = settings
        log = logger
        Dim capturePath = If(String.IsNullOrWhiteSpace(config.screenshotDirectory), Path.Combine(stateDirectory, "captures"), config.screenshotDirectory)
        store = New CaptureStore(capturePath, Path.Combine(stateDirectory, "pending"))
    End Sub

    Public Sub Run(stopSignal As EventWaitHandle)
        Dim sender As Thread = Nothing
        If config.mail.enabled Then
            sender = New Thread(Sub() SendPending(stopSignal)) With {.IsBackground = True}
            sender.Start()
        End If
        log("Capture started. Press Ctrl+C to stop.")
        Console.WriteLine("GoodGoodStudy running. Press Ctrl+C to stop.")
        Dim timer = Stopwatch.StartNew()
        Dim interval = CLng(config.intervalSeconds) * 1000L
        Dim nextCapture = interval
        Try
            Do
                Dim remaining = Math.Max(0L, nextCapture - timer.ElapsedMilliseconds)
                If stopSignal.WaitOne(CInt(Math.Min(remaining, Integer.MaxValue))) Then Exit Do
                Try
                    Dim limit = CLng(config.maxStorageMB) * 1024L * 1024L
                    If Not config.mail.enabled Then store.PruneLocal(config.retentionDays, limit)
                    ' Preserve unsent screenshots: pause collection instead of deleting queued data.
                    If store.StoredBytes() < limit Then
                        Capture()
                    Else
                        log("Storage limit reached; capture paused until space is available.")
                    End If
                    If config.mail.enabled Then
                        store.ArchiveReadyBatches(config.batchSize)
                    End If
                Catch ex As Exception
                    log("Capture/archive failed: " & ex.GetType().Name)
                End Try
                nextCapture += interval
                If nextCapture <= timer.ElapsedMilliseconds Then nextCapture = timer.ElapsedMilliseconds + interval
            Loop
        Finally
            stopSignal.Set()
            If sender IsNot Nothing Then sender.Join()
        End Try
    End Sub

    Private Sub Capture()
        Dim bounds = Screen.PrimaryScreen.Bounds
        Dim destination = Path.Combine(store.captureDirectory, CaptureStore.UniqueName(".png"))
        Dim temporary = destination & ".tmp"
        Try
            Using bitmap As New Bitmap(bounds.Width, bounds.Height), canvas = System.Drawing.Graphics.FromImage(bitmap)
                canvas.CopyFromScreen(bounds.Location, Point.Empty, bounds.Size)
                bitmap.Save(temporary, Imaging.ImageFormat.Png)
            End Using
            File.Move(temporary, destination)
        Finally
            If File.Exists(temporary) Then File.Delete(temporary)
        End Try
    End Sub

    Private Sub SendPending(stopSignal As EventWaitHandle)
        Dim retrySeconds = 5
        Do While Not stopSignal.WaitOne(0)
            Try
                Dim files = Directory.GetFiles(store.queueDirectory, "*.zip").OrderBy(Function(p) p, StringComparer.Ordinal).ToArray()
                For Each archive In files
                    If stopSignal.WaitOne(0) Then Return
                    ' Oversize attachments stay on disk for recovery rather than being discarded.
                    If New FileInfo(archive).Length > 10L * 1024L * 1024L Then
                        log("Oversize archive retained; skipped (10 MiB compressed limit).")
                        Continue For
                    End If
                    Using message As New MailMessage(), smtp As New SmtpClient(config.mail.host, config.mail.port)
                        message.From = New MailAddress(config.mail.sender)
                        message.To.Add(config.mail.recipient)
                        message.Subject = Environment.MachineName & " screenshots"
                        message.Body = "GoodGoodStudy screenshot batch."
                        message.Attachments.Add(New Attachment(archive))
                        smtp.EnableSsl = config.mail.enableSsl
                        smtp.Timeout = 15000
                        smtp.UseDefaultCredentials = False
                        smtp.Credentials = New NetworkCredential(config.mail.username, config.mail.password)
                        ServicePointManager.SecurityProtocol = ServicePointManager.SecurityProtocol Or SecurityProtocolType.Tls12
                        smtp.Send(message)
                    End Using
                    File.Delete(archive)
                    log("Screenshot batch sent and removed from queue.")
                Next
                retrySeconds = 5
            Catch ex As Exception
                log("Send failed; archive retained for retry: " & ex.GetType().Name)
                retrySeconds = Math.Min(retrySeconds * 2, 300)
            End Try
            If stopSignal.WaitOne(TimeSpan.FromSeconds(retrySeconds)) Then Exit Do
        Loop
    End Sub
End Class

Public NotInheritable Class RuntimeLog
    Private Shared ReadOnly Gate As New Object()
    Public Shared Sub Write(message As String)
        Try
            SyncLock Gate
                Dim root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "GoodGoodStudy")
                Directory.CreateDirectory(root)
                Dim destination = Path.Combine(root, "runtime.log")
                If File.Exists(destination) AndAlso New FileInfo(destination).Length > 1024L * 1024L Then
                    Dim previous = destination & ".1"
                    If File.Exists(previous) Then File.Delete(previous)
                    File.Move(destination, previous)
                End If
                File.AppendAllText(destination, DateTime.UtcNow.ToString("O") & " " & message & Environment.NewLine)
            End SyncLock
        Catch
            ' A log failure must not stop capture or expose configuration to the console.
        End Try
    End Sub
End Class
