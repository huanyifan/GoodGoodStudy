Option Strict On
Imports System.IO
Imports System.IO.Compression
Imports System.Linq

Public Class CaptureStore
    Public ReadOnly captureDirectory As String
    Public ReadOnly queueDirectory As String

    Public Sub New(capturePath As String, queuePath As String)
        captureDirectory = capturePath
        queueDirectory = queuePath
        Directory.CreateDirectory(capturePath)
        Directory.CreateDirectory(queuePath)
    End Sub

    Public Shared Function UniqueName(extension As String) As String
        Return DateTime.UtcNow.ToString("yyyyMMddTHHmmssfff") & "-" & Guid.NewGuid().ToString("N") & extension
    End Function

    Public Function Images() As String()
        Return Directory.GetFiles(captureDirectory, "*.png").OrderBy(Function(p) p, StringComparer.Ordinal).ToArray()
    End Function

    Public Function Archive(files As String()) As String
        If files.Length = 0 OrElse files.Any(Function(p) Not File.Exists(p)) Then Throw New InvalidDataException("No complete screenshot batch.")
        Dim archivePath = Path.Combine(queueDirectory, UniqueName(".zip"))
        Dim temporary = archivePath & ".tmp"
        Try
            Using zip = ZipFile.Open(temporary, ZipArchiveMode.Create)
                For Each image In files
                    zip.CreateEntryFromFile(image, Path.GetFileName(image), CompressionLevel.Fastest)
                Next
            End Using
            File.Move(temporary, archivePath)
        Finally
            If File.Exists(temporary) Then File.Delete(temporary)
        End Try
        ' The completed ZIP is durable before any source is removed.
        For Each image In files
            File.Delete(image)
        Next
        Return archivePath
    End Function

    Public Function ArchiveReadyBatches(batchSize As Integer) As Integer
        If batchSize < 1 OrElse batchSize > 100 Then Throw New ArgumentOutOfRangeException(NameOf(batchSize))
        Dim count = 0
        Dim pending = Images()
        While pending.Length >= batchSize
            Archive(pending.Take(batchSize).ToArray())
            count += 1
            pending = Images()
        End While
        Return count
    End Function

    Public Function StoredBytes() As Long
        Dim roots = If(String.Equals(captureDirectory, queueDirectory, StringComparison.OrdinalIgnoreCase),
                       New String() {captureDirectory}, New String() {captureDirectory, queueDirectory})
        Return roots.SelectMany(Function(root) Directory.GetFiles(root)).Sum(Function(p) New FileInfo(p).Length)
    End Function

    Public Sub PruneLocal(retentionDays As Integer, maxBytes As Long)
        For Each image In Images()
            If File.GetLastWriteTimeUtc(image) < DateTime.UtcNow.AddDays(-retentionDays) Then File.Delete(image)
        Next
        Dim total = StoredBytes()
        For Each image In Images()
            If total < maxBytes Then Exit For
            Dim length = New FileInfo(image).Length
            File.Delete(image)
            total -= length
        Next
    End Sub
End Class
