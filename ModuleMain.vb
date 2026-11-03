Option Strict On
Imports System.IO
Imports System.Threading

Module ModuleMain
    Public Function Main(args As String()) As Integer
        Dim stateDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "GoodGoodStudy")
        Try
            Directory.CreateDirectory(stateDirectory)
            If ConfigCommands.Execute(args, stateDirectory) Then Return 0
            Dim configUrl = RemoteConfig.DefaultUrl
            If args.Length = 2 AndAlso args(0) = "--config-url" Then
                configUrl = args(1)
            ElseIf args.Length <> 0 Then
                Throw New ArgumentException("Invalid arguments. See README.")
            End If
            Using instance As New Mutex(False, "Local\GoodGoodStudy-" & System.Security.Principal.WindowsIdentity.GetCurrent().User.Value)
                Dim acquired As Boolean
                Try
                    acquired = instance.WaitOne(0)
                Catch ex As AbandonedMutexException
                    acquired = True
                End Try
                If Not acquired Then Throw New InvalidOperationException("Already running.")
                Try
                    Dim loader As New RemoteConfig(stateDirectory, ConfigCrypto.LoadKey(stateDirectory), AddressOf RuntimeLog.Write)
                    Dim config = loader.Load(configUrl)
                    Using stopSignal As New ManualResetEvent(False)
                        AddHandler Console.CancelKeyPress, Sub(sender, e)
                                                               e.Cancel = True
                                                               stopSignal.Set()
                                                           End Sub
                        Dim runner As New CaptureRunner(config, stateDirectory, AddressOf RuntimeLog.Write)
                        runner.Run(stopSignal)
                    End Using
                Finally
                    instance.ReleaseMutex()
                End Try
            End Using
            Return 0
        Catch ex As Exception
            ' Exception messages may include secrets or URLs; log the type only.
            Console.Error.WriteLine("GoodGoodStudy stopped: " & ex.GetType().Name & ". Check configuration, key, URL and README.")
            RuntimeLog.Write("Startup failed: " & ex.GetType().Name)
            Return 1
        End Try
    End Function
End Module
