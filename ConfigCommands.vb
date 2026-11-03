Option Strict On
Imports System.IO
Imports System.Security.AccessControl
Imports System.Security.Principal
Imports System.Text

Public NotInheritable Class ConfigCommands
    Public Shared Function Execute(args As String(), stateDirectory As String) As Boolean
        If args.Length = 0 Then Return False
        Select Case args(0)
            Case "--init-key"
                Require(args.Length = 1)
                Require(Not File.Exists(Path.Combine(stateDirectory, "config-key.dpapi")))
                ConfigCrypto.SaveKey(stateDirectory, ConfigCrypto.GenerateKey())
                Console.WriteLine("Random key saved with Windows DPAPI for the current user.")
            Case "--export-key"
                Require(args.Length = 2)
                Require(Not File.Exists(args(1)))
                ' Create the export with an owner-only ACL before writing any key bytes.
                Dim security As New FileSecurity()
                security.SetAccessRuleProtection(True, False)
                security.AddAccessRule(New FileSystemAccessRule(WindowsIdentity.GetCurrent().User, FileSystemRights.FullControl, AccessControlType.Allow))
                Using output As New FileStream(args(1), FileMode.CreateNew, FileSystemRights.Write, FileShare.None, 4096, FileOptions.None, security)
                    Dim bytes = Encoding.ASCII.GetBytes(Convert.ToBase64String(ConfigCrypto.LoadKey(stateDirectory)))
                    output.Write(bytes, 0, bytes.Length)
                End Using
                Console.WriteLine("Key exported to the requested owner-only file. Transfer privately; never upload it.")
            Case "--import-key"
                Require(args.Length = 2 OrElse (args.Length = 3 AndAlso args(2) = "--replace"))
                Require(args.Length = 3 OrElse Not File.Exists(Path.Combine(stateDirectory, "config-key.dpapi")))
                Require(New FileInfo(args(1)).Length <= 256)
                ConfigCrypto.SaveKey(stateDirectory, Convert.FromBase64String(File.ReadAllText(args(1)).Trim()))
                Console.WriteLine("Key imported and protected for the current Windows user.")
            Case "--encrypt-config"
                Require(args.Length = 3)
                Require(New FileInfo(args(1)).Length <= 65536)
                Require(Path.GetFullPath(args(1)) <> Path.GetFullPath(args(2)))
                Dim encrypted = ConfigCrypto.Encrypt(File.ReadAllText(args(1), Encoding.UTF8), ConfigCrypto.LoadKey(stateDirectory))
                AtomicFile.WriteBytes(args(2), Encoding.UTF8.GetBytes(encrypted))
                Console.WriteLine("Encrypted configuration written. Only upload this encrypted output.")
            Case "--check-config"
                Require(args.Length = 1 OrElse args.Length = 2)
                Dim url = If(args.Length = 2, args(1), RemoteConfig.DefaultUrl)
                Dim loader As New RemoteConfig(stateDirectory, ConfigCrypto.LoadKey(stateDirectory), AddressOf Console.WriteLine)
                loader.Load(url)
                Console.WriteLine("Configuration validated; no screenshots taken and no email sent.")
            Case Else
                Return False
        End Select
        Return True
    End Function

    Private Shared Sub Require(condition As Boolean)
        If Not condition Then Throw New ArgumentException("Invalid command, existing key/output, or oversized input. See README.")
    End Sub
End Class
