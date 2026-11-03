Option Strict On
Imports System.IO
Imports System.Web.Script.Serialization

Public NotInheritable Class ConfigCommands
    Public Shared Function Execute(args As String(), stateDirectory As String) As Boolean
        If args.Length = 0 Then Return False
        Select Case args(0)
            Case "--create-profile"
                Require(args.Length = 2)
                Require(Not File.Exists(Path.Combine(stateDirectory, "device-profile.dpapi")))
                Dim profile = ClientProfile.Create()
                ClientProfile.WritePrivateFile(args(1), New JavaScriptSerializer().Serialize(profile))
                profile.Save(stateDirectory)
                Console.WriteLine("Device credential created. Enroll its token hash on the server; transfer the profile privately.")
            Case "--import-profile"
                Require(args.Length = 2 OrElse (args.Length = 3 AndAlso args(2) = "--replace"))
                Require(args.Length = 3 OrElse Not File.Exists(Path.Combine(stateDirectory, "device-profile.dpapi")))
                Require(New FileInfo(args(1)).Length <= 4096)
                ClientProfile.Parse(File.ReadAllText(args(1))).Save(stateDirectory)
                Console.WriteLine("Device credential imported and protected with Windows DPAPI. No session encryption key stored.")
            Case "--export-profile"
                Require(args.Length = 2)
                ClientProfile.WritePrivateFile(args(1), New JavaScriptSerializer().Serialize(ClientProfile.Load(stateDirectory)))
                Console.WriteLine("Device credential exported to an owner-only file. Keep it private.")
            Case "--check-config"
                Require(args.Length = 1 OrElse args.Length = 2)
                Dim url = If(args.Length = 2, args(1), RemoteConfig.DefaultUrl)
                Dim loader As New RemoteConfig(ClientProfile.Load(stateDirectory), AddressOf Console.WriteLine)
                loader.Load(url)
                Console.WriteLine("Configuration validated; no screenshots taken and no email sent.")
            Case Else
                Return False
        End Select
        Return True
    End Function

    Private Shared Sub Require(condition As Boolean)
        If Not condition Then Throw New ArgumentException("Invalid command or existing output/profile. See README.")
    End Sub
End Class
