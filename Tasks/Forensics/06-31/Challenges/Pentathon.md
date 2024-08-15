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

We find a file `msserver.py` on the filesystem in `C:\Users\challenge\AppData\Local\Temp\`. This was hinted at in the macro we found in the docm file.

Looking at the code, we see its some kind of encryption scheme for a server that XOR's it with its index and then converts it to base64.

We also have a pcap file `chall.pcap`. With Wireshark we can scan the packets and see base64 data being transferred. We extract the base64 data and reverse XOR it, leading to commands for slowly building a file `a.py` by echo'ing base64 strings into a file `file.txt`.

Looking at the first few lines, we see this text

```
d2ltYmls
Y2ljb2hZZW9pZWZuYmprAho=
ZWJqbCRpT2RYQE1MVG54
bEhhU01CQV9rfwcB
ZWJqbCRkUTZ/azlBPERGRXhzf0Fid0Vgf3spVm9UVlEReExhXUcUaURKGWZfZGZhAFJfX0FvT0BfXQhXSV5TaS4CJX55ZXh5aC8jJyljOjck
```

Using the server file, we make a script to decrypt the data

```py
import base64

def decr(data, flag):
    if flag:
        data = bytearray(data.encode())
        for i in range(len(data)):
            data[i] = data[i] ^ i
        data = base64.b64encode(data).decode()
    else:
        data = bytearray(base64.b64decode(data))
        for i in range(len(data)):
            data[i] = data[i] ^ i
        data = data.decode()
    return data

with open('encrypted_data.bin', 'r') as f:
    encrypted_data_lines = f.readlines()

for line in encrypted_data_lines:
    encrypted_data_base64 = line.strip()
    if encrypted_data_base64:
        decrypted_data = decr(encrypted_data_base64, 0)
        print(decrypted_data)
```

The first few commands turn out to be

```
whoami
chall\challenge

echo lIcPIGGXcv
lIcPIGGXcv
```

Making the first command `whoami`, and the flag `flag{whoami}`

# schmerz-3

**Flag** `flag{fA3bDtO6QL}`

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

