# usb100

**Flag:** `BHflagY{1d3cbfa0e052b1729a00950e9fc0f61a3f393bc97c0c74c8ecab1b58cd0f95c32e4c970bdfa6e23371d50680ca0c37f61f7206974d20d5cbb2f00151f4735dde}`

We are given a password protected zip file with a pcap dump in it. I tried to crack the password with `john` and `rockyou.txt` but turned up nothing. I looked around and saw the password was `flagyard`; not sure whether this was part of the challenge or not.

I then looked at the pcap file through Wireshark and saw what looked to be JPEG data being transmitted. I then used `binwalk` to extract all the files since it was easier than manually extracting the bytes from Wireshark.

```
…/Forensics - June 31st/Challenges/Files/blackhat $ binwalk --dd=".*" send.pcapng

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
20999         0x5207          JPEG image data, JFIF standard 1.01
55787         0xD9EB          JPEG image data, JFIF standard 1.01
130699        0x1FE8B         JPEG image data, JFIF standard 1.01
268263        0x417E7         JPEG image data, JFIF standard 1.01
268645        0x41965         Copyright string: "Copyright (c) 1998 Hewlett-Packard Company"
411135        0x645FF         JPEG image data, JFIF standard 1.01
458211        0x6FDE3         JPEG image data, JFIF standard 1.01
529459        0x81433         JPEG image data, JFIF standard 1.01
588823        0x8FC17         JPEG image data, JFIF standard 1.01
656379        0xA03FB         JPEG image data, JFIF standard 1.01
706339        0xAC723         Microsoft executable, portable (PE)
721795        0xB0383         XML document, version: "1.0"
745627        0xB609B         JPEG image data, JFIF standard 1.01
780415        0xBE87F         JPEG image data, JFIF standard 1.01
840183        0xCD1F7         JPEG image data, JFIF standard 1.01
875375        0xD5B6F         JPEG image data, JFIF standard 1.01
933527        0xE3E97         JPEG image data, JFIF standard 1.01
1060015       0x102CAF        JPEG image data, JFIF standard 1.01
1131667       0x114493        JPEG image data, JFIF standard 1.01
1178743       0x11FC77        JPEG image data, JFIF standard 1.01
1213531       0x12845B        JPEG image data, JFIF standard 1.01
1288443       0x13A8FB        JPEG image data, JFIF standard 1.01
1410835       0x158713        JPEG image data, JFIF standard 1.01
1490679       0x16BEF7        JPEG image data, JFIF standard 1.01
1538563       0x177A03        JPEG image data, JFIF standard 1.01
1622475       0x18C1CB        JPEG image data, JFIF standard 1.01
1664243       0x1964F3        JPEG image data, JFIF standard 1.01
1830855       0x1BEFC7        JPEG image data, JFIF standard 1.01
1927459       0x1D6923        JPEG image data, JFIF standard 1.01
```

We can see several image files and one Windows executable. Running that, we get the flag.

```
…/Challenges/Files/blackhat/_send.pcapng.extracted $ wine AC723
BHflagy{1d3cbfa0e052b1729a00950e9fc0f61a3f393bc97c0c74c8ecab1b58cd0f95c32e4c970bdfa6e23371d50680ca0c37f61f7206974d20d5cbb2f00151f4735dde}%
```

# Not supported

**Flag:** `BHflagY{d22a3eed050c23c0880cc912368905c9d2527a41c328f81ef115b9464b800f7425333edb71d57b440b94dc766a2d49611d46968477b09dfa1f246585d87d7b5a}`

We're given a Windows 11 memory dump. Since vol2 doesn't work with Windows 11, we use vol3.

```
~/Downloads $ python3 volatility3/vol.py --save-config config.json -f memdump.mem windows.info
Volatility 3 Framework 2.7.0
Progress:  100.00               PDB scanning finished
Variable Value

Kernel Base     0xf8075a400000
DTB     0x6d5000
Symbols file:///home/verma/Downloads/volatility3/volatility3/symbols/windows/ntkrnlmp.pdb/738ED8FF966E8502EFE17095B9F1F548-1.json.xz
Is64Bit True
IsPAE   False
layer_name      0 WindowsIntel32e
memory_layer    1 FileLayer
KdVersionBlock  0xf8075b009960
Major/Minor     15.22621
MachineType     34404
KeNumberProcessors      1
SystemTime      2023-09-30 19:16:56
NtSystemRoot    C:\Windows
NtProductType   NtProductWinNt
NtMajorVersion  10
NtMinorVersion  0
PE MajorOperatingSystemVersion  10
PE MinorOperatingSystemVersion  0
PE Machine      34404
PE TimeDateStamp        Thu May  4 22:30:48 2045
```

Then running `pslist` on the dump, we find the PID of Notepad.exe to be **6028**.

```
~/Downloads $ python3 volatility3/vol.py -c config.json -f memdump.mem windows.pslist
Volatility 3 Framework 2.7.0
Progress:  100.00               PDB scanning finished
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime        File output

4       0       System  0x9f0fecefb040  175     -       N/A    False    2023-09-30 18:59:33.000000      N/A     Disabled
64      4       Registry        0x9f0feceda080  4       -      N/A      False   2023-09-30 18:59:32.000000      N/A     Disabled
460     4       smss.exe        0x9f0fedf59040  2       -      N/A      False   2023-09-30 18:59:33.000000      N/A     Disabled
604     592     csrss.exe       0x9f0feff1a140  9       -      0        False   2023-09-30 18:59:37.000000      N/A     Disabled
668     592     wininit.exe     0x9f0ff04e9080  4       -      0        False   2023-09-30 18:59:37.000000      N/A     Disabled
676     660     csrss.exe       0x9f0ff04f6140  12      -      1        False   2023-09-30 18:59:37.000000      N/A     Disabled
728     668     services.exe    0x9f0ff0510180  6       -      0        False   2023-09-30 18:59:37.000000      N/A     Disabled
744     668     lsass.exe       0x9f0ff051a180  9       -      0        False   2023-09-30 18:59:37.000000      N/A     Disabled
772     660     winlogon.exe    0x9f0ff0522080  3       -      1        False   2023-09-30 18:59:37.000000      N/A     Disabled
.
.
.
6028    4644    Notepad.exe     0x9f0ff22350c0  22      -      2        False   2023-09-30 19:15:22.000000      N/A     Disabled
8820    1256    audiodg.exe     0x9f0ff13800c0  7       -      0        False   2023-09-30 19:16:12.000000      N/A     Disabled
9028    4644    FTK Imager.exe  0x9f0ff126d0c0  15      -      2        False   2023-09-30 19:16:35.000000      N/A     Disabled
```

Finally, we dump the memory of Notepad using `memdump` and use strings on it to get the flag.

```
~/Downloads $ python3 volatility3/vol.py -c config.json -f memdump.mem windows.memmap --pid 6028 --dump
```

```
~/Downloads $ grep -ia BHFlag pid.6028.dmp | tr -d ' '
@2023-09-30_181513�%BHflagY{d22a3eed050c23c0880cc912368905c9d2527a41c328f81ef115b9464b800f7425333edb71d57b440b94dc766a2d49611d46968477b09dfa1f246585d87d7b5a}
```
