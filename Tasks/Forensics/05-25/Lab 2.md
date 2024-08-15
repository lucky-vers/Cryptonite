# MemLabs 2 - A New World

**Flag 1:** `flag{w3lc0m3_T0_$T4g3_!_Of_L4B_2}`

**Flag 2:** `flag{w0w_th1s_1s_Th3SeC0nD_ST4g3!!}`

**Flag 3:** `flag{oK_So_Now_St4g3_3_is_DoNE!!}`

We similarly run `imageinfo` and get the profile as `Win7SP1x64`.

A hint is given with "environmental" in quotes, so we check the environmental variables.

```
root@416c9f418f7f:~# volatility -f dumps/MemoryDump_Lab2.raw --profile Win7SP1x64 envars
    2764 sppsvc.exe           0x0000000000251320 NEW_TMP                        C:\Windows\ZmxhZ3t3M2xjMG0zX1QwXyRUNGczXyFfT2ZfTDRCXzJ9
```

We see another base64 encoded string in the variable NEW_TMP, which when decoded gives us the first flag.

```
root@416c9f418f7f:~# echo ZmxhZ3t3M2xjMG0zX1QwXyRUNGczXyFfT2ZfTDRCXzJ9 | base64 -d
flag{w3lc0m3_T0_$T4g3_!_Of_L4B_2}
```

Now running `pslist`, we get a few interesting programs.

```
0xfffffa8002109b30 chrome.exe             2296   2664     27      658      2      0 2019-12-14 10:36:45 UTC+0000
0xfffffa80011956a0 notepad.exe            3260   3180      1       61      1      0 2019-12-14 10:38:20 UTC+0000
```

I dumped `notepad.exe` and poked around a bit, but found no leads there.

I then remembered seeing a `KeePass.exe` process in the list as well. I knew KeePass was a password manager which stored its database in `.kdbx` files, so I searched for them.

```
root@416c9f418f7f:~# volatility -f dumps/MemoryDump_Lab2.raw --profile Win7SP1x64 filescan | grep kdbx
Volatility Foundation Volatility Framework 2.6
0x000000003fb112a0     16      0 R--r-- \Device\HarddiskVolume2\Users\SmartNet\Secrets\Hidden.kdbx
```

I found one, and dumped it.

```
root@416c9f418f7f:~# volatility -f dumps/MemoryDump_Lab2.raw --profile Win7SP1x64 dumpfiles -Q 0x000000003fb112a0 -D .
Volatility Foundation Volatility Framework 2.6
DataSectionObject 0x3fb112a0   None   \Device\HarddiskVolume2\Users\SmartNet\Secrets\Hidden.kdbx
```

Now, we just need to locate the password. I used `filescan` again, and `grep`'d for anything with password in it.

```
root@416c9f418f7f:~# volatility -f dumps/MemoryDump_Lab2.raw --profile Win7SP1x64 filescan | grep -i password
Volatility Foundation Volatility Framework 2.6
0x000000003e868370     16      0 R--r-d \Device\HarddiskVolume2\Program Files (x86)\KeePass Password Safe 2\KeePass.exe.config
0x000000003e873070      8      0 R--r-d \Device\HarddiskVolume2\Program Files (x86)\KeePass Password Safe 2\KeePass.exe
0x000000003e8ef2d0     13      0 R--r-d \Device\HarddiskVolume2\Program Files (x86)\KeePass Password Safe 2\KeePass.exe
0x000000003e8f0360      4      0 R--r-d \Device\HarddiskVolume2\Program Files (x86)\KeePass Password Safe 2\KeePass.XmlSerializers.dll
0x000000003eaf7880     15      1 R--r-d \Device\HarddiskVolume2\Program Files (x86)\KeePass Password Safe 2\KeePass.XmlSerializers.dll
0x000000003fb0abc0     10      0 R--r-d \Device\HarddiskVolume2\Program Files (x86)\KeePass Password Safe 2\KeePassLibC64.dll
0x000000003fce1c70      1      0 R--r-d \Device\HarddiskVolume2\Users\Alissa Simpson\Pictures\Password.png
0x000000003fd62f20      2      0 R--r-- \Device\HarddiskVolume2\Program Files (x86)\KeePass Password Safe 2\KeePass.config.xml
0x000000003fecf820     15      0 R--r-d \Device\HarddiskVolume2\Program Files (x86)\KeePass Password Safe 2\unins000.exe
```

We find a `password.png` file. Dumping it, we make out the password to be `P4SSw0rd_123`.

![keepassword](../../../Images/keepass_password.png)

Opening the database, we get the flag in the `password` of the username `flag`.

Now, we finally look at the Chrome process from earlier. We use a [plugin suite](https://github.com/superponible/volatility-plugins) to access its browser history.

```
root@416c9f418f7f:~# volatility --plugins=vol-plugins/ -f dumps/MemoryDump_Lab2.raw --profile Win7SP1x64 chromehistory > history
Index  URL                                                                              Title                                                                            Visits Typed Last Visit Time            Hidden Favicon ID
------ -------------------------------------------------------------------------------- -------------------------------------------------------------------------------- ------ ----- -------------------------- ------ ----------
.
.
.
    32 https://mega.nz/#F!TrgSQQTS!H0ZrUzF0B-ZKNM3y9E76lg                               MEGA                                                                                  2     0 2019-12-14 10:21:39.602970        N/A
```

We find a MEGA link and download its contents, which turn out to be a zip file. Running `7z` on it gives us the following output.

```
7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=C.UTF-8,Utf16=on,HugeFiles=on,64 bits,12 CPUs AMD Ryzen 5 5500U with Radeon Graphics          (860F81),ASM,AES-NI)

Scanning the drive for archives:
1 file, 57457 bytes (57 KiB)

Extracting archive: Important.zip
--
Path = Important.zip
Type = zip
Physical Size = 57457
Comment = Password is SHA1(stage-3-FLAG) from Lab-1. Password is in lowercase.

Enter password (will not be echoed):
```

The SHA1 hash of the stage 3 flag of level 1 (`flag{w3ll_3rd_stage_was_easy}`) is `6045dd90029719a039fd2d2ebcca718439dd100a`. Now opening the image `Important.png`, we get the final flag.

![Important](../../../Images/Important.png)
