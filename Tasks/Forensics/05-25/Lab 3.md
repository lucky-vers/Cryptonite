# MemLabs 3 - The Evil's Den

**Flag:** `inctf{0n3_h4lf_1s_n0t_3n0ugh}`

After finding the profile, we first see the process list. Since we see `cmd.exe`, we run `cmdline` on it and get the following output.

```
root@c5a1bd3c48a2:~# volatility -f dumps/MemoryDump_Lab3.raw --profile Win7SP1x86_23418 cmdline
Command line : "C:\Windows\system32\NOTEPAD.EXE" C:\Users\hello\Desktop\evilscript.py
************************************************************************
notepad.exe pid:   3432
Command line : "C:\Windows\system32\NOTEPAD.EXE" C:\Users\hello\Desktop\vip.txt
```

There are two files of interest, `evilscript.py` and `vip.txt`. We find these files in memory and dump them as well. Their contents are:

**evilscript.py**

```python
import sys
import string

def xor(s):
	a = ''.join(chr(ord(i)^3) for i in s)
	return a

def encoder(x):
	return x.encode("base64")

if __name__ == "__main__":
	f = open("C:\\Users\\hello\\Desktop\\vip.txt", "w")
	arr = sys.argv[1]
	arr = encoder(xor(arr))
	f.write(arr)
	f.close()
```

**vip.txt**

```
am1gd2V4M20wXGs3b2U=
```

It seems `evilscript.py` is XORing `vip.txt` and then converting it to base64. Reversing the process, we get the following

```
>>> s = 'am1gd2V4M20wXGs3b2U='
>>> s = s.decode('base64')
>>> ''.join(chr(ord(i) ^ 3) for i in s)
inctf{0n3_h4lf
```

So we have one half of the flag. Now we just need to find the other one.

Since `steghide` is given as something needed for this challenge, we look for image files.

```
root@c5a1bd3c48a2:~# volatility -f dumps/MemoryDump_Lab3.raw --profile Win7SP1x86_23418 filescan | grep -E '(jpg|jpeg|png|webp)' | grep -v 'Content.IE5'
Volatility Foundation Volatility Framework 2.6
0x0000000004f34148      2      0 RW---- \Device\HarddiskVolume2\Users\hello\Desktop\suspision1.jpeg
0x0000000034091c38      8      0 R--r-- \Device\HarddiskVolume2\Users\hello\AppData\Roaming\Microsoft\Windows\Themes\TranscodedWallpaper.jpg
0x000000003ac5a378      2      0 -W---- \Device\HarddiskVolume2\Python27\Lib\test\imghdrdata\python.jpg
0x000000003d0521d0      2      0 R--r-d \Device\HarddiskVolume2\Windows\System32\pngfilt.dll
0x000000003d4afb50      8      0 -W---- \Device\HarddiskVolume2\Python27\Lib\test\imghdrdata\python.png
```

The file `suspision1.jpeg` seems to be interesting, so we dump it and call `steghide` on it.

```
root@c5a1bd3c48a2:~# steghide extract -sf suspision1.jpeg
Enter passphrase:
```

It's also mentioned the first half of the flag is required to get the second. So we try using it as the password, and it succeeds, giving us the flag's second half.

```
wrote extracted data to "secret text".
root@c5a1bd3c48a2:~# cat secret\ text
_1s_n0t_3n0ugh}
```
