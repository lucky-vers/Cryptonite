# usb100

**Flag:** `BHflagy{1d3cbfa0e052b1729a00950e9fc0f61a3f393bc97c0c74c8ecab1b58cd0f95c32e4c970bdfa6e23371d50680ca0c37f61f7206974d20d5cbb2f00151f4735dde}`

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
