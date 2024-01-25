**Flag:** `KCTF{mul71_l4y3r3d_57360_ec4dacb5}`

We're given a TAR archive. Extracting it, we get two files, `clue.jpg` and `peaceful.wav`.

Looking at the metadata for `clue.jpg`, we find base58 encoded text translating to `theoceanisactuallyreallydeeeepp`.

```
~/Downloads/challenge $ exiftool clue.jpg
ExifTool Version Number         : 12.70
File Name                       : clue.jpg
Directory                       : .
File Size                       : 20 kB
File Modification Date/Time     : 2024:01:04 16:55:01+05:30
File Access Date/Time           : 2024:01:25 13:38:33+05:30
File Inode Change Date/Time     : 2024:01:25 13:38:33+05:30
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : inches
X Resolution                    : 300
Y Resolution                    : 300
Comment                         : 8qQd3iMYmtsyto7aXUuw1KVRpQFCRxqRtJiRgP85e36y
Image Width                     : 612
Image Height                    : 344
Encoding Process                : Progressive DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:4:4 (1 1)
Image Size                      : 612x344
Megapixels                      : 0.211
```

This is a hint to use the software DeepSound on the file `peaceful.wav`.

Inserting it and entering the password as `theoceanisactuallyreallydeeeepp`, we get a new file, `flag.png`

Using `binwalk` on this, we find a new file, `flag.txt`. This contains our flag.
