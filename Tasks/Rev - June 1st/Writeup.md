# Level 1.0

**Flag:** `pwn.college{4YvYV-XtFWFTT7qTqi2nRZmoK5G.0VM1IDLwgTN5QzW}`

The license key converts hex to ASCII. We reverse the expected characters to get the flag.

```py
for i in [ 0x63, 0x6c, 0x6a, 0x79, 0x62 ]:
    print(chr(i), end = '')
```

# Level 1.1

**Flag:** `pwn.college{8U242dFuQ4pD7D0O42gX82X2tVT.0lM1IDLwgTN5QzW}`

The license key (`hgsaa`) is stored in plain text in the binary, we use `strings` to find it and reveal the flag.

# Level 2.0

**Flag:** `pwn.college{MNEKo9PI9DVwzdfhngZNl24zT3V.01M1IDLwgTN5QzW}`

The key is stored as hex and has index 2 and 3 swapped. Reversing it we get the flag.

```py
key = []
for i in [0x7a, 0x64, 0x6e, 0x69, 0x7a]:
    key.append(chr(i))

tmp = key[2]
key[2] = key[3]
key[3] = tmp

print(''.join(key))
```

# Level 2.1

The letters of the key are given in plain text. We permute all of them and find the flag.

**Flag:** `pwn.college{wBomsU6Nn1OflENlifWigCPt0BL.0FN1IDLwgTN5QzW}`

```py
import itertools
import subprocess

key = 'yxugw'
permutations = itertools.permutations(key)

for p in permutations:
    permutation_str = ''.join(p)

    result = subprocess.run(['/challenge/babyrev_level2.1'], input=permutation_str, text=True, capture_output=True)

    if 'pwn.' in result.stdout:
        print("License key was", p)
        print(result.stdout)
```

# Level 3.0

**Flag:** `pwn.college{A-ORDvouLqn-uWMjZNapVpdMbsL.0VN1IDLwgTN5QzW}`

The key is reversed.

```py
k = [0x71, 0x78, 0x6b, 0x61, 0x68]

for i in k[::-1]:
    print(chr(i), end = '')
```

# Level 3.1

**Flag:** `pwn.college{Aqc3dk8xecGDCy8vu1TbGbeckJ4.0lN1IDLwgTN5QzW}`

The key is found in the `strings` output and simply needs to be reversed.

# Level 4.0

**Flag:** `pwn.college{c86UhegHHdkcTuS6twwKj9wcAIJ.01N1IDLwgTN5QzW}`

The key is sorted.

# Level 4.1

**Flag:** `pwn.college{0SCLwLRKHfUDfyqJa9Jn5Zd4oqO.0FO1IDLwgTN5QzW}`

The key is given in the `strings` output.

# Level 5.0

**Flag:** `pwn.college{gT93xSZFNbPrnIm9FZ-AousATKm.0VO1IDLwgTN5QzW}`

All the key's characters have been XOR'd with `0x70`.

```py
for i in [0x07, 0x0a, 0x05, 0x1a, 0x01]:
    print(chr(i ^ 0x70), end = '')
```

# Level 5.1

**Flag:** `pwn.college{8LxesjmWeBewzdPPkSGkt3wtaGC.0FM2IDLwgTN5QzW}`

XOR'd version of the key is given in the `strings` output. We brute force it till we find the key `qfftw`.

```py
from string import ascii_lowercase

k = "0''56"

for i in range(150):
    s = ''
    for j in k:
        l = chr(ord(j) ^ i)
        s += l
    print(s)
```
