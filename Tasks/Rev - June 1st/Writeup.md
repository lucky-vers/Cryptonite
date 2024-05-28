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

# Level 6.0

**Flag:** `pwn.college{o1ZWbwJQ3uby7Mnya7vQz7h258D.0VM2IDLwgTN5QzW}`

The key is mangled through sorting and swapping. We convert the expected result to get the key.

```py
for i in [0x62, 0x64, 0x65, 0x68, 0x68, 0x68, 0x71, 0x6a, 0x6e, 0x6e, 0x6f, 0x69, 0x72, 0x76, 0x78, 0x79, 0x7a]:
    print(chr(i), end = '')
```

# Level 6.1

**Flag:** `pwn.college{QXD-1u7ltEQZbXRHN91IyXBV9aG.0lM2IDLwgTN5QzW}`

The string is XOR'd according to certain conditions, and then compared to a string of 17 hex characters. It is also reversed twice, but those cancel out.

```py
var28 = [0xa1, 0x3f, 0x97, 0xa9, 0x2d, 0x85, 0xa8, 0x3f, 0x95, 0xab, 0x34, 0x97, 0xa3, 0x39, 0x93, 0xb9, 0x33]

for i in range(len(var28)):
    rax_12 = i % 3
    if rax_12 == 2:
        var28[i] ^= 0xfd
    elif rax_12 == 0:
        var28[i] ^= 0xce
    elif rax_12 == 1:
        var28[i] ^= 0x58

for i in var28:
    print(chr(i), end='')
```

# Level 7.0

**Flag:** `pwn.college{AyNSTPqEUiPdKy6RIUrIsKxp0H4.01M2IDLwgTN5QzW}`

The input is mangled with a series of XOR's and swaps.

```py
import subprocess

hex_string = "cd4f050eddda9856180b97d9d056030e92d6cf5e0e009bdbd948051b9c"

def swap_indices(hex_str, idx1, idx2):
    byte_array = bytearray.fromhex(hex_str)
    byte_array[idx1], byte_array[idx2] = byte_array[idx2], byte_array[idx1]
    return byte_array.hex()

def xor_with_value(hex_str, value):
    byte_array = bytearray.fromhex(hex_str)
    value_bytes = value.to_bytes((value.bit_length() + 7) // 8, 'big')
    for i in range(len(byte_array)):
        byte_array[i] ^= value_bytes[i % len(value_bytes)]
    return byte_array.hex()

hex_string = swap_indices(hex_string, 3, 20)
hex_string = xor_with_value(hex_string, 0xdea6)
hex_string = swap_indices(hex_string, 4, 6)
hex_string = xor_with_value(hex_string, 0x1c58c7)
hex_string = xor_with_value(hex_string, 0x78d0)
byte_array = bytes.fromhex(hex_string)

ascii_string = byte_array.decode('ascii', errors='replace')

result = subprocess.run(
    '/home/verma/Downloads/babyrev_level7.0',
    input=ascii_string,
    text=True,
    capture_output=True
)

print(result.stdout)
```

# Level 7.1

**Flag:** `pwn.college{gUPb7ItZ9bTSAy9kpA5V-mePQ6s.0FN2IDLwgTN5QzW}`

The input characterrs are swapped and then XOR'd according to their indices

```py
import subprocess

def main():
    input = [0x40, 0xf3, 0x82, 0xd6, 0x9b, 0x57, 0xe2, 0x98, 0xdf, 0x6f, 0x5b, 0xf3, 0x9c, 0xd6, 0x7e, 0x68, 0xff, 0x94, 0xd0, 0x68, 0x52, 0xfd, 0x63, 0xc5, 0x52, 0x4a, 0xe6, 0x9b, 0xc3]

    xor = [
        0xb4,
        0xec,
        0x96,
        0x33,
        0x0a,
    ]

    input[15], input[24] = input[24], input[15]
    input[4], input[22] = input[22], input[4]

    for i in range(len(input) // 2):
        input[i], input[len(input) - 1 - i] = input[len(input) - 1 - i], input[i]

    for i in range(len(input)):
        input[i] ^= xor[i % 5]

    for i in range(len(input) // 2):
        input[i], input[len(input) - 1 - i] = input[len(input) - 1 - i], input[i]

    input_str = ''.join([chr(i) for i in input])

    result = subprocess.run(['./babyrev_level7.1'], input=input_str, capture_output=True, text=True)

    print(f"Input String: {input_str}")

    if 'win' in result.stdout:
        print(f"Input String: {input_str}")
        print(f"Output: {result.stdout}")
        exit(1)

if __name__ == "__main__":
    main()
```

# Level 8.0

**Flag:** `pwn.college{UoZkPKlwaT_uBfOIlWVkuS1nEq7.0VN2IDLwgTN5QzW}`

The program mangles the input key using a series of XOR's, reverses and swaps.

```py
def xor_elements(data, key):
    key_len = (key.bit_length() + 7) // 8
    key_bytes = key.to_bytes(key_len, 'big')
    return [b ^ key_bytes[i % key_len] for i, b in enumerate(data)]

def reverse_list(data):
    return data[::-1]

def swap_elements(data, index1, index2):
    data[index1], data[index2] = data[index2], data[index1]
    return data

data = [
    0xe6, 0x04, 0x15, 0x24, 0xaa, 0x13, 0x14, 0x6b, 0xb8, 0x2a, 0xaf, 0xcf, 0x36, 0x8e, 0xdf, 0x8a, 0xab,
    0x1f, 0xed, 0xa4, 0x27, 0xf6, 0x9b, 0x1e, 0x25, 0x71, 0x07, 0x9f, 0x69, 0x74, 0x2b, 0xb1, 0xd8, 0x31,
    0x85, 0xdf, 0x8c, 0xbb, 0x04
]

data = swap_elements(data, 4, 29)
data = reverse_list(data)
data = xor_elements(data, 0xa5c152)
data = reverse_list(data)
data = xor_elements(data, 0xfee13a)
data = swap_elements(data, 22, 27)
data = xor_elements(data, 0x2252e3fa33e9dd)

for i in data:
    print(chr(i), end = '')
```

# Level 8.1

**Flag:** `pwn.college{ELX_FKi5U3we0XommLMBMjuLopz.0lN2IDLwgTN5QzW}`

The key is swapped, reversed, and sorted before being compared with.

```py
x = [ord(i) for i in list('zxxxwvvvvttamssssdqqqpnntjjjiffertaa')]

def swap(x, a, b):
    x[a], x[b] = x[b], x[a]
    return x

x = swap(x, 11, 33)
x = x[::-1]
x = swap(x, 11, 23)
x = swap(x, 3, 18)
x = x[::-1]
x = x[::-1]

for i in x:
    print(chr(i), end = '')
```

# Level 9.0

**Flag:** `pwn.college{QlpqUEC2Afzb3vr2SeOqe9m8Ums.01N2IDLwgTN5QzW}`

We invert a `jne` instruction to `jz` at the offset `225b`.

# Level 9.1

**Flag:** `pwn.college{Mh83Q98d4VxbWHYa9tudHFpkw3C.0FO2IDLwgTN5QzW}`

We invert a `jne` instruction to `jz` at the offset `1d55`.

# Level 10.0

**Flag:** `pwn.college{IGyBL9X4EtUfJfgxqTT-JNgKjXY.0VO2IDLwgTN5QzW}`

We invert a `jne` instruction to `jz` at the offset `2687`.

# Level 10.1

**Flag:** `pwn.college{Y0tUw-Mjo-LFgsKbsn4IrnSP7Kd.0FM3IDLwgTN5QzW}`

We invert a `jne` instruction to `jz` at the offset `1a77`.

# Level 11.0

**Flag:** `pwn.college{oC5iPRY9HTVhi8eAvATIo2YUEHd.0VM3IDLwgTN5QzW}`

We invert a `jne` instruction to `jz` at the offsets `1e78` and `1be5`.

# Level 11.1

**Flag:** `pwn.college{0n-X3PYA_WAM2nDG8Vq2fYzBLjy.0lM3IDLwgTN5QzW}`

We invert a `jne` instruction to `jz` by changing the offsets:

- `23ac` to `84`
- `248e` to `74`

