# Level 1.0

**Flag:** `pwn.college{4YvYV-XtFWFTT7qTqi2nRZmoK5G.0VM1IDLwgTN5QzW}`

The license key converts hex to ASCII. We reverse the expected characters to get the flag.

**Solve Script:**

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

**Solve Script:**

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

License key is given in plain text in the binary, although swapped.
