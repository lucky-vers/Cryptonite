# Solve script used for every challenge

```py
from pwn import *

context.update(arch="amd64")
code = asm("""
    [required assembly]
    """)
process = process("/challenge/run")
process.write(code)

print(process.readall())
```

# level1

**Flag:** `pwn.college{8iEx2sa12hQRqGCbWcqBwjjT2pu.0FN5EDLwgTN5QzW}`

**Solution:**

```nasm
mov rdi, 0x1337
```

# level2

**Flag:** `pwn.college{QBjRFYntHnoj3rkLur4EXebUIj9.dBTM4MDLwgTN5QzW}`

**Solution:**

```nasm
mov rax, 0x1337
mov r12, 0xCAFED00D1337BEEF
mov rsp, 0x31337
```

# level3

**Flag:** `pwn.college{Ebrs04nwSsD5aOfw7fm6wA88R5X.0VN5EDLwgTN5QzW}`

**Solution:**

```nasm
add rdi, 0x331337
```

# level4

**Flag:** `pwn.college{EFv6xudMMr5h-otWfjBUPRbpg3E.0lN5EDLwgTN5QzW}`

**Solution:**

```nasm
imul rsi, rdi
add rsi, rdx
mov rax, rsi
```

# level5

**Flag:** `pwn.college{w2uOOaP5D1gMvke9ec-a0RBqhu9.01N5EDLwgTN5QzW}`

**Solution:**

```nasm
mov rax, rdi
div rsi
```

# level6

**Flag:** `pwn.college{gKS3YRXZYnAE-ezYbH5zEf9Et0d.0FO5EDLwgTN5QzW}`

**Solution:**

```nasm
mov rax, rdi
div rsi
mov rax, rdx
```

# level7

**Flag:** `pwn.college{IGvBPSOwFVSo14erN-9EuJFLsuH.dFTM4MDLwgTN5QzW}`

**Solution:**

```nasm
mov ah, 0x42
```

# level8

**Flag:** `pwn.college{Y2yJWO45UL0zg-x4Y9vC2gZLDgd.0VO5EDLwgTN5QzW}`

**Solution:**

```nasm
mov al, dil
mov bx, si
```

# level9

**Flag:** `pwn.college{EqGE232wvRjQL-gcq-OgZ4028X5.0FMwIDLwgTN5QzW}`

**Solution:**

```nasm
shr rdi, 32
mov al, dil
```
