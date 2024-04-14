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

# level10

**Flag:** `pwn.college{cfD_PJ0YKkhPGubsPFi8T-FQRyb.0VMwIDLwgTN5QzW}`

**Solution:**

```nasm
and rdi, rsi
and rax, rdi
```


# level11

**Flag:** `pwn.college{cp_HzeKjIkggwDDOR-2Yr72qWe9.0lMwIDLwgTN5QzW}`

**Solution:**

```nasm
and rdi, 1
and rax, rdi
xor rax, 1
```

# level12

**Flag:** `pwn.college{0h-rvYfa3rLhhbfHZ6TsnTEe_aa.dJTM4MDLwgTN5QzW}`

**Solution:**

```nasm
mov rax, [0x404000]
```

# level13

**Flag:** `pwn.college{IwX5iXXZHdO-91ODfJgJkEj7M7W.dNTM4MDLwgTN5QzW}`

**Solution:**

```nasm
mov [0x404000], rax
```

# level14

**Flag:** `pwn.college{UNli4mAqlIf6vnkmNDXE5FAhKAz.01MwIDLwgTN5QzW}`

**Solution:**

```nasm
mov rax, [0x404000]
mov rdi, [0x404000]
add rdi, 0x1337
mov [0x404000], rdi
```

# level15

**Flag:** `pwn.college{QMcDyEpx8D_WZyOFdWjlbqVwFaj.dRTM4MDLwgTN5QzW}`

**Solution:**

```nasm
mov al, [0x404000]
```

# level16

**Flag:** `pwn.college{MjGw7uMgylNjJLnFXPqG7mYhwWO.0FNwIDLwgTN5QzW}`

**Solution:**

```nasm
mov al, [0x404000]
mov bx, [0x404000]
mov ecx, [0x404000]
mov rdx, [0x404000]
```


# level17

**Flag:** `pwn.college{YFwBLWRZVNwXx6YEveR7OFEcNZo.0VNwIDLwgTN5QzW}`

**Solution:**

```nasm
mov rax, 0xdeadbeef00001337
mov rcx, 0xc0ffee0000
mov [rdi], rax
mov [rsi], rcx
```

# level18

**Flag:** `pwn.college{IJggd9mUypkIKHzrIQ1SZkziTPk.0lNwIDLwgTN5QzW}`

**Solution:**

```nasm
mov rax, [rdi]
mov rbx, [rdi + 8]
add rax, rbx
mov [rsi], rax
```

# level19

**Flag:** `pwn.college{IkI7MnMpt4ktrKILRFRFEaCQ_3D.01NwIDLwgTN5QzW}`

**Solution:**

```nasm
pop rax
sub rax, rdi
push rax
```

# level20

**Flag:** `pwn.college{40F97iOd52OHOwskB-Ad9hcC8Eh.0FOwIDLwgTN5QzW}`

**Solution:**

```nasm
push rdi
push rsi
pop rdi
pop rsi
```
