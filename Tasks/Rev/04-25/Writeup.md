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

# Level 1

**Flag:** `pwn.college{8iEx2sa12hQRqGCbWcqBwjjT2pu.0FN5EDLwgTN5QzW}`

**Solution:**

```nasm
mov rdi, 0x1337
```

# Level 2

**Flag:** `pwn.college{QBjRFYntHnoj3rkLur4EXebUIj9.dBTM4MDLwgTN5QzW}`

**Solution:**

```nasm
mov rax, 0x1337
mov r12, 0xCAFED00D1337BEEF
mov rsp, 0x31337
```

# Level 3

**Flag:** `pwn.college{Ebrs04nwSsD5aOfw7fm6wA88R5X.0VN5EDLwgTN5QzW}`

**Solution:**

```nasm
add rdi, 0x331337
```

# Level 4

**Flag:** `pwn.college{EFv6xudMMr5h-otWfjBUPRbpg3E.0lN5EDLwgTN5QzW}`

**Solution:**

```nasm
imul rsi, rdi
add rsi, rdx
mov rax, rsi
```

# Level 5

**Flag:** `pwn.college{w2uOOaP5D1gMvke9ec-a0RBqhu9.01N5EDLwgTN5QzW}`

**Solution:**

```nasm
mov rax, rdi
div rsi
```

# Level 6

**Flag:** `pwn.college{gKS3YRXZYnAE-ezYbH5zEf9Et0d.0FO5EDLwgTN5QzW}`

**Solution:**

```nasm
mov rax, rdi
div rsi
mov rax, rdx
```

# Level 7

**Flag:** `pwn.college{IGvBPSOwFVSo14erN-9EuJFLsuH.dFTM4MDLwgTN5QzW}`

**Solution:**

```nasm
mov ah, 0x42
```

# Level 8

**Flag:** `pwn.college{Y2yJWO45UL0zg-x4Y9vC2gZLDgd.0VO5EDLwgTN5QzW}`

**Solution:**

```nasm
mov al, dil
mov bx, si
```

# Level 9

**Flag:** `pwn.college{EqGE232wvRjQL-gcq-OgZ4028X5.0FMwIDLwgTN5QzW}`

**Solution:**

```nasm
shr rdi, 32
mov al, dil
```

# Level 10

**Flag:** `pwn.college{cfD_PJ0YKkhPGubsPFi8T-FQRyb.0VMwIDLwgTN5QzW}`

**Solution:**

```nasm
and rdi, rsi
and rax, rdi
```


# Level 11

**Flag:** `pwn.college{cp_HzeKjIkggwDDOR-2Yr72qWe9.0lMwIDLwgTN5QzW}`

**Solution:**

```nasm
and rdi, 1
and rax, rdi
xor rax, 1
```

# Level 12

**Flag:** `pwn.college{0h-rvYfa3rLhhbfHZ6TsnTEe_aa.dJTM4MDLwgTN5QzW}`

**Solution:**

```nasm
mov rax, [0x404000]
```

# Level 13

**Flag:** `pwn.college{IwX5iXXZHdO-91ODfJgJkEj7M7W.dNTM4MDLwgTN5QzW}`

**Solution:**

```nasm
mov [0x404000], rax
```

# Level 14

**Flag:** `pwn.college{UNli4mAqlIf6vnkmNDXE5FAhKAz.01MwIDLwgTN5QzW}`

**Solution:**

```nasm
mov rax, [0x404000]
mov rdi, [0x404000]
add rdi, 0x1337
mov [0x404000], rdi
```

# Level 15

**Flag:** `pwn.college{QMcDyEpx8D_WZyOFdWjlbqVwFaj.dRTM4MDLwgTN5QzW}`

**Solution:**

```nasm
mov al, [0x404000]
```

# Level 16

**Flag:** `pwn.college{MjGw7uMgylNjJLnFXPqG7mYhwWO.0FNwIDLwgTN5QzW}`

**Solution:**

```nasm
mov al, [0x404000]
mov bx, [0x404000]
mov ecx, [0x404000]
mov rdx, [0x404000]
```


# Level 17

**Flag:** `pwn.college{YFwBLWRZVNwXx6YEveR7OFEcNZo.0VNwIDLwgTN5QzW}`

**Solution:**

```nasm
mov rax, 0xdeadbeef00001337
mov rcx, 0xc0ffee0000
mov [rdi], rax
mov [rsi], rcx
```

# Level 18

**Flag:** `pwn.college{IJggd9mUypkIKHzrIQ1SZkziTPk.0lNwIDLwgTN5QzW}`

**Solution:**

```nasm
mov rax, [rdi]
mov rbx, [rdi + 8]
add rax, rbx
mov [rsi], rax
```

# Level 19

**Flag:** `pwn.college{IkI7MnMpt4ktrKILRFRFEaCQ_3D.01NwIDLwgTN5QzW}`

**Solution:**

```nasm
pop rax
sub rax, rdi
push rax
```

# Level 20

**Flag:** `pwn.college{40F97iOd52OHOwskB-Ad9hcC8Eh.0FOwIDLwgTN5QzW}`

**Solution:**

```nasm
push rdi
push rsi
pop rdi
pop rsi
```

# Level 21

**Flag:** `pwn.college{o2JCMwriC37kEnyt6VfFcZHcOQe.0VOwIDLwgTN5QzW}`

**Solution:**

```nasm
mov rax, [rsp]
add rax, [rsp + 8]
add rax, [rsp + 16]
add rax, [rsp + 24]
mov rbx, 4
div rbx
push rax
```

# Level 22

**Flag:** `pwn.college{kU1f5xkThpbUVs8HQLdMBj8CwDJ.dVTM4MDLwgTN5QzW}`

**Solution:**

```nasm
mov rax, 0x403000
jmp rax
```

# Level 23

**Flag:** `pwn.college{oekOH3Za6GBE56E49pj1lk7eezp.dZTM4MDLwgTN5QzW}`

**Solution:**

```nasm
    jmp rel_jump
    .rept 0x51
    nop
    .endr
rel_jump:
    mov rax, 0x1
```

# Level 24

**Flag:** `pwn.college{MVjOB77dtyqlNjM2VaFqFs-cLcz.0FMxIDLwgTN5QzW}`

**Solution:**

```nasm
    jmp jmpret
    .rept 0x51
    nop
    .endr
jmpret:
    pop rdi
    mov rax, 0x403000
    jmp rax
```

# Level 25

**Flag:** `pwn.college{wbGBl4gCUv_RWeWLz-UHRUXgSMM.0VMxIDLwgTN5QzW}`

**Solution:**

```nasm
    cmp DWORD PTR [rdi], 0x7f454c46
    je case_1

    cmp DWORD PTR [rdi], 0x00005a4d
    je case_2

    mov  eax, DWORD PTR [rdi + 4]
    imul eax, DWORD PTR [rdi + 8]
    imul eax, DWORD PTR [rdi + 12]
    jmp done

case_1:
    mov eax, DWORD PTR [rdi + 4]
    add eax, DWORD PTR [rdi + 8]
    add eax, DWORD PTR [rdi + 12]
    jmp done

case_2:
    mov eax, DWORD PTR [rdi + 4]
    sub eax, DWORD PTR [rdi + 8]
    sub eax, DWORD PTR [rdi + 12]
    jmp done

done:
```

# Level 26

**Flag:** `pwn.college{Ehr1IQrh3eEHNW9rXd1VJywbvBc.0lMxIDLwgTN5QzW}`

**Solution:**

```nasm
    cmp rdi, 3
    jle less
    jmp default
less:
    jmp [rsi + rdi * 8]

default:
    jmp [rsi + 0x20]
```

# Level 27

**Flag:** `pwn.college{MEC6PMmONMu8I1wT8Fu18YWBESO.01MxIDLwgTN5QzW}`

**Solution:**

```nasm
    mov rcx, rsi
    jmp loop

loop:
    add rax, [rdi]
    add rdi, 8
    sub rcx, 1
    cmp rcx, 0
    jne loop
    div rsi
    jmp done

done:
    nop
```

# Level 28

**Flag:** `pwn.college{ABLl3CRuH_9ivZ9D3masMiwsWRo.0FNxIDLwgTN5QzW}`

**Solution:**

```nasm
    cmp rdi, 0
    je zero
    jmp loop

loop:
    mov bl, [rdi + rax]
    cmp bl, 0
    je default
    inc rax
    jmp loop

zero:
    mov rax, 0

default:
    nop
```

# Level 29

**Flag:** `pwn.college{Q1NHsRgwwRR0aQz6pv5z-w_Q624.0VNxIDLwgTN5QzW}`

**Solution:**

```nasm
    mov rcx, rdi
    cmp rcx, 0
    je default

loop:
    mov rbx, [rcx]
    cmp rbx, 0
    je default

    cmp bl, 0x5a
    jg skip

    mov rdi, rbx

    mov rdx, 0x403000
    call rdx

    mov [rcx], al

    inc rsi
    jmp skip

skip:
    inc rcx
    jmp loop

default:
    mov rax, rsi
    ret
```

# Level 30

**Flag:** `pwn.college{oa22yAm0HSk9uCPMrtSMeFP7ax_.0lNxIDLwgTN5QzW}`

**Solution:**

```nasm
    push 0
    mov rbp, rsp
    sub rsp, 0xff
    mov r8, 0

l1:
    cmp r8, rsi
    je reset
    xor rax, rax
    mov al, byte ptr[rdi + r8]
    mov rbx, rbp
    sub rbx, rax
    inc byte ptr [rbx]
    inc r8
    jmp l1

reset:
    xor r8, r8

l2:
    cmp r8, 0xff
    je default
    mov rbx, rbp
    sub rbx, r8
    mov rax, 0
    mov al, byte ptr [rbx]

    cmp rax, r9
    jle l3
    mov r9, rax
    mov rdx, r8

l3:
    inc r8
    jmp l2

default:
    mov rax, rdx
    leave
    ret
```

