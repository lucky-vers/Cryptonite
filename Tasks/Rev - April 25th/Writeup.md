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

```
mov rdi, 0x1337
```

# level2

**Flag:** `pwn.college{QBjRFYntHnoj3rkLur4EXebUIj9.dBTM4MDLwgTN5QzW}`

**Solution:**

```
mov rax, 0x1337
mov r12, 0xCAFED00D1337BEEF
mov rsp, 0x31337
```
