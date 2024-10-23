# Do you even lift bro?

I solved this challenge along with Uday.

**Flag:** `flag{l1ftiN6_p41d_0ff!}`

Despite being a beginner challenge, it gave me insight on LLVM.

I first tried transpiling it into JavaScript using the `emscripten` package and `emcc` but kept getting errors in this.

We're given a file `swo.ll` which is LLVM IR (intermediate representation) —  a medium between high level C and low level assembly, that LLVM uses to translate any language to a common programming logic.

Uday managed to get it to compile to a binary, and I reversed the logic.

This did a few simple things:

- Make a bit using the `even()` function
- Run `even()` 8 times to get a single byte
- Use this byte to XOR the redacted flag.
- Repeat this XOR process 23 times for every char in the flag

Solve script:

```py
do_you = 0xDEAD  # Initialize do_you as needed
v6 = 0     # Initialize v6 as needed

def even():
    global do_you
    v1 = do_you & 1
    do_you = -(do_you & 1) & 0xB400 ^ (do_you >> 1)
    return v1

for i in range(23):
    for j in range(8):
        v2 = 2 * v6
        v6 = even() | v2

    print(hex(v6))
```

This gives the hex, which upon XORing with the encrypted array, gives the flag.

Things I learned in this:

- LLVM IR reversing, and the different ways to interpret/compile it.
- Simplifying the logic of code as much as possible. I tried feeding the entire logic of the code to GPT when only a small part of it mattered. Eventually I had to write the solve script for this by myself.

