# sonda

**Flag:** `flag{6n|L0V"6>f\$JE{uY}`

We're given a binary file that takes in a seed and uses `srand` to make a valid passphrase. Using z3 we find out the seed to be **17**, the passphrase to be `6n|L0V"6>f\$JE{uY`, and thus the valid flag to be `flag{6n|L0V"6>f\$JE{uY}`

```py
import ctypes
from z3 import *

# Load the C standard library
libc = ctypes.CDLL('libc.so.6')

# Declare the functions we'll use
libc.srand.argtypes = [ctypes.c_uint]
libc.rand.restype = ctypes.c_int

# Create a Z3 solver instance
solver = Solver()

# Declare the seed variable
seed = Int('seed')

# Add the constraints for seed
solver.add(seed % 17 == 0)
solver.add(seed <= 20)
solver.add(seed > 0)

# Check for a valid seed
if solver.check() == sat:
    model = solver.model()
    seed_value = model[seed].as_long()
    print(f"Valid seed found: {seed_value}")

    # Now, set the random seed using libc's srand and generate the sequence
    libc.srand(seed_value)
    ptr = [2 * seed_value + libc.rand() % (5 * seed_value)]
    for i in range(1, seed_value):
        v5 = ptr[i - 1]
        ptr.append(v5 + libc.rand() % 94 + 33)

    # Create a new Z3 solver for the string s
    solver2 = Solver()
    s = [Int(f's[{i}]') for i in range(seed_value)]

    # Add the constraints for the string s
    for j in range(seed_value):
        v9 = Sum(s[:j+1])
        solver2.add(v9 == ptr[j])

    # Add the constraints for s to be valid ASCII characters
    for i in range(seed_value):
        solver2.add(s[i] >= 0x20, s[i] <= 0x7E)

    if solver2.check() == sat:
        model2 = solver2.model()
        s_value = ''.join(chr(model2[s[i]].as_long()) for i in range(seed_value))
        print(f"Valid string found: {s_value}")
        print(f"flag{{{s_value}}}")
    else:
        print("No valid string found")
else:
    print("No valid seed found")
```

# Lock code

**Solution:** `[3 9 4]`

We're given a 3 digit passcode with some constraints. Entering those into z3 we get the solution.

```py
from z3 import *

# Initialize the Z3 solver
solver = Solver()

# Define the variables for the 3-digit code
code = [Int(f'code_{i}') for i in range(3)]
for i in range(3):
    solver.add(code[i] >= 0, code[i] <= 9)

# Define constraints based on the clues
# Clue 1: 291 -> One number is correct and well placed
solver.add(Sum([If(code[i] == 2, 1, 0) for i in range(3)]) +
           Sum([If(code[i] == 9, 1, 0) for i in range(3)]) +
           Sum([If(code[i] == 1, 1, 0) for i in range(3)]) == 1)
solver.add(Or(code[0] == 2, code[1] == 9, code[2] == 1))

# Clue 2: 245 -> One number is correct but wrong placed
solver.add(Sum([If(code[i] == 2, 1, 0) for i in range(3)]) +
           Sum([If(code[i] == 4, 1, 0) for i in range(3)]) +
           Sum([If(code[i] == 5, 1, 0) for i in range(3)]) == 1)
solver.add(And(code[0] != 2, code[1] != 4, code[2] != 5))

# Clue 3: 463 -> Two numbers are correct but wrong placed
solver.add(Sum([If(code[i] == 4, 1, 0) for i in range(3)]) +
           Sum([If(code[i] == 6, 1, 0) for i in range(3)]) +
           Sum([If(code[i] == 3, 1, 0) for i in range(3)]) == 2)
solver.add(And(code[0] != 4, code[1] != 6, code[2] != 3))

# Clue 4: 578 -> Nothing is correct
solver.add(Not(Or([code[i] == 5 for i in range(3)])))
solver.add(Not(Or([code[i] == 7 for i in range(3)])))
solver.add(Not(Or([code[i] == 8 for i in range(3)])))

# Clue 5: 569 -> One number is correct but wrong placed
solver.add(Sum([If(code[i] == 5, 1, 0) for i in range(3)]) +
           Sum([If(code[i] == 6, 1, 0) for i in range(3)]) +
           Sum([If(code[i] == 9, 1, 0) for i in range(3)]) == 1)
solver.add(And(code[0] != 5, code[1] != 6, code[2] != 9))

# Solve the constraints
if solver.check() == sat:
    model = solver.model()
    solution = [model[code[i]].as_long() for i in range(3)]
else:
    solution = None

print(solution)
```

# Custom Crypto

**Flag:** `pwned{100ks_g0Od_D03snT_w0rK}`

We're given an encryption method in `enc.py` and its result in `enc.txt`. It uses a message in `flag.txt` and a key in `key.txt`. We solve this adding constraints in z3 to get the flag.

```py
from z3 import *

# Given encrypted values
encrypted_values = [28, 24, 1, 9, 9, 19, 93, 93, 94, 2, 26, 13, 6, 92, 61, 11, 15, 39, 91, 91, 20, 28, 54, 8, 17, 89, 23, 61]

# Initialize Z3 solver
solver = Solver()

# Create BitVec variables for the encrypted and decrypted characters
enc = [BitVec(f"enc_{i:02}", 8) for i in range(0, len(encrypted_values))]
dec = [BitVec(f"dec_{i:02}", 8) for i in range(0, len(encrypted_values))]
key = [BitVec(f"key_{i:02}", 8) for i in range(0, 4)]

# Add known prefix constraint to guide the solver
known_prefix = 'pwned'
for i, v in enumerate(known_prefix):
    solver.add(dec[i] == ord(v))

# Add constraints for encryption/decryption relationship
for i in range(len(encrypted_values)):
    chunk = i // 4
    offset = i % 4
    solver.add(enc[i] == encrypted_values[i])
    solver.add((dec[i] + chunk) ^ key[offset] == enc[i])
    # Ensure the decrypted values are within the ASCII printable range
    solver.add(dec[i] >= 32)
    solver.add(dec[i] <= 126)

# Check for a solution
if solver.check() == sat:
    model = solver.model()
    solution = sorted([(d, model[d]) for d in model], key=lambda x: str(x[0]))
    filtered_solution = [x for x in solution if str(x[0]).startswith("dec")]
    flag = ''.join(map(lambda x: chr(int(str(x[1]))), filtered_solution))
    print(f"Flag: {flag}")
else:
    print("No solution found")
```

# MathGenMe

**Flag:** `pwned{0i_m4t3_y0u_g0t_a_l0ic3nse_f0r_th4t_m4th?}`

We're given a license key and an executable that generates them. We open the binary to find it generates keys by transforming 4-byte blocks of the password. We reverse this process using z3 for the given license key to get the flag.

```py
from z3 import *

# The given license key
license_key = "04b2fc467e104c0c610e3bf0a009a9f3621905df1997ce0b6cd6a3ea68af4d4deaaf024906f7b259ba32035ac4dad586"
license_bytes = [int(license_key[i:i+2], 16) for i in range(0, len(license_key), 2)]

# Initialize Z3 solver
solver = Solver()

# Variables for the password characters
password = [BitVec(f's{i}', 8) for i in range(48)]
constraints = []

# Add constraints that password characters are in ASCII range (printable characters)
for p in password:
    constraints.append(p >= 32)
    constraints.append(p <= 126)

# Apply the transformations for each block of 4 characters
for i in range(0, 48, 4):
    s0 = password[i]
    s1 = password[i+1]
    s2 = password[i+2]
    s3 = password[i+3]

    v0 = 33 * s3 + 89 * s2 + 103 * s1 + 66 * s0
    v1 = 73 * s0 + -125 * s1 + -103 * s2 + 51 * s3
    v2 = 113 * s1 + s3 + 54 * s0 + 8 * s2
    v3 = 25 * s2 + 23 * s3 + 119 * s0 + 3 * s1

    constraints.append(v0 & 0xFF == license_bytes[i])
    constraints.append(v1 & 0xFF == license_bytes[i+1])
    constraints.append(v2 & 0xFF == license_bytes[i+2])
    constraints.append(v3 & 0xFF == license_bytes[i+3])

# Add constraints to the solver
solver.add(constraints)

# Check if the solution exists and get the model
if solver.check() == sat:
    model = solver.model()
    decoded_password = ''.join(chr(model[p].as_long()) for p in password)
    print(f"Password: {decoded_password}")
else:
    print("No solution found")
```

# server

**Solution:** `sup3r_s3cr3t_p4ssw0rd_unbr3ak4bl`

Given is a executable that starts a server. Entering the correct password gives us the flag, but this doesn't work on the binary provided for some reason.

The password is checked through 4 functions and various operations. We reverse them to get the password. I had to look at the solutions for this as my z3 script wasn't working no matter what I tried.

I also used the `manual.py` file to get the answer, as the given z3 solve script didn't run on my weak machine despite me leaving it there for hours.

```py
arrs = [
    "0D 02 0B 13 1B 09 0A 00 10 06 07 1A 05 12 04 19 11 0E 17 16 0F 1C 1D 18 08 15 01 03 1F 0C 1E 14",
    "A8 5F 43 DF 90 15 A2 F5 77 48 49 6C 67 20 0E CD B6 C8 4A E7 89 2F A1 A6 E8 B7 E1 C6 58 A9 D4 5A 4D 9E 34 05 53 C2 76 D3 C5 B3 BF C9 AF 98 25 68 D9 2D E6 65 D7 59 D6 0A 31 8F 99 AA 7C C0 35 B5 ED 4B EB D5 8E 6B 9D 37 2E 62 0F 07 9B 87 B8 BD DE 69 C7 CF 66 46 60 04 D0 A7 F8 70 7E FA 9A 03 08 C4 F6 8B 79 33 23 DD DA C1 13 CE 16 EE 93 63 12 6F 83 0D 71 64 4C 51 00 BA EF 95 6E 22 E5 94 30 FB 14 41 7A 1C 2A 56 B9 38 42 F0 44 F3 F2 9F 52 4E D8 CB 24 32 BE 0C A3 09 85 01 1D A5 28 45 F4 47 CC AE C3 AB A0 92 72 57 AC 3E E3 B4 74 1B 81 4F DC 2B 50 02 27 B2 6D F1 54 FE 80 5E 3B 36 E2 FF 11 EA FD 1A 97 86 26 73 B1 D2 3A 1E 5D 39 7F 1F A4 91 5C 55 EC E4 29 8C F7 7D 18 82 BC 2C 75 40 BB 17 8D F9 D1 E9 0B 7B 10 CA 6A FC 19 3C 8A B0 AD 21 96 5B 06 61 3D 3F 88 78 DB 84 9C E0",
    "42 33 21 68 00 00 00 00 00 00 00 00 00 00 00 00",
    "50 21 50 EB 86 B0 44 65 4F 3E 44 0D 41 EA A2 EB 13 E4 B2 0C 4F FD F6 9E C9 30 45 0D 54 30 D7 11",
]

arrs = [[int(x, 16) for x in arr.split()] for arr in arrs]

src = [0] * 32

for i in range(32):
    src[i] = arrs[3][i] ^ arrs[2][i % 4]

arrs_1_reverse = {}
for i in range(256):
    arrs_1_reverse.update({arrs[1][i]: i})

src = [arrs_1_reverse[v] for v in src]

final = [0] * 32
for i in range(32):
    final[arrs[0][i]] = src[i]

print("Decrypted password:", ''.join([chr(f) for f in final]))
```

# sweet

**Solution:** `f1e391e593bd011`

A file `sweet.c` is given, which performs bit-shifts on a password. I used the solve script to answer this:

```py
from z3 import *

def find_solution():
    for input_len in range(1, 32):
        s = Solver()
        input_vars = [BitVec(f"i_{i}", 8) for i in range(input_len)]
        output = BitVecVal(0, 64)

        for i in range(input_len):
            output += ZeroExt(64 - 8, input_vars[i])
            output <<= 1

        s.add(output == 0x2d64a)

        if s.check() == sat:
            m = s.model()
            solution = sorted([(d, m[d]) for d in m], key=lambda x: str(x[0]))
            flag = "".join([f"{int(str(x[1]), 10):x}" for x in solution])
            return flag

print(find_solution())
```

