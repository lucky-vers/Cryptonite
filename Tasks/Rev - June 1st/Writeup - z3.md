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

**Flag** `pwned{100ks_g0Od_D03snT_w0rK}`

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

