**Flag:** `N0PS{r1CKUNr0111N6}`

We're given a reversed ELF binary disguised as an image. We first un-reverse it to get an executable.

```py
import sys

def reverse_file_bytes(input_file_path, output_file_path):
    # Open the input file in binary read mode
    with open(input_file_path, 'rb') as input_file:
        # Read the file content
        file_content = input_file.read()

    # Reverse the bytes
    reversed_content = file_content[::-1]

    # Open the output file in binary write mode
    with open(output_file_path, 'wb') as output_file:
        # Write the reversed bytes to the output file
        output_file.write(reversed_content)

input_file_path  = sys.argv[1]
output_file_path = sys.argv[2]
reverse_file_bytes(input_file_path, output_file_path)
```

Opening the file in ida, we can see the binary accepts 4 integer arguments, then first passes them to a function.

```c
__int64 __fastcall sub_1460(int a1, int a2, int a3, int a4)
{
  unsigned int v4; // r8d

  v4 = 0;
  if ( 3 * a4 + a3 + 4 * a2 - 10 * a1 != 28 )
    return 0;
  if ( 9 * a2 - 8 * a1 + 6 * a3 - 2 * a4 == 72 && a4 + -3 * a2 - 2 * a1 - 8 * a3 == 29 )
    LOBYTE(v4) = a3 + 5 * a1 + 7 * a2 - 6 * a4 == 88;
  return v4;
}
```

If this returns 0, the binary immediately exits. If it returns 1, it performs other operations, including `puts`. So we need to find values for the 4 arguments we pass that return 1. We do this using `z3`.

```py
from z3 import *

# Define integer variables
a1 = Int('a1')
a2 = Int('a2')
a3 = Int('a3')
a4 = Int('a4')

# Create a solver instance
solver = Solver()

# Add the constraints from the function
solver.add(3 * a4 + a3 + 4 * a2 - 10 * a1 == 28)
solver.add(9 * a2 - 8 * a1 + 6 * a3 - 2 * a4 == 72)
solver.add(a4 - 3 * a2 - 2 * a1 - 8 * a3 == 29)
solver.add(a3 + 5 * a1 + 7 * a2 - 6 * a4 == 88)

# Check if the constraints are satisfiable and print the solutions
if solver.check() == sat:
    model = solver.model()
    print(f"a1 = {model[a1]}")
    print(f"a2 = {model[a2]}")
    print(f"a3 = {model[a3]}")
    print(f"a4 = {model[a4]}")
else:
    print("No solution found")
```

Hence, we get the integer arguments as **-3**, **8**, **-7**, and **-9**. And sure enough, using them as arguments, we get the flag.

```
~/Downloads $ ./out.bin -3 8 -7 -9
N0PS{r1CKUNr0111N6}
```
