# Lock code

We're given a 3 digit passcode with some constraints. Entering those into z3 we get the solution as **[3 9 4]**.

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
