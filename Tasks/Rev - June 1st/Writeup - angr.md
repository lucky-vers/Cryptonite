# Level 00

**Flag:** `JXWVXRKX`

We find the expected address to be `0x804867d` and use angr to solve for it.

```py
import angr

def main():
    p = angr.pect('../problems/00_angr_find')
    init = p.factory.entry_state()
    s = p.factory.simgr(init)
    good = 0x804867d
    s.explore(find=good)

    if s.found:
        solution = s.found[0]
        print('Flag: ', solution.posix.dumps(0))

if __name__ == '__main__':
    main()
```

# Level 01

**Flag:** `HUJOZMYS`

We need to go to the addres `0x080485e5` and avoid the address `0x080485A8`.

```py
import angr
p = angr.pect('../problems/01_angr_avoid')
init = p.factory.entry_state()
s = p.factory.simgr(init)

good = 0x080485e5
bad = 0x080485A8

s.explore(find=good, avoid=bad)

if s.found:
    solution = s.found[0]
    print(solution.posix.dumps(0))
```

# Level 02

**Flag:** `HETOBRCU`

We find a path using the correct and incorrect outputs.

```py
import angr

# Load the binary
project = angr.Project('./02_angr_find_condition', auto_load_libs=False)

# Create an initial state at the entry point
initial_state = project.factory.entry_state()

# Use a simulation manager to manage exploration
simulation = project.factory.simulation_manager(initial_state)

# Define a function to find the 'Good job' address
def is_good_job(state):
    return b'Good Job.' in state.posix.dumps(1)

# Define a function to avoid the 'Try again' address
def is_try_again(state):
    return b'Try again.' in state.posix.dumps(1)

# Explore the binary to find a path to 'Good job' and avoid 'Try again'
simulation.explore(find=is_good_job, avoid=is_try_again)

# Check the results
if simulation.found:
    solution_state = simulation.found[0]
    print("Found a path to 'Good job'")
    print(solution_state.posix.dumps(0))  # Print the input that leads to 'Good job'
else:
    print("Could not find a path to 'Good job'")
```

We use the same solve script on the remaining levels to get their flags. Not sure whether this was supposed to be the way to do it.

# Level 03

**Flag:** `b9ffd04e ccf63fe8 8fd4d959`

# Level 04

**Flag:** `1704280884 2382341151`

# Level 05

**Flag:** `NAXTHGNR JVSFTPWE LMGAUHWC XMDCPALU`

# Level 06

**Flag:** `UBDKLMBV UNOERNYS`

# Level 07

**Flag:** `AZOMMMZM`
