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

We need to go to the addres `0x080485e5` and avoid the address `0x080485A8`

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
