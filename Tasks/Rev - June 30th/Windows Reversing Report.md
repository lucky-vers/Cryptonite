# Winassembly

**https://tryhackme.com/r/room/win64assembly**

A fairly rudimentary room. The first few modules are just simple learning of number systems, registers, and the like.

We're then introducted to more advanced concepts such as assembly instructions, compare flags, and calling conventions.

The last one I found most insightful, I finally understood what the `__fastcall` paramter meant in function definitions arising from Windows decompilation— its the Windows calling convention. A few more details of it are given below

- The first four non-floating-point parameters are passed left-to-right in registers `rcx`, `rdx`, `r8` and `r9` respectively.
- The first four floating-point parameters are passed in registers `xmm0` to `xmm3`.
- Any more than four parameters and they are pushed to the stack from right to left.
- A function's return value is passed to `rax` if it's a non-floating-point or `xmm0` if it's a float or double.

We also learn a bit about a different calling convention, `cdecl`.

The final module teaches us about the stack and the functioning of stack-frames on function calls.
