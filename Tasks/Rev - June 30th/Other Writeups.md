# challenges.re

## Reverse Engineering challenge #43.

**Description:** `There is a small executable file, some utility. It opens another file, reads it, calculate something and prints a real number. Try to understand what it does.`

We're given an executable `unknown_utility_2_3.exe` which takes a filename and returns some sort of floating point value with it.

```
~/Downloads $ wine unknown_utility_2_3.exe unknown_utility_2_3.exe
6.062700
```

Running it on other files seems to give different results. I suspect this finds a file's entropy and returns it as a number.

Decompiling it in IDA, we see a few functions being called to it.

Looking at main, it seems to be calling a few functions to find the entropy

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
    void *file_contents; // eax
    int possibly_file_size; // edi
    void *copy_of_contents; // ebx
    void *possible_output_ptr; // esi
    int v7; // eax
    long double v8; // fst7
    int v10[4]; // [esp+1Ch] [ebp-10h] BYREF

    sub_402570();
    if ( argc != 2 )
      printf_0("Usage: %s <filename>\n", *argv);
    file_contents = read(argv[1], v10);
    possibly_file_size = v10[0];
    copy_of_contents = file_contents;
    possible_output_ptr = calloc(v10[0], 4u);
    v7 = entropy_finder(copy_of_contents, possible_output_ptr, possibly_file_size);
    v8 = entropy_calc(possible_output_ptr, v7, v10[0]);
    printf("%lf\n", v8);
    free(copy_of_contents);
    return 0;
}
```

The function `entropy_finder` decompiles to this

```c
int __cdecl entropy_finder(unsigned __int8 *file_contents, int output, int filesize)
{
    unsigned __int8 *copied_contents; // edx
    int result; // eax
    unsigned __int8 *end_of_file_ptr; // esi
    int copied_contents_value; // ecx
    int out_ptr[259]; // [esp+0h] [ebp-40Ch] BYREF

    memset(out_ptr, 0xFFu, 0x400u);
    if ( filesize <= 0 )
        return 0;
    copied_contents = file_contents;
    result = 0;
    end_of_file_ptr = &file_contents[filesize];
    do
    {
        while ( 1 )
        {
            copied_contents_value = *copied_contents;
            if ( out_ptr[copied_contents_value] == -1 )
                break;
            ++copied_contents;
            ++*(output + 4 * out_ptr[copied_contents_value]);
            if ( copied_contents == end_of_file_ptr )
                return result;
        }
        out_ptr[copied_contents_value] = result;
        ++copied_contents;
        ++result;
        ++*(output + 4 * out_ptr[copied_contents_value]);
    }
    while ( copied_contents != end_of_file_ptr );
    return result;
}
```

This does the following:

1. The outer do-while loop continues until `copied_contents` reaches `end_of_file_ptr`.
2. The inner while (1) loop:

    - Reads a byte from `file_contents` via `copied_contents_value`.
    - Checks if `out_ptr[copied_contents_value]` is -1 (i.e., this byte value hasn't been encountered before).
    - If not -1, it increments the value at `output + 4 * out_ptr[copied_contents_value]` and moves to the next byte.
    - If it reaches the end of the file, it returns `result`.

3. If `out_ptr[copied_contents_value]` is -1, it means this byte value hasn't been seen before:

    - It sets `out_ptr[copied_contents_value]` to `result`.
    - Moves to the next byte and increments `result`.
    - Increments the value at `output + 4 * out_ptr[copied_contents_value]`.

4. Returns the count of unique byte values in the file in `result`.

Now, moving to the next function `entropy_calc`

```c
long double __cdecl entropy_calc(int out_contents, int unique_bytes, int file_size)
{
  int v3; // ebx
  long double result; // fst7
  long double v5; // fst7
  long double v6; // fst7
  double result_copy; // [esp+18h] [ebp-24h]

  if ( unique_bytes <= 0 )
    return 0.0;
  v3 = 0;
  result = 0.0;
  do
  {
    result_copy = result;
    v5 = *(out_contents + 4 * v3++);
    v6 = v5 / file_size;
    sub_40296C(v6);
    result = result_copy - v6 * v6;
  }
  while ( v3 != unique_bytes );
  return result;
}
```

This calls another function, takes its square, and subtracts it from `result`, then loops through each unique byte and does the same.

Another function `sub_402570` is also called which modifies the number passed to it and returns a value based on whether the absolute value of the first argument minus 1 equals 0.29 or not.

```c
long double __cdecl sub_40296C(double a1)
{
  char v3; // c2
  char v4; // c0
  long double v5; // fst5

  _FST6 = a1;
  __asm { fxam }
  if ( v4 && !v3 )
    return a1;
  v5 = a1 - 1.0;
  if ( fabs(v5) > 0.29 )
    return __FYL2X__(_FST6, 1.0);
  else
    return __FYL2XP1__(v5, 1.0);
}
```

In general, this takes a file and calculates the amount of unique bytes in it, and prints it in floating point form.

