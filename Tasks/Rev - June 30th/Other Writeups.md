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
    void *file_contents;
    int possibly_file_size;
    void *copy_of_contents;
    void *possible_output_ptr;
    int v7;
    long double v8;
    int v10[4];

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
    unsigned __int8 *copied_contents;
    int result;
    unsigned __int8 *end_of_file_ptr;
    int copied_contents_value;
    int out_ptr[259];

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
  int v3;
  long double result;
  long double v5;
  long double v6;
  double result_copy;

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
  char v3;
  char v4;
  long double v5;

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

# HackTheBox

## Encryption Bot

**Flag:** `HTB{3nCrypT10N_W1tH_B1Ts!!}`

We're given a `flag.enc` and a binary.

Opening the binary, we find it needs an input of exactly 27 characters.

```c
result = strlen(a1);
if ( (_DWORD)result != 27 )
{
    puts("I'm encrypt only specific length of character.");
    puts("(-_-) Find it (-_-)");
    exit(1);
}
```

After this check, it calls another function which seems to create a large array, store the character in the input in it at an index, and perform two functions on every character.

```c
__int64 __fastcall sub_131D(const char *a1)
{
    size_t v1;
    char v3[2124];
    int i;

    for ( i = 0; ; ++i )
    {
        v1 = i;
        if ( v1 >= strlen(a1) )
            break;
        *&v3[4 * i + 2000] = a1[i];
        sub_11D9(*&v3[4 * i + 2000], v3);
    }
    sub_129F();
    return 0LL;
}
```

The first function streams the data into a file `data.dat` after modifying it.

```c
__int64 __fastcall sub_11D9(int a1)
{
    int v3[20];
    FILE *stream;
    int j;
    int i;

    stream = fopen("data.dat", "a");
    for ( i = 0; i <= 7; ++i )
    {
        v3[i] = a1 % 2;
        a1 /= 2;
    }
    for ( j = 7; j >= 0; --j )
        fprintf(stream, "%d", v3[j]);
    fclose(stream);
    return 0LL;
}
```

The other one seems to modify `data.dat` and further change based on its index.

```c
int sub_14BA()
{
    int v1[400];
    int v2;
    char v3;
    FILE *stream;
    unsigned int j;
    unsigned int v6;
    int v7;
    int i;

    stream = fopen("data.dat", "r+");
    sub_1291();
    for ( i = 1; i <= 216; ++i )
    {
        v3 = fgetc(stream);
        if ( v3 == 48 )
        {
            v1[i - 1] = 0;
        }
        else if ( v3 == 49 )
        {
            v1[i - 1] = 1;
        }
        if ( i && !(i % 6) )
        {
            v7 = i - 1;
            v6 = 0;
            for ( j = 0; j <= 5; ++j )
            {
                v2 = sub_13AB(j);
                v6 += v2 * v1[v7--];
            }
            sub_13E9(v6);
        }
    }
    return fclose(stream);
}
```

This changes the character if its index is a multiple of 6.

```c
__int64 __fastcall sub_13AB(int a1)
{
    unsigned int v3;

    v3 = 1;
    while ( a1 )
    {
        v3 *= 2;
        --a1;
    }
    sub_129F();
    return v3;
}
```

This further prints the character at the index given to it in the function.

```c
__int64 __fastcall sub_13E9(int a1)
{
    char v2[400];

    strcpy(v2, "RSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQabcdefghijklmnopqrstuvwxyz");
    memset(&v2[63], 0, 337);
    putchar(v2[a1]);
    return 0LL;
}
```

So this executable seems to encrypt data by taking a 27 character string and creating a 36 character ciphertext by using a coded list and taking an index from it, then padding the binary to 6 bits.

I looked around for writeups and saw this solve script, which I modified and used to get the flag.


```py
data = "RSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQabcdefghijklmnopqrstuvwxyz"
flag_encrypt = "9W8TLp4k7t0vJW7n3VvMCpWq9WzT3C8pZ9Wz"
index = [data.index(char) for char in flag_encrypt if char in data]

binary = ''.join(format(num, '06b') for num in index)
binary_chunks = [binary[i:i+8] for i in range(0, len(binary), 8)]

flag = ''.join([chr(int(chunk, 2)) for chunk in binary_chunks])
print(flag)
```
