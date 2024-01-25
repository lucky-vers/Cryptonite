**Flag:** `KCTF{kN1gHT_aRm0uRy_aCC3ss_GranTed}`

We recieve a binary file `knight_armoury`. Importing it into binaryninja, we come across the following code.

```c
void var_78;
if (sub_401a5e(&var_78) == 0)
{
    sub_412830("Invalid pass key.");
}
else
{
    sub_412830("Pass key is valid. Here is your …");
    sub_412a50(0xa);
    sub_412a50(0xa);
    sub_412830("      /| ________________");
    sub_412830("O|===|* >________________>");
    sub_412830("      \|");
    sub_412a50(0xa);
    sub_412a50(0xa);
    sub_404eb0("cat flag.txt");
}
*(uint64_t*)((char*)fsbase + 0x28);
if (rax == *(uint64_t*)((char*)fsbase + 0x28))
{
    return 0;
}
sub_42cbf0();
```

Going into function `sub_401a5e`, we get

```c
uint64_t sub_401a5e(int64_t arg1)
{
    sub_401a2e();
    int32_t rax_2;
    rax_2 = j_sub_41eff0(arg1, "IaMaKnight", "IaMaKnight") == 0;
    return ((uint64_t)rax_2);
}
```

It seems to be performing some operations on the string "IaMaKnight". I try using Ceasar cipher iterations on it.

```py
import os

def rotate_char(char, shift):
    if char.isalpha():
        base = ord('a') if char.islower() else ord('A')
        return chr((ord(char) - base + shift) % 26 + base)
    else:
        return char

def rotate_string(input_string, shift):
    rotated_string = ''
    for char in input_string:
        rotated_string += rotate_char(char, shift)
    return rotated_string

def main():
    original_string = "IaMaKnight"

    for i in range(25):
        original_string = rotate_string(original_string, i)
        print(original_string)
        os.system(f"echo '{original_string}' | ./knight_armoury | grep 'Pass key is valid.'")

if __name__ == "__main__":
    main()
```

And sure enough, when the pass key is `YqCqAdywxj`, we get our flag

```
~/Downloads $ python3 main.py
IaMaKnight
JbNbLojhiu
LdPdNqljkw
OgSgQtomnz
SkWkUxsqrd
XpBpZcxvwi
DvHvFidbco
KcOcMpkijv
SkWkUxsqrd
BtFtDgbzam
LdPdNqljkw
WoAoYbwuvh
IaMaKnight
VnZnXavtug
JbNbLojhiu
YqCqAdywxj
cat: flag.txt: No such file or directory
Enter your pass key to access knight armoury >> Pass key is valid. Here is your sword
```

```
~/Downloads $ echo YqCqAdywxj | nc 198.58.104.183 11337
              {}
             {{}}
             {{}}
              {}
            .-''-.
           /  __  \
          /.-'  '-.\
          \::.  .::/
           \'    '/
      __ ___)    (___ __
    .'   \\        //   `.
   /     | '-.__.-' |     \
   |     |  '::::'  |     |
   |    /    '::'    \    |
   |_.-;\     __     /;-._|
   \.'^`\    \/    //`^'./
   /   _.-._ _||_ _.-._   \
  `\___\    '-..-'    /___/`
       /'---.  `\.---'\`
in    ||    |`\\\|    || the
world ||    | || |    || of
      |;.__.' || '.__.;|
      |       ||       |
      {{{{{{{{||}}}}}}}}
hackers|      ||      |
we     |.-==-.||.-==-.| are
       <.    .||.    .>
        \'=='/||\'=='/
        |   / || \   |
knights |   | || |   |
        |   | || |   |
        /^^\| || |/^^\
       /   .' || '.   \
kctf  /   /   ||   \   \ 2024
     (__.'    \/    '.__)
Enter your pass key to access knight armoury >> Pass key is valid. Here is your sword


      /| ________________
O|===|* >________________>
      \|



KCTF{kN1gHT_aRm0uRy_aCC3ss_GranTed}
```

