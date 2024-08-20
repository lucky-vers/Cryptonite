# idekCTF Report

## The Moon

We're given a lua file that when ran always seems to give us a message that says our flag is wrong. I tried solving this challenge but couldn't get anywhere past decompiling the lua bytecode. \\

After the CTF ended, I looked at this write-up explaining it

https://gist.github.com/TrixterTheTux/6ed0999479443823538fe2d1b8739458

Things I learned in this challenge:

- Lua reverse engineering
- Lua debugging

We're also given files `moon.idek` (a binary file) and `Dockerfile`.

The lua file `moon.lua` contains this:

```lua
flag = "idek{...}"

assert(arg[0] == "moon.lua", "Run me as 'lua moon.lua'")
assert(_VERSION == "Lua 5.1", "Unsupported Lua version (5.1 needed)")
assert(0xfffffffff ~= 0xffffffff, "Unsupported architecture (x64 needed)")

function from_hex(data)
    return data:gsub("(%x%x)", function(x) return string.char(tonumber(x, 16)) end)
end

file_loader, err = loadstring(from_hex([[1b4c756...]]), "file_loader")()
assert(err == nil, "something went really wrong")

function check_flag(...)
    local res, err = load(file_loader, "flag_checker")
    assert(err == nil, "something went wrong")

    return res(...)
end

assert(check_flag()(flag), "flag is wrong :(")
```

Decompiling the hex bytecode, we find out what the `file_loader` function does — read the file `moon.idek` and chunk by chunk XOR the data with an encryption key.

The bytecode also contains several integrity checks to prevent us accessing too much info.

The first check is to make sure we can't modify `moon.lua`, as it checks for the number of lines and the line length in it.

Subsequent checks include a CRC32 checksum along with others. Finally, the `flag_checker` function is loaded after all checks pass.

The flag checking function looks somewhat like this:

```lua
local secret_value = 2238572670
local constraints = {}
constraints[#constraints + 1] = function(flag) return (flag[1] + flag[2] + flag[3]) * secret_value == 123456789 end
constraints[#constraints + 1] = function(flag) return (flag[40] + flag[6] * flag[5]) * secret_value == 32152619259210 end
constraints[#constraints + 1] = function(flag) return (flag[6] * flag[8] + flag[22]) * secret_value == 13357563121890 end
constraints[#constraints + 1] = function(flag) return (flag[44] * flag[47] + flag[48]) * secret_value == 12997152922020 end
constraints[#constraints + 1] = function(flag) return (flag[48] * flag[11] + flag[35]) * secret_value == 5477787323490 end
constraints[#constraints + 1] = function(flag) return (flag[35] + flag[12] + flag[24]) * secret_value == 707388963720 end
constraints[#constraints + 1] = function(flag) return (flag[10] * flag[36] * flag[42]) * secret_value == 1480862831231070 end
constraints[#constraints + 1] = function(flag) return (flag[34] - flag[9] + flag[43]) * secret_value == 228334412340 end
constraints[#constraints + 1] = function(flag) return (flag[11] + flag[17] - flag[39]) * secret_value == 134314360200 end
.
.
.
```

Putting all these constraints into Z3, we can get the flag as `idek{th3_m0on_h4t3s_b31ng_t4mp3r3d_w1th_c3aec291}`

