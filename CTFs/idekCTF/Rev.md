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

