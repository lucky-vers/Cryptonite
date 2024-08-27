# Sekai Reverse Report

## Crackme

**Things I learned after writeup**

- A bit of android and React reversing
- Usage of `react-native-decompiler`
- HTTP unpinning using HTTP Toolkit

We're given an `.apk` file built using React Native. Using `react-native-decompiler` we find ~600 `.js` files.

We find a js function with a key and IV, hinting at AES encryption.

```js
var _ = {
    LOGIN: 'LOGIN',
    EMAIL_PLACEHOLDER: 'user@sekai.team',
    PASSWORD_PLACEHOLDER: 'password',
    BEGIN: 'CRACKME',
    SIGNUP: 'SIGN UP',
    LOGOUT: 'LOGOUT',
    KEY: 'react_native_expo_version_47.0.0',
    IV: '__sekaictf2023__',
};
```

Grepping for `AES` we find this function

```js
e.validatePassword = function (e) {
    if (17 !== e.length) return false;
    var t = module700.default.enc.Utf8.parse(module456.default.KEY),
    n = module700.default.enc.Utf8.parse(module456.default.IV);
    return (
        '03afaa672ff078c63d5bdb0ea08be12b09ea53ea822cd2acef36da5b279b9524' ===
            module700.default.AES.encrypt(e, t, {
                iv: n,
            }).ciphertext.toString(module700.default.enc.Hex)
    );
};
```

We use this script to decrypt the needed password

```py
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import binascii

# Given key and IV
key = b'react_native_expo_version_47.0.0'  # Convert key to bytes
iv = b'__sekaictf2023__'                   # Convert IV to bytes

# The ciphertext we need to decrypt (in hex format)
ciphertext_hex = '03afaa672ff078c63d5bdb0ea08be12b09ea53ea822cd2acef36da5b279b9524'

# Convert the hex ciphertext to bytes
ciphertext = binascii.unhexlify(ciphertext_hex)

# Create AES cipher object
cipher = AES.new(key[:32], AES.MODE_CBC, iv)  # Truncate the key to 32 bytes if necessary

# Decrypt and unpad the plaintext
plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

# Convert bytes to string
plaintext = plaintext.decode('utf-8')

print("Decrypted text:", plaintext)
```

Which gives us the password as `s3cr3t_SEKAI_P@ss`.

After this we found other functions which seemed to indicate that we need to access a Firebase database.

I didn't solve the challenge, Harshith did. He used HTTP Toolkit to send requests using the valid credentials, and after running it for a while, he got the flag as `SEKAI{15_React_N@71v3_R3v3rs3_H@RD???}`.


