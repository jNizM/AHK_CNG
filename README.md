# AHK implementation for CNG
Cryptography API: Next Generation (CNG) is the long-term replacement for the CryptoAPI.  
CNG is designed to be extensible at many levels and cryptography agnostic in behavior.


## Creating a Hash with CNG

### Hashing Algorithm
* MD2, MD4, MD5
* SHA1
* SHA2 (SHA256, SHA384, SHA512)
* PBKDF2


## Encrypt and Decrypt with CNG

### Tested Encryption Algorithm
* AES (EBC / CBC / CFB) with Key + IV
* DES (ECB / CBC)
* RC2
* RC4



## Examples

**Create a SHA-1 Hash from String**
```AutoHotkey
MsgBox % Crypt.Hash.String("SHA1", "The quick brown fox jumps over the lazy dog")
; -> 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12
```

**Create a SHA-256 Hash with HMAC from String**
```AutoHotkey
MsgBox % Crypt.Hash.HMAC("SHA256", "The quick brown fox jumps over the lazy dog", "Secret Salt")
; -> 68dba4b3a6d5c36b6e3567e1a925fe87c7386162e8fb6e2e9f17ade4aa7dc262
```

**Create a SHA-256 Hash from a File**
```AutoHotkey
MsgBox % Crypt.Hash.File("SHA256", "C:\Program Files\AutoHotkey\AutoHotkey.exe")
; -> 0a9964fe0e0fb3f0679df317a65f9945c474dab8c4370b45b93da64a8b201b9f
```

**Create a PBKDF2 Hash with SHA-1, 1500 Iterations and a Keysize of 192 from a String**
```AutoHotkey
MsgBox % Crypt.Hash.PBKDF2("SHA1", "The quick brown fox jumps over the lazy dog", "Secret Salt", 1500, 192)
; -> 531c1bbae7c3de019d1f53adcac7d85bf2b04caba9d6d6d1
```

**Encrypt a String with AES + CBC and with Key + IV and Base64 Output**
```AutoHotkey
MsgBox % Crypt.Encrypt.String("AES", "CBC", "abcdefghijklmnop", "1234567890123456", "1234567890123456")
; -> Nn9CFFuC+/O84cV1NiwLYoyd25Z9nmWv16dIFKzf2b4=
```

**Decrypt a String with AES + CBC and with Key + IV and Base64 Input**
```AutoHotkey
MsgBox % Crypt.Decrypt.String("AES", "CBC", "Nn9CFFuC+/O84cV1NiwLYoyd25Z9nmWv16dIFKzf2b4=", "1234567890123456", "1234567890123456")
; -> abcdefghijklmnop
```

**Encrypt a String with AES + ECB + Key and Hexraw Output**
```AutoHotkey
MsgBox % Crypt.Encrypt.String("AES", "ECB", "abcdefghijklmnop", "1234567890123456",,, "HEXRAW")
; -> fcad715bd73b5cb0488f840f3bad7889050187a0cde5a9872cbab091ab73e553
```

**Decrypt a String with AES + ECB + Key and Hexraw Input**
```AutoHotkey
MsgBox % Crypt.Decrypt.String("AES", "ECB", "fcad715bd73b5cb0488f840f3bad7889050187a0cde5a9872cbab091ab73e553", "1234567890123456",,, "HEXRAW")
; -> abcdefghijklmnop
```



## Questions / Bugs / Issues
Report any bugs or issues on the [AHK Thread](https://www.autohotkey.com/boards/viewtopic.php?f=6&t=23413). Same for any questions.


## Copyright and License
[MIT License](LICENSE)


## Donations (PayPal)
[Donations are appreciated if I could help you](https://www.paypal.me/smithz)