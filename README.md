# AHK implementation for CNG
Cryptography API: Next Generation (CNG) is the long-term replacement for the CryptoAPI.  
CNG is designed to be extensible at many levels and cryptography agnostic in behavior.

[![AHK](https://img.shields.io/badge/ahk-2.0--beta.3%20(x64)-C3D69B.svg?style=flat-square)]()
[![OS](https://img.shields.io/badge/os-windows%2011%20(x64)-C3D69B.svg?style=flat-square)]()


## Creating a Hash with CNG

### Hash Algorithm Identifiers
* MD2
* MD4
* MD5
* SHA1
* SHA256
* SHA384
* SHA512
* PBKDF2


## Encrypt and Decrypt with CNG

### Encryption Algorithm Identifiers
* AES + ECB [Key]
* AES + CBC [Key + IV]
* AES + CFB [Key + IV]
* DES + ECB [Key]
* DES + CBC [Key + IV]
* RC2 [Key]
* RC4 [Key]



## Examples

**Create a SHA-1 Hash from String**
```AutoHotkey
MsgBox Hash.String("SHA1", "The quick brown fox jumps over the lazy dog")
; -> 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12
```

**Create a SHA-256 Hash with HMAC from String**
```AutoHotkey
MsgBox Hash.HMAC("SHA256", "The quick brown fox jumps over the lazy dog", "Secret Salt")
; -> 68dba4b3a6d5c36b6e3567e1a925fe87c7386162e8fb6e2e9f17ade4aa7dc262
```

**Create a SHA-256 Hash from a File**
```AutoHotkey
MsgBox Hash.File("SHA256", "C:\Program Files\AutoHotkey\AutoHotkey.exe")
; -> c93fde911140a7330f6d2d89bdb8e011b86153b43d64c7e2b66a741abacf9472
```

**Create a PBKDF2 Hash with SHA-1, 1500 Iterations and a Keysize of 192 from a String**
```AutoHotkey
MsgBox Hash.PBKDF2("SHA1", "The quick brown fox jumps over the lazy dog", "Secret Salt", 1500, 192)
; -> 531c1bbae7c3de019d1f53adcac7d85bf2b04caba9d6d6d1
```

**Encrypt a String with AES + CBC and with Key + IV and Base64 Output**
```AutoHotkey
MsgBox Encrypt.String("AES", "CBC", "abcdefghijklmnop", "1234567890123456", "1234567890123456")
; -> Nn9CFFuC+/O84cV1NiwLYoyd25Z9nmWv16dIFKzf2b4=
```

**Decrypt a String with AES + CBC and with Key + IV and Base64 Input**
```AutoHotkey
MsgBox Decrypt.String("AES", "CBC", "Nn9CFFuC+/O84cV1NiwLYoyd25Z9nmWv16dIFKzf2b4=", "1234567890123456", "1234567890123456")
; -> abcdefghijklmnop
```

**Encrypt a File with AES + ECB with Key**
```AutoHotkey
Encrypt.File("AES", "ECB", "test.txt", "test.enc", "1234567890123456")
```

**Decrypt a File with AES + ECB with Key**
```AutoHotkey
Decrypt.File("AES", "ECB", "test.enc", "test.txt", "1234567890123456")
```

**HashCalc (Gui)**

[![HashCalc](https://raw.githubusercontent.com/jNizM/HashCalc/master/img/HashCalc_01.png)](https://github.com/jNizM/HashCalc)


## Questions / Bugs / Issues
Report any bugs or issues on the [AHK Thread](https://www.autohotkey.com/boards/viewtopic.php?f=6&t=96117) ([v1.1](https://www.autohotkey.com/boards/viewtopic.php?f=6&t=23413)). Same for any questions.


## Copyright and License
[![MIT License](https://img.shields.io/github/license/jNizM/AHK_CNG.svg?style=flat-square&color=C3D69B)](LICENSE)


## Donations (PayPal)
[![PayPal](https://img.shields.io/badge/paypal-donate-B2A2C7.svg?style=flat-square)](https://www.paypal.me/smithz)