# AHK implementation for CNG (Cryptography API: Next Generation)


## Creating a Hash with CNG
### [MD2](src/hash/bcrypt_md2.ahk) / [MD2 + HMAC](src/hash/bcrypt_md2_hmac.ahk) & [MD2 File](src/hash/bcrypt_md2_file.ahk)
```AutoHotkey
MsgBox % bcrypt_md2("The quick brown fox jumps over the lazy dog")
; ==> 03d85a0d629d2c442e987525319fc471

MsgBox % bcrypt_md2_hmac("The quick brown fox jumps over the lazy dog", "Secret Salt")
; ==> 6c05fa7a6f6de43ea70cf4e20fc1c648

MsgBox % bcrypt_md2_file("C:\Windows\notepad.exe")
; ==> 69f8d340e8b74d454fbc06e876f5a49a
```

### [MD4](src/hash/bcrypt_md4.ahk) / [MD4 + HMAC](src/hash/bcrypt_md4_hmac.ahk) & [MD4 File](src/hash/bcrypt_md4_file.ahk)
```AutoHotkey
MsgBox % bcrypt_md4("The quick brown fox jumps over the lazy dog")
; ==> 1bee69a46ba811185c194762abaeae90

MsgBox % bcrypt_md4_hmac("The quick brown fox jumps over the lazy dog", "Secret Salt")
; ==> 54864ebb1c93bbbfaa860d8b2d567133

MsgBox % bcrypt_md4_file("C:\Windows\notepad.exe")
; ==> 831b14ab0a7dbccb969898dc2b425dd1
```

### [MD5](src/hash/bcrypt_md5.ahk) / [MD5 + HMAC](src/hash/bcrypt_md5_hmac.ahk) & [MD5 File](src/hash/bcrypt_md5_file.ahk)
```AutoHotkey
MsgBox % bcrypt_md5("The quick brown fox jumps over the lazy dog")
; ==> 9e107d9d372bb6826bd81d3542a419d6

MsgBox % bcrypt_md5_hmac("The quick brown fox jumps over the lazy dog", "Secret Salt")
; ==> ad8af8953b9f7f880887ab3bd7a7674a

MsgBox % bcrypt_md5_file("C:\Windows\notepad.exe")
; ==> 3b508cae5debcba928b5bc355517e2e6
```

### [SHA1](src/hash/bcrypt_sha1.ahk) / [SHA1 + HMAC](src/hash/bcrypt_sha1_hmac.ahk) & [SHA1 File](src/hash/bcrypt_sha1_file.ahk)
```AutoHotkey
MsgBox % bcrypt_sha1("The quick brown fox jumps over the lazy dog")
; ==> 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12

MsgBox % bcrypt_sha1_hmac("The quick brown fox jumps over the lazy dog", "Secret Salt")
; ==> d736602b0b10855afb5b0699232200a2284d9661

MsgBox % bcrypt_sha1_file("C:\Windows\notepad.exe")
; ==> 40f2e778cf1effa957c719d2398e641eff20e613
```

### [SHA256](src/hash/bcrypt_sha256.ahk) / [SHA256 + HMAC](src/hash/bcrypt_sha256_hmac.ahk) & [SHA256 File](src/hash/bcrypt_sha256_file.ahk)
```AutoHotkey
MsgBox % bcrypt_sha256("The quick brown fox jumps over the lazy dog")
; ==> d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592

MsgBox % bcrypt_sha256_hmac("The quick brown fox jumps over the lazy dog", "Secret Salt")
; ==> 68dba4b3a6d5c36b6e3567e1a925fe87c7386162e8fb6e2e9f17ade4aa7dc262

MsgBox % bcrypt_sha256_file("C:\Windows\notepad.exe")
; ==> da0acee8f60a460cfb5249e262d3d53211ebc4c777579e99c8202b761541110a
```

### [SHA384](src/hash/bcrypt_sha384.ahk) / [SHA384 + HMAC](src/hash/bcrypt_sha384_hmac.ahk) & [SHA384 File](src/hash/bcrypt_sha384_file.ahk)
```AutoHotkey
MsgBox % bcrypt_sha384("The quick brown fox jumps over the lazy dog")
; ==> ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1

MsgBox % bcrypt_sha384_hmac("The quick brown fox jumps over the lazy dog", "Secret Salt")
; ==> d91c0d4c3a6c50239354340a89eee6688e1e8f7d760d619bac0f53dd5b5e9ec0cac437d10f7e143e3bba183970850fae

MsgBox % bcrypt_sha384_file("C:\Windows\notepad.exe")
; ==> c53e42934f2baa4a88d2402ab40b2eeb3184e99a23dd393a268b392273609513ade10651c063f6753df0ad4ad21dfd71
```

### [SHA512](src/hash/bcrypt_sha512.ahk) / [SHA512 + HMAC](src/hash/bcrypt_sha512_hmac.ahk) & [SHA512 File](src/hash/bcrypt_sha512_file.ahk)
```AutoHotkey
MsgBox % bcrypt_sha512("The quick brown fox jumps over the lazy dog")
; ==> 07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6

MsgBox % bcrypt_sha512_hmac("The quick brown fox jumps over the lazy dog", "Secret Salt")
; ==> 8ba0777b278b406b07df08150b98d2c57c68f83a980088e3011f76ea8e6d26b84244a678218408e97066d8dfe8aee20569044d214131327b016ea69a487ef471

MsgBox % bcrypt_sha512_file("C:\Windows\notepad.exe")
; ==> 5f5a3b5e64b4a149865f65d678028cef3bc0de16ef265c130b985494ab6690193f8f5e065c6e57d723beb208411aca6debd4afb55a64ce06f3326a76b9469145
```



## Info
* URL: [AHK Thread](https://autohotkey.com/boards/viewtopic.php?f=6&t=23413)


## Contributing
* thanks to AutoHotkey Community