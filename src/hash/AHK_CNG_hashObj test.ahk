#include AHK_CNG_hashObj.ahk

bcrypt:=new hash

msgbox,,md2,% bcrypt.md2("The quick brown fox jumps over the lazy dog")
msgbox,,md4,% bcrypt.md4("The quick brown fox jumps over the lazy dog")
msgbox,,md5,% bcrypt.md5("The quick brown fox jumps over the lazy dog")
msgbox,,sha1,% bcrypt.sha1("The quick brown fox jumps over the lazy dog")
msgbox,,sha256,% bcrypt.sha256("The quick brown fox jumps over the lazy dog")
msgbox,,sha384,% bcrypt.sha384("The quick brown fox jumps over the lazy dog")
msgbox,,sha512,% bcrypt.sha512("The quick brown fox jumps over the lazy dog")

msgbox,,md2+hmac,% bcrypt.hmac.md2("The quick brown fox jumps over the lazy dog","Secret Salt")
msgbox,,md4+hmac,% bcrypt.hmac.md4("The quick brown fox jumps over the lazy dog","Secret Salt")
msgbox,,md5+hmac,% bcrypt.hmac.md5("The quick brown fox jumps over the lazy dog","Secret Salt")
msgbox,,sha1+hmac,% bcrypt.hmac.sha1("The quick brown fox jumps over the lazy dog","Secret Salt")
msgbox,,sha256+hmac,% bcrypt.hmac.sha256("The quick brown fox jumps over the lazy dog","Secret Salt")
msgbox,,sha384+hmac,% bcrypt.hmac.sha384("The quick brown fox jumps over the lazy dog","Secret Salt")
msgbox,,sha512+hmac,% bcrypt.hmac.sha512("The quick brown fox jumps over the lazy dog","Secret Salt")

exitApp
