#include AHK_CNG_hashObj.ahk

bcrypt:=new hash
ms:="The quick brown fox jumps over the lazy dog",ss:="Secret Salt",fpath:=a_scriptDir . "\file.txt"
if(!fileExist(fpath)){
    f:=fileOpen(fpath,"w")
    f.write(ms . ".")
    f.close()
}

str.="MD2:                     " . bcrypt.md2(ms) . "`n"
str.="MD4:                     " . bcrypt.md4(ms) . "`n"
str.="MD5:                     " . bcrypt.md5(ms) . "`n"
str.="SHA1:                    " . bcrypt.sha1(ms) . "`n"
str.="SHA256:                  " . bcrypt.sha256(ms) . "`n"
str.="SHA384:                  " . bcrypt.sha384(ms) . "`n"
str.="SHA512:                  " . bcrypt.sha512(ms) . "`n`n"

str.="MD2+HMAC:                " . bcrypt.hmac.md2(ms,ss) . "`n"
str.="MD4+HMAC:                " . bcrypt.hmac.md4(ms,ss) . "`n"
str.="MD5+HMAC:                " . bcrypt.hmac.md5(ms,ss) . "`n"
str.="SHA1+HMAC:               " . bcrypt.hmac.sha1(ms,ss) . "`n"
str.="SHA256+HMAC:             " . bcrypt.hmac.sha256(ms,ss) . "`n"
str.="SHA384+HMAC:             " . bcrypt.hmac.sha384(ms,ss) . "`n"
str.="SHA512+HMAC:             " . bcrypt.hmac.sha512(ms,ss) . "`n`n"

str.="MD2 (file):              " . bcrypt.md2(fpath,1) . "`n"
str.="MD4 (file):              " . bcrypt.md4(fpath,1) . "`n"
str.="MD5 (file):              " . bcrypt.md5(fpath,1) . "`n"
str.="SHA1 (file):             " . bcrypt.sha1(fpath,1) . "`n"
str.="SHA256 (file):           " . bcrypt.sha256(fpath,1) . "`n"
str.="SHA384 (file):           " . bcrypt.sha384(fpath,1) . "`n"
str.="SHA512 (file):           " . bcrypt.sha512(fpath,1) . "`n`n"

str.="MD2+HMAC (file):         " . bcrypt.hmac.md2(fpath,ss,1) . "`n"
str.="MD4+HMAC (file):         " . bcrypt.hmac.md4(fpath,ss,1) . "`n"
str.="MD5+HMAC (file):         " . bcrypt.hmac.md5(fpath,ss,1) . "`n"
str.="SHA1+HMAC (file):        " . bcrypt.hmac.sha1(fpath,ss,1) . "`n"
str.="SHA256+HMAC (file):      " . bcrypt.hmac.sha256(fpath,ss,1) . "`n"
str.="SHA384+HMAC (file):      " . bcrypt.hmac.sha384(fpath,ss,1) . "`n"
str.="SHA512+HMAC (file):      " . bcrypt.hmac.sha512(fpath,ss,1) . "`n`n"

clipboard:=str
exitApp
