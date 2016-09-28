MsgBox % bcrypt_pbkdf2_sha1("The quick brown fox jumps over the lazy dog", "Secret Salt")
; ==> 275607744d6aa8c633512e6fd44cec860f1b9f18



bcrypt_pbkdf2_sha1(password, salt, iterations := 4096, keysize := 20)
{
    static BCRYPT_SHA1_ALGORITHM       := "SHA1"
    static BCRYPT_ALG_HANDLE_HMAC_FLAG := 0x00000008

    if !(hBCRYPT := DllCall("LoadLibrary", "str", "bcrypt.dll", "ptr"))
        throw Exception("Failed to load bcrypt.dll", -1)

    if (NT_STATUS := DllCall("bcrypt\BCryptOpenAlgorithmProvider", "ptr*", hAlgo, "ptr", &BCRYPT_SHA1_ALGORITHM, "ptr", 0, "uint", BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0)
        throw Exception("BCryptOpenAlgorithmProvider: " NT_STATUS, -1)

    VarSetCapacity(pbPass, cbPass := StrPut(password, "UTF-8"), 0) && StrPut(password, &pbPass, "UTF-8")
    VarSetCapacity(pbSalt, cbSalt := StrPut(salt, "UTF-8"), 0) && StrPut(salt, &pbSalt, "UTF-8")
    VarSetCapacity(pbDKey, keysize, 0)
    if (NT_STATUS := DllCall("bcrypt\BCryptDeriveKeyPBKDF2", "ptr", hAlgo, "ptr", &pbPass, "uint", cbPass - 1, "ptr", &pbSalt, "uint", cbSalt - 1, "int64", iterations, "ptr", &pbDKey, "uint", keysize, "uint", 0) != 0)
        throw Exception("BCryptDeriveKeyPBKDF2: " NT_STATUS, -1)

    loop % keysize
        pbkdf2 .= Format("{:02x}", NumGet(pbDKey, A_Index - 1, "UChar"))

    DllCall("bcrypt\BCryptCloseAlgorithmProvider", "ptr", hAlgo, "uint", 0)
    DllCall("FreeLibrary", "ptr", hBCRYPT)

    return pbkdf2
}