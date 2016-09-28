﻿MsgBox % bcrypt_md4_hmac("The quick brown fox jumps over the lazy dog", "Secret Salt")
; ==> 54864ebb1c93bbbfaa860d8b2d567133



bcrypt_md4_hmac(string, hmac)
{
    static BCRYPT_MD4_ALGORITHM        := "MD4"
    static BCRYPT_ALG_HANDLE_HMAC_FLAG := 0x00000008
    static BCRYPT_OBJECT_LENGTH        := "ObjectLength"
    static BCRYPT_HASH_LENGTH          := "HashDigestLength"

    if !(hBCRYPT := DllCall("LoadLibrary", "str", "bcrypt.dll", "ptr"))
        throw Exception("Failed to load bcrypt.dll", -1)

    if (NT_STATUS := DllCall("bcrypt\BCryptOpenAlgorithmProvider", "ptr*", hAlgo, "ptr", &BCRYPT_MD4_ALGORITHM, "ptr", 0, "uint", BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0)
        throw Exception("BCryptOpenAlgorithmProvider: " NT_STATUS, -1)

    if (NT_STATUS := DllCall("bcrypt\BCryptGetProperty", "ptr", hAlgo, "ptr", &BCRYPT_OBJECT_LENGTH, "uint*", cbHashObject, "uint", 4, "uint*", cbResult, "uint", 0) != 0)
        throw Exception("BCryptGetProperty: " NT_STATUS, -1)

    if (NT_STATUS := DllCall("bcrypt\BCryptGetProperty", "ptr", hAlgo, "ptr", &BCRYPT_HASH_LENGTH, "uint*", cbHash, "uint", 4, "uint*", cbResult, "uint", 0) != 0)
        throw Exception("BCryptGetProperty: " NT_STATUS, -1)

    VarSetCapacity(pbHashObject, cbHashObject, 0) && VarSetCapacity(pbSecret, cbSecret := StrPut(hmac, "UTF-8"), 0) && StrPut(hmac, &pbSecret, "UTF-8")
    if (NT_STATUS := DllCall("bcrypt\BCryptCreateHash", "ptr", hAlgo, "ptr*", hHash, "ptr", &pbHashObject, "uint", cbHashObject, "ptr", &pbSecret, "uint", cbSecret - 1, "uint", 0) != 0)
        throw Exception("BCryptCreateHash: " NT_STATUS, -1)

    VarSetCapacity(pbInput, cbInput := StrPut(string, "UTF-8"), 0) && StrPut(string, &pbInput, "UTF-8")
    if (NT_STATUS := DllCall("bcrypt\BCryptHashData", "ptr", hHash, "ptr", &pbInput, "uint", cbInput - 1, "uint", 0) != 0)
        throw Exception("BCryptHashData: " NT_STATUS, -1)

    VarSetCapacity(pbHash, cbHash, 0)
    if (NT_STATUS := DllCall("bcrypt\BCryptFinishHash", "ptr", hHash, "ptr", &pbHash, "uint", cbHash, "uint", 0) != 0)
        throw Exception("BCryptHashData: " NT_STATUS, -1)

    loop % cbHash
        o .= Format("{:02x}", NumGet(pbHash, A_Index - 1, "UChar"))

    DllCall("bcrypt\BCryptDestroyHash", "ptr", hHash)
    DllCall("bcrypt\BCryptCloseAlgorithmProvider", "ptr", hAlgo, "uint", 0)
    DllCall("FreeLibrary", "ptr", hBCRYPT)

    return o
}