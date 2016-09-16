class hash { ; to extend/be embedded in main obj
    
    md2(string){
        return this.hashThis(string,"MD2")
    }
    
    md4(string){
        return this.hashThis(string,"MD4")
    }
    
    md5(string){
        return this.hashThis(string,"MD5")
    }
    
    sha1(string){
        return this.hashThis(string,"SHA1")
    }
    
    sha256(string){
        return this.hashThis(string,"SHA256")
    }
    
    sha384(string){
        return this.hashThis(string,"SHA384")
    }
    
    sha512(string){
        return this.hashThis(string,"SHA512")
    }
    
    hashThis(string,BCRYPT_ALGORITHM){
        static BCRYPT_OBJECT_LENGTH := "ObjectLength"
        static BCRYPT_HASH_LENGTH   := "HashDigestLength"
        hash:=""
        
        if !(hBCRYPT := DllCall("LoadLibrary", "str", "bcrypt.dll", "ptr"))
            throw Exception("Failed to load bcrypt.dll", -1)
        
        if (NT_STATUS := DllCall("bcrypt\BCryptOpenAlgorithmProvider", "ptr*", hAlgo, "ptr", &BCRYPT_ALGORITHM, "ptr", 0, "uint", 0) != 0)
            throw Exception("BCryptOpenAlgorithmProvider: " NT_STATUS, -1)
        
        if (NT_STATUS := DllCall("bcrypt\BCryptGetProperty", "ptr", hAlgo, "ptr", &BCRYPT_OBJECT_LENGTH, "uint*", cbHashObject, "uint", 4, "uint*", cbResult, "uint", 0) != 0)
            throw Exception("BCryptGetProperty: " NT_STATUS, -1)
        
        if (NT_STATUS := DllCall("bcrypt\BCryptGetProperty", "ptr", hAlgo, "ptr", &BCRYPT_HASH_LENGTH, "uint*", cbHash, "uint", 4, "uint*", cbResult, "uint", 0) != 0)
            throw Exception("BCryptGetProperty: " NT_STATUS, -1)
        
        VarSetCapacity(pbHashObject, cbHashObject, 0)
        if (NT_STATUS := DllCall("bcrypt\BCryptCreateHash", "ptr", hAlgo, "ptr*", hHash, "ptr", &pbHashObject, "uint", cbHashObject, "ptr", 0, "uint", 0, "uint", 0) != 0)
            throw Exception("BCryptCreateHash: " NT_STATUS, -1)
        
        VarSetCapacity(pbInput, cbInput := StrPut(string, "UTF-8"), 0) && StrPut(string, &pbInput, "UTF-8")
        if (NT_STATUS := DllCall("bcrypt\BCryptHashData", "ptr", hHash, "ptr", &pbInput, "uint", cbInput - 1, "uint", 0) != 0)
            throw Exception("BCryptHashData: " NT_STATUS, -1)
        
        VarSetCapacity(pbHash, cbHash, 0)
        if (NT_STATUS := DllCall("bcrypt\BCryptFinishHash", "ptr", hHash, "ptr", &pbHash, "uint", cbHash, "uint", 0) != 0)
            throw Exception("BCryptHashData: " NT_STATUS, -1)
        
        loop % cbHash
            hash .= Format("{:02x}", NumGet(pbHash, A_Index - 1, "UChar"))

        DllCall("bcrypt\BCryptDestroyHash", "ptr", hHash)
        DllCall("bcrypt\BCryptCloseAlgorithmProvider", "ptr", hAlgo, "uint", 0)
        DllCall("FreeLibrary", "ptr", hBCRYPT)
        
        return hash
    }
    

    class hmac {
        
        md2(string,hmac){
            return this.hmacThis(string,hmac,"MD2")
        }

        md4(string,hmac){
            return this.hmacThis(string,hmac,"MD4")
        }

        md5(string,hmac){
            return this.hmacThis(string,hmac,"MD5")
        }

        sha1(string,hmac){
            return this.hmacThis(string,hmac,"SHA1")
        }

        sha256(string,hmac){
            return this.hmacThis(string,hmac,"SHA256")
        }

        sha384(string,hmac){
            return this.hmacThis(string,hmac,"SHA384")
        }

        sha512(string,hmac){
            return this.hmacThis(string,hmac,"SHA512")
        }
        
        hmacThis(string,hmac,BCRYPT_ALGORITHM){
            
            static BCRYPT_ALG_HANDLE_HMAC_FLAG := 0x00000008
            static BCRYPT_OBJECT_LENGTH        := "ObjectLength"
            static BCRYPT_HASH_LENGTH          := "HashDigestLength"
            hash:=""
            
            if !(hBCRYPT := DllCall("LoadLibrary", "str", "bcrypt.dll", "ptr"))
                throw Exception("Failed to load bcrypt.dll", -1)
            
            if (NT_STATUS := DllCall("bcrypt\BCryptOpenAlgorithmProvider", "ptr*", hAlgo, "ptr", &BCRYPT_ALGORITHM, "ptr", 0, "uint", BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0)
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
                hash .= Format("{:02x}", NumGet(pbHash, A_Index - 1, "UChar"))
            
            DllCall("bcrypt\BCryptDestroyHash", "ptr", hHash)
            DllCall("bcrypt\BCryptCloseAlgorithmProvider", "ptr", hAlgo, "uint", 0)
            DllCall("FreeLibrary", "ptr", hBCRYPT)
            
            return hash
        }
    }
}
