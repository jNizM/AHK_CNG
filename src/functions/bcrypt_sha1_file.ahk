v := 0x0
file := FileOpen("TestFile", "rw")
loop % 256
	file.WriteUChar(v++)
file.Close()

MsgBox % bcrypt_sha1_file("TestFile")
; -> 4916d6bdb7f78e6803698cab32d1586ea457dfc8

FileDelete, TestFile



bcrypt_sha1_file(filename, bytes := 1048576 , offset := 0, length := -1, encoding := "utf-8")
{
    static BCRYPT_SHA1_ALGORITHM := "SHA1"
    static BCRYPT_OBJECT_LENGTH  := "ObjectLength"
    static BCRYPT_HASH_LENGTH    := "HashDigestLength"

	try
	{
		; loads the specified module into the address space of the calling process
		if !(hBCRYPT := DllCall("LoadLibrary", "str", "bcrypt.dll", "ptr"))
			throw Exception("Failed to load bcrypt.dll", -1)

		; open an algorithm handle
		if (NT_STATUS := DllCall("bcrypt\BCryptOpenAlgorithmProvider", "ptr*", hAlg, "ptr", &BCRYPT_SHA1_ALGORITHM, "ptr", 0, "uint", 0) != 0)
			throw Exception("BCryptOpenAlgorithmProvider: " NT_STATUS, -1)

		; calculate the size of the buffer to hold the hash object
		if (NT_STATUS := DllCall("bcrypt\BCryptGetProperty", "ptr", hAlg, "ptr", &BCRYPT_OBJECT_LENGTH, "uint*", cbHashObject, "uint", 4, "uint*", cbData, "uint", 0) != 0)
			throw Exception("BCryptGetProperty: " NT_STATUS, -1)

		; allocate the hash object
		VarSetCapacity(pbHashObject, cbHashObject, 0)
		;	throw Exception("Memory allocation failed", -1)

		; calculate the length of the hash
		if (NT_STATUS := DllCall("bcrypt\BCryptGetProperty", "ptr", hAlg, "ptr", &BCRYPT_HASH_LENGTH, "uint*", cbHash, "uint", 4, "uint*", cbData, "uint", 0) != 0)
			throw Exception("BCryptGetProperty: " NT_STATUS, -1)

		; allocate the hash buffer
		VarSetCapacity(pbHash, cbHash, 0)
		;	throw Exception("Memory allocation failed", -1)

		; create a hash
		if (NT_STATUS := DllCall("bcrypt\BCryptCreateHash", "ptr", hAlg, "ptr*", hHash, "ptr", &pbHashObject, "uint", cbHashObject, "ptr", 0, "uint", 0, "uint", 0) != 0)
			throw Exception("BCryptCreateHash: " NT_STATUS, -1)

		; create a hash
		if !(IsObject(f := FileOpen(filename, "r", encoding)))
			throw Exception("Failed to open file: " filename, -1)
		length := length < 0 ? f.length - offset : length
		if ((offset + length) > f.length)
			throw Exception("Invalid parameters offset / length!", -1)
		f.Pos(offset)
		while (length > bytes) && (dataread := f.RawRead(data, bytes))
		{
			if (NT_STATUS := DllCall("bcrypt\BCryptHashData", "ptr", hHash, "ptr", &data, "uint", dataread, "uint", 0) != 0)
				throw Exception("BCryptHashData: " NT_STATUS, -1)
			length -= dataread
		}
		if (length > 0)
		{
			if (dataread := f.RawRead(data, length))
				if (NT_STATUS := DllCall("bcrypt\BCryptHashData", "ptr", hHash, "ptr", &data, "uint", dataread, "uint", 0) != 0)
					throw Exception("BCryptHashData: " NT_STATUS, -1)
		}

		; close the hash
		if (NT_STATUS := DllCall("bcrypt\BCryptFinishHash", "ptr", hHash, "ptr", &pbHash, "uint", cbHash, "uint", 0) != 0)
			throw Exception("BCryptFinishHash: " NT_STATUS, -1)

		loop % cbHash
			hash .= Format("{:02x}", NumGet(pbHash, A_Index - 1, "uchar"))
	}
	catch exception
	{
		; represents errors that occur during application execution
		throw Exception
	}
	finally
	{
		; cleaning up resources
		if (f)
			f.Close()
		if (pbInput)
			VarSetCapacity(pbInput, 0)
		if (hHash)
			DllCall("bcrypt\BCryptDestroyHash", "ptr", hHash)
		if (pbHash)
			VarSetCapacity(pbHash, 0)
		if (pbHashObject)
			VarSetCapacity(pbHashObject, 0)
		if (hAlg)
			DllCall("bcrypt\BCryptCloseAlgorithmProvider", "ptr", hAlg, "uint", 0)
		if (hBCRYPT)
			DllCall("FreeLibrary", "ptr", hBCRYPT)
	}

	return hash
}