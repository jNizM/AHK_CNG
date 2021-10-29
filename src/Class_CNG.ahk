; ========================================================================================================================================================================


class Hash extends CNG
{

	static String(AlgId, String, Encoding := "UTF-8", Output := "HEXRAW")
	{
		static hAlgorithm := hHash := 0

		try
		{
			; open an algorithm handle
			hAlgorithm := this.BCrypt.OpenAlgorithmProvider(AlgId)

			; create a hash
			hHash := this.BCrypt.CreateHash(hAlgorithm)

			; hash some data
			Data := this.StrBuf(String, Encoding)
			this.BCrypt.HashData(hHash, Data, Data.Size - 1)

			; calculate the length of the hash
			HASH_LENGTH := this.BCrypt.GetProperty(hAlgorithm, this.BCrypt.Constants.BCRYPT_HASH_LENGTH, 4)

			; close the hash
			HASH_DATA := Buffer(HASH_LENGTH, 0)
			FINISH_HASH := this.BCrypt.FinishHash(hHash, &HASH_DATA, HASH_LENGTH)

			; convert bin to string (base64 / hex)
			HASH := this.Crypt.BinaryToString(HASH_DATA, HASH_LENGTH, Output)
		}
		catch as Exception
		{
			; represents errors that occur during application execution
			throw Exception
		}
		finally
		{
			; cleaning up resources
			if (hHash)
				this.BCrypt.DestroyHash(hHash)

			if (hAlgorithm)
				this.BCrypt.CloseAlgorithmProvider(hAlgorithm)
		}

		return HASH
	}



	static File(AlgId, FileName, Bytes := 1048576, Offset := 0, Length := -1, Encoding := "UTF-8", Output := "HEXRAW")
	{
		static hAlgorithm := hHash := File := 0

		try
		{
			; open an algorithm handle
			hAlgorithm := this.BCrypt.OpenAlgorithmProvider(AlgId)

			; create a hash
			hHash := this.BCrypt.CreateHash(hAlgorithm)

			; hash some data
			if !(File := FileOpen(FileName, "r", Encoding))
				throw Error("Failed to open file: " FileName, -1)
			Length := Length < 0 ? File.Length - Offset : Length
			Data := Buffer(Bytes)
			if ((Offset + Length) > File.Length)
				throw Error("Invalid parameters offset / length!", -1)
			while (Length > Bytes) && (Dataread := File.RawRead(Data, Bytes)) {
				this.BCrypt.HashData(hHash, Data, Dataread)
				Length -= Dataread
			}
			if (Length > 0) {
				if (Dataread := File.RawRead(Data, Length))
					this.BCrypt.HashData(hHash, Data, Dataread)
			}

			; calculate the length of the hash
			HASH_LENGTH := this.BCrypt.GetProperty(hAlgorithm, this.BCrypt.Constants.BCRYPT_HASH_LENGTH, 4)

			; close the hash
			HASH_DATA := Buffer(HASH_LENGTH, 0)
			FINISH_HASH := this.BCrypt.FinishHash(hHash, &HASH_DATA, HASH_LENGTH)

			; convert bin to string (base64 / hex)
			HASH := this.Crypt.BinaryToString(HASH_DATA, HASH_LENGTH, Output)
		}
		catch as Exception
		{
			; represents errors that occur during application execution
			throw Exception
		}
		finally
		{
			; cleaning up resources
			if (File)
				File.Close()

			if (hHash)
				this.BCrypt.DestroyHash(hHash)

			if (hAlgorithm)
				this.BCrypt.CloseAlgorithmProvider(hAlgorithm)
		}

		return HASH
	}



	static HMAC(AlgId, String, Hmac, Encoding := "UTF-8", Output := "HEXRAW")
	{
		static hAlgorithm := hHash := 0

		try
		{
			; open an algorithm handle
			hAlgorithm := this.BCrypt.OpenAlgorithmProvider(AlgId, this.BCrypt.Constants.BCRYPT_ALG_HANDLE_HMAC_FLAG)

			; create a hash
			Mac := this.StrBuf(Hmac, Encoding)
			hHash := this.BCrypt.CreateHash(hAlgorithm, Mac, Mac.Size - 1)

			; hash some data
			Data := this.StrBuf(String, Encoding)
			this.BCrypt.HashData(hHash, Data, Data.Size - 1)

			; calculate the length of the hash
			HASH_LENGTH := this.BCrypt.GetProperty(hAlgorithm, this.BCrypt.Constants.BCRYPT_HASH_LENGTH, 4)

			; close the hash
			HASH_DATA := Buffer(HASH_LENGTH, 0)
			FINISH_HASH := this.BCrypt.FinishHash(hHash, &HASH_DATA, HASH_LENGTH)

			; convert bin to string (base64 / hex)
			HASH := this.Crypt.BinaryToString(HASH_DATA, HASH_LENGTH, Output)
		}
		catch as Exception
		{
			; represents errors that occur during application execution
			throw Exception
		}
		finally
		{
			; cleaning up resources
			if (hHash)
				this.BCrypt.DestroyHash(hHash)

			if (hAlgorithm)
				this.BCrypt.CloseAlgorithmProvider(hAlgorithm)
		}

		return HASH
	}



	static PBKDF2(AlgId, Password, Salt, Iterations := 4096, KeySize := 256, Encoding := "UTF-8", Output := "HEXRAW")
	{
		static hAlgorithm := hHash := 0

		try
		{
			; check key bit length
			if (Mod(KeySize, 8) != 0)
				throw Error("The desired key bit length must be a multiple of 8!", -1)

			; open an algorithm handle
			hAlgorithm := this.BCrypt.OpenAlgorithmProvider(AlgId, this.BCrypt.Constants.BCRYPT_ALG_HANDLE_HMAC_FLAG)

			; derives a key from a hash value
			PBKDF2_DATA := this.BCrypt.DeriveKeyPBKDF2(hAlgorithm, Password, Salt, Iterations, KeySize / 8, Encoding)

			; convert bin to string (base64 / hex)
			PBKDF2 := this.Crypt.BinaryToString(PBKDF2_DATA, PBKDF2_DATA.size, Output)
		}
		catch as Exception
		{
			; represents errors that occur during application execution
			throw Exception
		}
		finally
		{
			; cleaning up resources
			if (hAlgorithm)
				this.BCrypt.CloseAlgorithmProvider(hAlgorithm)
		}

		return PBKDF2
	}
}


; ===========================================================================================================================================================================


class CNG
{

	class BCrypt
	{

		#DllLoad "*i bcrypt.dll"


		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		; //
		; // FUNCTION NAME: BCrypt.CloseAlgorithmProvider
		; //
		; // This function closes an algorithm provider.
		; //
		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		static CloseAlgorithmProvider(hAlgorithm)
		{
			NT_STATUS := DllCall("bcrypt\BCryptCloseAlgorithmProvider", "Ptr",  hAlgorithm
																	  , "UInt", Flags := 0
																	  , "UInt")

			if (NT_STATUS = this.NT.SUCCESS)
				return true
			throw Error(this.GetErrorMessage(NT_STATUS), -1)
		}


		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		; //
		; // FUNCTION NAME: BCrypt.CreateHash
		; //
		; // This function is called to create a hash or Message Authentication Code (MAC) object.
		; //
		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		static CreateHash(hAlgorithm, Buf := 0, Size := 0)
		{
			NT_STATUS := DllCall("bcrypt\BCryptCreateHash", "Ptr",  hAlgorithm
														  , "Ptr*", &hHash := 0
														  , "Ptr",  0
														  , "UInt", 0
														  , "Ptr",  Buf
														  , "UInt", Size
														  , "UInt", Flags := 0 ; (this.Constants.BCRYPT_HASH_REUSABLE_FLAG)
														  , "UInt")

			if (NT_STATUS = this.NT.SUCCESS)
				return hHash
			throw Error(this.GetErrorMessage(NT_STATUS), -1)
		}


		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		; //
		; // FUNCTION NAME: BCrypt.DeriveKeyPBKDF2
		; //
		; // This function derives a key from a hash value by using the PBKDF2 key derivation algorithm as defined by RFC 2898.
		; //
		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		static DeriveKeyPBKDF2(hAlgorithm, Pass, Salt, Iterations, DerivedKey, Encoding := "UTF-8")
		{
			Passwd := CNG.StrBuf(Pass, Encoding)
			Salt   := CNG.StrBuf(Salt, Encoding)
			DKey   := Buffer(DerivedKey, 0)

			NT_STATUS := DllCall("bcrypt\BCryptDeriveKeyPBKDF2", "Ptr",   hAlgorithm
			                                                   , "Ptr",   Passwd
															   , "UInt",  Passwd.Size - 1
															   , "Ptr",   Salt
															   , "UInt",  Salt.Size - 1
															   , "Int64", Iterations
															   , "Ptr",   DKey
															   , "UInt",  DerivedKey
															   , "UInt",  Flags := 0
															   , "UInt")

			if (NT_STATUS = this.NT.SUCCESS)
				return DKey
			throw Error(this.GetErrorMessage(NT_STATUS), -1)
		}


		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		; //
		; // FUNCTION NAME: BCrypt.DestroyHash
		; //
		; // This function destroys a hash or Message Authentication Code (MAC) object.
		; //
		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		static DestroyHash(hHash)
		{
			NT_STATUS := DllCall("bcrypt\BCryptDestroyHash", "Ptr", hHash, "UInt")

			if (NT_STATUS = this.NT.SUCCESS)
				return true
			throw Error(this.GetErrorMessage(NT_STATUS), -1)
		}


		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		; //
		; // FUNCTION NAME: BCrypt.DestroyKey
		; //
		; // This function destroys a key.
		; //
		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		static DestroyKey(hKey)
		{
			NT_STATUS := DllCall("bcrypt\BCryptDestroyKey", "Ptr", hKey, "UInt")

			if (NT_STATUS = this.NT.SUCCESS)
				return true
			throw Error(this.GetErrorMessage(NT_STATUS), -1)
		}


		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		; //
		; // FUNCTION NAME: BCrypt.FinishHash
		; //
		; // This function retrieves the hash or Message Authentication Code (MAC) value for the data accumulated from prior calls to BCrypt.HashData.
		; //
		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		static FinishHash(hHash, &Buf, Size)
		{
			Buf := Buffer(Size, 0)
			NT_STATUS := DllCall("bcrypt\BCryptFinishHash", "Ptr",  hHash
														  , "Ptr",  Buf
														  , "UInt", Size
														  , "UInt", Flags := 0
														  , "UInt")

			if (NT_STATUS = this.NT.SUCCESS)
				return Size
			throw Error(this.GetErrorMessage(NT_STATUS), -1)
		}


		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		; //
		; // FUNCTION NAME: BCrypt.GetProperty
		; //
		; // This function retrieves the value of a named property for a CNG object.
		; //
		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		static GetProperty(hObject, Property, Size)
		{
			NT_STATUS := DllCall("bcrypt\BCryptGetProperty", "Ptr",   hObject
														   , "Ptr",   StrPtr(Property)
														   , "Ptr*",  &Buf := 0
														   , "UInt",  Size
														   , "UInt*", &Result := 0
														   , "UInt",  Flags := 0
														   , "UInt")

			if (NT_STATUS = this.NT.SUCCESS)
				return Buf
			throw Error(this.GetErrorMessage(NT_STATUS), -1)
		}


		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		; //
		; // FUNCTION NAME: BCrypt.HashData
		; //
		; // This function performs a one way hash or Message Authentication Code (MAC) on a data buffer.
		; //
		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		static HashData(hHash, Buf, Size)
		{
			NT_STATUS := DllCall("bcrypt\BCryptHashData", "Ptr",  hHash
														, "Ptr",  Buf
														, "UInt", Size
														, "UInt", Flags := 0
														, "UInt")

			if (NT_STATUS = this.NT.SUCCESS)
				return true
			throw Error(this.GetErrorMessage(NT_STATUS), -1)
		}


		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		; //
		; // FUNCTION NAME: BCrypt.OpenAlgorithmProvider
		; //
		; // This function loads and initializes a CNG provider.
		; //
		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		static OpenAlgorithmProvider(AlgId, Flags := 0)
		{
			NT_STATUS := DllCall("bcrypt\BCryptOpenAlgorithmProvider", "Ptr*", &hAlgorithm := 0
																	 , "Str",  AlgId
																	 , "Ptr",  Implementation := 0
																	 , "UInt", Flags
																	 , "UInt")

			if (NT_STATUS = this.NT.SUCCESS)
				return hAlgorithm
			throw Error(this.GetErrorMessage(NT_STATUS), -1)
		}


		static GetErrorMessage(STATUS_CODE)
		{
			switch STATUS_CODE
			{
				case this.NT.BUFFER_TOO_SMALL:
					return "The buffer is too small to contain the entry. No information has been written to the buffer."
				case this.NT.INVALID_HANDLE:
					return "An invalid HANDLE was specified."
				case this.NT.INVALID_PARAMETER:
					return "An invalid parameter was passed to a service or function."
				case this.NT.NOT_FOUND:
					return "The object was not found."
				case this.NT.NOT_SUPPORTED:
					return "The request is not supported."
				case this.NT.NO_MEMORY:
					return "Not enough virtual memory or paging file quota is available to complete the specified operation."
				default:
					return "BCrypt failed " STATUS_CODE
			}
		}


		class Constants
		{
			static BCRYPT_ALG_HANDLE_HMAC_FLAG            := 0x00000008
			static BCRYPT_HASH_REUSABLE_FLAG              := 0x00000020
			static BCRYPT_BLOCK_PADDING                   := 0x00000001


			; AlgOperations flags for use with BCryptEnumAlgorithms()
			static BCRYPT_CIPHER_OPERATION                := 0x00000001
			static BCRYPT_HASH_OPERATION                  := 0x00000002
			static BCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION := 0x00000004
			static BCRYPT_SECRET_AGREEMENT_OPERATION      := 0x00000008
			static BCRYPT_SIGNATURE_OPERATION             := 0x00000010
			static BCRYPT_RNG_OPERATION                   := 0x00000020
			static BCRYPT_KEY_DERIVATION_OPERATION        := 0x00000040


			; https://docs.microsoft.com/en-us/windows/win32/seccng/cng-algorithm-identifiers
			static BCRYPT_3DES_ALGORITHM                  := "3DES"
			static BCRYPT_3DES_112_ALGORITHM              := "3DES_112"
			static BCRYPT_AES_ALGORITHM                   := "AES"
			static BCRYPT_AES_CMAC_ALGORITHM              := "AES-CMAC"
			static BCRYPT_AES_GMAC_ALGORITHM              := "AES-GMAC"
			static BCRYPT_DES_ALGORITHM                   := "DES"
			static BCRYPT_DESX_ALGORITHM                  := "DESX"
			static BCRYPT_MD2_ALGORITHM                   := "MD2"
			static BCRYPT_MD4_ALGORITHM                   := "MD4"
			static BCRYPT_MD5_ALGORITHM                   := "MD5"
			static BCRYPT_RC2_ALGORITHM                   := "RC2"
			static BCRYPT_RC4_ALGORITHM                   := "RC4"
			static BCRYPT_RNG_ALGORITHM                   := "RNG"
			static BCRYPT_SHA1_ALGORITHM                  := "SHA1"
			static BCRYPT_SHA256_ALGORITHM                := "SHA256"
			static BCRYPT_SHA384_ALGORITHM                := "SHA384"
			static BCRYPT_SHA512_ALGORITHM                := "SHA512"
			static BCRYPT_PBKDF2_ALGORITHM                := "PBKDF2"
			static BCRYPT_XTS_AES_ALGORITHM               := "XTS-AES"


			; https://docs.microsoft.com/en-us/windows/win32/seccng/cng-property-identifiers
			static BCRYPT_BLOCK_LENGTH                    := "BlockLength"
			static BCRYPT_CHAINING_MODE                   := "ChainingMode"
			static BCRYPT_CHAIN_MODE_CBC                  := "ChainingModeCBC"
			static BCRYPT_CHAIN_MODE_CCM                  := "ChainingModeCCM"
			static BCRYPT_CHAIN_MODE_CFB                  := "ChainingModeCFB"
			static BCRYPT_CHAIN_MODE_ECB                  := "ChainingModeECB"
			static BCRYPT_CHAIN_MODE_GCM                  := "ChainingModeGCM"
			static BCRYPT_HASH_LENGTH                     := "HashDigestLength"
			static BCRYPT_OBJECT_LENGTH                   := "ObjectLength"
		}


		class NT
		{
			static SUCCESS           := 0x00000000
			static BUFFER_TOO_SMALL  := 0xC0000023
			static INVALID_HANDLE    := 0xC0000008
			static INVALID_PARAMETER := 0xC000000D
			static NO_MEMORY         := 0xC0000017
			static NOT_FOUND         := 0xC0000225
			static NOT_SUPPORTED     := 0xC00000BB
		}
	}


	; =======================================================================================================================================================================


	class Crypt
	{

		#DllLoad "*i crypt32.dll"


		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		; //
		; // FUNCTION NAME: Crypt.BinaryToString
		; //
		; // This function converts an array of bytes into a formatted string.
		; //
		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		static BinaryToString(BufIn, SizeIn, Flags := "BASE64")
		{
			static CRYPT_STRING :=  { BASE64: 0x1, BINARY: 0x2, HEX: 0x4, HEXRAW: 0xc }
			static CRYPT_STRING_NOCRLF := 0x40000000

			if !(DllCall("crypt32\CryptBinaryToStringW", "Ptr",   BufIn
													   , "UInt",  SizeIn
													   , "UInt",  (CRYPT_STRING.%Flags% | CRYPT_STRING_NOCRLF)
													   , "Ptr",   0
													   , "UInt*", &Size := 0))
				throw Error("Can't compute the destination buffer size, error: " A_LastError, -1)

			BufOut := Buffer(Size << 1, 0)
			if !(DllCall("crypt32\CryptBinaryToStringW", "Ptr",   BufIn
													   , "UInt",  SizeIn
													   , "UInt",  (CRYPT_STRING.%Flags% | CRYPT_STRING_NOCRLF)
													   , "Ptr",   BufOut
													   , "UInt*", Size))
				throw Error("Can't convert source buffer to " Flags ", error: " A_LastError, -1)

			return StrGet(BufOut)
		}


		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		; //
		; // FUNCTION NAME: Crypt.StringToBinary
		; //
		; // This function converts a formatted string into an array of bytes.
		; //
		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		static StringToBinary(String, &Binary, Flags := "BASE64")
		{
			static CRYPT_STRING := { BASE64: 0x1, BINARY: 0x2, HEX: 0x4, HEXRAW: 0xc }

			if !(DllCall("crypt32\CryptStringToBinaryW", "Ptr",   StrPtr(String)
			                                           , "UInt",  0
													   , "UInt",  CRYPT_STRING.%Flags%
													   , "Ptr",   0
													   , "UInt*", &Size := 0
													   , "Ptr",   0
													   , "Ptr",   0))
				throw Error("Can't compute the destination buffer size, error: " A_LastError, -1)

			Binary := Buffer(Size, 0)
			if !(DllCall("crypt32\CryptStringToBinaryW", "Ptr",   StrPtr(String)
			                                           , "UInt",  0
													   , "UInt",  CRYPT_STRING.%Flags%
													   , "Ptr",   Binary
													   , "UInt*", Binary.Size
													   , "Ptr",   0
													   , "Ptr",   0))
				throw Error("Can't convert source buffer to " Flags ", error: " A_LastError, -1)

			return Binary.Size
		}
	}


	; =======================================================================================================================================================================


	static StrBuf(Str, Encoding := "UTF-8")
	{
		Buf := Buffer(StrPut(Str, Encoding))
		StrPut(Str, Buf, Encoding)
		return Buf
	}

}

; ===========================================================================================================================================================================
