#Requires AutoHotkey v2.0+

; ==============================================================================
; Author ........: jNizM
; Released ......: 2016-10-21
; Modified ......: 2023-02-15
; Tested with....: AutoHotkey v2.0.2 (x64)
; Tested on .....: Windows 11 - 22H2 (x64)
; Function ......: B64Encode()
;
; Parameter(s)...: String
;                  Encoding (default = UTF-8)
;
; Return ........: Converts a readable string to a base64 string.
; ==============================================================================

B64Encode(String, Encoding := "UTF-8")
{
	static CRYPT_STRING_BASE64 := 0x00000001
	static CRYPT_STRING_NOCRLF := 0x40000000

	; add parameter type checking


	switch Encoding
	{

	case 'RAW':
		; add a character to the size which will be removed later
		; as we are removing the NULL before sending to CryptBinaryToStringW
		String.size += 1
		Binary := String
		
	default:
		Binary := Buffer(StrPut(String, Encoding))
		StrPut(String, Binary, Encoding)
		
	}

	if !DllCall("crypt32\CryptBinaryToStringW",
	             "ptr" , Binary,
	             "uint", Binary.Size - 1,
	             "uint", (CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF),
	             "ptr" , 0,
	             "ptr*", &Size := 0)
		throw OSError()

	Base64 := Buffer(Size << 1, 0)
	if !DllCall("crypt32\CryptBinaryToStringW",
	             "ptr" , Binary,
	             "uint", Binary.Size - 1,
	             "uint", (CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF),
	             "ptr" , Base64,
	             "ptr*", &Size)
		throw OSError()

	return StrGet(Base64)
}

; ==============================================================================
; Author ........: jNizM
; Released ......: 2016-10-21
; Modified ......: 2023-02-15
; Tested with....: AutoHotkey v2.0.2 (x64)
; Tested on .....: Windows 11 - 22H2 (x64)
; Function ......: B64Decode()
;
; Parameter(s)...: Base64 - encoded string
;
; Return ........: Converts a base64 string to a readable string.
; ==============================================================================

B64Decode(Base64, Encoding := 'UTF-8')
{
	static CRYPT_STRING_BASE64 := 0x00000001

	; add parameter type checking
	if !DllCall("crypt32\CryptStringToBinaryW",
	             "str" , Base64,
	             "uint", 0,
	             "uint", CRYPT_STRING_BASE64,
	             "ptr" , 0,
	             "ptr*", &Size := 0,
	             "ptr" , 0,
	             "ptr" , 0)
		throw OSError()

	Decoded := Buffer(Size)
	if !DllCall("crypt32\CryptStringToBinaryW",
	             "str" , Base64,
	             "uint", 0,
	             "uint", CRYPT_STRING_BASE64,
	             "ptr" , Decoded,
	             "ptr*", &Size,
	             "ptr" , 0,
	             "ptr" , 0)
		throw OSError()

	return Encoding = 'RAW' ? Decoded : StrGet(Decoded, "UTF-8")
}