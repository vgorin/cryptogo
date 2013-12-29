cryptogo
========

Package cryptogo implements some useful cryptography-related functions:

	1. Hashes:
		1.1. hash.MD5Bytes
				calculates an MD5 chechsum of the input byte array as a byte array
		1.2. hash.MD5Base64
				calculates an MD5 chechsum of the input byte array as a base64-encoded string
		1.3. hash.MD5Hex
				calculates an MD5 chechsum of the input byte array as a hex-encoded string

	2. Password-based (PB):
		2.1. pb.PBAesEncrypt
				encrypts input byte array using string password specified into a new (encrypted) byte array
		2.2. pb.PBAesDecrypt
				decrypts input byte array using string password specified into a new (decrypted) byte array
		2.3. pb.PBSignRequest
				signs an http request using a string password; adds 2 additional headers to the request
		2.4. pb.PBVerifyRequest
				verifies previously signed http request using a string password

	3. Paddings
		3.1. pad.Pkcs5Pad
				adds PKCS #5 padding to an input byte array, returning new (padded) byte array
		3.2. pad.Pkcs5Unpad
				removes PKCS #5 padding from an input byte array, returning new (striped) byte array

	4. Random
		4.1. rnd.RandomBytes
				generates a random byte array of the specified length
		4.2. IV
			synonim for RandomBytes, used to generate random IV
		4.3. Salt
			synonim for RandomBytes, used to generate random Salt
