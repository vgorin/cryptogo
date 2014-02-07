cryptogo
========

Project cryptogo provides simple cryptography API

	1. Hashes:
		1.1. hash.MD5Bytes, hash.MD5Base64, hash.MD5Hex
				calculates an MD5 chechsum of the input byte array as a byte array, base64-encoded string or hex-encoded string
		1.2. hash.SHA1Bytes, hash.SHA1Base64, hash.SHA1Hex
				calculates an SHA1 chechsum of the input byte array as a byte array, base64-encoded string or hex-encoded string
		1.3. hash.SHA224Bytes, hash.SHA224Base64, hash.SHA224Hex
				calculates an SHA-224 chechsum of the input byte array as a byte array, base64-encoded string or hex-encoded string
		1.4. hash.SHA256Bytes, hash.SHA256Base64, hash.SHA256Hex
				calculates an SHA-256 chechsum of the input byte array as a byte array, base64-encoded string or hex-encoded string
		1.5. hash.SHA384Bytes, hash.SHA384Base64, hash.SHA384Hex
				calculates an SHA-384 chechsum of the input byte array as a byte array, base64-encoded string or hex-encoded string
		1.6. hash.SHA512Bytes, hash.SHA512Base64, hash.SHA512Hex
				calculates an SHA-512 chechsum of the input byte array as a byte array, base64-encoded string or hex-encoded string

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
		3.1. pad.PKCS7Pad
				adds PKCS #7 padding to an input byte array, returning new (padded) byte array
		3.2. pad.PKCS7Unpad
				removes PKCS #7 padding from an input byte array, returning new (striped) byte array;
				checks if padding is correct
		3.3. pad.X923Pad
				adds ANSI X.923 padding to an input byte array, returning new (padded) byte array
		3.4. pad.X923Unad
				removes ANSI X.923 padding from an input byte array, returning new (striped) byte array;
				checks if padding is correct

	4. Random
		4.1. rnd.RandomBytes
				generates a random byte array of the specified length
		4.2. IV
				synonim for RandomBytes, used to generate random IV
		4.3. Salt
				synonim for RandomBytes, used to generate random Salt

	5. Asymetric Cryptography
		5.1. asym.GenerateKeyPair
				generates private/public key pair, result is returned as two strings

		5.2. asym.Sign
				signes a byte array (usually hash) using private key specified

		5.3. asym.Verify
				verifies a byte array signature using public key specified
