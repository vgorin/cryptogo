# cryptogo

Simple cryptography API in [Go](https://golang.org/)

1. Hashes:

    * hash.MD5Bytes, hash.MD5Base64, hash.MD5Hex  
        calculates an MD5 chechsum of the input byte array as a byte array,
        base64-encoded string or hex-encoded string

    * hash.SHA1Bytes, hash.SHA1Base64, hash.SHA1Hex  
        calculates an SHA1 chechsum of the input byte array as a byte array,
        base64-encoded string or hex-encoded string

    * hash.SHA224Bytes, hash.SHA224Base64, hash.SHA224Hex  
        calculates an SHA-224 chechsum of the input byte array as a byte array,
        base64-encoded string or hex-encoded string

    * hash.SHA256Bytes, hash.SHA256Base64, hash.SHA256Hex  
        calculates an SHA-256 chechsum of the input byte array as a byte array,
        base64-encoded string or hex-encoded string

    * hash.SHA384Bytes, hash.SHA384Base64, hash.SHA384Hex  
        calculates an SHA-384 chechsum of the input byte array as a byte array,
        base64-encoded string or hex-encoded string

    * hash.SHA512Bytes, hash.SHA512Base64, hash.SHA512Hex  
        calculates an SHA-512 chechsum of the input byte array as a byte array,
        base64-encoded string or hex-encoded string

1. Password-based (PB):

    * pb.PBAesEncrypt
        encrypts input byte array using string password specified into a new (encrypted) byte array

    * pb.PBAesDecrypt
        decrypts input byte array using string password specified into a new (decrypted) byte array

    * pb.PBSignRequest
        signs an http request using a string password; adds 2 additional headers to the request

    * pb.PBVerifyRequest
        verifies previously signed http request using a string password

1. Paddings

    * pad.PKCS7Pad
        adds PKCS #7 padding to an input byte array, returning new (padded) byte array

    * pad.PKCS7Unpad
        removes PKCS #7 padding from an input byte array, returning new (striped) byte array;  
        checks if padding is correct

    * pad.X923Pad
        adds ANSI X.923 padding to an input byte array, returning new (padded) byte array

    * pad.X923Unad
        removes ANSI X.923 padding from an input byte array, returning new (striped) byte array;  
        checks if padding is correct

1. Random

    * rnd.RandomBytes
        generates a random byte array of the specified length

    * IV
        synonim for RandomBytes, used to generate random IV

    * Salt
        synonim for RandomBytes, used to generate random Salt

1. Asymetric Cryptography

    * asym.GenerateKeyPair
        generates private/public key pair, result is returned as two strings

    * asym.Sign
        signes a byte array (usually hash) using private key specified

    * asym.Verify
        verifies a byte array signature using public key specified
