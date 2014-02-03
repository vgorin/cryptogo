// Copyright 2013-2014 Vasiliy Gorin. All rights reserved.
// Use of this source code is governed by a GNU-style
// license that can be found in the LICENSE file.

/*
Package pb implements some useful password-based (PB) functions:
	1. AES-related (192-bit AES):
		1.1. PBAesEncrypt
				encrypts input byte array using string password specified into a new (encrypted) byte array
		1.2. PBAesDecrypt
				decrypts input byte array using string password specified into a new (decrypted) byte array

	2. HTTP-related
		2.1. PBSignRequest
				signs an http request using a string password; adds 2 additional headers to the request
		2.2. PBVerifyRequest
				verifies previously signed http request using a string password

*/
package pb

import "crypto/sha1"

import "code.google.com/p/go.crypto/pbkdf2"

const PBKDF2_ITERATIONS = 1 << 15 // 32k (approx.)
const PBKDF2_SALT_LENGTH = 1 << 4 // 128 bit
const AES_BLOCK_LENGTH = 1 << 4   // 128 bit
const AES_KEY_LENGTH = 24         // 24 bytes (192-bit)
const HMAC_KEY_LENGTH = 1 << 5    // 32 bytes (256-bit)

func PBKDF2Key(password string, salt []byte, keylen byte) (key []byte) {
	key = pbkdf2.Key([]byte(password), salt, PBKDF2_ITERATIONS, int(keylen), sha1.New)
	return key
}
