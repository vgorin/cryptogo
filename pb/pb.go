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

// AES_BLOCK_LENGTH AES block length (128 bit)
const AES_BLOCK_LENGTH = 1 << 4 // 128 bit

// PBKDF2Key generates a key from given password using PBKDF2 function
// Executes on the DefaultPBE
func PBKDF2Key(password string, salt []byte, keylen int) (key []byte) {
	return DefaultPBE.PBKDF2Key(password, salt, keylen)
}

// PBKDF2Key generates a key from given password using PBKDF2 function
func (p *pbe) PBKDF2Key(password string, salt []byte, keylen int) (key []byte) {
	key = pbkdf2.Key([]byte(password), salt, p.pbkdf2_iterations, int(keylen), sha1.New)
	return key
}

// pbe is structure for storing setting for password-based encryption/decryption
type pbe struct {
	pbkdf2_iterations,
	pbkdf2_salt_length,
	aes_key_length,
	hmac_key_length int
}

// New creates new pbe structure with the settings specified
func New(pbkdf2_iterations, pbkdf2_salt_length, aes_key_length, hmac_key_length int) *pbe {
	if pbkdf2_iterations < 1 {
		panic("pbkdf2_iterations < 1")
	}
	if pbkdf2_salt_length < 1 {
		panic("pbkdf2_salt_length < 1")
	}
	if aes_key_length != 16 && aes_key_length != 24 && aes_key_length != 32 {
		panic("aes_key_length must be one of: 16 (AES-128), 24 (AES-192), 32 (AES-256)")
	}
	if hmac_key_length != 20 && hmac_key_length != 28 && hmac_key_length != 32 && hmac_key_length != 48 && hmac_key_length != 64 {
		panic("hmac_key_length must be one of: 20 (SHA1), 28 (SHA-224), 32 (SHA-256), 48 (SHA-384), 64 (SHA-512)")
	}
	return &pbe{
		pbkdf2_iterations:  pbkdf2_iterations,
		pbkdf2_salt_length: pbkdf2_salt_length,
		aes_key_length:     aes_key_length,
		hmac_key_length:    hmac_key_length,
	}
}

// DefaultPBE
// PBKDF2_ITERATIONS:	32k
// PBKDF2_SALT_LENGTH:	128 bit
// AES_KEY_LENGTH:		192 bit
// HMAC_KEY_LENGTH:		256 bit
var DefaultPBE *pbe = New(1<<15, 1<<4, 24, 1<<5)
