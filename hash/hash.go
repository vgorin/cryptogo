// Copyright 2013-2014 Vasiliy Gorin. All rights reserved.
// Use of this source code is governed by a GNU-style
// license that can be found in the LICENSE file.

/*
Package hash implements some useful hash-related functions:
	1. MD5:
		1.1. MD5Bytes
				calculates an MD5 chechsum of the input byte array as a byte array
		1.2. MD5Base64
				calculates an MD5 chechsum of the input byte array as a base64-encoded string
		1.3. MD5Hex
				calculates an MD5 chechsum of the input byte array as a hex-encoded string

	2. SHA1:
		2.1. SHA1Bytes
				calculates an SHA1 chechsum of the input byte array as a byte array
		2.2. SHA1Base64
				calculates an SHA1 chechsum of the input byte array as a base64-encoded string
		2.3. SHA1Hex
				calculates an SHA1 chechsum of the input byte array as a hex-encoded string

	3. SHA-224:
		3.1. SHA224Bytes
				calculates an SHA-224 chechsum of the input byte array as a byte array
		3.2. SHA224Base64
				calculates an SHA-224 chechsum of the input byte array as a base64-encoded string
		3.3. SHA224Hex
				calculates an SHA-224 chechsum of the input byte array as a hex-encoded string

	4. SHA-256:
		4.1. SHA256Bytes
				calculates an SHA-256 chechsum of the input byte array as a byte array
		4.2. SHA256Base64
				calculates an SHA-256 chechsum of the input byte array as a base64-encoded string
		4.3. SHA256Hex
				calculates an SHA-256 chechsum of the input byte array as a hex-encoded string

	5. SHA-384:
		5.1. SHA384Bytes
				calculates an SHA-384 chechsum of the input byte array as a byte array
		5.2. SHA384Base64
				calculates an SHA-384 chechsum of the input byte array as a base64-encoded string
		5.3. SHA384Hex
				calculates an SHA-384 chechsum of the input byte array as a hex-encoded string

	6. SHA-512:
		6.1. SHA512Bytes
				calculates an SHA-512 chechsum of the input byte array as a byte array
		6.2. SHA512Base64
				calculates an SHA-512 chechsum of the input byte array as a base64-encoded string
		6.3. SHA512Hex
				calculates an SHA-512 chechsum of the input byte array as a hex-encoded string

*/
package hash

import "encoding/base64"
import "encoding/hex"
import "crypto/md5"
import "crypto/sha1"
import "crypto/sha256"
import "crypto/sha512"

// MD5Bytes calculates MD5 sum of the input array, returning result as a byte array
func MD5Bytes(buf []byte) []byte {
	s := md5.Sum(buf)
	return s[:]
}

// MD5Base64 calculates MD5 sum of the input array, returning result as a base64-encoded string
func MD5Base64(buf []byte) string {
	return base64.StdEncoding.EncodeToString(MD5Bytes(buf))
}

// MD5Hex calculates MD5 sum of the input array, returning result as a hex-encoded string
func MD5Hex(buf []byte) string {
	return hex.EncodeToString(MD5Bytes(buf))
}

// SHA1Bytes calculates SHA1 sum of the input array, returning result as a byte array
func SHA1Bytes(buf []byte) []byte {
	s := sha1.Sum(buf)
	return s[:]
}

// SHA1Base64 calculates SHA1 sum of the input array, returning result as a base64-encoded string
func SHA1Base64(buf []byte) string {
	return base64.StdEncoding.EncodeToString(SHA1Bytes(buf))
}

// SHA1Hex calculates SHA1 sum of the input array, returning result as a hex-encoded string
func SHA1Hex(buf []byte) string {
	return hex.EncodeToString(SHA1Bytes(buf))
}

// SHA224Bytes calculates SHA-224 sum of the input array, returning result as a byte array
func SHA224Bytes(buf []byte) []byte {
	s := sha256.Sum224(buf)
	return s[:]
}

// SHA224Base64 calculates SHA-224 sum of the input array, returning result as a base64-encoded string
func SHA224Base64(buf []byte) string {
	return base64.StdEncoding.EncodeToString(SHA224Bytes(buf))
}

// SHA224Hex calculates SHA-224 sum of the input array, returning result as a hex-encoded string
func SHA224Hex(buf []byte) string {
	return hex.EncodeToString(SHA224Bytes(buf))
}

// SHA256Bytes calculates SHA-256 sum of the input array, returning result as a byte array
func SHA256Bytes(buf []byte) []byte {
	s := sha256.Sum256(buf)
	return s[:]
}

// SHA256Base64 calculates SHA-256 sum of the input array, returning result as a base64-encoded string
func SHA256Base64(buf []byte) string {
	return base64.StdEncoding.EncodeToString(SHA256Bytes(buf))
}

// SHA256Hex calculates SHA-256 sum of the input array, returning result as a hex-encoded string
func SHA256Hex(buf []byte) string {
	return hex.EncodeToString(SHA256Bytes(buf))
}

// SHA384Bytes calculates SHA-384 sum of the input array, returning result as a byte array
func SHA384Bytes(buf []byte) []byte {
	s := sha512.Sum384(buf)
	return s[:]
}

// SHA384Base64 calculates SHA-384 sum of the input array, returning result as a base64-encoded string
func SHA384Base64(buf []byte) string {
	return base64.StdEncoding.EncodeToString(SHA384Bytes(buf))
}

// SHA384Hex calculates SHA-384 sum of the input array, returning result as a hex-encoded string
func SHA384Hex(buf []byte) string {
	return hex.EncodeToString(SHA384Bytes(buf))
}

// SHA512Bytes calculates SHA-512 sum of the input array, returning result as a byte array
func SHA512Bytes(buf []byte) []byte {
	s := sha512.Sum512(buf)
	return s[:]
}

// SHA512Base64 calculates SHA-512 sum of the input array, returning result as a base64-encoded string
func SHA512Base64(buf []byte) string {
	return base64.StdEncoding.EncodeToString(SHA512Bytes(buf))
}

// SHA512Hex calculates SHA-512 sum of the input array, returning result as a hex-encoded string
func SHA512Hex(buf []byte) string {
	return hex.EncodeToString(SHA512Bytes(buf))
}

