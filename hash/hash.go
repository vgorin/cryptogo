// Copyright 2013 Vasiliy Gorin. All rights reserved.
// Use of this source code is governed by a GNU-style
// license that can be found in the LICENSE file.

/*
Package hash implements some useful hash-related functions:
	1. MD5-based:
		1.1. MD5Bytes
				calculates an MD5 chechsum of the input byte array as a byte array
		1.2. MD5Base64
				calculates an MD5 chechsum of the input byte array as a base64-encoded string
		1.3. MD5Hex
				calculates an MD5 chechsum of the input byte array as a hex-encoded string
*/
package hash

import "encoding/base64"
import "encoding/hex"
import "crypto/md5"

// MD5Bytes calculates MD5 sum of the input array, returning result as a byte array
func MD5Bytes(buf []byte) []byte {
	m16 := md5.Sum(buf)
	return m16[:]
}

// MD5Base64 calculates MD5 sum of the input array, returning result as a base64-encoded string
func MD5Base64(buf []byte) string {
	return base64.StdEncoding.EncodeToString(MD5Bytes(buf))
}

// MD5Hex calculates MD5 sum of the input array, returning result as a hex-encoded string
func MD5Hex(buf []byte) string {
	return hex.EncodeToString(MD5Bytes(buf))
}

