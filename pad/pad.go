// Copyright 2013 Vasiliy Gorin. All rights reserved.
// Use of this source code is governed by a GNU-style
// license that can be found in the LICENSE file.

/*
Package pad implements some useful padding-related functions:
	1. PKCS5 Padding
		1.1. Pkcs5Pad
				adds PKCS #5 padding to an input byte array, returning new (padded) byte array
		1.2. Pkcs5Unpad
				removes PKCS #5 padding from an input byte array, returning new (striped) byte array
*/
package pad

import "bytes"

// Pkcs5Pad adds padding to the data block as described by RFC2898 (PKCS #5)
func Pkcs5Pad(original []byte, keylen byte) (padded []byte) {
	padlen := keylen - byte(len(original)%int(keylen))
	if padlen == 0 {
		padlen = keylen
	}

	padded = append(original, bytes.Repeat([]byte{padlen}, int(padlen))...)
	return padded
}

// Pkcs5Pad removes padding from the data block as described by RFC2898 (PKCS #5)
func Pkcs5Unpad(padded []byte) (original []byte, err error) {
	// TODO: need to check all padding bytes (check padding itself)
	plen := len(padded)
	padlen := int(padded[plen-1])
	return padded[:plen-padlen], nil
}

