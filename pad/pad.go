// Copyright 2013-2014 Vasiliy Gorin. All rights reserved.
// Use of this source code is governed by a GNU-style
// license that can be found in the LICENSE file.

/*
Package pad implements some useful padding-related functions:
	1. PKCS7 Padding
		1.1. PKCS77Pad
				adds PKCS #7 padding to an input byte array, returning new (padded) byte array
		1.2. PKCS7Unpad
				removes PKCS #7 padding from an input byte array, returning new (striped) byte array;
				checks if padding is correct

	2. ANSI X.923 Padding
		2.1. X923Pad
				adds ANSI X.923 padding to an input byte array, returning new (padded) byte array
		2.2. X923Unad
				removes ANSI X.923 padding from an input byte array, returning new (striped) byte array;
				checks if padding is correct

*/
package pad

import "bytes"
import "fmt"

// PKCS7Pad adds PKCS7 padding to the data block, http://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7
func PKCS7Pad(message []byte, blocksize int) (padded []byte) {
	// block size must be bigger or equal 2
	if blocksize < 1<<1 {
		panic("block size is too small (minimum is 2 bytes)")
	}
	// block size up to 255 requires 1 byte padding
	if blocksize < 1<<8 {
		// calculate padding length
		padlen := PadLength(len(message), blocksize)

		// define PKCS7 padding block
		padding := bytes.Repeat([]byte{byte(padlen)}, padlen)

		// apply padding
		padded = append(message, padding...)
		return padded
	}
	// block size bigger or equal 256 is not currently supported
	panic("unsupported block size")
}

// PKCS7Unpad removes PKCS7 padding from the data block, http://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7
// this function may return an error id padding is incorrect,
// however it will return unpaded data in any case
func PKCS7Unpad(padded []byte) (message []byte, err error) {
	// read padding length
	plen := len(padded)
	last_byte := padded[plen-1]
	padlen := int(last_byte)

	// check validity of PKCS7 padding
	for i := padlen; i > 1; i-- {
		if padded[plen-i] != last_byte {
			err = fmt.Errorf("Invalid padding (byte -%d: %d). Is the message supplied PKCS7 padded?", i, padded[plen-i])
			break
		}
	}

	// remove padding
	return padded[:plen-padlen], err
}

// X923Pad adds ANSI X.923 padding to the data block, http://en.wikipedia.org/wiki/Padding_(cryptography)#ANSI_X.923
func X923Pad(message []byte, blocksize int) (padded []byte) {
	// block size must be bigger or equal 2
	if blocksize < 1<<1 {
		panic("block size is too small (minimum is 2 bytes)")
	}
	// block size up to 255 requires 1 byte padding
	if blocksize < 1<<8 {
		// calculate padding length
		padlen := PadLength(len(message), blocksize)

		// define ANSI X.923 padding block
		padding := make([]byte, padlen)
		padding[padlen-1] = byte(padlen)

		// apply padding
		padded = append(message, padding...)
		return padded
	}
	// block size bigger or equal 256 is not currently supported
	panic("unsupported block size")
}

// X923Pad removes ANSI X.923 padding from the data block, http://en.wikipedia.org/wiki/Padding_(cryptography)#ANSI_X.923
// this function may return an error id padding is incorrect,
// however it will return unpaded data in any case
func X923Unpad(padded []byte) (message []byte, err error) {
	// read padding length
	plen := len(padded)
	last_byte := padded[plen-1]
	padlen := int(last_byte)

	// check validity of ANSI X.923 padding
	for i := padlen; i > 1; i-- {
		if padded[plen-i] != 0 {
			err = fmt.Errorf("Invalid padding (byte -%d: %d). Is the message supplied ANSI X.923 padded?", i, padded[plen-i])
			break
		}
	}

	// remove padding
	return padded[:plen-padlen], err
}

// PadLength calculates padding length
func PadLength(slice_length, blocksize int) (padlen int) {
	padlen = blocksize - slice_length%blocksize
	if padlen == 0 {
		padlen = blocksize
	}
	return padlen
}
