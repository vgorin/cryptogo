// Copyright 2013 Vasiliy Gorin. All rights reserved.
// Use of this source code is governed by a GNU-style
// license that can be found in the LICENSE file.

/*
Package rnd implements random-related functions:
	1. RandomBytes
			generates a random byte array of the specified length
	2. IV
			synonim for RandomBytes, used to generate random IV
	3. Salt
			synonim for RandomBytes, used to generate random Salt


*/
package rnd

import "crypto/rand"

var IV = random_bytes_byte

var Salt = random_bytes_byte

func random_bytes_byte(length byte) (rnd []byte, err error) {
	return RandomBytes(int(length))
}

// RandomBytes generates an array of length 'length' containing random bytes
func RandomBytes(length int) (rnd []byte, err error) {
	rnd = make([]byte, length)
	r, err := rand.Read(rnd)
	if err != nil || r != int(length) {
		return nil, err
	}
	return rnd, nil
}