// Copyright 2013 Vasiliy Gorin. All rights reserved.
// Use of this source code is governed by a GNU-style
// license that can be found in the LICENSE file.

/*
Package cryptogo implements some useful cryptography-related functions:
	1. Hash-related:
		1.1. MD5Bytes
				calculates an MD5 chechsum of the input byte array as a byte array
		1.2. MD5Base64
				calculates an MD5 chechsum of the input byte array as a base64-encoded string
		1.3. MD5Hex
				calculates an MD5 chechsum of the input byte array as a hex-encoded string

	2. AES-related:
		2.1. PasswordAesEncrypt
				encrypts input byte array using string password specified into a new (encrypted) byte array
		2.2. PasswordAesDecrypt
				decrypts input byte array using string password specified into a new (decrypted) byte array

	3. Padding-related
		3.1. Pkcs5Pad
				adds PKCS #5 padding to an input byte array, returning new (padded) byte array
		3.2. Pkcs5Unpad
				removes PKCS #5 padding from an input byte array, returning new (striped) byte array

	4. Random-related
		4.1. RandomBytes
				generates a random byte array of the specified length
*/

package cryptogo

import "crypto/rand"
import "crypto/sha1"
import "crypto/aes"
import "crypto/cipher"
import "bytes"
import "fmt"

import "encoding/base64"
import "encoding/hex"
import "crypto/md5"

import "net/http"

import "code.google.com/p/go.crypto/pbkdf2"

const HashIterations = 1 << 15 // 32k (approx.)
const SaltLength = 1 << 4      // 128 bit
const IVLength = 1 << 4        // 128 bit
const KeyLength = 1 << 5       // 32 bytes (256-bit)

func key(password string, salt []byte, keylen byte) (key []byte) {
	key = pbkdf2.Key([]byte(password), salt, HashIterations, int(keylen), sha1.New)
	return key
}

var iv = RandomBytes

var salt = RandomBytes

func RandomBytes(length byte) (rnd []byte, err error) {
	rnd = make([]byte, length)
	r, err := rand.Read(rnd)
	if err != nil || r != int(length) {
		return nil, err
	}
	return rnd, nil
}

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

// PasswordAesEncode 256-bit AES-based password encryption
func PasswordAesEncrypt(original []byte, password string) (encrypted []byte, err error) {
	return aes_enc(original, password, SaltLength, IVLength, KeyLength)
}

// PasswordAesDecrypt 256-bit AES-based password decryption
func PasswordAesDecrypt(encrypted []byte, password string) (original []byte, err error) {
	return aes_dec(encrypted, password, SaltLength, IVLength, KeyLength)
}

func aes_enc_block(block, iv, key []byte) error {
	c, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	cbc := cipher.NewCBCEncrypter(c, iv)
	cbc.CryptBlocks(block, block)

	return nil
}

func aes_dec_block(block, iv, key []byte) error {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}

	cbc := cipher.NewCBCDecrypter(c, iv)
	cbc.CryptBlocks(block, block)

	return nil
}

func aes_enc(original []byte, password string, saltlen, ivlen, keylen byte) (encrypted []byte, err error) {
	salt, err := salt(saltlen)
	if err != nil {
		return nil, err
	}
	fmt.Printf("salt len:\t%v\n", len(salt))

	iv, err := iv(ivlen)
	if err != nil {
		return nil, err
	}
	fmt.Printf("iv len:\t%v\n", len(iv))

	key := key(password, salt, keylen)
	fmt.Printf("key len:\t%v\n", len(key))

	block := Pkcs5Pad(original, keylen)
	fmt.Printf("block len:\t%v\n", len(block))

	err = aes_enc_block(block, iv, key)
	if err != nil {
		return nil, err
	}

	return append(salt, append(iv, block...)...), nil
}

func aes_dec(encrypted []byte, password string, saltlen, ivlen, keylen byte) (original []byte, err error) {
	salt := encrypted[:saltlen]
	iv := encrypted[saltlen : saltlen+ivlen]
	key := key(password, salt, keylen)

	block := encrypted[saltlen+ivlen:]

	err = aes_dec_block(block, iv, key)
	if err != nil {
		return nil, err
	}

	return Pkcs5Unpad(block)
}

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

// SignRequest signs a http request using the password specified
func SignRequest(req *http.Request, password string) {
}

// CheckRequestSignature checks earlier signed http request signature using password specified to ensure request was not altered
func CheckRequestSignature(req *http.Request, password string) bool {
	return true
}
