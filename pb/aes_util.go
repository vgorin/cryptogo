// Copyright 2013-2014 Vasiliy Gorin. All rights reserved.
// Use of this source code is governed by a GNU-style
// license that can be found in the LICENSE file.

package pb

import "crypto/aes"
import "crypto/cipher"

import "github.com/vgorin/cryptogo/rnd"
import "github.com/vgorin/cryptogo/pad"

// PBAesEncode 256-bit AES-based password-based encryption
func PBAesEncrypt(original []byte, password string) (encrypted []byte, err error) {
	return pb_aes_enc(original, password, PBKDF2_SALT_LENGTH, AES_KEY_LENGTH)
}

// PBAesDecrypt 256-bit AES-based password-based decryption
func PBAesDecrypt(encrypted []byte, password string) (original []byte, err error) {
	return pb_aes_dec(encrypted, password, PBKDF2_SALT_LENGTH, AES_KEY_LENGTH)
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

func pb_aes_enc(original []byte, password string, saltlen, keylen byte) (encrypted []byte, err error) {
	salt, err := rnd.Salt(saltlen)
	if err != nil {
		return nil, err
	}
	//	fmt.Printf("salt len:\t%v\n", len(salt))

	iv, err := rnd.IV(AES_BLOCK_LENGTH)
	if err != nil {
		return nil, err
	}
	//	fmt.Printf("iv len:\t%v\n", len(iv))

	key := PBKDF2Key(password, salt, keylen)
	//	fmt.Printf("key len:\t%v\n", len(key))

	block := pad.PKCS7Pad(original, AES_BLOCK_LENGTH)
	//	fmt.Printf("block len:\t%v\n", len(block))

	err = aes_enc_block(block, iv, key)
	if err != nil {
		return nil, err
	}

	return append(salt, append(iv, block...)...), nil
}

func pb_aes_dec(encrypted []byte, password string, saltlen, keylen byte) (original []byte, err error) {
	salt := encrypted[:saltlen]
	iv := encrypted[saltlen : saltlen+AES_BLOCK_LENGTH]
	key := PBKDF2Key(password, salt, keylen)

	block := encrypted[saltlen+AES_BLOCK_LENGTH:]

	err = aes_dec_block(block, iv, key)
	if err != nil {
		return nil, err
	}

	return pad.PKCS7Unpad(block)
}
