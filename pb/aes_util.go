// Copyright 2013-2014 Vasiliy Gorin. All rights reserved.
// Use of this source code is governed by a GNU-style
// license that can be found in the LICENSE file.

package pb

import "crypto/aes"
import "crypto/cipher"

import "github.com/vgorin/cryptogo/rnd"
import "github.com/vgorin/cryptogo/pad"

// AllocateSlice allocates slice of the specified length
// with a capacity enough to perform encryption of this slice
// without creating a new one
// This is the desired method to create slices to encrypt with PBAesEncryptPtr
// Executes on the DefaultPBE
func AllocateSlice(length int) []byte {
	return DefaultPBE.AllocateSlice(length)
}

// AllocateSlice allocates slice of the specified length
// with a capacity enough to perform encryption of this slice
// without creating a new one
// This is the desired method to create slices to encrypt with PBAesEncryptPtr
func (p *pbe) AllocateSlice(length int) []byte {
	// calculate padding length
	padlen := pad.PadLength(length, AES_BLOCK_LENGTH)

	// capacity = length + padding length + IV length + salt length
	capacity := length + padlen + AES_BLOCK_LENGTH + p.pbkdf2_salt_length

	// allocate slice and return
	slice := make([]byte, length, capacity)
	return slice
}

// PBAesEncrypt: AES-based password-based encryption
// Executes on the DefaultPBE
func PBAesEncrypt(original []byte, password string) (encrypted []byte, err error) {
	return DefaultPBE.PBAesEncrypt(original, password)
}

// PBAesEncrypt: AES-based password-based encryption
func (p *pbe) PBAesEncrypt(original []byte, password string) (encrypted []byte, err error) {
	encrypted = p.AllocateSlice(len(original))
	copy(encrypted, original)
	err = p.PBAesEncryptPtr(&encrypted, password)
	if err != nil {
		return nil, err
	}
	return encrypted, nil
}

// PBAesEncryptPtr: AES-based password-based encryption
// Changes the slice supplied itself
// Executes on the DefaultPBE
func PBAesEncryptPtr(block *[]byte, password string) error {
	return DefaultPBE.PBAesEncryptPtr(block, password)
}

// PBAesEncryptPtr: AES-based password-based encryption
// Changes the slice supplied itself
func (p *pbe) PBAesEncryptPtr(block *[]byte, password string) error {
	// extract constants
	saltlen := p.pbkdf2_salt_length
	keylen := p.aes_key_length
	blocklen := AES_BLOCK_LENGTH

	// generate salt
	salt, err := rnd.Salt(saltlen)
	if err != nil {
		return err
	}

	// generate IV
	iv, err := rnd.IV(blocklen)
	if err != nil {
		return err
	}

	// generate key
	key := p.PBKDF2Key(password, salt, keylen)

	// pad data block
	*block = pad.PKCS7Pad(*block, blocklen)

	// encrypt it
	err = aes_enc_block(*block, iv, key)
	if err != nil {
		return err
	}

	// join padded block + IV + salt into single buffer
	*block = append(*block, iv...)
	*block = append(*block, salt...)

	return nil
}

// PBAesDecrypt: AES-based password-based decryption
// Executes on the DefaultPBE
func PBAesDecrypt(encrypted []byte, password string) (original []byte, err error) {
	return DefaultPBE.PBAesDecrypt(encrypted, password)
}

// PBAesDecrypt: AES-based password-based decryption
func (p *pbe) PBAesDecrypt(encrypted []byte, password string) (original []byte, err error) {
	original = make([]byte, len(encrypted))
	copy(original, encrypted)
	err = p.PBAesDecryptPtr(&original, password)
	if err != nil {
		return nil, err
	}
	return original, nil
}

// PBAesDecryptPtr: AES-based password-based decryption
// Changes the slice supplied itself
// Executes on the DefaultPBE
func PBAesDecryptPtr(block *[]byte, password string) error {
	return DefaultPBE.PBAesDecryptPtr(block, password)
}

// PBAesDecryptPtr: AES-based password-based decryption
// Changes the slice supplied itself
func (p *pbe) PBAesDecryptPtr(block *[]byte, password string) error {
	// extract constants
	saltlen := p.pbkdf2_salt_length
	keylen := p.aes_key_length
	blocklen := AES_BLOCK_LENGTH

	// define indexes
	salt_idx := len(*block)-saltlen
	iv_idx := salt_idx - blocklen

	// extract salt & IV
	salt := (*block)[salt_idx:]
	iv := (*block)[iv_idx : salt_idx]

	// restore key
	key := PBKDF2Key(password, salt, keylen)

	// remove salt & IV
	*block = (*block)[:iv_idx]

	// decrypt
	err := aes_dec_block(*block, iv, key)
	if err != nil {
		return err
	}

	// remove padding
	*block, err = pad.PKCS7Unpad(*block)

	return err
}

// aes_enc_block performs cbc.CryptBlocks on the block (encryption)
func aes_enc_block(block, iv, key []byte) error {
	c, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	cbc := cipher.NewCBCEncrypter(c, iv)
	cbc.CryptBlocks(block, block)

	return nil
}

// aes_dec_block performs cbc.CryptBlocks on the block (decryption)
func aes_dec_block(block, iv, key []byte) error {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}

	cbc := cipher.NewCBCDecrypter(c, iv)
	cbc.CryptBlocks(block, block)

	return nil
}
