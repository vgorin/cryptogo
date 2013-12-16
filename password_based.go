package cryptogo

import "crypto/rand"
import "crypto/sha1"
import "crypto/aes"
import "crypto/cipher"
import "bytes"
import "fmt"

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
