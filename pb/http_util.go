// Copyright 2013-2014 Vasiliy Gorin. All rights reserved.
// Use of this source code is governed by a GNU-style
// license that can be found in the LICENSE file.

package pb

import "hash"
import "crypto/hmac"
import "crypto/sha1"
import "crypto/sha256"
import "crypto/sha512"
import "encoding/hex"
import "net/http"
import "bytes"

import "github.com/vgorin/cryptogo/rnd"
import "github.com/vgorin/cryptogo/util"

const REQ_HEADER_SALT = "X-Cryptogo-Salt"
const REQ_HEADER_HMAC = "X-Cryptogo-Hmac"

// PBSignRequest signs a http request using the password specified
// Signature changes if:
// 	remote address changes
// 	request URI changes
// 	request header is deleted
// 	request header is added
// 	request header is modified
//
// Signature doesn't change if:
// 	request header ordering is changed
//
// Executes on the DefaultPBE
func PBSignRequest(req *http.Request, password string, pattern *util.SignaturePattern) error {
	return DefaultPBE.PBSignRequest(req, password, pattern)
}

// PBSignRequest signs a http request using the password specified
// Signature changes if:
// 	remote address changes
// 	request URI changes
// 	request header is deleted
// 	request header is added
// 	request header is modified
//
// Signature doesn't change if:
// 	request header ordering is changed
func (p *pbe) PBSignRequest(req *http.Request, password string, pattern *util.SignaturePattern) error {
	saltlen := p.pbkdf2_salt_length
	keylen := p.hmac_key_length

	salt, err := rnd.Salt(saltlen)
	if err != nil {
		return err
	}

	salt_hex := hex.EncodeToString(salt)
	req.Header.Set(REQ_HEADER_SALT, salt_hex)

	key := PBKDF2Key(password, salt, keylen)
	message := util.MarshalRequest(req, pattern)
	hmac_sha := hmac_sha(message, key)

	signature_hex := hex.EncodeToString(hmac_sha)
	req.Header.Set(REQ_HEADER_HMAC, signature_hex)

	return nil
}

// PBVerifyRequest checks earlier signed http request signature using password specified to ensure request was not altered
// Executes on the DefaultPBE
func PBVerifyRequest(req *http.Request, password string, pattern *util.SignaturePattern) bool {
	return DefaultPBE.PBVerifyRequest(req, password, pattern)
}

// PBVerifyRequest checks earlier signed http request signature using password specified to ensure request was not altered
func (p *pbe) PBVerifyRequest(req *http.Request, password string, pattern *util.SignaturePattern) bool {
	keylen := p.hmac_key_length

	salt_hex := req.Header.Get(REQ_HEADER_SALT)
	if salt_hex == "" {
		return false
	}
	salt, err := hex.DecodeString(salt_hex)
	if err != nil {
		return false
	}

	signature_hex := req.Header.Get(REQ_HEADER_HMAC)
	if signature_hex == "" {
		return false
	}

	// temporary remove signature header
	req.Header.Del(REQ_HEADER_HMAC)
	defer req.Header.Set(REQ_HEADER_HMAC, signature_hex)

	signature, err := hex.DecodeString(signature_hex)
	if err != nil {
		return false
	}

	key := PBKDF2Key(password, salt, keylen)
	message := util.MarshalRequest(req, pattern)
	hmac_sha := hmac_sha(message, key)

	return bytes.Compare(signature, hmac_sha) == 0
}

// hmac_sha calculates SHA-based HMAC using the key specified
func hmac_sha(message, key []byte) []byte {
	var mac hash.Hash
	switch len(key) {
	case 20:
		mac = hmac.New(sha1.New, key)
	case 28:
		mac = hmac.New(sha256.New224, key)
	case 32:
		mac = hmac.New(sha256.New, key)
	case 48:
		mac = hmac.New(sha512.New384, key)
	case 64:
		mac = hmac.New(sha512.New, key)
	default:
		panic("unsupported key length " + string(len(key)))
	}

	return mac.Sum(message)
}
