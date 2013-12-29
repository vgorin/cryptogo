// Copyright 2013 Vasiliy Gorin. All rights reserved.
// Use of this source code is governed by a GNU-style
// license that can be found in the LICENSE file.

package pb

import "crypto/hmac"
import "crypto/sha256"
import "encoding/hex"
import "net/http"
import "bytes"
import "sort"

import "github.com/vgorin/cryptogo/rnd"

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
func PBSignRequest(req *http.Request, password string) error {
	return pb_sign_request(req, password, PBKDF2_SALT_LENGTH, HMAC_KEY_LENGTH)
}

// PBVerifyRequest checks earlier signed http request signature using password specified to ensure request was not altered
func PBVerifyRequest(req *http.Request, password string) bool {
	return pb_validate_request(req, password, HMAC_KEY_LENGTH)
}

func pb_sign_request(req *http.Request, password string, saltlen, keylen byte) error {
	salt, err := rnd.Salt(saltlen)
	if err != nil {
		return err
	}

	salt_hex := hex.EncodeToString(salt)
	req.Header.Set(REQ_HEADER_SALT, salt_hex)

	key := PBKDF2Key(password, salt, keylen)
	message := marshal_request(req)
	hmac256 := hmac_sha256(message, key)

	signature_hex := hex.EncodeToString(hmac256)
	req.Header.Set(REQ_HEADER_HMAC, signature_hex)

	return nil
}

func pb_validate_request(req *http.Request, password string, keylen byte) bool {
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
	message := marshal_request(req)
	hmac256 := hmac_sha256(message, key)

	return bytes.Compare(signature, hmac256) == 0
}

func hmac_sha256(message, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)

	return mac.Sum(nil)
}

func marshal_request(req *http.Request) []byte {
	buffer := new(bytes.Buffer)
	buffer.WriteString(req.RemoteAddr)
	buffer.WriteString(req.RequestURI)

	header := req.Header

	// sort headers
	keys := make([]string, len(header))
	i := 0
	for k, _ := range header {
		keys[i] = k
		i++
	}
	sort.Strings(keys)
	for _, key := range keys {
		values := header[key]
		buffer.WriteString(key) // and write them to the buffer
		//sort header values
		sort.Strings(values)
		for _, value := range values {
			buffer.WriteString(value) // and write them to the buffer as well
		}
	}

	return buffer.Bytes()
}
