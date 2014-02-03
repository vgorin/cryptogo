// Copyright 2013-2014 Vasiliy Gorin. All rights reserved.
// Use of this source code is governed by a GNU-style
// license that can be found in the LICENSE file.

package asym

import "net/http"

import "github.com/vgorin/cryptogo/util"

const REQ_HEADER_SIGNATURE = "X-Cryptogo-Signature"

// ECSignRequest signs a http request using the private key specified
// Signature changes if:
// 	remote address changes
// 	request URI changes
// 	request header is deleted
// 	request header is added
// 	request header is modified
//
// Signature doesn't change if:
// 	request header ordering is changed
func ECSignRequest(req *http.Request, pattern *util.SignaturePattern, private_key_hex string) error {
	hash := util.HashRequest(req, pattern)
	signature_hex, err := Sign(hash, private_key_hex)
	if err != nil {
		return err
	}
	req.Header.Set(REQ_HEADER_SIGNATURE, signature_hex)
	return nil
}

// ECVerifyRequest checks earlier signed http request signature using public key specified to ensure request was not altered
func ECVerifyRequest(req *http.Request, pattern *util.SignaturePattern, public_key_hex string) bool {
	hash := util.HashRequest(req, pattern)
	signature_hex := req.Header.Get(REQ_HEADER_SIGNATURE)
	if signature_hex == "" {
		return false
	}
	verify, err := Verify(hash, public_key_hex, signature_hex)
	if err != nil {
		return false
	}
	return verify
}
