// Copyright 2013-2014 Vasiliy Gorin. All rights reserved.
// Use of this source code is governed by a GNU-style
// license that can be found in the LICENSE file.

/*
Package asym implements asymetric cryptography related functions:
	1. GenerateKeyPair
			generates private/public key pair, result is returned as two strings

	2. Sign
			signes a byte array (usually hash) using private key specified

	3. Verify
			verifies a byte array signature using public key specified

Currently all functions in this package use elliptic curves based algorithms

*/

package asym

import "crypto/rand"
import "crypto/elliptic"
import "crypto/ecdsa"
import "crypto/x509"
import "encoding/hex"
import "encoding/json"
import "math/big"
import "errors"

// GenerateKeyPair generates a private/public key pair,
// keys are returned as hex-encoded strings
func GenerateKeyPair() (private_key_hex, public_key_hex string) {
	// generate keys
	private_key, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		panic(err)
	}

	// marshal private key
	private_key_bytes, err := x509.MarshalECPrivateKey(private_key)
	if err != nil {
		panic(err)
	}

	// marshal public key
	public_key_bytes, err := x509.MarshalPKIXPublicKey(&private_key.PublicKey)
	if err != nil {
		panic(err)
	}

	// hex encode and return result
	private_key_hex = hex.EncodeToString(private_key_bytes)
	public_key_hex = hex.EncodeToString(public_key_bytes)

	return private_key_hex, public_key_hex
}

// signature is a structure for storing signature obtained from ecdsa.Sign
type signature struct {
	R,
	S *big.Int
}

// Sign calculates a signature for a byte array hash using hex-encoded private key
// It is supposed that a hash is calculated for an original message to sign
// Signature is a hex-encoded JSON
func Sign(hash []byte, private_key_hex string) (signature_hex string, err error) {
	// decode private key from hex
	private_key_bytes, err := hex.DecodeString(private_key_hex)
	if err != nil {
		return "", err
	}

	// x509 parse private key
	private_key, err := x509.ParseECPrivateKey(private_key_bytes)
	if err != nil {
		return "", err
	}

	// sign
	r, s, err := ecdsa.Sign(rand.Reader, private_key, hash)
	if err != nil {
		return "", err
	}

	// prepare a signature structure to marshal into json
	signature := &signature{
		R: r,
		S: s,
	}

	// marshal to json
	signature_json, err := json.Marshal(signature)
	if err != nil {
		return "", err
	}

	// encode to hex
	signature_hex = hex.EncodeToString(signature_json)
	return signature_hex, nil
}

// Verify verifies a previously generated signature for byte array hash using hex-encoded public key
func Verify(hash []byte, public_key_hex, signature_hex string) (result bool, err error) {
	// decode public key from hex
	public_key_bytes, err := hex.DecodeString(public_key_hex)
	if err != nil {
		return false, nil
	}

	// x509 parse public key
	public_key, err := x509.ParsePKIXPublicKey(public_key_bytes)
	if err != nil {
		return false, nil
	}

	// check that parse key is ecdsa.PublicKey
	switch public_key := public_key.(type) {
	case *ecdsa.PublicKey:
		// decode signature json from hex
		signature_json, err := hex.DecodeString(signature_hex)
		if err != nil {
			return false, nil
		}

		// unmarhsal signature structure to extract signature from
		signature := new(signature)
		err = json.Unmarshal(signature_json, signature)
		if err != nil {
			return false, nil
		}

		// verify signature
		return ecdsa.Verify(public_key, hash, signature.R, signature.S), nil

	default:
		// only ECDSA public keys are supported
		return false, errors.New("only ECDSA public keys supported")
	}
}
