package asym

import "testing"

func TestSignVerify(t *testing.T) {
	// generate key pair
	private_key_hex, public_key_hex := GenerateKeyPair()
	t.Logf("private key:\t%s", private_key_hex)
	t.Logf("public key:\t%s", public_key_hex)

	// define hash to sign
	hash := []byte("this is my hash!")

	// sign it
	signature, err := Sign(hash, private_key_hex)
	if err != nil {
		t.Fatalf("error signing hash: %s", err)
	}
	t.Logf("signature:\t%s", signature)

	// verify it
	verify, err := Verify(hash, public_key_hex, signature)
	if err != nil {
		t.Fatalf("error verifying hash: %s", err)
	}
	t.Logf("verification result: %t", verify)
	if !verify {
		t.Fail()
	}

	// compute another signature
	hash2 := []byte("this is my second hash!")
	signature2, err := Sign(hash2, private_key_hex)
	if err != nil {
		t.Fatalf("error signing hash: %s", err)
	}
	// check that second signature is not correct for first hash
	verify2, err := Verify(hash, public_key_hex, signature2)
	if err != nil {
		t.Fatalf("error verifying hash: %s", err)
	}
	if verify2 {
		t.Fail()
	}
}

