package asym

import "testing"
import "net/http"

func TestSignVerifyRequest(t *testing.T) {
	// generate key pair
	private_key_hex, public_key_hex := GenerateKeyPair()
	t.Logf("private key:\t%s", private_key_hex)
	t.Logf("public key:\t%s", public_key_hex)

	request := http.NewRequest()

}

