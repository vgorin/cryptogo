// Copyright 2013-2014 Vasiliy Gorin. All rights reserved.
// Use of this source code is governed by a GNU-style
// license that can be found in the LICENSE file.

package pb

import "testing"
import "bytes"

func TestPBAes(t *testing.T) {
	message := "this is my tiny message"
	t.Logf("message: %s", message)
	password := "this is my easy to guess password"
	message_bytes := []byte(message)
	encrypted_bytes, err := PBAesEncrypt(message_bytes, password)
	if err != nil {
		t.Error(err)
	}
	decrypted_bytes, err := PBAesDecrypt(encrypted_bytes, password)
	decrypted := string(decrypted_bytes)
	t.Logf("decrypted: %s", decrypted)
	if bytes.Compare(message_bytes, decrypted_bytes) != 0 {
		t.Error("original and decryoted messages mismatch")
	}
}

