// Copyright 2013-2014 Vasiliy Gorin. All rights reserved.
// Use of this source code is governed by a GNU-style
// license that can be found in the LICENSE file.

package pad

import "testing"

func TestX923Padding(t *testing.T) {
	msg := "this is my test message of length 36"
	msg_bytes := []byte(msg)
	t.Logf("message (len=%d): %s", len(msg_bytes), msg)
	padded_bytes := X923Pad(msg_bytes, 17)
	padded := string(padded_bytes)
	t.Logf("padded (len=%d): %s", len(padded_bytes), padded)
	t.Logf("padded bytes (len=%d): %v", len(padded_bytes), padded_bytes)
	original_bytes, err := X923Unpad(padded_bytes)
	if err != nil {
		t.Error(err)
	}
	original := string(original_bytes)
	t.Logf("unpadded: %s", original)

	padded_bytes[len(padded_bytes)-5] = 77
	original_bytes, err = X923Unpad(padded_bytes)
	t.Logf("expected error: %s", err)
	if err == nil {
		t.Error("expected error but got nil")
	}
}

func TestPKCS7Padding(t *testing.T) {
	msg := "this is my test message of length 36"
	msg_bytes := []byte(msg)
	t.Logf("message (len=%d): %s", len(msg_bytes), msg)
	padded_bytes := PKCS7Pad(msg_bytes, 17)
	padded := string(padded_bytes)
	t.Logf("padded (len=%d): %s", len(padded_bytes), padded)
	t.Logf("padded bytes (len=%d): %v", len(padded_bytes), padded_bytes)
	original_bytes, err := PKCS7Unpad(padded_bytes)
	if err != nil {
		t.Error(err)
	}
	original := string(original_bytes)
	t.Logf("unpadded: %s", original)

	padded_bytes[len(padded_bytes)-5] = 77
	original_bytes, err = PKCS7Unpad(padded_bytes)
	t.Logf("expected error: %s", err)
	if err == nil {
		t.Error("expected error but got nil")
	}
}
