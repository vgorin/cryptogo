// Copyright 2013-2014 Vasiliy Gorin. All rights reserved.
// Use of this source code is governed by a GNU-style
// license that can be found in the LICENSE file.

package cryptogo

import "testing"

import "net/http"

import "github.com/vgorin/cryptogo/pb"

func TestSignRequest(t *testing.T) {
	pattern := pb.NewSignaturePattern([]string{"header0, header1, header2, header3"}, nil)

	request, _ := create_request()
	pb.PBSignRequest(request, "password0", pattern)
	if !pb.PBVerifyRequest(request, "password0", pattern) {
		t.Fatal("check signature failed on the same request")
	}

	request_copy, _ := create_request()
	pb.PBSignRequest(request_copy, "password0", pattern)
	if !pb.PBVerifyRequest(request_copy, "password0", pattern) {
		t.Fatal("check signature failed on the request copy")
	}

	modified, _ := create_request()
	pb.PBSignRequest(request_copy, "password0", pattern)
	modified.Header.Add("header3", "value0")
	if pb.PBVerifyRequest(modified, "password0", pattern) {
		t.Fatal("check signature succeeded on different requests")
	}

	shuffled, _ := create_request()
	pb.PBSignRequest(shuffled, "password0", pattern)
	shuffled.Header.Del("header0")
	shuffled.Header.Add("header0", "value0")
	if !pb.PBVerifyRequest(shuffled, "password0", pattern) {
		t.Fatal("check signature failed on the shuffled request copy")
	}

	shuffled, _ = create_request()
	pb.PBSignRequest(shuffled, "password0", pattern)
	shuffled.Header.Del("header1")
	shuffled.Header.Add("header1", "value1")
	shuffled.Header.Add("header1", "value0")
	if !pb.PBVerifyRequest(shuffled, "password0", pattern) {
		t.Fatal("check signature failed on the shuffled request copy")
	}

	excluded, _ := create_request()
	pb.PBSignRequest(excluded, "password0", pattern)
	excluded.Header.Add("header5", "value0")
	if !pb.PBVerifyRequest(excluded, "password0", pattern) {
		t.Fatal("check signature failed on the excluded header request copy")
	}
}

func create_request() (*http.Request, error) {
	request, err := http.NewRequest("GET", "http://google.com/?query=search+me=please&pages=100", nil)
	if err != nil {
		return nil, err
	}
	request.RemoteAddr = "remote_address"
	request.RequestURI = "request_uri"
	request.Header.Add("header0", "value0")
	request.Header.Add("header1", "value0")
	request.Header.Add("header1", "value1")
	return request, nil
}
