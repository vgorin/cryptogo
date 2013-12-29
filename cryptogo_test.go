package cryptogo

import "testing"

import "net/http"

import "github.com/vgorin/cryptogo/pb"

func TestSignRequest(t *testing.T) {
	request, _ := create_request()
	pb.PBSignRequest(request, "password0")
	if !pb.PBVerifyRequest(request, "password0") {
		t.Fatal("check signature failed on the same request")
	}

	request_copy, _ := create_request()
	pb.PBSignRequest(request_copy, "password0")
	if !pb.PBVerifyRequest(request_copy, "password0") {
		t.Fatal("check signature failed on the request copy")
	}

	modified, _ := create_request()
	pb.PBSignRequest(request_copy, "password0")
	modified.Header.Add("header3", "value0")
	if pb.PBVerifyRequest(modified, "password0") {
		t.Fatal("check signature succeeded on different requests")
	}

	shuffled, _ := create_request()
	pb.PBSignRequest(shuffled, "password0")
	shuffled.Header.Del("header0")
	shuffled.Header.Add("header0", "value0")
	if !pb.PBVerifyRequest(shuffled, "password0") {
		t.Fatal("check signature failed on the shuffled request copy")
	}

	shuffled, _ = create_request()
	pb.PBSignRequest(shuffled, "password0")
	shuffled.Header.Del("header1")
	shuffled.Header.Add("header1", "value1")
	shuffled.Header.Add("header1", "value0")
	if !pb.PBVerifyRequest(shuffled, "password0") {
		t.Fatal("check signature failed on the shuffled request copy")
	}
}

func create_request() (*http.Request, error) {
	request, err := http.NewRequest("GET", "http://google.com", nil)
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
