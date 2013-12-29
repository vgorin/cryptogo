package cryptogo

import "testing"

import "net/http"

func TestSignRequest(t *testing.T) {
	request, _ := create_request()
	PasswordSignRequest(request, "password0")
	if !PasswordVerifyRequest(request, "password0") {
		t.Fatal("check signature failed on the same request")
	}

	request_copy, _ := create_request()
	PasswordSignRequest(request_copy, "password0")
	if !PasswordVerifyRequest(request_copy, "password0") {
		t.Fatal("check signature failed on the request copy")
	}

	modified, _ := create_request()
	PasswordSignRequest(request_copy, "password0")
	modified.Header.Add("header3", "value0")
	if PasswordVerifyRequest(modified, "password0") {
		t.Fatal("check signature succeeded on different requests")
	}

	shuffled, _ := create_request()
	PasswordSignRequest(shuffled, "password0")
	shuffled.Header.Del("header0")
	shuffled.Header.Add("header0", "value0")
	if !PasswordVerifyRequest(shuffled, "password0") {
		t.Fatal("check signature failed on the shuffled request copy")
	}

	shuffled, _ = create_request()
	PasswordSignRequest(shuffled, "password0")
	shuffled.Header.Del("header1")
	shuffled.Header.Add("header1", "value1")
	shuffled.Header.Add("header1", "value0")
	if !PasswordVerifyRequest(shuffled, "password0") {
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
