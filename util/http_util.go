package util

import "net/http"
import "bytes"
import "sort"

import "github.com/vgorin/cryptogo/hash"

type SignaturePattern struct {
	// IncludesHeaders has higher priority then ExcludesHeaders
	IncludeHeaders,
	ExcludeHeaders []string
}

// NewSignaturePattern creates new signature_pattern structure
// Use NewSignaturePattern(nil, nil) to create an empty pattern which affects nothing
func NewSignaturePattern(IncludeHeaders, ExcludeHeaders []string) *SignaturePattern {
	pattern := SignaturePattern{IncludeHeaders, ExcludeHeaders}
	if len(pattern.IncludeHeaders) > 0 {
		sort.Strings(pattern.IncludeHeaders)
	}
	if len(pattern.ExcludeHeaders) > 0 {
		sort.Strings(pattern.ExcludeHeaders)
	}
	return &pattern
}

// MarshalRequest creates a composite string representation of a request
// it includes headers from signature_pattern.include_headers
// it excludes headers from signature_pattern.exclude_headers
func MarshalRequest(req *http.Request, pattern *SignaturePattern) []byte {
	buffer := new(bytes.Buffer)
	buffer.WriteString(req.RemoteAddr)
	buffer.WriteString(req.RequestURI)

	header := req.Header

	// sort headers
	var keys []string
	if len(pattern.IncludeHeaders) == 0 {
		exc_len := len(pattern.ExcludeHeaders)
		keys := make([]string, len(header))
		i := 0
		for k, _ := range header {
			if exc_len > 0 && sort.SearchStrings(pattern.ExcludeHeaders, k) == exc_len {
				keys[i] = k
				i++
			}
		}
	} else {
		keys = pattern.IncludeHeaders
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

// HashRequest calculates SHA1 hash on the marshalled request
func HashRequest(req *http.Request, pattern *SignaturePattern) []byte {
	marshal := MarshalRequest(req, pattern)
	hash := hash.SHA1Bytes(marshal)
	return hash
}
