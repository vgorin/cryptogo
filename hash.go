package cryptogo

import "encoding/base64"
import "encoding/hex"
import "crypto/md5"

func MD5Bytes(buf []byte) []byte {
	m16 := md5.Sum(buf)
	return m16[:]
}

func MD5Base64(buf []byte) string {
	return base64.StdEncoding.EncodeToString(MD5Bytes(buf))
}

func MD5Hex(buf []byte) string {
	return hex.EncodeToString(MD5Bytes(buf))
}
