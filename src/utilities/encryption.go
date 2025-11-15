package utilities

import (
	"crypto/rand"
	"encoding/base64"
)

func GenerateRandomEncodedByteString(size int) string {
	bytes := make([]byte, size)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)
}
