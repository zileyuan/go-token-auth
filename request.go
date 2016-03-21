package tokenauth

import (
	"encoding/base64"
	"fmt"
)

func Signature(key, accesskey, timestamp, duration, signaturemethod, version string) ([]byte, error) {
	ready := `accesskey=%v&timestamp=%v&duration=%v&signaturemethod=%v&version=%v`
	ready = fmt.Sprintf(ready, accesskey, timestamp, duration, signaturemethod, version)
	aes := AesEncrypt{Key: key}
	bytes, err := aes.Encrypt(ready)
	if err == nil {
		result := base64.StdEncoding.EncodeToString(bytes)
		return []byte(fmt.Sprintf(ready+`&signature=%v`, result)), nil
	}
	return nil, err
}

func AuthSignature(key, accesskey, timestamp, duration, signaturemethod, version, signature string) bool {
	ready := `accesskey=%v&timestamp=%v&duration=%v&signaturemethod=%v&version=%v`
	ready = fmt.Sprintf(ready, accesskey, timestamp, duration, signaturemethod, version)

	bytes, err := base64.StdEncoding.DecodeString(signature)
	if err == nil {
		aes := AesEncrypt{Key: key}
		result, err := aes.Decrypt(bytes)
		return err == nil && result == ready
	}
	return false
}
