package tokenauth

import (
	"crypto/aes"
	"crypto/cipher"
)

type AesEncrypt struct {
	Key string
}

func (ae *AesEncrypt) getKey() []byte {
	keyLen := len(ae.Key)
	if keyLen < 16 {
		panic("aes key's length can't less than 16")
	}
	arrKey := []byte(ae.Key)
	if keyLen >= 32 {
		//fetch head 32 char as real key
		return arrKey[:32]
	}
	if keyLen >= 24 {
		//fetch head 24 char as real key
		return arrKey[:24]
	}
	//fetch head 16 char as real key
	return arrKey[:16]
}

//encrypt string
func (ae *AesEncrypt) Encrypt(strMesg string) ([]byte, error) {
	key := ae.getKey()
	var iv = []byte(key)[:aes.BlockSize]
	encrypted := make([]byte, len(strMesg))
	aesBlockEncrypter, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesEncrypter := cipher.NewCFBEncrypter(aesBlockEncrypter, iv)
	aesEncrypter.XORKeyStream(encrypted, []byte(strMesg))
	return encrypted, nil
}

//decrypt bytes
func (ae *AesEncrypt) Decrypt(src []byte) (strDesc string, err error) {
	defer func() {
		//recover process
		if e := recover(); e != nil {
			err = e.(error)
		}
	}()
	key := ae.getKey()
	var iv = []byte(key)[:aes.BlockSize]
	decrypted := make([]byte, len(src))
	var aesBlockDecrypter cipher.Block
	aesBlockDecrypter, err = aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	aesDecrypter := cipher.NewCFBDecrypter(aesBlockDecrypter, iv)
	aesDecrypter.XORKeyStream(decrypted, src)
	return string(decrypted), nil
}
