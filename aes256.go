package crypto_go

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/mergermarket/go-pkcs7"
	"io"
)

type Aes256Opt struct {
	Key    string
	KeyLen int
}

func NewAes256Opt(key string, len int) *Aes256Opt {
	return &Aes256Opt{Key: key, KeyLen: len}
}

func (a *Aes256Opt) check(text string) bool {
	return "" != a.Key && "" != text
}

func (a *Aes256Opt) GenKey() interface{} {
	if 0 >= a.KeyLen {
		return a
	}

	a.Key = RandStringBytesMaskImpr(a.KeyLen)
	return a
}

func (a *Aes256Opt) Encrypt(text string) (string, error) {
	if !a.check(text) {
		return "", ParamInvalidateErr
	}

	key := []byte(a.Key)
	plainText := []byte(text)
	plainText, err := pkcs7.Pad(plainText, aes.BlockSize)
	if err != nil {
		return "", TextHadErr
	}
	if len(plainText)%aes.BlockSize != 0 {
		return "", TextWrongBzErr
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText[aes.BlockSize:], plainText)
	return fmt.Sprintf("%x", cipherText), nil
}

func (a *Aes256Opt) Decrypt(_cipherText string) (string, error) {
	if !a.check(_cipherText) {
		return "", ParamInvalidateErr
	}

	key := []byte(a.Key)
	cipherText, _ := hex.DecodeString(_cipherText)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	if len(cipherText) < aes.BlockSize {
		return "", CipherMismatchErr
	}
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]
	if len(cipherText)%aes.BlockSize != 0 {
		return "", CipherTextBzErr
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(cipherText, cipherText)

	cipherText, _ = pkcs7.Unpad(cipherText, aes.BlockSize)
	return fmt.Sprintf("%s", cipherText), nil
}
