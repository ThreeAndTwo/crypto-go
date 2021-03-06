package crypto

type ICrypto interface {
	GenKey() interface{}
	Encrypt(plainText string) (string, error)
	Decrypt(cipherText string) (string, error)
}
