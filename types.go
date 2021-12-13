package crypto

type CryptoType string

const (
	Aes256 CryptoType = "aes256"
	Rsa    CryptoType = "rsa"
	Dsa    CryptoType = "dsa"
	Ecc    CryptoType = "ecc"
	DH     CryptoType = "dh"
	MD5    CryptoType = "md5"
	Sha512 CryptoType = "sha512"
)
