package crypto_go

type Crypto struct {
	CryptoType CryptoType
	Options    interface{}
}

func CryptoGetter(_cryptoType CryptoType, _options interface{}) ICrypto {
	switch _cryptoType {
	case Aes256:
		opts := _options.(Aes256Opt)
		return NewAes256Opt(opts.Key, opts.KeyLen)
	case Rsa:

	case Dsa:

	case Ecc:

	case DH:

	case MD5:

	case Sha512:

	default:
		// use md5

	}

	return nil
}
