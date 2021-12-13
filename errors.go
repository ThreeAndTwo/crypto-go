package crypto

import "errors"

var (
	ParamInvalidateErr = errors.New("param invalidated")
	TextHadErr         = errors.New("plain text has error")
	TextWrongBzErr     = errors.New("plain text has the wrong block size")
	CipherTextBzErr    = errors.New("cipher text is not a multiple of the block size")
	CipherMismatchErr  = errors.New("cipher text too short")
)
