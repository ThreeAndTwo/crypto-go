package crypto_go

import (
	"testing"
)

func TestCryptoGetter(t *testing.T) {
	type fields struct {
		cryptoType CryptoType
		_options   interface{}
		plainText string
	}

	tests := []struct {
		name  string
		field fields
		want  bool
	}{
		{
			name: "ase gen",
			field: fields{
				cryptoType: Aes256,
				_options:   Aes256Opt{Key: "", KeyLen: 32},
				plainText: "123456",
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cg := CryptoGetter(tt.field.cryptoType, tt.field._options)
			key := cg.GenKey()
			cg = key.(*Aes256Opt)

			cipherText, err := cg.Encrypt(tt.field.plainText)
			if (err != nil) == tt.want {
				t.Log(err)
				return
			}
			t.Log("encrypt", cipherText)

			plainText, err := cg.Decrypt(cipherText)
			if (err != nil) == tt.want {
				t.Log(err)
				return
			}

			if plainText != tt.field.plainText {
				t.Errorf("misMatch")
			}
			t.Log("match")
		})

	}
}
