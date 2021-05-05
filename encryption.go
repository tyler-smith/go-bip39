package bip39

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
)

func EncryptEntropy(entropy []byte, password string) ([]byte, error) {
	pwHash := sha256.Sum256([]byte(password))

	ci, err := aes.NewCipher(pwHash[:])
	if err != nil {
		return nil, err
	}

	iv := make([]byte, 16)
	enc := cipher.NewCTR(ci, iv)

	out := make([]byte, len(entropy))
	enc.XORKeyStream(out, entropy)

	return out, nil
}
