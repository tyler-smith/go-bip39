package bip39

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"golang.org/x/crypto/pbkdf2"
)

func EncryptMnemonic(mnemonic string, password string) (string, error) {
	entropy, err := EntropyFromMnemonic(mnemonic)
	if err != nil {
		return "", err
	}
	encEntropy, err := EncryptEntropy(entropy, password)
	if err != nil {
		return "", err
	}
	return NewMnemonic(encEntropy)
}

func EncryptEntropy(entropy []byte, password string) ([]byte, error) {
	pwHash := pbkdf2.Key([]byte(password), []byte("mnemonic-encryption"), 2048, 32, sha512.New)

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
