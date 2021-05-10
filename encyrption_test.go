package bip39

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestEcryptMnemonic(t *testing.T) {
	mnmonic := "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform"
	expectedEncMnemonic := "father level place shallow review foil illegal elbow wine warm soft penalty token banner cage century someone warfare horn vote crumble now attack gorilla"
	password := "securePassword"

	encMnemonic, err := EncryptMnemonic(mnmonic, password)
	assert.NoError(t, err)
	assert.Equal(t, expectedEncMnemonic, encMnemonic)
}

func TestEcryptEntropy(t *testing.T) {
	mnmonic := "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform"
	expectedEncMnemonic := "father level place shallow review foil illegal elbow wine warm soft penalty token banner cage century someone warfare horn vote crumble now attack gorilla"
	password := "securePassword"

	entropy, err := EntropyFromMnemonic(mnmonic)
	assert.NoError(t, err)

	mnemonicFromEntropy, err := NewMnemonic(entropy)
	assert.NoError(t, err)
	assert.Equal(t, mnemonicFromEntropy, mnmonic)

	encEntropy, err := EncryptEntropy(entropy, password)
	assert.NoError(t, err)
	assert.Equal(t, len(encEntropy), len(entropy))

	encMnemonic, err := NewMnemonic(encEntropy)
	assert.NoError(t, err)

	// Check the encMnemonic
	assert.Equal(t, expectedEncMnemonic, encMnemonic)

	// Get back to original mnemonic
	encEntropyNew, err := EntropyFromMnemonic(encMnemonic)
	assert.Equal(t, encEntropy, encEntropyNew)
	assert.NoError(t, err)

	// Decrypt the encrypted entropy
	plainEntropy, err := EncryptEntropy(encEntropy, password)
	assert.Equal(t, entropy, plainEntropy)
}
