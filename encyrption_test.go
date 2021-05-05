package bip39

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestEcryptMnemonic(t *testing.T) {
	mnmonic := "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform"
	expectedEncMnemonic := "artist depart host scheme update hen short doctor lemon coffee they walk drill welcome mimic expect renew purse wear slow punch need comic team"
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
