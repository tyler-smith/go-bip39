// Package bip39 is the Golang implementation of the BIP39 spec.
//
// The official BIP39 spec can be found at
// https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
package bip39

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"strings"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/text/unicode/norm"
)

const (
	// normalizedSeparator is the string separator to use for normalized
	// mnemonic strings.
	normalizedSeparator = "\x20"
)

var (
	// Bitwise operands for working with big.Ints.
	bigOne           = big.NewInt(1)
	bigTwo           = big.NewInt(2)
	wordANDMask      = big.NewInt(2047) // 2^11-1
	wordShiftOperand = big.NewInt(2048) // 2^11

	// ErrChecksumIncorrect is returned when entropy has the incorrect checksum.
	ErrChecksumIncorrect = errors.New("checksum incorrect")

	// ErrEntropyNotFullyRead is returned when entropy is not completely filled.
	ErrEntropyNotFullyRead = errors.New("entropy not fully read")

	// _cryptoRandReader is the io.Reader to get cryptographic randomness from.
	// It is switchable only so we can test failure cases.
	_cryptoRandReader = rand.Reader
)

// ErrUnknownWord is returned when trying to parse an unknown word from a
// Language while decoding a mnemonic string back into a word set.
type ErrUnknownWord struct {
	word string
}

// Error returns a human-readable error string for the ErrUnknownWord.
func (e ErrUnknownWord) Error() string { return "unknown word: `" + e.word + "`" }

// Mnemonic is a valid BIP39 mnemonic. Logically a Mnemonic is composition of
// entropy and a Language.
type Mnemonic struct {
	entropy []byte
	lang    Language

	// Memoizations
	str   string
	words []string
	seed  []byte
}

// Generate constructs a Mnemonic from entropy read from the cryptographic
// random number generator provided by the environment.
func Generate(s sizeParams, lang Language, password string) (*Mnemonic, error) {
	entropy, err := entropyFromReader(s.entropyLen, _cryptoRandReader)
	if err != nil {
		return nil, err
	}

	return FromEntropy(lang, entropy, password)
}

// FromEntropy constructs a Mnemonic from a valid entropy slice.
func FromEntropy(lang Language, entropy []byte, password string) (*Mnemonic, error) {
	words, err := wordsFromEntropy(lang, entropy)
	if err != nil {
		return nil, err
	}

	str := compileMnemonic(words)

	return &Mnemonic{
		entropy: entropy,
		lang:    lang,
		str:     str,
		words:   words,
		seed:    seedFromMnemonicString(str, password),
	}, nil
}

// FromString constructs a Mnemonic from a valid mnemonic string.
func FromString(lang Language, rawMnemonic string, password string) (m *Mnemonic, err error) {
	m = &Mnemonic{
		lang:  lang,
		str:   rawMnemonic,
		words: parseRawMnemonic(rawMnemonic),
		seed:  seedFromMnemonicString(rawMnemonic, password),
	}

	m.entropy, err = entropyFromWords(m.lang, m.words)
	if err != nil {
		return nil, err
	}

	return m, nil
}

// Entropy returns the entropy underlying the Mnemonic.
func (m Mnemonic) Entropy() []byte { return m.entropy }

// String returns normalized mnemonic string for the Mnemonic.
func (m *Mnemonic) String() string { return m.str }

// Words returns the word set for the Mnemonic.
func (m *Mnemonic) Words() []string { return m.words }

// Seed returns the pre-computed seed for the Mnemonic.
func (m Mnemonic) Seed() []byte { return m.seed }

// entropyFromReader reads `byteLen` bytes from the Reader. It returns an error
// if reading from the Reader returns an error or fails to read the correct
// number of bytes.
func entropyFromReader(byteLen int, rand io.Reader) ([]byte, error) {
	e := make([]byte, byteLen)

	read, err := rand.Read(e)
	if err != nil {
		return nil, err
	}

	if read != byteLen {
		return nil, ErrEntropyNotFullyRead
	}

	return e, err
}

// wordsFromEntropy turns an entropy slice into a word set using the given
// Language for wordSet lookups.
func wordsFromEntropy(lang Language, entropy []byte) ([]string, error) {
	// Get the sizeParams for the size of the entropy we were given. This both
	// validates that the entropy is a valid size as well as tells us how many
	// wordSet we need to parse out of the entropy data.
	sizeParams, err := sizeParamsFromEntropyLen(len(entropy))
	if err != nil {
		return nil, err
	}

	// Add checksum to entropy and create a big.Int so we can easily use bitwise
	// operations on the entire array of bytes.
	entropy = addChecksum(sizeParams, entropy)
	entropyInt := new(big.Int).SetBytes(entropy)

	// Slice to hold wordSet and a big.Int to use for bitwise operations on
	// single, 11 bit, wordSet.
	wordInt := big.NewInt(0)
	words := make([]string, sizeParams.wordLen)

	// For each expected word:
	//   - AND-mask the least-significant 11 bits and find the word at that index
	//     in the word list.
	//   - Bitshift the entropy 11 bits right
	//   - Add word to the last empty slot
	// EndFor
	for i := len(words) - 1; i >= 0; i-- {
		// Get CS bits and bitshift to the right for next time.
		// word = entropy & 0x11111111111
		// entropy = entropy >> 11
		wordInt.And(entropyInt, wordANDMask)
		entropyInt.Div(entropyInt, wordShiftOperand)

		// Get the bytes representing the CS bits as a 2 byte slice.
		wordBytes := padByteSlice(wordInt.Bytes(), 2)

		// Convert bytes to a index and add the word at that index to the word
		// slice at next position.
		words[i] = lang.wordSet[binary.BigEndian.Uint16(wordBytes)]
	}

	return words, nil
}

// entropyFromWords turns a word set back into entropy using the given Language
// for index lookups.
func entropyFromWords(lang Language, words []string) ([]byte, error) {
	sizeType, err := sizeParamsFromWordSetLen(len(words))
	if err != nil {
		return nil, err
	}

	// Decode the wordSet into a single big.Int that represents the entire entropy
	// Logically we are doing this:
	//   entropyAndChecksum = 0
	//   for word in wordSet
	//	   entropyAndChecksum = (entropyAndChecksum << 11 ) | wordIndex
	entropyAndChecksum := big.NewInt(0)

	for _, word := range words {
		index, found := lang.indices[word]
		if !found {
			return nil, ErrUnknownWord{word}
		}

		entropyAndChecksum.
			Mul(entropyAndChecksum, wordShiftOperand).
			Or(entropyAndChecksum, big.NewInt(int64(index)))
	}

	// Split entropyAndChecksum into entropy and givenChecksum
	// Logically we are doing this:
	//   givenChecksum = entropyAndChecksum & checksumMask
	//   entropy = entropyAndChecksum >> checksumSize
	var (
		givenChecksum = big.NewInt(0).And(entropyAndChecksum, sizeType.checksumANDMask)
		rawEntropy    = big.NewInt(0).Div(entropyAndChecksum, sizeType.checksumShiftOperand)
	)

	// Re-calculate the checksum from the raw entropy and compare with the one
	// given as part of the mnemonic.
	var (
		rawEntropyBytes      = padByteSlice(rawEntropy.Bytes(), sizeType.entropyLen)
		computedChecksumBits = firstSHA256Byte(rawEntropyBytes) >> (8 - sizeType.checksumBitLen)
	)

	if !givenChecksum.IsInt64() || givenChecksum.Int64() != int64(computedChecksumBits) {
		return nil, ErrChecksumIncorrect
	}

	return rawEntropyBytes, nil
}

// seedFromMnemonicString calculates the seed bytes for the given mnemonic
// string and password by applying the KDF.
func seedFromMnemonicString(mnemonicStr string, password string) []byte {
	return pbkdf2.Key([]byte(mnemonicStr), []byte("mnemonic"+password), 2048, 64, sha512.New)
}

// addChecksum appends to the entropy the first `size.checksumBitLen` of
// sha256(rawEntropy).
func addChecksum(size *sizeParams, rawEntropy []byte) []byte {
	cs := firstSHA256Byte(rawEntropy)

	// For each bit of check sum we want we shift the entropyBytes one the left
	// and then set the (new) right most bit equal to checksum bit at that index
	// staring from the left
	entropy := new(big.Int).SetBytes(rawEntropy)

	for i := uint8(0); i < size.checksumBitLen; i++ {
		entropy.Mul(entropy, bigTwo)
		//
		if cs&(1<<(7-i)) > 0 {
			entropy.Or(entropy, bigOne)
		}
	}

	return padByteSlice(entropy.Bytes(), size.entropyLen+1)
}

// firstSHA256Byte returns the first byte of sha256(data).
func firstSHA256Byte(data []byte) byte {
	hasher := sha256.New()
	_, _ = hasher.Write(data) // The returned error can never be non-nil

	return hasher.Sum(nil)[0] // The returned slice len can never != 32
}

// parseRawMnemonic takes an unnormalized mnemonic string and returns its
// word set.
func parseRawMnemonic(rawMnemonic string) []string {
	return strings.Split(normalizeMnemonicString(rawMnemonic), normalizedSeparator)
}

// compileMnemonic takes in a word set and returns its normalized string.
func compileMnemonic(words []string) string {
	return normalizeMnemonicString(strings.Join(words, normalizedSeparator))
}

// normalizeMnemonicString applies the standard normalizations to the string.
func normalizeMnemonicString(m string) string {
	return norm.NFKD.String(m)
}

// padByteSlice returns a byte slice of the requested size with contents of the
// given slice left padded. Empty spaces are filled with bytes(0)s.
func padByteSlice(slice []byte, padToLen int) []byte {
	offset := padToLen - len(slice)
	if offset <= 0 {
		return slice
	}

	newSlice := make([]byte, padToLen)
	copy(newSlice[offset:], slice)

	return newSlice
}
