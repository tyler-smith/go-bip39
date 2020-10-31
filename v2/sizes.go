package bip39

import (
	"errors"
	"math/big"
)

var (
	// Size128Bits configures a 128-bit/12-word mnemonic.
	Size128Bits = sizes[0]

	// Size160Bits configures a 160-bit/15-word mnemonic.
	Size160Bits = sizes[1]

	// Size192Bits configures a 192-bit/18-word mnemonic.
	Size192Bits = sizes[2]

	// Size224Bits configures a 224-bit/21-word mnemonic.
	Size224Bits = sizes[3]

	// Size256Bits configures a 256-bit/24-word mnemonic.
	Size256Bits = sizes[4]

	// ErrEntropyInvalidLength is returned when trying to use an entropy with an
	// invalid size.
	ErrEntropyInvalidLength = errors.New("entropy length must be [128, 256] and a multiple of 32")

	// ErrWordSetInvalidLength is returned when trying to use a mnemonic string
	// with an invalid size.
	ErrWordSetInvalidLength = errors.New("mnemonic word count must be one of 12, 15, 18, 21, 24")
)

// sizeParams defines all the parameters used for working mnemonics of a set size.
type sizeParams struct {
	wordLen              int
	entropyLen           int
	checksumBitLen       uint8
	checksumANDMask      *big.Int
	checksumShiftOperand *big.Int
}

// sizes defines constants for each valid size of mnemonic.
var sizes = [5]sizeParams{
	{
		wordLen:    12,
		entropyLen: 16,

		checksumBitLen:       4,
		checksumANDMask:      big.NewInt(15), // 2^4-1
		checksumShiftOperand: big.NewInt(16), // 2^4
	},
	{
		wordLen:    15,
		entropyLen: 20,

		checksumBitLen:       5,
		checksumANDMask:      big.NewInt(31), // 2^5-1
		checksumShiftOperand: big.NewInt(32), // 2^5
	},
	{
		wordLen:    18,
		entropyLen: 24,

		checksumBitLen:       6,
		checksumANDMask:      big.NewInt(63), // 2^6-1
		checksumShiftOperand: big.NewInt(64), // 2^6
	},
	{
		wordLen:    21,
		entropyLen: 28,

		checksumBitLen:       7,
		checksumANDMask:      big.NewInt(127), // 2^7-1
		checksumShiftOperand: big.NewInt(128), // 2^7
	},
	{
		wordLen:    24,
		entropyLen: 32,

		checksumBitLen:       8,
		checksumANDMask:      big.NewInt(255), // 2^8-1
		checksumShiftOperand: big.NewInt(256), // 2^8
	},
}

// sizeParamsFromEntropyLen returns the sizeParams for given byte len by projecting
// the len to an index of sizes.
func sizeParamsFromEntropyLen(l int) (*sizeParams, error) {
	sizeType := (l - 16) / 4
	if sizeType < 0 || sizeType > 4 {
		return nil, ErrEntropyInvalidLength
	}

	return &sizes[sizeType], nil
}

// sizeParamsFromWordSetLen returns the sizeParams for given word set len by
// projecting the len to an index of sizes.
func sizeParamsFromWordSetLen(l int) (*sizeParams, error) {
	sizeType := (l - 12) / 3
	if sizeType < 0 || sizeType > 4 {
		return nil, ErrWordSetInvalidLength
	}

	return &sizes[sizeType], nil
}
