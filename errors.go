package bip39

import (
	"errors"
	"fmt"
)

var (
	// ErrInvalideMnemonic is returned when trying to use a malformed mnemonic.
	ErrInvalideMnemonic = errors.New("Invalid menomic")

	// ErrEntropyLengthInvalid is returned when trying to use an entropy set with
	// an invalid size.
	ErrEntropyLengthInvalid = errors.New("Entropy length must be [128, 256] and a multiple of 32")

	// ErrValidatedSeedLengthMismatch is returned when a validated seed is not the
	// same size as the given seed. This should never happen is present only as a
	// sanity assertion.
	ErrValidatedSeedLengthMismatch = errors.New("Seed length does not match validated seed length")
)

// UnknownWordErr is returned when a mnemonic contains a word that isn't in the
// word list being used.
type UnknownWordErr struct {
	Word string
}

// Error returns the error string for an `UnknownWordErr`.
func (err UnknownWordErr) Error() string {
	return fmt.Sprintf("Word `%v` not found in reverse map", err)
}

// ChecksumErr is returned when a mnemonic contains an invalid checksum.
type ChecksumErr struct {
	byteIndex int
}

// Error returns the error string for an `ChecksumErr`.
func (err ChecksumErr) Error() string {
	return fmt.Sprintf("Mnemonic checksum error, decoding byte index %d", err.byteIndex)
}

// EntropySizeErr is returned when an entropy slice has an incorrect size.
type EntropySizeErr struct {
	expected int
	actual   int
}

// Error returns the error string for an `EntropySizeErr`.
func (err EntropySizeErr) Error() string {
	return fmt.Sprintf("Wrong entropy + checksum size - expected %d, got %d", err.expected, err.actual)
}
