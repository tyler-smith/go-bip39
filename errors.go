package bip39

import (
	"errors"
	"fmt"
)

var (
	// ErrInvalidMnemonic is returned when trying to use a malformed mnemonic.
	ErrInvalidMnemonic = errors.New("Invalid menomic")

	// ErrEntropyLengthInvalid is returned when trying to use an entropy set with
	// an invalid size.
	ErrEntropyLengthInvalid = errors.New("Entropy length must be [128, 256] and a multiple of 32")

	// ErrValidatedSeedLengthMismatch is returned when a validated seed is not the
	// same size as the given seed. This should never happen is present only as a
	// sanity assertion.
	ErrValidatedSeedLengthMismatch = errors.New("Seed length does not match validated seed length")

	// ErrChecksumIncorrect is returned when entropy has the incorrect checksum.
	ErrChecksumIncorrect = errors.New("Checksum incorrect")
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

// EntropySizeErr is returned when an entropy slice has an incorrect size.
type EntropySizeErr struct {
	expected int
	actual   int
}

// Error returns the error string for an `EntropySizeErr`.
func (err EntropySizeErr) Error() string {
	return fmt.Sprintf("Wrong entropy + checksum size - expected %d, got %d", err.expected, err.actual)
}
