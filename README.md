# go-bip39

Use [bip39](https://github.com/bitcoin/bips/tree/master/bip-0039) in Go!

[![PkgGoDev](https://pkg.go.dev/badge/tyler-smith/go-bip39)](https://pkg.go.dev/tyler-smith/go-bip39)
[![GitHub release](https://img.shields.io/github/release/Naereen/StrapDown.js.svg)](https://GitHub.com/Naereen/StrapDown.js/releases/)
[![MIT License](https://img.shields.io/github/license/tyler-smith/go-bip39.svg?maxAge=2592000&color=blue)](https://github.com/tyler-smith/go-bip39/blob/master/LICENSE)
[![Build Status](https://travis-ci.org/tyler-smith/go-bip39.svg?branch=master)](https://travis-ci.org/tyler-smith/go-bip39)
[![Go Report Card](https://goreportcard.com/badge/github.com/tyler-smith/go-bip39)](https://goreportcard.com/report/github.com/tyler-smith/go-bip39)

[![Contributors](https://img.shields.io/github/contributors/tyler-smith/go-bip39.svg?color=blue)](https://github.com/tyler-smith/go-bip39/graphs/contributors)
[![PGP](https://img.shields.io/keybase/pgp/tylersmith?color=green)](https://keybase.io/tylersmith)

## Example

```go
package main

import (
	"fmt"
  "github.com/tyler-smith/go-bip39"
  "github.com/tyler-smith/go-bip32"
)

func main(){
  // Generate a mnemonic for memorization or user-friendly seeds
  entropy, _ := bip39.NewEntropy(256)
  mnemonic, _ := bip39.NewMnemonic(entropy)

  // Generate a Bip32 HD wallet for the mnemonic and a user supplied password
  seed := bip39.NewSeed(mnemonic, "Secret Passphrase")

  masterKey, _ := bip32.NewMasterKey(seed)
  publicKey := masterKey.PublicKey()

  // Display mnemonic and keys
  fmt.Println("Mnemonic: ", mnemonic)
  fmt.Println("Master private key: ", masterKey)
  fmt.Println("Master public key: ", publicKey)
}
```
