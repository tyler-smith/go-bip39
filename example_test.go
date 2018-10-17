package bip39_test

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/tyler-smith/go-bip39"
)

func ExampleNewMnemonic() {
	// the entropy can be any byte slice, generated how pleased,
	// as long its bit size is a multiple of 32 and is within
	// the inclusive range of {128,256}
	entropy, err := hex.DecodeString("066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad")
	if err != nil {
		log.Fatalln(err)
	}

	// generate a mnemomic
	mnemomic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println(mnemomic)

	// output:
	// all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform
}

func ExampleNewSeed() {
	seed := bip39.NewSeed("all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform", "TREZOR")
	fmt.Println(hex.EncodeToString(seed))

	// output:
	// 26e975ec644423f4a4c4f4215ef09b4bd7ef924e85d1d17c4cf3f136c2863cf6df0a475045652c57eb5fb41513ca2a2d67722b77e954b4b3fc11f7590449191d
}
