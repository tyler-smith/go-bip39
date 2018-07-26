package main

import (
	"fmt"
	"log"
	"os"

	bip39 "github.com/tyler-smith/go-bip39"
	"github.com/tyler-smith/go-bip39/wordlists"
	"github.com/urfave/cli"
)

const (
	name       = "bip39"
	version    = "0.1.0"
	usage      = "Generate secure mnemonic crypto keys"
	useageText = "bip39 --entropy=256 --language=english"

	helpTemplate = `NAME:
	{{.Name}}{{if .Usage}} - {{.Usage}}{{end}}

USAGE:
	{{if .UsageText}}{{.UsageText}}{{else}}{{.HelpName}} {{if .VisibleFlags}}[global options]{{end}}{{if .Commands}} command [command options]{{end}} {{if .ArgsUsage}}{{.ArgsUsage}}{{else}}[arguments...]{{end}}{{end}}{{if .Version}}{{if not .HideVersion}}

VERSION:
	{{.Version}}{{end}}{{end}}{{if .Description}}

DESCRIPTION:
	{{.Description}}{{end}}{{if .VisibleFlags}}

OPTIONS:
	{{range $index, $option := .VisibleFlags}}{{if $index}}
	{{end}}{{$option}}{{end}}{{end}}
`
)

func main() {
	err := newApp().Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func newApp() *cli.App {
	app := cli.NewApp()
	app.Name = name
	app.Usage = usage
	app.Version = version
	app.UsageText = useageText
	cli.AppHelpTemplate = helpTemplate

	app.Flags = []cli.Flag{
		cli.IntFlag{
			Name:  "entropy, e",
			Value: 256,
			Usage: "Entropy size to use for the mnemonic. Must be 128 or 256.",
		},
		cli.StringFlag{
			Name:  "language, l",
			Value: "english",
			Usage: "Language to use for mnemonic",
		},
		cli.BoolFlag{
			Name:  "no-newline, n",
			Usage: "Don't output newline after mnemonic",
		},
	}

	app.Action = func(c *cli.Context) error {
		mnemonic, err := generateMnemonic(c.Int("entropy"), c.String("language"))
		if err != nil {
			return err
		}

		if c.Bool("no-newline") {
			fmt.Print(mnemonic)
		} else {
			fmt.Println(mnemonic)
		}

		return nil
	}

	return app
}

func generateMnemonic(entropySize int, language string) (string, error) {
	wordList, ok := wordlists.AvailableLists[language]
	if !ok {
		return "", bip39.ErrUknownLanguage
	}
	bip39.SetWordList(wordList)

	entropy, err := bip39.NewEntropy(entropySize)
	if err != nil {
		return "", err
	}

	return bip39.NewMnemonic(entropy)
}
