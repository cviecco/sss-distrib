package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"

	"github.com/alecthomas/kong"
	"github.com/cviecco/sss-distrib/lib/client"
	"github.com/cviecco/sss-distrib/lib/sssdoc"
)

// Three commands (for now)
//    GenerateDoc
//    DemoServer
//    Client
//       check
//       pushShare
//

type Context struct {
	Debug bool
}

type GenDocCmd struct {
	NumReqiredKeys int      `arg:"" name:"requirekeycount" help:"Number of shares needed for recombining." type:"int"`
	OutputPath     string   `arg:"" name:"output" help:"FileOutputPath." type:"path"`
	PublicKeyPaths []string `arg:"" name:"path" help:"Files with public keys (one per file)." type:"path"`
}

func (gd *GenDocCmd) Run(ctx *Context) error {
	//fmt.Printf("%+v", gd)
	recipients, err := sssdoc.LoadMultifiles(gd.PublicKeyPaths)
	if err != nil {
		return fmt.Errorf("error loading public key files: %w", err)
	}
	var outWriter io.Writer
	outWriter = os.Stdout
	// TODO: create output filepath if needed (io.OpenFile

	sd, err := sssdoc.GenerateNewDocFromKeys(recipients, gd.NumReqiredKeys)
	if err != nil {
		return fmt.Errorf("error generating share doc: %w", err)
	}
	serialized, err := json.MarshalIndent(*sd, " ", "    ")
	if err != nil {
		return fmt.Errorf("error serializing share doc: %w", err)
	}

	io.WriteString(outWriter, string(serialized))
	return nil
}

type GenNewEncAgeKey struct {
	OutputPath string `arg:"" name:"output" help:"FileOutputPath." type:"path"`
}

func (gnak *GenNewEncAgeKey) Run(ctx *Context) error {
	// 1. get passwd from terminal
	// 2. run generate
	// 3. getpublic from key
	// 4. writepublic to file

	// TODO generate passphrase on empty
	fmt.Println("please enter your passphrase:")
	pass, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return err
	}
	sdclient, err := client.NewAgeKeyWithPassPhrase(gnak.OutputPath, string(pass), "someurl")
	if err != nil {
		return err
	}
	publicKeyBytes, err := sdclient.GetPublicKey()
	if err != nil {
		return err
	}
	pubkeyPath := gnak.OutputPath + ".pub"
	pubFile, err := os.OpenFile(pubkeyPath, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer pubFile.Close()
	_, err = pubFile.Write(publicKeyBytes)
	if err != nil {
		return err
	}
	return nil

	//return fmt.Errorf("not implemented")
}

type RmCmd struct {
	Force     bool `help:"Force removal."`
	Recursive bool `help:"Recursively remove files."`

	Paths []string `arg:"" name:"path" help:"Paths to remove." type:"path"`
}

func (r *RmCmd) Run(ctx *Context) error {
	fmt.Println("rm", r.Paths)
	return nil
}

type LsCmd struct {
	Paths []string `arg:"" optional:"" name:"path" help:"Paths to list." type:"path"`
}

func (l *LsCmd) Run(ctx *Context) error {
	fmt.Println("ls", l.Paths)
	return nil
}

var cli struct {
	Debug bool `help:"Enable debug mode."`

	Rm     RmCmd           `cmd:"" help:"Remove files."`
	Ls     LsCmd           `cmd:"" help:"List paths."`
	GenDoc GenDocCmd       `cmd:"" help:"Generate SSS document."`
	GenAge GenNewEncAgeKey `cmd:"" help:"Generate New Encypte Age key and public key files."`
}

func main() {
	ctx := kong.Parse(&cli)
	// Call the Run() method of the selected parsed command.
	err := ctx.Run(&Context{Debug: cli.Debug})
	ctx.FatalIfErrorf(err)
}
