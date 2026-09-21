package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

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
	OutputPath     string   `name:"output" help:"FileOutputPath." type:"path"`
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
	if gd.OutputPath != "" {
		outFile, err := os.OpenFile(gd.OutputPath, os.O_CREATE|os.O_RDWR, 0644)
		if err != nil {
			return err
		}
		defer outFile.Close()
		outWriter = outFile
	}

	sd, err := sssdoc.GenerateNewDocFromKeys(recipients, gd.NumReqiredKeys)
	if err != nil {
		return fmt.Errorf("error generating share doc: %w", err)
	}
	serialized, err := json.MarshalIndent(*sd, " ", "    ")
	if err != nil {
		return fmt.Errorf("error serializing share doc: %w", err)
	}

	_, err = io.WriteString(outWriter, string(serialized))
	return err
}

type GenNewEncAgeKey struct {
	OutputPath string `arg:"" name:"output" help:"FileOutputPath." type:"path"`
}

func (gnak *GenNewEncAgeKey) Run(ctx *Context) error {
	// 1. get passwd from terminal
	// 2. run generate
	// 3. getpublic from key
	// 4. writepublic to file

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	// TODO generate passphrase on empty
	fmt.Println("please enter your passphrase:")
	pass, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return err
	}
	sdclient, err := client.NewGenerateAgeKeyWithPassPhrase(gnak.OutputPath, string(pass), "someurl", logger)
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

type ServerDemoCmd struct {
	ListenPort int    `name:"port" default:"8080" help:"port to attach to (localhost)" `
	DocPath    string `name:"docpath" type:"path"`
}

func (scommand *ServerDemoCmd) Run(ctx *Context) error {
	//load processor from path
	f, err := os.Open(scommand.DocPath)
	if err != nil {
		return err
	}
	defer f.Close()
	serializedDoc, err := io.ReadAll(f)
	if err != nil {
		return err
	}
	processor, err := sssdoc.NewProcessorFromShareDocJSON(serializedDoc)
	if err != nil {
		return err
	}
	// This is the second time we have written this.. maybe time to unify?
	mux := http.NewServeMux()
	mux.HandleFunc(sssdoc.DocInfoPath, processor.ServeShareDocHandler)
	mux.HandleFunc(sssdoc.KeyInfoPath, processor.GetKeyExchangePublicKeysHandler)
	mux.HandleFunc(sssdoc.ProcessSharePath, processor.ProcessKeyShareHandler)

	addr := fmt.Sprintf("127.0.0.1:%d", scommand.ListenPort)
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	processor.ProcesssingTarget = host

	server := &http.Server{
		Addr:           addr,
		Handler:        mux,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	fmt.Printf("starting server at %s\n", addr)
	err = server.ListenAndServe()
	if err != nil {
		return err
	}
	return nil
}

type ClientCmd struct {
	ServerURL string `name:"server" default:"http://127.0.0.1:8080" help:"url to connect to" `
	KeyPath   string `name:"keypath" help:"path to the encypted private key" type:"path"`
}

func (cl *ClientCmd) Run(ctx *Context) error {

	var programLevel = new(slog.LevelVar) // Info by default
	if ctx.Debug {
		programLevel.Set(slog.LevelDebug)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: programLevel}))

	f, err := os.Open(cl.KeyPath)
	if err != nil {
		return err
	}
	// TODO: do some initial checks if the url is valid before
	// asking for interactive stuff.
	_, err = url.Parse(cl.ServerURL)
	if err != nil {
		return err
	}

	fmt.Println("please enter your passphrase:")
	pass, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return err
	}
	// TODO, we should to some peeking to ensure we got the right type of
	// key, for now we assume age encrypted key
	sdclient, err := client.LoadAgeKeyWithPassPhraseAndReader(f, string(pass), logger)
	if err != nil {
		fmt.Printf("cannot load key, bad passphrase?\n")
		return nil
	}
	logger.Info("key loaded")
	err = sdclient.SetBaseURL(cl.ServerURL)
	if err != nil {
		return err
	}
	err = sdclient.PushShareToServer()
	if err != nil {
		return err
	}
	logger.Info("share pushed successfully")
	return nil
}

var cli struct {
	Debug bool `help:"Enable debug mode."`

	GenDoc GenDocCmd       `cmd:"" help:"Generate SSS document."`
	GenAge GenNewEncAgeKey `cmd:"" help:"Generate New Encypte Age key and public key files."`
	Server ServerDemoCmd   `cmd:"" help:"Sart new Demo server."`
	Client ClientCmd       `cmd:"" help:"Sart new client"`
}

func main() {
	ctx := kong.Parse(&cli)
	// Call the Run() method of the selected parsed command.
	err := ctx.Run(&Context{Debug: cli.Debug})
	ctx.FatalIfErrorf(err)
}
