package cmd

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/minio/cli"
	"github.com/minio/mfs/pkg/credentials"
	"github.com/minio/mfs/pkg/logger"

	miniohttp "github.com/minio/minio/pkg/http"
)

var serverFlags = []cli.Flag{
	cli.StringFlag{
		Name:  "address",
		Value: ":9001",
		Usage: "Bind to a specific ADDRESS:PORT, ADDRESS can be an IP or hostname.",
	},
	cli.StringFlag{
		Name:  "cred-store",
		Value: credentials.FSStore,
		Usage: "Credentials store to be used by the Minio Federation Server.",
	},
}

var serverCmd = cli.Command{
	Name:   "server",
	Usage:  "Start federation server.",
	Flags:  append(serverFlags, globalFlags...),
	Action: serverMain,
	CustomHelpTemplate: `NAME:
  {{.HelpName}} - {{.Usage}}

USAGE:
  {{.HelpName}} {{if .VisibleFlags}}[FLAGS] {{end}}PATH [PATH...]
{{if .VisibleFlags}}
FLAGS:
  {{range .VisibleFlags}}{{.}}
  {{end}}{{end}}
`,
}

// serverMain handler called for 'minio server' command.
func serverMain(ctx *cli.Context) {
	if ctx.Args().Present() && ctx.Args().First() == "help" {
		cli.ShowCommandHelpAndExit(ctx, "server", 1)
	}

	// Create certs path.
	logger.FatalIf(credentials.CreateConfigDir(), "Unable to create configuration directories.")

	// Init the error tracing module.
	initError()

	// Initialize a new credentials store, filesystem based.
	if ctx.String("cred-store") != credentials.FSStore {
		logger.FatalIf(errors.New("Invalid argument"), fmt.Sprintf("Unable to recognize credentials store %s", ctx.String("cred-store")))
	}
	globalMFSCreds = credentials.NewFSStore()
	globalMFSCreds.Save()

	// Check and load SSL certificates.
	var err error
	globalPublicCerts, globalRootCAs, globalTLSCertificate, globalIsSSL, err = getSSLConfig()
	logger.FatalIf(err, "Invalid SSL certificate file")

	// Set system resources to maximum.
	logger.ErrorIf(setMaxResources(), "Unable to change resource limit")

	// Configure server.
	// Declare handler to avoid lint errors.
	var handler http.Handler
	// Initialize router. `SkipClean(true)`stops gorilla/mux from normalizing URL path.
	handler = configureMFSHandler()

	globalHTTPServer = miniohttp.NewServer([]string{ctx.String("address")}, handler, globalTLSCertificate)
	globalHTTPServer.ReadTimeout = globalConnReadTimeout
	globalHTTPServer.WriteTimeout = globalConnWriteTimeout
	globalHTTPServer.ErrorLogFunc = logger.ErrorIf
	go func() {
		globalHTTPServerErrorCh <- globalHTTPServer.Start()
	}()

	signal.Notify(globalOSSignalCh, os.Interrupt, syscall.SIGTERM)
	handleSignals()
}
