package cmd

import (
	"os"
	"path/filepath"
	"sort"

	"github.com/minio/cli"
	"github.com/minio/mc/pkg/console"
	"github.com/minio/minio/pkg/trie"
	"github.com/minio/minio/pkg/words"

	"github.com/minio/mfs/pkg/credentials"
)

// global flags for mfs.
var globalFlags = []cli.Flag{
	cli.StringFlag{
		Name:  "config-dir, C",
		Value: credentials.GetConfigDir(),
		Usage: "Path to configuration directory.",
	},
	cli.BoolFlag{
		Name:  "quiet",
		Usage: "Disable startup information.",
	},
}

// Help template for mfs.
var mfsHelpTemplate = `NAME:
  {{.Name}} - {{.Usage}}

DESCRIPTION:
  {{.Description}}

USAGE:
  {{.HelpName}} {{if .VisibleFlags}}[FLAGS] {{end}}COMMAND{{if .VisibleFlags}}{{end}} [ARGS...]

COMMANDS:
  {{range .VisibleCommands}}{{join .Names ", "}}{{ "\t" }}{{.Usage}}
  {{end}}{{if .VisibleFlags}}
FLAGS:
  {{range .VisibleFlags}}{{.}}
  {{end}}{{end}}
VERSION:
  ` + Version +
	`{{ "\n"}}`

func newApp(name string) *cli.App {
	// Collection of mfs commands currently supported are.
	commands := []cli.Command{}

	// Collection of mfs commands currently supported in a trie tree.
	commandsTree := trie.NewTrie()

	// registerCommand registers a cli command.
	registerCommand := func(command cli.Command) {
		commands = append(commands, command)
		commandsTree.Insert(command.Name)
	}

	findClosestCommands := func(command string) []string {
		var closestCommands []string
		for _, value := range commandsTree.PrefixMatch(command) {
			closestCommands = append(closestCommands, value.(string))
		}

		sort.Strings(closestCommands)
		// Suggest other close commands - allow missed, wrongly added and
		// even transposed characters
		for _, value := range commandsTree.Walk(commandsTree.Root()) {
			if sort.SearchStrings(closestCommands, value.(string)) < len(closestCommands) {
				continue
			}
			// 2 is arbitrary and represents the max
			// allowed number of typed errors
			if words.DamerauLevenshteinDistance(command, value.(string)) < 2 {
				closestCommands = append(closestCommands, value.(string))
			}
		}

		return closestCommands
	}

	// Register all commands.
	registerCommand(serverCmd)
	registerCommand(versionCmd)

	// Set up app.
	cli.HelpFlag = cli.BoolFlag{
		Name:  "help, h",
		Usage: "Show help.",
	}

	app := cli.NewApp()
	app.Name = name
	app.Author = "Minio.io"
	app.Version = Version
	app.Usage = "Minio Federation Service."
	app.Description = `Minio Federation Service is a namespace, identity and access management server for Mfs Servers.`
	app.Flags = globalFlags
	app.HideVersion = true     // Hide `--version` flag, we already have `mfs version`.
	app.HideHelpCommand = true // Hide `help, h` command, we already have `mfs --help`.
	app.Commands = commands
	app.CustomAppHelpTemplate = mfsHelpTemplate
	app.CommandNotFound = func(ctx *cli.Context, command string) {
		console.Printf("‘%s’ is not a mfs sub-command. See ‘mfs --help’.\n", command)
		closestCommands := findClosestCommands(command)
		if len(closestCommands) > 0 {
			console.Println()
			console.Println("Did you mean one of these?")
			for _, cmd := range closestCommands {
				console.Printf("\t‘%s’\n", cmd)
			}
		}

		os.Exit(1)
	}

	return app
}

// Main main for mfs server.
func Main(args []string) {
	// Set the mfs app name.
	appName := filepath.Base(args[0])

	// Run the app - exit on error.
	if err := newApp(appName).Run(args); err != nil {
		os.Exit(1)
	}
}
