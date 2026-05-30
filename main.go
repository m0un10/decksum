// decksum summarises a Kong decK declarative config (YAML or JSON).
//
//	deck gateway dump -o - | decksum
//	decksum kong.yaml --format markdown >> "$GITHUB_STEP_SUMMARY"
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/goccy/go-yaml"
)

var version = "dev"

const usage = `decksum — summarise a Kong decK declarative config

Usage:
  deck gateway dump -o - | decksum [flags]
  decksum [flags] kong.yaml

Reads YAML or JSON from the file argument, or stdin when no file (or "-") is given.

Flags:
  -f, --format string   output format: text, markdown, json (default "text")
      --no-tree         omit the per-service route tree
      --no-color        disable ANSI colour in text output
      --fail-on-warn    exit with status 2 if any warnings are found (for CI)
  -v, --version         print version
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("decksum", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	var format string
	var noTree, noColor, failOnWarn, showVersion bool
	fs.StringVar(&format, "format", "text", "")
	fs.StringVar(&format, "f", "text", "")
	fs.BoolVar(&noTree, "no-tree", false, "")
	fs.BoolVar(&noColor, "no-color", false, "")
	fs.BoolVar(&failOnWarn, "fail-on-warn", false, "")
	fs.BoolVar(&showVersion, "version", false, "")
	fs.BoolVar(&showVersion, "v", false, "")
	if err := fs.Parse(reorder(args)); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 1
	}
	if showVersion {
		fmt.Fprintln(stdout, "decksum", version)
		return 0
	}

	var in io.Reader = stdin
	name := "stdin"
	if fs.NArg() > 1 {
		fmt.Fprintln(stderr, "decksum: expected at most one file argument")
		return 1
	}
	if fs.NArg() == 1 && fs.Arg(0) != "-" {
		f, err := os.Open(fs.Arg(0))
		if err != nil {
			fmt.Fprintln(stderr, "decksum:", err)
			return 1
		}
		defer f.Close()
		in, name = f, fs.Arg(0)
	} else if isTerminal(stdin) {
		fmt.Fprint(stderr, usage)
		return 1
	}

	data, err := io.ReadAll(in)
	if err != nil {
		fmt.Fprintln(stderr, "decksum: reading", name+":", err)
		return 1
	}
	if len(bytes.TrimSpace(data)) == 0 {
		fmt.Fprintln(stderr, "decksum: no input on", name)
		return 1
	}
	var raw any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		fmt.Fprintf(stderr, "decksum: %s is not valid YAML/JSON:\n%v\n", name, err)
		return 1
	}
	doc := asMap(raw)
	if doc == nil {
		fmt.Fprintf(stderr, "decksum: %s does not look like a decK file (top level is not a map)\n", name)
		return 1
	}

	s := Summarize(doc)
	opts := renderOpts{tree: !noTree, color: !noColor && isTerminal(stdout) && os.Getenv("NO_COLOR") == ""}
	switch format {
	case "text", "":
		renderText(stdout, s, opts)
	case "markdown", "md":
		renderMarkdown(stdout, s, opts)
	case "json":
		if err := renderJSON(stdout, s); err != nil {
			fmt.Fprintln(stderr, "decksum:", err)
			return 1
		}
	default:
		fmt.Fprintf(stderr, "decksum: unknown format %q (want text, markdown or json)\n", format)
		return 1
	}

	if failOnWarn {
		for _, f := range s.Findings {
			if f.Level == "warn" {
				return 2
			}
		}
	}
	return 0
}

// reorder moves flags ahead of positional args so "decksum kong.yaml -f md" works.
func reorder(args []string) []string {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			pos = append(pos, args[i+1:]...)
			return append(flags, pos...)
		case a == "-" || len(a) < 2 || a[0] != '-':
			pos = append(pos, a)
		default:
			flags = append(flags, a)
			if (a == "-f" || a == "--format" || a == "-format") && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
		}
	}
	return append(flags, pos...)
}

func isTerminal(v any) bool {
	f, ok := v.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}
