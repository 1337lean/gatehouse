package app

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/1337lean/gatehouse/internal/policy"
	"github.com/1337lean/gatehouse/internal/report"
	"github.com/1337lean/gatehouse/internal/verify"
)

const (
	ExitOK        = 0
	ExitViolation = 1
	ExitUsage     = 2
	ExitInternal  = 3
)

func Run(args []string, out, errw io.Writer, version string) int {
	if len(args) == 0 {
		return usage(errw)
	}
	switch args[0] {
	case "version":
		fmt.Fprintln(out, version)
		return ExitOK
	case "init":
		return initCmd(args[1:], out, errw)
	case "policy":
		if len(args) > 1 && args[1] == "check" {
			return policyCmd(args[2:], out, errw)
		}
		return usage(errw)
	case "verify":
		return verifyCmd(args[1:], out, errw)
	case "help", "-h", "--help":
		return usage(out)
	default:
		fmt.Fprintf(errw, "unknown command %q\n", args[0])
		return usage(errw)
	}
}

func usage(w io.Writer) int {
	fmt.Fprintln(w, "Usage: gatehouse <init|policy check|verify|version> [options]")
	return ExitUsage
}

func initCmd(args []string, out, errw io.Writer) int {
	f := flag.NewFlagSet("init", flag.ContinueOnError)
	f.SetOutput(errw)
	path := f.String("policy", "gatehouse.json", "policy path")
	force := f.Bool("force", false, "overwrite")
	if f.Parse(args) != nil {
		return ExitUsage
	}
	if f.NArg() != 0 {
		fmt.Fprintln(errw, "init does not accept positional arguments")
		return ExitUsage
	}
	b, _ := json.MarshalIndent(policy.Default, "", "  ")
	b = append(b, '\n')
	if e := writePolicy(*path, b, *force); e != nil {
		if os.IsExist(e) {
			fmt.Fprintln(errw, "policy already exists (use --force)")
			return ExitUsage
		}
		fmt.Fprintln(errw, e)
		return ExitInternal
	}
	fmt.Fprintf(out, "created %s\n", *path)
	return ExitOK
}

func policyCmd(args []string, out, errw io.Writer) int {
	f := flag.NewFlagSet("policy check", flag.ContinueOnError)
	f.SetOutput(errw)
	path := f.String("policy", "gatehouse.json", "policy path")
	format := f.String("format", "human", "human or json")
	if f.Parse(args) != nil {
		return ExitUsage
	}
	if f.NArg() != 0 {
		fmt.Fprintln(errw, "policy check does not accept positional arguments")
		return ExitUsage
	}
	if *format != "human" && *format != "json" {
		fmt.Fprintln(errw, "unknown format")
		return ExitUsage
	}
	p, e := policy.Load(*path)
	valid := e == nil
	if *format == "json" {
		json.NewEncoder(out).Encode(map[string]any{"valid": valid, "error": errString(e)})
	} else if e != nil {
		fmt.Fprintf(errw, "invalid policy: %v\n", e)
	} else {
		fmt.Fprintln(out, "policy is valid")
	}
	if e != nil {
		return ExitViolation
	}
	_ = p
	return ExitOK
}

func verifyCmd(args []string, out, errw io.Writer) int {
	f := flag.NewFlagSet("verify", flag.ContinueOnError)
	f.SetOutput(errw)
	path := f.String("policy", "gatehouse.json", "policy path")
	format := f.String("format", "human", "human, json, or sarif")
	if f.Parse(args) != nil {
		return ExitUsage
	}
	if f.NArg() != 1 {
		fmt.Fprintln(errw, "verify requires a bundle directory")
		return ExitUsage
	}
	if *format != "human" && *format != "json" && *format != "sarif" {
		fmt.Fprintln(errw, "unknown format")
		return ExitUsage
	}
	p, e := policy.Load(*path)
	if e != nil {
		fmt.Fprintf(errw, "load policy: %v\n", e)
		return ExitInternal
	}
	r, e := verify.Bundle(filepath.Clean(f.Arg(0)), p)
	if e != nil {
		fmt.Fprintln(errw, e)
		return ExitInternal
	}
	if e = report.Write(out, *format, r); e != nil {
		fmt.Fprintln(errw, e)
		return ExitUsage
	}
	if !r.Valid {
		return ExitViolation
	}
	return ExitOK
}

func writePolicy(path string, data []byte, force bool) error {
	if !force {
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if err != nil {
			return err
		}
		if err := writeAndSync(file, data); err != nil {
			_ = os.Remove(path)
			return err
		}
		return nil
	}

	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".gatehouse-policy-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0644); err != nil {
		temporary.Close()
		return err
	}
	if err := writeAndSync(temporary, data); err != nil {
		return err
	}
	// Renaming replaces a symlink itself rather than truncating its target.
	return os.Rename(temporaryPath, path)
}

func writeAndSync(file *os.File, data []byte) error {
	written, err := file.Write(data)
	if err == nil && written != len(data) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func errString(e error) string {
	if e == nil {
		return ""
	}
	return e.Error()
}
