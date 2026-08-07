package app

import (
	"encoding/json"
	"errors"
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
	out = &trackingWriter{writer: out}
	errw = &trackingWriter{writer: errw}
	if len(args) == 0 {
		return usage(errw)
	}
	switch args[0] {
	case "version":
		return writeExit(out, ExitOK, "%s\n", version)
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
		if code := writeExit(errw, ExitUsage, "unknown command %q\n", args[0]); code != ExitUsage {
			return code
		}
		return usage(errw)
	}
}

func usage(w io.Writer) int {
	return writeExit(w, ExitUsage, "Usage: gatehouse <init|policy check|verify|version> [options]\n\nExit codes: 0 success, 1 policy/bundle violation, 2 usage or invalid policy, 3 operational/output failure.\n")
}

func initCmd(args []string, out, errw io.Writer) int {
	f := flag.NewFlagSet("init", flag.ContinueOnError)
	flagOutput := &trackingWriter{writer: errw}
	f.SetOutput(flagOutput)
	path := f.String("policy", "gatehouse.json", "policy path")
	force := f.Bool("force", false, "overwrite")
	if f.Parse(args) != nil {
		if flagOutput.err != nil {
			return ExitInternal
		}
		return ExitUsage
	}
	if f.NArg() != 0 {
		return writeExit(errw, ExitUsage, "init does not accept positional arguments\n")
	}
	b, err := json.MarshalIndent(policy.Default, "", "  ")
	if err != nil {
		return writeExit(errw, ExitInternal, "encode default policy: %v\n", err)
	}
	b = append(b, '\n')
	if e := writePolicy(*path, b, *force); e != nil {
		if os.IsExist(e) {
			return writeExit(errw, ExitUsage, "policy already exists (use --force)\n")
		}
		return writeExit(errw, ExitInternal, "%v\n", e)
	}
	return writeExit(out, ExitOK, "created %s\n", *path)
}

func policyCmd(args []string, out, errw io.Writer) int {
	f := flag.NewFlagSet("policy check", flag.ContinueOnError)
	flagOutput := &trackingWriter{writer: errw}
	f.SetOutput(flagOutput)
	path := f.String("policy", "gatehouse.json", "policy path")
	format := f.String("format", "human", "human or json")
	if f.Parse(args) != nil {
		if flagOutput.err != nil {
			return ExitInternal
		}
		return ExitUsage
	}
	if f.NArg() != 0 {
		return writeExit(errw, ExitUsage, "policy check does not accept positional arguments\n")
	}
	if *format != "human" && *format != "json" {
		return writeExit(errw, ExitUsage, "unknown format\n")
	}
	p, e := policy.Load(*path)
	valid := e == nil
	resultCode := ExitOK
	if e != nil {
		resultCode = ExitInternal
		if errors.Is(e, policy.ErrInvalid) {
			resultCode = ExitUsage
		}
	}
	if *format == "json" {
		if encodeErr := json.NewEncoder(out).Encode(map[string]any{"valid": valid, "error": errString(e)}); encodeErr != nil {
			return writeExit(errw, ExitInternal, "write report: %v\n", encodeErr)
		}
	} else if e != nil {
		if code := writeExit(errw, resultCode, "invalid policy: %v\n", e); code != resultCode {
			return code
		}
	} else {
		if code := writeExit(out, ExitOK, "policy is valid\n"); code != ExitOK {
			return code
		}
	}
	_ = p
	return resultCode
}

func verifyCmd(args []string, out, errw io.Writer) int {
	f := flag.NewFlagSet("verify", flag.ContinueOnError)
	flagOutput := &trackingWriter{writer: errw}
	f.SetOutput(flagOutput)
	path := f.String("policy", "gatehouse.json", "policy path")
	format := f.String("format", "human", "human, json, or sarif")
	if f.Parse(args) != nil {
		if flagOutput.err != nil {
			return ExitInternal
		}
		return ExitUsage
	}
	if f.NArg() != 1 {
		return writeExit(errw, ExitUsage, "verify requires a bundle directory\n")
	}
	if *format != "human" && *format != "json" && *format != "sarif" {
		return writeExit(errw, ExitUsage, "unknown format\n")
	}
	p, e := policy.Load(*path)
	if e != nil {
		code := ExitInternal
		if errors.Is(e, policy.ErrInvalid) {
			code = ExitUsage
		}
		return writeExit(errw, code, "load policy: %v\n", e)
	}
	r, e := verify.Bundle(filepath.Clean(f.Arg(0)), p)
	if e != nil {
		return writeExit(errw, ExitInternal, "%v\n", e)
	}
	if e = report.Write(out, *format, r); e != nil {
		return writeExit(errw, ExitInternal, "write report: %v\n", e)
	}
	if !r.Valid {
		return ExitViolation
	}
	return ExitOK
}

func writeExit(w io.Writer, successCode int, format string, args ...any) int {
	message := fmt.Sprintf(format, args...)
	written, err := io.WriteString(w, message)
	if err == nil && written != len(message) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return ExitInternal
	}
	return successCode
}

type trackingWriter struct {
	writer io.Writer
	err    error
}

func (w *trackingWriter) Write(data []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	written, err := w.writer.Write(data)
	if err == nil && written != len(data) {
		err = io.ErrShortWrite
	}
	if err != nil {
		w.err = err
	}
	return written, err
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
