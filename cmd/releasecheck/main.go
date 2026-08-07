package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/1337lean/gatehouse/internal/distcheck"
)

func main() {
	directory := flag.String("dist", "dist", "GoReleaser distribution directory")
	smoke := flag.Bool("smoke", true, "run the archive executable for this host")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "releasecheck does not accept positional arguments")
		os.Exit(2)
	}
	if err := distcheck.Verify(*directory, *smoke); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stdout, "verified all Gatehouse release archives and checksums")
}
