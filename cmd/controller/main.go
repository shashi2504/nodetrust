// Command controller runs in the cluster. It reconciles Node taints and the
// out-of-band critical path from signed NodeTrust updates. Implemented in
// Phase 5.
package main

import (
	"flag"
	"fmt"
	"os"

	"nodetrust/internal/version"
)

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version.String("controller"))
		return
	}
	fmt.Fprintln(os.Stderr, "nodetrust-controller: not implemented yet (Phase 5)")
	os.Exit(1)
}
