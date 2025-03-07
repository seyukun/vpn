package main

import (
	"fmt"
	"os"
	"wgvpm/macro"

	"github.com/pkg/taptun"
)

func main() {
	tun, err := taptun.NewTun("vpm0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s](%s:%d) Error: %s\n", tun, macro.FILE__(), macro.LINE__(), err.Error())
		os.Exit(1)
	}
	defer tun.Close()
}
