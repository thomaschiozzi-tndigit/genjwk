package main

import (
	"os"

	"github.com/thomaschiozzi-tndigit/genjwk/internal/cli"
)

func main() {
	result := cli.Run()
	os.Exit(result)
}
