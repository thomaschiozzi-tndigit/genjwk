package cli

import (
	"flag"
	"fmt"
	"os"

	"github.com/thomaschiozzi-tndigit/genjwk/internal/genjwk"
)

const version = "v0.1.1"

const cliUsage = `genjwk ` + version + ` [--public] [--enc] [--alg] {ec|rsa}

Generate a fresh jwk.
Positional arguments:
    ec: generate an elliptic curve key (recommended)
    rsa: generate an rsa key 

Optional arguments:
	--public: if set, only the public portion of the key is generated
	--enc: if set, will try to create a key used for encryption, otherwise key
		is assumed to be for signing operations 
	--alg: if set, wil assign default algorithm for that key`

type ProgramArgs struct {
	Public bool
	IsEnc  bool
	IsAlg  bool
	Kty    genjwk.KeyTypes
}

func (pa *ProgramArgs) KeyUse() string {
	if pa.IsEnc {
		return "enc"
	}
	return "sig"
}

func overrideUsage() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		fmt.Println(cliUsage)
	}
}

func parseArgs() (ProgramArgs, error) {
	pa := ProgramArgs{}
	flag.BoolVar(&pa.Public, "public", false, "if set, only the public portion of the key is generated")
	flag.BoolVar(&pa.IsEnc, "enc", false, "if set, will try to create a key used for encryption, otherwise key is assumed to be for signing operations")
	flag.BoolVar(&pa.IsAlg, "alg", false, "if set, wil assign default algorithm for that key")
	flag.Parse()
	pargs := flag.Args()
	if len(pargs) != 1 {
		return ProgramArgs{}, fmt.Errorf("%w: missing positional argument {ec|rsa}", genjwk.ErrorBadUsage)
	}
	kyt := genjwk.KtyFromValue(pargs[0])
	if kyt == genjwk.INVALID {
		return ProgramArgs{}, fmt.Errorf("%w: invalid value for positional argument {ec|rsa}", genjwk.ErrorBadUsage)
	}
	pa.Kty = kyt
	return pa, nil
}
