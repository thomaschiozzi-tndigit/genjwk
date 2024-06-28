package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

const cliUsage = `genjwk [--public] [--enc] [--alg] {ec|rsa}

Generate a fresh jwk.
Positional arguments:
    ec: generate an elliptic curve key (recommended)
    rsa: generate an rsa key 

Optional arguments:
	--public: if set, only the public portion of the key is generated
	--enc: if set, will try to create a key used for encryption, otherwise key
		is assumed to be for signing operations 
	--alg: if set, wil assign default algorithm for that key`

func keyFromValue(value string) keyType {
	switch v := strings.ToLower(value); v {
	case "ec":
		return EC
	case "rsa":
		return RSA
	default:
		return INVALID
	}
}

type ProgramArgs struct {
	Public bool
	IsEnc  bool
	IsAlg  bool
	Kty    keyType
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
		return ProgramArgs{}, fmt.Errorf("%w: missing positional argument {ec|rsa}", ErrorBadUsage)
	}
	kyt := keyFromValue(pargs[0])
	if kyt == INVALID {
		return ProgramArgs{}, fmt.Errorf("%w: invalid value for positional argument {ec|rsa}", ErrorBadUsage)
	}
	return pa, nil
}
