package cli

import (
	"fmt"

	"github.com/thomaschiozzi-tndigit/genjwk/internal/genjwk"
)

func Run() int {
	overrideUsage()
	pa, err := parseArgs()
	// TODO: wrap and refactor
	if err != nil {
		fmt.Println(err.Error() + "\n\n" + cliUsage)
		return errToErrCode(err)
	}
	var k string
	if pa.Kty == EC {
		k, err = genjwk.GenEcdsaKey(pa.Public)
	} else {
		usage := "sig"
		if pa.IsEnc {
			usage = "enc"
		}
		k, err = genjwk.GenRsaKey(pa.Public, usage)
	}
	if err != nil {
		fmt.Printf("failed to generate key: %s\n", err.Error())
		return errToErrCode(err)
	}
	fmt.Print(k)
	return 0
}
