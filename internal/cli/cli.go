package cli

import (
	"fmt"

	"github.com/thomaschiozzi-tndigit/genjwk/internal/genjwk"
)

func Run() (status int) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("failed to unexpected program state!")
			fmt.Println(r)
			status = genjwk.ErrCodeGeneric
		}
	}()
	overrideUsage()
	pa, err := parseArgs()
	if err != nil {
		fmt.Println(err.Error() + "\n\n" + cliUsage)
		status = genjwk.ErrToErrCode(err)
		return
	}
	key, err := runWithArgs(pa)
	if err != nil {
		fmt.Println("failed to due error: " + err.Error())
		status = genjwk.ErrToErrCode(err)
		return
	}
	fmt.Print(key)
	return 0
}

func runWithArgs(pa ProgramArgs) (serializedKey string, err error) {
	key, err := genjwk.GenNewKey(pa.Kty, pa.KeyUse(), pa.Public, pa.IsAlg)
	if err != nil {
		fmt.Println("the program failed due to the following error: " + err.Error())
		return "", err
	}
	serializedKey = genjwk.SerializeKey(key)
	return
}
