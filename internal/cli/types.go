package cli

import "errors"

type keyType int

const (
	ErrCodeGeneric = 1
	ErrCodeBadArgs = 1000
)

const (
	INVALID keyType = iota // assign zero value to failcase
	EC
	RSA
)

var ErrorBadUsage = errors.New("invalid program usage")

func errToErrCode(err error) int {
	if err == nil {
		return 0
	}
	if errors.Is(err, ErrorBadUsage) {
		return ErrCodeBadArgs
	}
	return ErrCodeGeneric
}
