package genjwk

import (
	"errors"
	"strconv"
	"strings"
)

type KeyTypes int

func KtyFromValue(value string) KeyTypes {
	switch v := strings.ToUpper(value); v {
	case "EC":
		return EC
	case "RSA":
		return RSA
	default:
		return INVALID
	}
}

func KtyToValue(kty KeyTypes) string {
	switch kty {
	case INVALID:
		return "_invalid"
	case EC:
		return "EC"
	case RSA:
		return "RSA"
	default:
		panic("unrecognized kty :" + strconv.Itoa(int(kty)))
	}
}

const (
	ErrCodeGeneric = 1
	ErrCodeBadArgs = 1000
)

const (
	INVALID KeyTypes = iota // assign zero value to failcase
	EC
	RSA
)

var ErrInvalidKeyType = errors.New("invalid key type")
var ErrorBadUsage = errors.New("invalid program usage")

func ErrToErrCode(err error) int {
	if err == nil {
		return 0
	}
	if errors.Is(err, ErrorBadUsage) {
		return ErrCodeBadArgs
	}
	return ErrCodeGeneric
}
