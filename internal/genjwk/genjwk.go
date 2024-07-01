package genjwk

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/lestrrat-go/jwx/jwk"
)

func toPublic(key jwk.Key) (jwk.Key, error) {
	pubKey, err := key.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to convert to publci key: %w", err)
	}
	return pubKey, err
}

func defaultAlg(kty string, use string) string {
	switch use {
	case "sig":
		switch ku := strings.ToUpper(kty); ku {
		case "EC":
			return "ES256"
		case "RSA":
			return "RS256"
		case "":
			panic("missing key use")
		default:
			panic("unexpected key type: " + kty)
		}
	case "enc":
		switch ku := strings.ToUpper(kty); ku {
		case "EC":
			return "ECDH-ES"
		case "RSA":
			return "RSA_OAEP"
		case "":
			panic("missing key use")
		default:
			panic("unexpected key type: " + kty)
		}
	case "":
		panic("missing key use")
	default:
		panic("unexpected key use: " + use)
	}
}

func genBaseKey(kty KeyTypes) (jwk.Key, error) {
	switch kty {
	case INVALID:
		return nil, ErrInvalidKeyType
	case EC:
		return baseGenEcdsaKwy()
	case RSA:
		return baseGenRsaKey()
	default:
		panic("invalid enum case: " + strconv.Itoa(int(kty)))
	}
}

func GenNewKey(kty KeyTypes, use string, isPublic bool, withAlg bool) (jwk.Key, error) {
	key, err := genBaseKey(kty)
	if err != nil {
		return nil, fmt.Errorf("failed to generate %s key: %w", KtyToValue(kty), err)
	}
	if use != "" {
		key.Set("use", use)
	}
	if withAlg {
		alg := defaultAlg(KtyToValue(kty), use)
		key.Set("alg", alg)
	}
	if isPublic {
		key, err = toPublic(key)
		if err != nil {
			return nil, err
		}
	}
	return key, nil
}

func SerializeKey(key jwk.Key) string {
	serialized, err := json.Marshal(key)
	if err != nil {
		panic(fmt.Errorf("failed to serialized key: %w", err))
	}
	return string(serialized)
}
