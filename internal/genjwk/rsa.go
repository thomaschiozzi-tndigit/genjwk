package genjwk

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"

	"github.com/lestrrat-go/jwx/jwk"
)

const rsaModulusSize = 3072 // in bits

func baseGenRsaKey() (jwk.Key, error) {
	rawKey, err := rsa.GenerateKey(rand.Reader, rsaModulusSize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA private key: %w", err)
	}
	key, err := jwk.New(rawKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create private key: %w", err)

	}
	kid, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("failed to produce key thumbprint for RSA key: %w", err)
	}
	if err = key.Set(jwk.KeyIDKey, base64.RawURLEncoding.EncodeToString(kid)); err != nil {
		return nil, fmt.Errorf("error in key extension: %w", err)
	}
	return key, nil
}
