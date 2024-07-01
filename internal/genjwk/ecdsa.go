package genjwk

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/lestrrat-go/jwx/jwk"
)

func baseGenEcdsaKwy() (jwk.Key, error) {
	rawKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ecdsa base key: %w", err)
	}
	key, err := jwk.New(rawKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create private key: %w", err)
	}
	kid, err := key.Thumbprint(crypto.SHA256)
	if err = key.Set(jwk.KeyIDKey, base64.RawURLEncoding.EncodeToString(kid)); err != nil {
		return nil, fmt.Errorf("error in key extension: %w", err)
	}
	return key, nil
}
