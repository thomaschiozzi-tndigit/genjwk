package genjwk

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/jwk"
)

const rsaModulusSize = 3072 // in bits

func GenEcdsaKey(public bool) (string, error) {
	rawKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("failed to generare ECDSA key: %w", err)
	}
	var key jwk.Key
	if public {
		key, err = jwk.New(rawKey.PublicKey)
		if err != nil {
			return "", fmt.Errorf("failed to create public only key: %w", err)
		}
	} else {
		key, err = jwk.New(rawKey)
		if err != nil {
			return "", fmt.Errorf("failed to create private key: %w", err)

		}
	}
	kid, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("failed to produce key thumbprint for RSA key: %w", err)
	}
	serKid := base64.RawURLEncoding.EncodeToString(kid)
	key.Set(jwk.KeyIDKey, serKid)
	key.Set(jwk.KeyUsageKey, "sig")
	serKey, err := json.Marshal(key)
	if err != nil {
		return "", fmt.Errorf("failed to serialize key: %w", err)
	}
	return string(serKey), nil
}

func GenRsaKey(public bool, usage string) (string, error) {
	if usage == "" || (usage != "sig" && usage != "enc") {
		return "", fmt.Errorf("invalid usage %s: must be either sig or enc", usage)
	}
	rawKey, err := rsa.GenerateKey(rand.Reader, rsaModulusSize)
	if err != nil {
		return "", fmt.Errorf("failed to generate RSA private key: %w", err)
	}
	var key jwk.Key
	if public {
		key, err = jwk.New(rawKey.PublicKey)
		if err != nil {
			return "", fmt.Errorf("failed to create public only key: %w", err)
		}
	} else {
		key, err = jwk.New(rawKey)
		if err != nil {
			return "", fmt.Errorf("failed to create private key: %w", err)

		}
	}
	kid, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("failed to produce key thumbprint for RSA key: %w", err)
	}
	serKid := base64.RawURLEncoding.EncodeToString(kid)
	key.Set(jwk.KeyIDKey, serKid)
	key.Set(jwk.KeyUsageKey, usage)
	serKey, err := json.Marshal(key)
	if err != nil {
		return "", fmt.Errorf("failed to serialize key: %w", err)
	}
	return string(serKey), nil
}
