package keys

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"github.com/autom8ter/gocrypt/certificates"
)

type KeyType int

const (
	RSA KeyType = iota
	DSA
	ECDSA
)

func (k KeyType) Generate() string {
	var priv interface{}
	var err error
	switch k {
	case RSA:
		// good enough for government work
		priv, err = rsa.GenerateKey(rand.Reader, 4096)
	case DSA:
		key := new(dsa.PrivateKey)
		// again, good enough for government work
		if err = dsa.GenerateParameters(&key.Parameters, rand.Reader, dsa.L2048N256); err != nil {
			return fmt.Sprintf("failed to generate dsa params: %s", err)
		}
		err = dsa.GenerateKey(key, rand.Reader)
		priv = key
	case ECDSA:
		// again, good enough for government work
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	default:
		return fmt.Sprintf("unknown key type %v", k)
	}
	if err != nil {
		return fmt.Sprintf("failed to generate private key: %s", err)
	}

	return string(pem.EncodeToMemory(certificates.PemBlockForKey(priv)))
}
