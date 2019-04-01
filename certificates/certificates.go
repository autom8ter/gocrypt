package certificates

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
)

type Certificate struct {
	Cert string
	Key  string
}

func BuildCustomCertificate(b64cert string, b64key string) (*Certificate, error) {
	crt := &Certificate{}

	cert, err := base64.StdEncoding.DecodeString(b64cert)
	if err != nil {
		return crt, errors.New("unable to decode base64 certificate")
	}

	key, err := base64.StdEncoding.DecodeString(b64key)
	if err != nil {
		return crt, errors.New("unable to decode base64 private key")
	}

	decodedCert, _ := pem.Decode(cert)
	if decodedCert == nil {
		return crt, errors.New("unable to decode certificate")
	}
	_, err = x509.ParseCertificate(decodedCert.Bytes)
	if err != nil {
		return crt, fmt.Errorf(
			"error parsing certificate: decodedCert.Bytes: %s",
			err,
		)
	}

	decodedKey, _ := pem.Decode(key)
	if decodedKey == nil {
		return crt, errors.New("unable to decode key")
	}
	_, err = x509.ParsePKCS1PrivateKey(decodedKey.Bytes)
	if err != nil {
		return crt, fmt.Errorf(
			"error parsing prive key: decodedKey.Bytes: %s",
			err,
		)
	}

	crt.Cert = string(cert)
	crt.Key = string(key)

	return crt, nil
}

func GenerateCertificateAuthority(
	cn string,
	daysValid int,
) (*Certificate, error) {
	ca := &Certificate{}

	template, err := GetBaseCertTemplate(cn, nil, nil, daysValid)
	if err != nil {
		return ca, err
	}
	// Override KeyUsage and IsCA
	template.KeyUsage = x509.KeyUsageKeyEncipherment |
		x509.KeyUsageDigitalSignature |
		x509.KeyUsageCertSign
	template.IsCA = true

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return ca, fmt.Errorf("error generating rsa key: %s", err)
	}

	ca.Cert, ca.Key, err = GetCertAndKey(template, priv, template, priv)
	if err != nil {
		return ca, err
	}

	return ca, nil
}

func GenerateSelfSignedCertificate(
	cn string,
	ips []interface{},
	alternateDNS []interface{},
	daysValid int,
) (Certificate, error) {
	cert := Certificate{}

	template, err := GetBaseCertTemplate(cn, ips, alternateDNS, daysValid)
	if err != nil {
		return cert, err
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return cert, fmt.Errorf("error generating rsa key: %s", err)
	}

	cert.Cert, cert.Key, err = GetCertAndKey(template, priv, template, priv)
	if err != nil {
		return cert, err
	}

	return cert, nil
}

func GenerateSignedCertificate(
	cn string,
	ips []interface{},
	alternateDNS []interface{},
	daysValid int,
	ca Certificate,
) (Certificate, error) {
	cert := Certificate{}

	decodedSignerCert, _ := pem.Decode([]byte(ca.Cert))
	if decodedSignerCert == nil {
		return cert, errors.New("unable to decode Certificate")
	}
	signerCert, err := x509.ParseCertificate(decodedSignerCert.Bytes)
	if err != nil {
		return cert, fmt.Errorf(
			"error parsing certificate: decodedSignerCert.Bytes: %s",
			err,
		)
	}
	decodedSignerKey, _ := pem.Decode([]byte(ca.Key))
	if decodedSignerKey == nil {
		return cert, errors.New("unable to decode key")
	}
	signerKey, err := x509.ParsePKCS1PrivateKey(decodedSignerKey.Bytes)
	if err != nil {
		return cert, fmt.Errorf(
			"error parsing prive key: decodedSignerKey.Bytes: %s",
			err,
		)
	}

	template, err := GetBaseCertTemplate(cn, ips, alternateDNS, daysValid)
	if err != nil {
		return cert, err
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return cert, fmt.Errorf("error generating rsa key: %s", err)
	}

	cert.Cert, cert.Key, err = GetCertAndKey(
		template,
		priv,
		signerCert,
		signerKey,
	)
	if err != nil {
		return cert, err
	}

	return cert, nil
}
