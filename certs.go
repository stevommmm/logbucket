package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"time"
)

func LoadOrGenerateCert(certpath, keypath string) *tls.Config {
	var cert tls.Certificate
	var err error
	if certpath != "" && keypath != "" {
		cert, err = tls.LoadX509KeyPair(certpath, keypath)
		if err != nil {
			log.Fatal(err)
		}

	} else {
		cert, err = selfSignedCert()
		if err != nil {
			log.Fatal(err)
		}
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
}

// https://gist.github.com/shivakar/cd52b5594d4912fbeb46
func selfSignedCert() (tls.Certificate, error) {
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.Unix()),
		Subject: pkix.Name{
			CommonName: "logbucket",
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(0, 1, 1), // 1 month 1 day
		SubjectKeyId:          []byte("logbucket"),
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, template,
		priv.Public(), priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	var outCert tls.Certificate
	outCert.Certificate = append(outCert.Certificate, cert)
	outCert.PrivateKey = priv

	return outCert, nil
}
