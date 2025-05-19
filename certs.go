package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"slices"
	"time"
)

func cipherSuites() []uint16 {
	suites := []uint16{}
	// Add in all the defaults
	for _, c := range tls.CipherSuites() {
		suites = append(suites, c.ID)
	}
	// for _, c := range tls.InsecureCipherSuites() {
	// 	suites = append(suites, c.ID)
	// }
	suites = slices.Compact(suites)
	fmt.Printf("Allowing: ")
	for _, s := range suites {
		fmt.Printf("%s ", tls.CipherSuiteName(s))
	}
	fmt.Println("")
	return suites
}

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
		CipherSuites: cipherSuites(),
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
