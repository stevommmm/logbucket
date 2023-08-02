package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"regexp"
	"sort"
	"time"

	"github.com/klauspost/compress/zstd"
	"gopkg.in/yaml.v3"
)

var CHUNK_SIZE = 1000000 * 512
var NEWLINE byte = '\n'
var REGEXES []*regexp.Regexp
var TLS_CONF *tls.Config

type RawConfig struct {
	Regexes []string `yaml:"regexes"`
	TLS     struct {
		Cert string `yaml:"cert"`
		Key  string `yaml:"key"`
	} `yaml:"tls"`
}

type bConn struct {
	r *bufio.Reader
	net.Conn
}

func newbConn(c net.Conn) *bConn {
	return &bConn{
		bufio.NewReaderSize(c, 1),
		c,
	}
}

func (b bConn) FirstByte() ([]byte, error) {
	return b.r.Peek(1)
}

func (b bConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
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

func zOpenNow() (*os.File, *zstd.Encoder) {
	f, err := os.Create(fmt.Sprintf("log.%d", time.Now().Unix()))
	if err != nil {
		log.Fatal(err)
	}

	zlog, err := zstd.NewWriter(f, zstd.WithEncoderLevel(zstd.SpeedDefault))
	if err != nil {
		log.Fatal(err)
	}
	return f, zlog
}

func logConsumer(c chan map[string]string) {
	f, zlog := zOpenNow()
	total := 0

	for {
		raw := <-c
		line, err := json.Marshal(raw)
		if err != nil {
			log.Fatal()
		}
		if (len(line) + total) > CHUNK_SIZE {
			zlog.Close()
			f.Close()
			log.Printf("Rotating log at %d bytes\n", total)
			f, zlog = zOpenNow()
			total = 0
		}

		if n, err := zlog.Write(append(line, NEWLINE)); err != nil {
			log.Fatal(err)
		} else {
			total += n
		}

		zlog.Flush()
	}

	zlog.Close()
	f.Close()
}

// https://stackoverflow.com/questions/20750843/using-named-matches-from-go-regex
func findNamedMatches(regex *regexp.Regexp, str string) map[string]string {
	results := make(map[string]string)
	match := regex.FindStringSubmatch(str)

	for i, name := range match {
		if i == 0 {
			continue
		}
		results[regex.SubexpNames()[i]] = name
	}
	return results
}

func handleClient(c *bConn, ch chan map[string]string) {
	defer c.Close()
	remoteAddr := c.RemoteAddr().String()
	log.Printf("Client connected from %q\n", remoteAddr)

	var scanner *bufio.Scanner

	// Handle TLS clients on same port
	if fb, err := c.FirstByte(); err != nil {
		log.Printf("TLS Peek failed for %q with %s\n", remoteAddr, err)
		return
	} else {
		// https://tls12.xargs.org/#client-hello
		if fb[0] == 22 { // 22 as \x16
			log.Printf("Client upgraded to TLS for %q\n", remoteAddr)
			var s *tls.Conn
			s = tls.Server(c, TLS_CONF)
			defer s.Close()
			scanner = bufio.NewScanner(s)
		} else {
			scanner = bufio.NewScanner(c)
		}
	}

	// Input lines are newline delim
	scanner.Split(bufio.ScanLines)

LINEREAD:
	for scanner.Scan() {
		line := scanner.Text()
		for _, reg := range REGEXES {
			if matches := findNamedMatches(reg, line); len(matches) > 0 {
				ch <- matches
				continue LINEREAD
			}
		}
		// Record lines without a match
		log.Printf("[!] %q\n", line)
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "Reading client socket", err)
	}

	log.Println("Client at", remoteAddr, "disconnected")
}

func main() {
	cliConfig := flag.String("config", "./config.yml", "Configuration yaml file path.")
	cliListen := flag.String("listen", ":9999", "Address to listen on.")
	flag.Parse()

	f, err := os.Open(*cliConfig)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	var conf RawConfig
	if err := yaml.NewDecoder(f).Decode(&conf); err != nil {
		log.Fatal(err)
	}

	// Compile regexes from config
	for _, reg := range conf.Regexes {
		comp, err := regexp.Compile(reg)
		if err != nil {
			log.Println("[x]", err)
		} else {
			REGEXES = append(REGEXES, comp)
		}
	}

	// Load or generate a self-signed cert for use
	var cert tls.Certificate
	if conf.TLS.Cert != "" && conf.TLS.Key != "" {
		var err error
		cert, err = tls.LoadX509KeyPair(conf.TLS.Cert, conf.TLS.Key)
		if err != nil {
			log.Fatal(err)
		}

	} else {
		var err error
		cert, err = selfSignedCert()
		if err != nil {
			log.Fatal(err)
		}
	}

	TLS_CONF = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	// Sort by capture groups so we grab the most specific data before the least
	sort.SliceStable(REGEXES, func(i, j int) bool {
		return REGEXES[i].NumSubexp() < REGEXES[j].NumSubexp()
	})

	log.Println("Attempting regexes in order:")
	for i, r := range REGEXES {
		log.Printf("  #%d: %q", i, r.String())
	}

	c := make(chan map[string]string, 10)
	ln, err := net.Listen("tcp", *cliListen)
	if err != nil {
		log.Fatal(err)
	}

	go logConsumer(c)

	for {
		cl, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go handleClient(newbConn(cl), c)
	}
}
