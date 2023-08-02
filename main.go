package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"flag"
	"fmt"
	"errors"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
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

func zOpenNow(btime time.Duration) (*os.File, *zstd.Encoder) {
	now := time.Now()
	f, err := os.OpenFile(fmt.Sprintf("log.%d", now.Truncate(btime).Unix()), os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		log.Fatal(err)
	}

	zlog, err := zstd.NewWriter(f, zstd.WithEncoderLevel(zstd.SpeedDefault))
	if err != nil {
		log.Fatal(err)
	}
	return f, zlog
}

func logConsumer(c chan []byte, btime time.Duration) {
	f, zlog := zOpenNow(btime)
	total := 0

	for {
		line, ok := <-c
		if !ok {
			zlog.Flush()
			break
		}
		if (len(line) + total) > CHUNK_SIZE {
			zlog.Close()
			f.Close()
			f, zlog = zOpenNow(btime)
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

func handleClient(ctx context.Context, c *bConn, ch chan []byte) {
	defer c.Close()
	remoteAddr := c.RemoteAddr().String()
	fmt.Printf("[info][%s] Client connected\n", remoteAddr)

	var scanner *bufio.Scanner

	// Handle TLS clients on same port
	if fb, err := c.FirstByte(); err != nil {
		fmt.Fprintf(os.Stderr, "[error][%s] TLS Peek failed: %s\n", remoteAddr, err)
		return
	} else {
		// https://tls12.xargs.org/#client-hello
		if fb[0] == 22 { // 22 as \x16
			fmt.Printf("[info][%s] Client upgraded to TLS\n", remoteAddr)
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

	// Interrupt worker on os signals
	go func() {
		<-ctx.Done()
		c.Close()
	}()

LINEREAD:
	for scanner.Scan() {
		line := scanner.Text()
		for i := len(REGEXES) - 1; i > 0; i-- {
			if matches := findNamedMatches(REGEXES[i], line); len(matches) > 0 {
				matches["_ingest"] = fmt.Sprintf("%d", time.Now().Unix())
				matches["_remote"] = remoteAddr
				data, err := json.Marshal(matches)
				if err != nil {
					fmt.Fprintf(os.Stderr, "[error][%s] Can't mashal client content to JSON: %s\n", remoteAddr, err)
					return
				}
				ch <- data
				continue LINEREAD
			}
		}
		// Record lines without a match
		fmt.Printf("[warn][%s] Unhandled log: %q\n", remoteAddr, line)
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "[error][%s] Line scanner fail: %s\n", remoteAddr, err)
	}

	fmt.Printf("[info][%s] Client disconnected\n", remoteAddr)
}

func main() {
	cliConfig := flag.String("config", "./config.yml", "Configuration yaml file path.")
	cliListen := flag.String("listen", ":6514", "Address to listen on.")
	cliBucket := flag.Duration("timebucket", 1*time.Hour, "Time slice to bucket logs into.")
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
			fmt.Fprintf(os.Stderr, "[error] Regex compilation: %s\n", err)
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

	fmt.Println("[info] Attempting regexes in order:")
	for i := len(REGEXES) - 1; i >= 0; i-- {
		fmt.Printf("  %d: (%d) %q\n", i+1, REGEXES[i].NumSubexp(), REGEXES[i].String())
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer stop()

	c := make(chan []byte, 10)
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", *cliListen)
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	go func() {
		<-ctx.Done()
		log.Println("Got interrupt.")
		ln.Close()
		close(c)
	}()

	go logConsumer(c, *cliBucket)

	for {
		cl, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				break
			}
			fmt.Fprintf(os.Stderr, "Accept error: %s\n", err)
			continue
		}
		go handleClient(ctx, newbConn(cl), c)
	}
}
