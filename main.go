package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"
	"gopkg.in/yaml.v3"
)

var (
	NEWLINE byte = '\n'
	Runtime RuntimeConfig
)

type RawConfig struct {
	ChanBufSize    int      `yaml:"chanbufsize"`
	Listen         string   `yaml:"listen"`
	TimeBucket     string   `yaml:"timebucket"`
	BucketLocation string   `yaml:"location"`
	Regexes        []string `yaml:"regexes"`
	Forwards       []string `yaml:"forwards"`
	TLS            struct {
		Cert string `yaml:"cert"`
		Key  string `yaml:"key"`
	} `yaml:"tls"`
}

type RuntimeConfig struct {
	ChanBufSize    int
	TimeBucket     time.Duration
	BucketLocation string
	Regexes        []*regexp.Regexp
	Forwards       []chan []byte
	Tls            *tls.Config
	Waits          sync.WaitGroup
	Finalizer      context.Context
}

func (rc *RuntimeConfig) Stats() {
	for {
		select {
		case <-rc.Finalizer.Done():
		default:
			time.Sleep(time.Minute)
			var o strings.Builder
			o.WriteString("[metrics] channel buffers: ")
			for i, ch := range rc.Forwards {
				fmt.Fprintf(&o, "[%d: %d]", i, len(ch))
			}
			fmt.Fprintf(&o, " routines:%d", runtime.NumGoroutine())
			fmt.Println(o.String())
		}
	}
}

func (rc *RuntimeConfig) NewChannel() chan []byte {
	c := make(chan []byte, rc.ChanBufSize)
	rc.Forwards = append(rc.Forwards, c)
	return c
}

func (rc *RuntimeConfig) WrapConnTLS(c net.Conn) *tls.Conn {
	return tls.Server(c, rc.Tls)
}

func zOpenNow(btime time.Duration) (*os.File, *zstd.Encoder, int64) {
	now := time.Now()
	f, err := os.OpenFile(filepath.Join(
		Runtime.BucketLocation,
		fmt.Sprintf("log.%d", now.Truncate(btime).Unix()),
	), os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		log.Fatal(err)
	}

	zlog, err := zstd.NewWriter(f, zstd.WithEncoderLevel(zstd.SpeedDefault))
	if err != nil {
		log.Fatal(err)
	}
	return f, zlog, now.Truncate(btime).Add(btime).Unix()
}

func UnixOutHandler(c chan []byte, sockpath string) {
	defer Runtime.Waits.Done()

Outer:
	for {
		select {
		case <-Runtime.Finalizer.Done():
			break Outer
		default:
			if info, err := os.Stat(sockpath); err != nil {
				time.Sleep(10 * time.Second)
				break
			} else if info.Mode()&fs.ModeSocket == 0 {
				fmt.Fprintf(os.Stderr, "[error] Found non-unix socket at forward path %q\n", sockpath)
				time.Sleep(10 * time.Second)
				break
			}
			conn, err := net.DialTimeout("unix", sockpath, 10*time.Second)
			if err != nil {
				log.Println(err)
				time.Sleep(10 * time.Second)
				break
			}
			fmt.Printf("[info] Connected to forward sock %s\n", sockpath)
			for {
				line, ok := <-c
				if !ok {
					return
				}
				if _, err := conn.Write(append(line, NEWLINE)); err != nil {
					log.Println(err)
					break
				}
			}
		}
	}
	log.Println("UnixOutHandler exit")
}

func FileOutHandler(c chan []byte) {
	defer Runtime.Waits.Done()
	f, zlog, until := zOpenNow(Runtime.TimeBucket)
	total := 0

Outer:
	for {
		select {
		case <-Runtime.Finalizer.Done():
			zlog.Flush()
			break Outer
		default:
			line, ok := <-c
			if !ok {
				zlog.Flush()
				break Outer
			}
			if time.Now().Unix() >= until {
				zlog.Close()
				f.Close()
				f, zlog, until = zOpenNow(Runtime.TimeBucket)
				total = 0
			}

			if n, err := zlog.Write(append(line, NEWLINE)); err != nil {
				log.Fatal(err)
			} else {
				total += n
			}
			zlog.Flush()
		}
	}

	zlog.Close()
	f.Close()
	log.Println("FileOutHandler exit")
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

func handleUDP(c net.PacketConn) {
	buf := make([]byte, 1024)
	for {
		select {
		case <-Runtime.Finalizer.Done():
			return
		default:
			n, addr, err := c.ReadFrom(buf)
			if n > 0 {
				line := buf[:n]
				parseline(string(line), addr.String())
			}
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				fmt.Fprintf(os.Stderr, "[error][%s] UDP handler: %s\n", addr, err)
			}
		}
	}
	log.Println("handleUDP exit")
}

func handleClient(c *bConn) {
	defer Runtime.Waits.Done()
	defer c.Close()
	remoteAddr := c.RemoteAddr().String()
	fmt.Printf("[info][%s] Client connected\n", remoteAddr)

	var scanner *bufio.Scanner

	// Handle plain tcp and tls
	if fb, err := c.FirstByte(); err != nil {
		fmt.Fprintf(os.Stderr, "[error][%s] TLS Peek failed: %s\n", remoteAddr, err)
		return
	} else {
		// https://tls12.xargs.org/#client-hello
		if fb[0] == 22 { // 22 as \x16
			fmt.Printf("[info][%s] Client upgraded to TLS\n", remoteAddr)
			s := Runtime.WrapConnTLS(c)
			defer s.Close() // stacking closes tls.Conn>net.Conn
			scanner = bufio.NewScanner(s)
		} else {
			scanner = bufio.NewScanner(c)
		}
	}
	// Input lines are newline delim
	scanner.Split(bufio.ScanLines)
OUTER:
	for {
		select {
		case <-Runtime.Finalizer.Done():
			break OUTER
		default:
			if !scanner.Scan() {
				break OUTER
			}
			line := scanner.Text()
			parseline(line, remoteAddr)

		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "[error][%s] Line scanner fail: %s\n", remoteAddr, err)
	}

	fmt.Printf("[info][%s] Client disconnected\n", remoteAddr)
}

func parseline(line, remoteAddr string) {
	if strings.HasPrefix(line, "{") && strings.HasSuffix(line, "}") {
		raw := make(map[string]interface{})
		// wasteful parse then fmt, should be a better way
		if err := json.Unmarshal([]byte(line), &raw); err == nil {
			raw["_ingest"] = fmt.Sprintf("%d", time.Now().Unix())
			raw["_remote"] = remoteAddr
			if data, err := json.Marshal(raw); err == nil {
				for _, ch := range Runtime.Forwards {
					select {
					case ch <- data:
					default:
					}
				}
				return
			}
		}
	}
	// Handle more expensive regex testing
	for i := len(Runtime.Regexes) - 1; i > 0; i-- {
		if matches := findNamedMatches(Runtime.Regexes[i], line); len(matches) > 0 {
			matches["_ingest"] = fmt.Sprintf("%d", time.Now().Unix())
			matches["_remote"] = remoteAddr
			data, err := json.Marshal(matches)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[error][%s] Can't mashal client content to JSON: %s\n", remoteAddr, err)
				return
			}
			for _, ch := range Runtime.Forwards {
				select {
				case ch <- data:
				default:
				}
			}
			// We had a match, dont test the rest of the regex
			return
		}
	}
	// Record lines without a match
	fmt.Printf("[warn][%s] Unhandled log: %q\n", remoteAddr, line)
}

func main() {
	cliConfig := flag.String("config", "./config.yml", "Configuration yaml file path.")
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

	if tb, err := time.ParseDuration(conf.TimeBucket); err != nil {
		log.Fatal(err)
	} else {
		Runtime.TimeBucket = tb
	}
	Runtime.ChanBufSize = conf.ChanBufSize
	Runtime.BucketLocation = conf.BucketLocation

	// Compile regexes from config
	for _, reg := range conf.Regexes {
		comp, err := regexp.Compile(reg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[error] Regex compilation: %s\n", err)
		} else {
			Runtime.Regexes = append(Runtime.Regexes, comp)
		}
	}

	// Load or generate a self-signed cert for use
	Runtime.Tls = LoadOrGenerateCert(conf.TLS.Cert, conf.TLS.Key)

	// Sort by capture groups so we grab the most specific data before the least
	sort.SliceStable(Runtime.Regexes, func(i, j int) bool {
		return Runtime.Regexes[i].NumSubexp() < Runtime.Regexes[j].NumSubexp()
	})
	fmt.Println("[info] Attempting regexes in order:")
	for i := len(Runtime.Regexes) - 1; i >= 0; i-- {
		fmt.Printf("  %d: (%d) %q\n", i+1, Runtime.Regexes[i].NumSubexp(), Runtime.Regexes[i].String())
	}

	// OS signal hook
	var stop context.CancelFunc
	Runtime.Finalizer, stop = signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer stop()

	ln, err := (&net.ListenConfig{}).Listen(Runtime.Finalizer, "tcp", conf.Listen)
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	lnp, err := (&net.ListenConfig{}).ListenPacket(Runtime.Finalizer, "udp", conf.Listen)
	if err != nil {
		log.Fatal(err)
	}
	defer lnp.Close()

	// Shut down listener on OS signal, then close consumer channel
	go func() {
		<-Runtime.Finalizer.Done()
		log.Println("Got interrupt.")
		ln.Close()
		lnp.Close()
		time.Sleep(time.Second) // give everyone a moment to close before channels exit
		for _, c := range Runtime.Forwards {
			close(c)
		}
		log.Println("Forward channels closed.")
	}()

	go handleUDP(lnp)

	// Start a single consumer to do the file IO
	{
		c := Runtime.NewChannel()
		Runtime.Waits.Add(1)
		go FileOutHandler(c)
	}

	// Start senders for each unix sock fwd
	for _, upath := range conf.Forwards {
		c := Runtime.NewChannel()
		Runtime.Waits.Add(1)
		go UnixOutHandler(c, upath)
	}

	go Runtime.Stats()

	for {
		cl, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				break
			}
			fmt.Fprintf(os.Stderr, "Accept error: %s\n", err)
			continue
		}
		Runtime.Waits.Add(1)
		go handleClient(newbConn(cl))
	}

	fmt.Println("[info] Waiting for goroutines to complete")
	Runtime.Waits.Wait()
}
