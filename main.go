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
	"sync/atomic"
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

type Forward struct {
	Chan  chan []byte
	Count *atomic.Uint64
}

type RuntimeConfig struct {
	ChanBufSize    int
	TimeBucket     time.Duration
	BucketLocation string
	Regexes        []*regexp.Regexp
	Forwards       []Forward
	Tls            *tls.Config
	Waits          sync.WaitGroup
	Finalizer      context.Context
}

func (rc *RuntimeConfig) Stats(dest string) {
	hn, err := os.Hostname()
	if err != nil {
		hn = "unknown"
	}
	hn = strings.ReplaceAll(hn, ".", "_")

	for {
		select {
		case <-rc.Finalizer.Done():
		default:
			if dest != "-" {
				c, err := net.Dial("tcp", dest)
				if err != nil {
					log.Println(err)
				} else {
					now := time.Now().Unix()
					for i, ch := range rc.Forwards {
						fmt.Fprintf(c, "logbucket.%s.forward.%d.queue %d %d\n", hn, i, len(ch.Chan), now)
						sent := ch.Count.Swap(uint64(0))
						fmt.Fprintf(c, "logbucket.%s.forward.%d.sent %d %d\n", hn, i, sent, now)
					}
					fmt.Fprintf(c, "logbucket.%s.routines %d %d\n", hn, runtime.NumGoroutine(), now)
					c.Close()
				}
			}
			time.Sleep(time.Minute)
		}
	}
}

func (rc *RuntimeConfig) NewChannel() *Forward {
	c := make(chan []byte, rc.ChanBufSize)
	fwd := Forward{Chan: c, Count: &atomic.Uint64{}}
	rc.Forwards = append(rc.Forwards, fwd)
	return &fwd
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

func UnixOutHandler(fwd *Forward, sockpath string) {
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
				line, ok := <-fwd.Chan
				if !ok {
					return
				}
				if _, err := conn.Write(append(line, NEWLINE)); err != nil {
					log.Println(err)
					break
				}
				fwd.Count.Add(uint64(1))
			}
		}
	}
	log.Println("UnixOutHandler exit")
}

func FileOutHandler(fwd *Forward) {
	defer Runtime.Waits.Done()
	f, zlog, until := zOpenNow(Runtime.TimeBucket)

Outer:
	for {
		select {
		case <-Runtime.Finalizer.Done():
			zlog.Flush()
			break Outer
		default:
			line, ok := <-fwd.Chan
			if !ok {
				zlog.Flush()
				break Outer
			}
			if time.Now().Unix() >= until {
				zlog.Close()
				f.Close()
				f, zlog, until = zOpenNow(Runtime.TimeBucket)
			}

			if _, err := zlog.Write(append(line, NEWLINE)); err != nil {
				log.Fatal(err)
			} else {
				fwd.Count.Add(uint64(1))
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
				line := strings.ReplaceAll(string(buf[:n]), "\n", "\\n")
				parseline(line, addr.String())
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
					case ch.Chan <- data:
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
				case ch.Chan <- data:
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
	cliStats := flag.String("stats", "-", "Graphite destination host:port.")
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
			close(c.Chan)
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

	go Runtime.Stats(*cliStats)

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
