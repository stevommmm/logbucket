package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	NEWLINE     byte = '\n'
	STOP        context.Context
	metricp     atomic.Pointer[map[string]int64]
	resolved    map[string]string
	resolvelock sync.RWMutex
)

type Message struct {
	Remote string `json:"_remote"`
}

func Stats(dest string) {
	hn, err := os.Hostname()
	if err != nil {
		hn = "unknown"
	}
	hn = strings.ReplaceAll(hn, ".", "_")

	for {
		select {
		case <-STOP.Done():
			return
		default:
			if dest != "-" {
				s, err := net.Dial("tcp", dest)
				if err != nil {
					log.Println(err)
				} else {
					now := time.Now().Unix()
					// Swap out old metrics with new map
					lmetrics := metricp.Swap(&map[string]int64{})
					for n, sent := range *lmetrics {
						fmt.Fprintf(s, "logbucket.%s.metrics.%s %d %d\n", hn, strings.ReplaceAll(n, ".", "_"), sent, now)
					}
					s.Close()
				}
			}
			time.Sleep(time.Minute)
		}
	}
}

func cachedresolve(addr string) string {
	resolvelock.RLock()
	n, ok := resolved[addr]
	resolvelock.RUnlock()

	if ok {
		return n
	}

	// Write to shared map
	resolvelock.Lock()
	defer resolvelock.Unlock()
	names, err := net.LookupAddr(addr)
	if err != nil {
		return addr
	}
	if len(names) == 0 {
		return addr
	}
	resolved[addr] = names[0]
	return names[0]
}

func main() {
	resolved = make(map[string]string)
	cliStats := flag.String("stats", "-", "Graphite destination host:port.")
	cliSocket := flag.String("socket", "metrics.sock", "Logbucket ingest unix socket.")
	flag.Parse()

	// Set init value for metric
	metricp.Store(&map[string]int64{})

	// OS signal hook
	var stop context.CancelFunc
	STOP, stop = signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer stop()

	os.Remove(*cliSocket)

	ln, err := (&net.ListenConfig{}).Listen(STOP, "unix", *cliSocket)
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()
	defer os.Remove(*cliSocket)

	go Stats(*cliStats)

	log.Println("Listening on ", *cliSocket)

	for {
		select {
		case <-STOP.Done():
			return
		default:
			cl, err := ln.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					break
				}
				fmt.Fprintf(os.Stderr, "Accept error: %s\n", err)
				continue
			}
			dec := json.NewDecoder(cl)
			var m Message

			for {
				select {
				case <-STOP.Done():
					return
				default:
					err := dec.Decode(&m)
					if err == io.EOF {
						return
					}
					if err != nil {
						fmt.Fprintf(os.Stderr, "[error] Line scanner fail: %s\n", err)
						break
					}

					h, _, err := net.SplitHostPort(m.Remote)
					if err == nil {
						hn := cachedresolve(h)
						hn = strings.ReplaceAll(hn, ".", "_")

						m := metricp.Load()
						// Probably safe?
						(*m)[hn] += 1
					}
				}
			}
		}
	}
}
