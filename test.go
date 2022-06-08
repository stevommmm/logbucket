package main

import (
	"compress/zlib"
	"crypto/tls"
	"encoding/gob"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/coreos/go-systemd/sdjournal"
	"github.com/go-logfmt/logfmt"
)

var (
	cliUncompress = flag.String("uncompress", "", "File path to uncompress to raw text")
	cliTarget     = flag.String("target", "", "Remove journal receiver.")
	cliListen     = flag.String("listen", "", "Operate in server mode and accept logs on this address.")
	cliCert       = flag.String("cert", "./cert.pem", "TLS key+certificate in PEM format.")
	cliInsecure   = flag.Bool("insecure", false, "Disable TLS verification.")
	interrupt     chan struct{}
	sockgroup     sync.WaitGroup
)

func FollowJournal(target string, tlsSecure bool) {
	journal, err := sdjournal.NewJournal()
	if err != nil {
		log.Fatal(err)
	}
	journal.SeekTail()

	for {
		log.Printf("Establishing connection to %s\n", *cliTarget)
		conn, err := tls.Dial("tcp", target, &tls.Config{
			InsecureSkipVerify: tlsSecure,
		})
		if err != nil {
			log.Println(err)
		} else {

			// Line encoder
			enc := logfmt.NewEncoder(conn)

			for {
				select {
				case <-interrupt:
					conn.Close()
					return
				default:
					journal.Wait(sdjournal.IndefiniteWait)
					journal.Next()
					entry, err := journal.GetEntry()
					if err != nil {
						log.Println(err)
						break
					}
					for k, v := range entry.Fields {
						enc.EncodeKeyval(k, v)
					}
					if err := enc.EndRecord(); err != nil {
						log.Println(err)
						break
					}
				}
			}
			conn.Close()
		}
		// Sleep a random period of up to a second to spread reconnects when we have multiple clients
		time.Sleep((time.Duration(rand.Intn(500) + 500)) * time.Millisecond)
	}
}

func HandleClient(conn net.Conn) {
	defer sockgroup.Done()
	defer conn.Close()

	remoteHost, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		log.Println(err)
		return
	}

	now := time.Now()

	logLocation := fmt.Sprintf("logs/%d/%d/%d/", now.Year(), now.Month(), now.Day())
	logName := fmt.Sprintf("%s%s.log.z", logLocation, remoteHost)

	if err := os.MkdirAll(logLocation, 0750); err != nil {
		log.Println(err)
		return
	}

	f, err := os.OpenFile(logName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println(err)
		return
	}
	defer f.Close()

	w, _ := zlib.NewWriterLevel(f, zlib.BestCompression)
	defer w.Close()
	defer w.Flush()

	enc := logfmt.NewEncoder(w)

	records := 0

	for {
		select {
		case <-interrupt:
			conn.Close()
			return
		default:
			var q map[string]string
			err := dec.Decode(&q)
			if err != nil {
				if errors.Is(err, io.EOF) {
					// Client has disconnected, save whatever we have
					enc.EndRecord()
					log.Printf(". %s has disconnected", remoteHost)
					return
				}
				log.Println("decode error 1:", err)
				return
			}
			enc.EncodeKeyval("__RECEIVED", time.Now().Unix())
			for k, v := range q {
				enc.EncodeKeyval(k, v)
			}
			enc.EndRecord()
			records += 1
			fmt.Println("Records:", records)

			// i, _ := f.Stat()
			// fmt.Println(i.Name(), i.Size())
		}
	}
}

func main() {
	flag.Parse()

	interrupt = make(chan struct{})

	if *cliTarget == "" && *cliListen == "" && *cliUncompress == "" {
		log.Println("One of -cliUncompress, -target or -listen must be defined.")
		os.Exit(1)
	}

	go func() {
		s := make(chan os.Signal, 1)
		signal.Notify(s, os.Interrupt, syscall.SIGTERM)
		<-s
		fmt.Println("Got interrupt")
		close(interrupt)
	}()

	if *cliUncompress != "" {
		f, err := os.Open(*cliUncompress)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		zr, err := zlib.NewReader(f)
		if err != nil {
			log.Fatal(err)
		}
		defer zr.Close()
		io.Copy(os.Stdout, zr)
		return
	}

	if *cliTarget != "" {
		FollowJournal(*cliTarget, *cliInsecure)
		return
	}

	if *cliListen != "" {
		cert, err := tls.LoadX509KeyPair(*cliCert, *cliCert)
		if err != nil {
			log.Fatal(err)
		}

		log.Printf("Listening on %s\n", *cliListen)
		addr, err := net.ResolveTCPAddr("tcp", *cliListen)
		if err != nil {
			log.Fatal("Bad listen address given")
		}
		tcpl, err := net.ListenTCP("tcp", addr)
		if err != nil {
			log.Println(err)
			time.Sleep(10 * time.Second)

		}
		listener := tls.NewListener(tcpl, &tls.Config{
			Certificates: []tls.Certificate{cert}, InsecureSkipVerify: *cliInsecure,
		})

	listenLoop:
		for {
			select {
			case <-interrupt:
				listener.Close()
				break listenLoop
			default:
				tcpl.SetDeadline(time.Now().Add(time.Second))
				conn, err := listener.Accept()
				if err != nil {
					if operr, ok := err.(*net.OpError); ok {
						if operr.Timeout() {
							continue
						}
					}
					log.Printf("server: accept: %s", err)
					continue
				}
				log.Printf("server: accepted from %s", conn.RemoteAddr())
				sockgroup.Add(1)
				go HandleClient(conn) // Closed from within func
			}
		}
	}
	sockgroup.Wait()
}
