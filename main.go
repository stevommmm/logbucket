package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/klauspost/compress/zstd"
)

var CHUNK_SIZE = 1000000 * 4

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

func logConsumer(c chan string) {
	f, zlog := zOpenNow()
	total := 0

	for {
		line := <-c
		if (len(line) + total) > CHUNK_SIZE {
			zlog.Close()
			f.Close()
			log.Printf("Rotating log at %d bytes\n", total)
			f, zlog = zOpenNow()
			total = 0
		}

		if n, err := zlog.Write([]byte(line + "\n")); err != nil {
			log.Fatal(err)
		} else {
			total += n
		}
	}

	zlog.Close()
	f.Close()
}

func handleClient(c net.Conn, ch chan string) {
	defer c.Close()
	remoteAddr := c.RemoteAddr().String()
	log.Println("Client connected from", remoteAddr)

	// echo received messages
	scanner := bufio.NewScanner(c)
	scanner.Split(bufio.ScanLines)
	for {
		ok := scanner.Scan()
		if !ok {
			break
		}
		ch <- scanner.Text()
	}

	log.Println("Client at", remoteAddr, "disconnected")
}

func main() {
	c := make(chan string)
	ln, err := net.Listen("tcp", "127.0.0.1:9999")
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
		go handleClient(cl, c)
	}
}
