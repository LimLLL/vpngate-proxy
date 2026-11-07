package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// testserver exists for isolated runner namespace validation. It is not part
// of deployed proxy images and has no application credentials or public UI.
func main() {
	address := flag.String("listen", "127.0.0.1:18080", "TCP listen address")
	mode := flag.String("mode", "http", "http or raw TCP echo")
	ready := flag.String("ready-file", "", "ready marker for the orchestrator")
	flag.Parse()
	listener, err := net.Listen("tcp", *address)
	if err != nil {
		log.Fatal(err)
	}
	if *ready != "" {
		if err := writeReady(*ready); err != nil {
			log.Fatal(err)
		}
	}
	if *mode == "raw" {
		if err := serveRaw(listener); err != nil {
			log.Fatal(err)
		}
		return
	}
	server := &http.Server{Handler: http.HandlerFunc(tunnelResponse)}
	log.Printf("test HTTP listening at %s", *address)
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func tunnelResponse(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Proxy-Authorization") != "" {
		http.Error(w, "proxy credentials must not reach the target", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Connection", "close")
	_, _ = fmt.Fprintf(w, "vpn-client=%s\n", r.RemoteAddr)
}

func serveRaw(listener net.Listener) error {
	var sequence atomic.Uint64
	defer listener.Close()
	for {
		connection, err := listener.Accept()
		if err != nil {
			return err
		}
		id := sequence.Add(1)
		go func() {
			defer connection.Close()
			deadline := time.Now().Add(4 * time.Minute)
			_ = connection.SetDeadline(deadline)
			reader := bufio.NewReader(connection)
			writer := bufio.NewWriter(connection)
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					if !errors.Is(err, io.EOF) {
						log.Printf("raw test connection: %v", err)
					}
					return
				}
				if strings.TrimSpace(line) != "ping" {
					return
				}
				_, _ = fmt.Fprintf(writer, "pong stream=%d\n", id)
				if err := writer.Flush(); err != nil {
					return
				}
			}
		}()
	}
}
