package main

import (
	"bufio"
	"crypto/subtle"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// testauth implements OpenVPN's via-file username/password protocol for a
// disposable CI server, without relying on custom launcher environment values.
func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "OpenVPN via-file username/password path required")
		os.Exit(1)
	}
	file, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024), 8192)
	var fields [2]string
	for index := range fields {
		if !scanner.Scan() || scanner.Err() != nil {
			fmt.Fprintln(os.Stderr, "invalid username/password file")
			os.Exit(1)
		}
		fields[index] = strings.TrimSuffix(scanner.Text(), "\r")
	}
	valid := subtle.ConstantTimeCompare([]byte(fields[0]), []byte("vpn")) == 1 &&
		subtle.ConstantTimeCompare([]byte(fields[1]), []byte("vpn")) == 1
	result := "rejected"
	if valid {
		result = "accepted"
	}
	audit := fmt.Sprintf("%s user=vpn", result)
	path, err := os.Executable()
	if err == nil {
		_ = os.WriteFile(filepath.Join(filepath.Dir(path), "auth-result"), []byte(audit+"\n"), 0o600)
	}
	if !valid {
		fmt.Fprintln(os.Stderr, "unexpected test credentials")
		os.Exit(1)
	}
}
