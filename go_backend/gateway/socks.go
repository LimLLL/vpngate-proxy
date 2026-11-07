package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"

	"time"
)

func (p *Proxy) handleSocks(client net.Conn, reader *bufio.Reader) {
	username, password, err := authenticateSocks(reader, client, p.validCredentials)
	if err != nil {
		return
	}
	header, err := readSocks(reader, 4)
	if err != nil {
		return
	}
	if header[0] != 5 || header[1] != 1 || header[2] != 0 {
		writeSocksReply(client, 7)
		return
	}
	var host string
	switch header[3] {
	case 1:
		address, err := readSocks(reader, 4)
		if err != nil {
			return
		}
		host = net.IP(address).String()
	case 3:
		length, err := readSocks(reader, 1)
		if err != nil {
			return
		}
		address, err := readSocks(reader, int(length[0]))
		if len(address) == 0 || err != nil {
			writeSocksReply(client, 8)
			return
		}
		host = string(address)
	case 4:
		writeSocksReply(client, 8)
		return
	default:
		writeSocksReply(client, 8)
		return
	}
	portBytes, err := readSocks(reader, 2)
	if err != nil {
		return
	}
	port := int(binary.BigEndian.Uint16(portBytes))
	if port == 0 {
		writeSocksReply(client, 8)
		return
	}
	ctx, cancel := context.WithTimeout(p.ctx, 45*time.Second)
	defer cancel()
	lease, egress, err := p.acquireTunnel(ctx, username, password)
	if err != nil {
		log.Printf("SOCKS5 authentication or session error: %v", err)
		writeSocksReply(client, 1)
		return
	}
	defer lease.Release()
	upstream, err := egress.DialContext(ctx, host, port)
	if err != nil {
		log.Printf("%s SOCKS5 %s:%d: %v", lease.Info.TUNName, host, port, err)
		writeSocksReply(client, 4)
		return
	}
	defer upstream.Close()
	if !writeSocksReply(client, 0) {
		return
	}
	relay(p.ctx, readerConn{Reader: reader, Conn: client}, upstream)
}

func authenticateSocks(reader *bufio.Reader, writer io.Writer, validate func(string, string) bool) (string, string, error) {
	greeting, err := readSocks(reader, 2)
	if err != nil {
		return "", "", err
	}
	if greeting[0] != 5 {
		return "", "", errors.New("invalid SOCKS version")
	}
	methods, err := readSocks(reader, int(greeting[1]))
	if err != nil {
		return "", "", err
	}
	if bytes.IndexByte(methods, 2) < 0 {
		_, _ = writer.Write([]byte{5, 255})
		return "", "", errors.New("SOCKS username/password authentication is required")
	}
	if _, err := writer.Write([]byte{5, 2}); err != nil {
		return "", "", err
	}
	version, err := readSocks(reader, 1)
	if err != nil {
		return "", "", err
	}
	if version[0] != 1 {
		return "", "", errors.New("unsupported SOCKS authentication version")
	}
	userLength, err := readSocks(reader, 1)
	if err != nil {
		return "", "", err
	}
	username, err := readSocks(reader, int(userLength[0]))
	if err != nil {
		return "", "", err
	}
	passwordLength, err := readSocks(reader, 1)
	if err != nil {
		return "", "", err
	}
	password, err := readSocks(reader, int(passwordLength[0]))
	if err != nil {
		return "", "", err
	}
	if !validate(string(username), string(password)) {
		_, _ = writer.Write([]byte{1, 1})
		return "", "", errors.New("proxy credentials or session were rejected")
	}
	if _, err := writer.Write([]byte{1, 0}); err != nil {
		return "", "", err
	}
	return string(username), string(password), nil
}

func readSocks(reader io.Reader, length int) ([]byte, error) {
	buffer := make([]byte, length)
	_, err := io.ReadFull(reader, buffer)
	return buffer, err
}

func writeSocksReply(writer io.Writer, code byte) bool {
	_, err := writer.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
	return err == nil
}
