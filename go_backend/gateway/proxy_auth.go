package gateway

import (
	"encoding/base64"
	"errors"
	"io"
	"net"
	"strings"
)

func proxyBasicCredentials(header string) (string, string, error) {
	scheme, token, found := strings.Cut(strings.TrimSpace(header), " ")
	if !found || !strings.EqualFold(scheme, "Basic") {
		return "", "", errors.New("required HTTP Basic proxy credentials")
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(token)
	if err != nil {
		return "", "", errors.New("invalid base64 proxy credentials")
	}
	username, password, found := strings.Cut(string(decoded), ":")
	if !found {
		return "", "", errors.New("proxy credentials require username:password")
	}
	return username, password, nil
}

// readerConn retains CONNECT protocol bytes already read into the request buffer.
type readerConn struct {
	io.Reader
	net.Conn
}

func (c readerConn) Read(data []byte) (int, error) {
	return c.Reader.Read(data)
}
