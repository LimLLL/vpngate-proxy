package nodes

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

// serverReply is the start of a P_CONTROL_HARD_RESET_SERVER_V2.
var serverReply = []byte{opHardResetServerV2 << 3, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0}

func clientReset(packet []byte) bool {
	return len(packet) == 14 && packet[0] == opHardResetClientV2<<3
}

// udpServer answers client resets with reply, or stays silent when reply is nil.
func udpServer(t *testing.T, reply []byte) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buffer := make([]byte, 1500)
		for {
			n, from, err := conn.ReadFrom(buffer)
			if err != nil {
				return
			}
			if reply != nil && clientReset(buffer[:n]) {
				_, _ = conn.WriteTo(reply, from)
			}
		}
	}()
	return strconv.Itoa(conn.LocalAddr().(*net.UDPAddr).Port)
}

func checkWithin(host, port, protocol string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return Handshake(ctx, host, port, protocol)
}

func TestHandshakeUDP(t *testing.T) {
	if err := checkWithin("127.0.0.1", udpServer(t, serverReply), "udp", 2*time.Second); err != nil {
		t.Fatalf("a server answering the reset failed the check: %v", err)
	}
	if err := checkWithin("127.0.0.1", udpServer(t, nil), "udp", 300*time.Millisecond); err == nil {
		t.Fatal("a silent server passed the check")
	}
	if err := checkWithin("127.0.0.1", udpServer(t, []byte{0x20, 0, 0}), "udp", 2*time.Second); err == nil {
		t.Fatal("a reply that is not a server reset passed the check")
	}
}

func TestHandshakeTCP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var length [2]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			return
		}
		packet := make([]byte, binary.BigEndian.Uint16(length[:]))
		if _, err := io.ReadFull(conn, packet); err != nil || !clientReset(packet) {
			return
		}
		framed := binary.BigEndian.AppendUint16(nil, uint16(len(serverReply)))
		_, _ = conn.Write(append(framed, serverReply...))
	}()
	port := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	if err := checkWithin("127.0.0.1", port, "tcp", 2*time.Second); err != nil {
		t.Fatalf("a TCP server answering the reset failed the check: %v", err)
	}
}
