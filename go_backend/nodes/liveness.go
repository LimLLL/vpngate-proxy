package nodes

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// OpenVPN control opcodes, sent in the top five bits of a packet's first byte.
const (
	opHardResetClientV2 = 7
	opHardResetServerV2 = 8
)

// Handshake reports whether an OpenVPN server answers at host:port. It sends
// the client's opening P_CONTROL_HARD_RESET_CLIENT_V2 and waits for the
// server's P_CONTROL_HARD_RESET_SERVER_V2. Nothing is authenticated and no
// session is set up, so a check costs a volunteer server two small packets.
// Servers using tls-auth or tls-crypt ignore the packet; VPNGate's SoftEther
// servers use neither. Without a deadline on ctx it gives up after 5 seconds.
func Handshake(ctx context.Context, host, port, protocol string) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(5 * time.Second)
	}
	network := "udp"
	if protocol == "tcp" {
		network = "tcp"
	}
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(host, port))
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	// Opcode and key ID 0, a random session ID, no acknowledgements and
	// packet ID 0.
	packet := make([]byte, 14)
	packet[0] = opHardResetClientV2 << 3
	if _, err := rand.Read(packet[1:9]); err != nil {
		return err
	}
	if network == "tcp" {
		return handshakeTCP(conn, packet)
	}
	return handshakeUDP(conn, packet, deadline)
}

// handshakeTCP frames the packet with OpenVPN's two-byte length prefix.
func handshakeTCP(conn net.Conn, packet []byte) error {
	framed := binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(packet)), uint16(len(packet)))
	if _, err := conn.Write(append(framed, packet...)); err != nil {
		return err
	}
	var reply [3]byte // length prefix and opcode
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return err
	}
	return serverReset(reply[2:])
}

// handshakeUDP sends the packet a second time when a second passes without
// an answer, in case either datagram was lost.
func handshakeUDP(conn net.Conn, packet []byte, deadline time.Time) error {
	reply := make([]byte, 1500)
	for attempt := 1; ; attempt++ {
		if _, err := conn.Write(packet); err != nil {
			return err
		}
		wait := deadline
		if retry := time.Now().Add(time.Second); attempt == 1 && retry.Before(deadline) {
			wait = retry
		}
		if err := conn.SetReadDeadline(wait); err != nil {
			return err
		}
		n, err := conn.Read(reply)
		if err == nil {
			return serverReset(reply[:n])
		}
		var netErr net.Error
		if attempt == 2 || !wait.Before(deadline) || !errors.As(err, &netErr) || !netErr.Timeout() {
			return err
		}
	}
}

func serverReset(reply []byte) error {
	if len(reply) == 0 || reply[0]>>3 != opHardResetServerV2 {
		return fmt.Errorf("not an OpenVPN server reset: % x", reply)
	}
	return nil
}

// Checker reports whether a node answers; a nil error means it does.
type Checker func(context.Context, Candidate) error

// Probe checks nodes with up to workers checks at a time and records the
// results, all nodes or with onlyNew just those never checked. Results that
// arrive after ctx ends are discarded. It returns how many nodes answered and
// how many were checked.
func (r *Registry) Probe(ctx context.Context, check Checker, onlyNew bool, workers int) (alive, total int) {
	r.mu.Lock()
	var targets []Candidate
	for _, node := range r.nodes {
		if !onlyNew || node.ProbedAt.IsZero() {
			targets = append(targets, node.Candidate)
		}
	}
	r.mu.Unlock()

	jobs := make(chan Candidate)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < max(1, workers); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				err := check(ctx, target)
				if ctx.Err() != nil {
					continue
				}
				r.ReportProbe(target.ID, err == nil, time.Now())
				mu.Lock()
				total++
				if err == nil {
					alive++
				}
				mu.Unlock()
			}
		}()
	}
	for _, target := range targets {
		select {
		case jobs <- target:
		case <-ctx.Done():
		}
	}
	close(jobs)
	wg.Wait()
	return alive, total
}
