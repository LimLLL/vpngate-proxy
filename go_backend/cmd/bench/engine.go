package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/LimLLL/vpngate-proxy/go_backend/core"
	"github.com/LimLLL/vpngate-proxy/go_backend/nodes"
)

// engine opens one tunnel on a fixed TUN device; connect time is measured
// around Connect, and ends when the engine reports the tunnel ready.
type engine interface {
	Name() string
	Version() string
	Connect(ctx context.Context, profile, device string) (tunnel, error)
}

type tunnel interface {
	Close(ctx context.Context) error
	// PID is the engine process for out-of-process tunnels, 0 otherwise.
	PID() int
}

// coreEngine embeds the official OpenVPN 3 Core in this process, as the
// gateway does.
type coreEngine struct{ timeout time.Duration }

func (coreEngine) Name() string    { return "core" }
func (coreEngine) Version() string { return core.Platform() }

func (e coreEngine) Connect(ctx context.Context, profile, device string) (tunnel, error) {
	client, err := core.NewClient(nodes.PrepareProfile(profile, device), "vpn", "vpn", max(1, int(e.timeout/time.Second)))
	if err != nil {
		return nil, err
	}
	info, err := client.Connect(ctx)
	if err == nil && info.TUNName != device {
		err = fmt.Errorf("expected %s, Core opened %q", device, info.TUNName)
	}
	if err != nil {
		closeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return nil, errors.Join(err, client.Close(closeCtx))
	}
	return coreTunnel{client}, nil
}

type coreTunnel struct{ client *core.Client }

func (t coreTunnel) Close(ctx context.Context) error { return t.client.Close(ctx) }
func (coreTunnel) PID() int                          { return 0 }

// cliEngine runs one OpenVPN 2.x process per tunnel. Data channel offload is
// disabled so both engines move packets in user space.
type cliEngine struct {
	timeout time.Duration
	workDir string
}

func (cliEngine) Name() string { return "cli" }

func (cliEngine) Version() string {
	// openvpn --version exits non-zero by design; only its first line matters.
	output, _ := exec.Command("openvpn", "--version").CombinedOutput()
	line, _, _ := strings.Cut(string(output), "\n")
	return strings.TrimSpace(line)
}

func (e cliEngine) Connect(ctx context.Context, profile, device string) (tunnel, error) {
	dir, err := os.MkdirTemp(e.workDir, device+"-")
	if err != nil {
		return nil, err
	}
	started := false
	defer func() {
		if !started {
			_ = os.RemoveAll(dir)
		}
	}()
	config, credentials := filepath.Join(dir, "profile.ovpn"), filepath.Join(dir, "auth.txt")
	if err := os.WriteFile(config, []byte(nodes.PrepareProfile(profile, device)), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(credentials, []byte("vpn\nvpn\n"), 0o600); err != nil {
		return nil, err
	}
	command := exec.Command("openvpn", "--config", config, "--auth-user-pass", credentials,
		"--connect-timeout", strconv.Itoa(max(1, int(e.timeout/time.Second))),
		"--route-delay", "0", "--disable-dco", "--verb", "3")
	output, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	command.Stderr = command.Stdout
	if err := command.Start(); err != nil {
		return nil, err
	}
	// From here the tunnel owns dir and removes it on Close.
	started = true
	t := &cliTunnel{command: command, dir: dir, exited: make(chan struct{})}
	ready := make(chan struct{})
	go t.read(output, ready)
	select {
	case <-ready:
		return t, nil
	case <-t.exited:
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("openvpn exited before connecting: %v: %s", t.waitErr, t.tail())
	case <-ctx.Done():
		closeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return nil, errors.Join(ctx.Err(), t.Close(closeCtx))
	}
}

type cliTunnel struct {
	command *exec.Cmd
	dir     string
	exited  chan struct{}
	waitErr error

	mu    sync.Mutex
	lines []string
}

// read drains the process output, which must never block, and signals the
// line OpenVPN 2.x prints once the TUN is configured.
func (t *cliTunnel) read(output io.Reader, ready chan struct{}) {
	var once sync.Once
	scanner := bufio.NewScanner(output)
	for scanner.Scan() {
		line := scanner.Text()
		t.mu.Lock()
		t.lines = append(t.lines, line)
		if len(t.lines) > 20 {
			t.lines = t.lines[1:]
		}
		t.mu.Unlock()
		if strings.Contains(line, "Initialization Sequence Completed") {
			once.Do(func() { close(ready) })
		}
	}
	t.waitErr = t.command.Wait()
	close(t.exited)
}

func (t *cliTunnel) tail() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return strings.Join(t.lines, " | ")
}

func (t *cliTunnel) PID() int { return t.command.Process.Pid }

func (t *cliTunnel) Close(ctx context.Context) error {
	defer os.RemoveAll(t.dir)
	if err := t.command.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	select {
	case <-t.exited:
		return nil
	case <-ctx.Done():
		_ = t.command.Process.Kill()
		<-t.exited
		return fmt.Errorf("openvpn needed SIGKILL: %w", ctx.Err())
	}
}
