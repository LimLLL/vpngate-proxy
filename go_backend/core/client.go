// Package core exposes one native OpenVPN 3 connection without driver-specific APIs.
package core

/*
#cgo CFLAGS: -I${SRCDIR}/..
#cgo LDFLAGS: -lvpngate_bridge
#include "bridge.h"
#include <stdlib.h>

// cgo's export header declares C string inputs as char*, not const char*.
// The native callbacks remain const char* and these inputs are only read.
extern void vpngateGoEvent(uint32_t id, char *name, char *info,
                           int error, int fatal);
extern void vpngateGoLog(uint32_t id, char *text);
*/
import "C"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"unsafe"
)

type Event struct {
	Name  string
	Info  string
	Error bool
	Fatal bool
}

type ConnectionInfo struct {
	Defined     bool   `json:"defined"`
	User        string `json:"user"`
	ServerHost  string `json:"serverHost"`
	ServerPort  string `json:"serverPort"`
	ServerProto string `json:"serverProto"`
	ServerIP    string `json:"serverIp"`
	VpnIP4      string `json:"vpnIp4"`
	VpnIP6      string `json:"vpnIp6"`
	MTU         string `json:"vpnMtu"`
	Gateway4    string `json:"gw4"`
	Gateway6    string `json:"gw6"`
	TUNName     string `json:"tunName"`
}

type Client struct {
	handle *C.VPNHandle
	id     C.uint32_t

	// OnEvent receives events after the controller has read them. Set it before
	// calling Connect; it must not block the caller's goroutine.
	OnEvent func(Event)

	events chan Event
	Logs   chan string
	done   chan struct{}

	mu         sync.Mutex
	started    bool
	closed     bool
	connectErr error
}

var registry sync.Map
var nextID atomic.Uint32

func Platform() string {
	return C.GoString(C.vpn_platform())
}

//export vpngateGoEvent
func vpngateGoEvent(id C.uint32_t, name, info *C.char, nativeError, fatal C.int) {
	if owner, ok := registry.Load(uint32(id)); ok {
		client := owner.(*Client)
		// Events are ordered and never dropped. Input must be drained by the
		// connection's controller; in particular, CONNECTED cannot be lost.
		client.events <- Event{Name: C.GoString(name), Info: C.GoString(info),
			Error: nativeError != 0, Fatal: fatal != 0}
	}
}

//export vpngateGoLog
func vpngateGoLog(id C.uint32_t, text *C.char) {
	if owner, ok := registry.Load(uint32(id)); ok {
		client := owner.(*Client)
		select {
		case client.Logs <- C.GoString(text):
		default:
			// Excessive diagnostics must not stall the native data plane.
		}
	}
}

func statusError(status C.VPNStatus) error {
	defer C.vpn_status_free(&status)
	if status.error != 0 {
		return fmt.Errorf("OpenVPN 3 %s: %s", C.GoString(status.code), C.GoString(status.message))
	}
	return nil
}

// NewClient evaluates the profile and provides credentials to one native session.
func NewClient(profile, username, password string, connectTimeout int) (*Client, error) {
	id := C.uint32_t(nextID.Add(1))
	handle := C.vpn_client_new(id, C.VPNEventCallback(C.vpngateGoEvent), C.VPNLogCallback(C.vpngateGoLog))
	if handle == nil {
		return nil, errors.New("failed to initialize the OpenVPN 3 Core client")
	}
	c := &Client{handle: handle, id: id, events: make(chan Event, 64),
		Logs: make(chan string, 256), done: make(chan struct{})}
	registry.Store(uint32(id), c)

	profileC, userC, passwordC := C.CString(profile), C.CString(username), C.CString(password)
	defer C.free(unsafe.Pointer(profileC))
	defer C.free(unsafe.Pointer(userC))
	defer C.free(unsafe.Pointer(passwordC))
	if err := statusError(C.vpn_client_configure(handle, profileC, userC, passwordC, C.int(connectTimeout))); err != nil {
		c.closeUnstarted()
		return nil, err
	}
	return c, nil
}

// Connect starts the native session and waits for CONNECTED. The session stays
// active after return; Close must be called to release its native resources.
func (c *Client) Connect(ctx context.Context) (ConnectionInfo, error) {
	c.mu.Lock()
	if c.started || c.closed {
		c.mu.Unlock()
		return ConnectionInfo{}, errors.New("client is already started or closed")
	}
	c.started = true
	c.mu.Unlock()

	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		err := statusError(C.vpn_client_connect(c.handle))
		c.mu.Lock()
		c.connectErr = err
		c.mu.Unlock()
		close(c.done)
	}()

	for {
		select {
		case event := <-c.events:
			if c.OnEvent != nil {
				c.OnEvent(event)
			}
			if event.Fatal {
				return ConnectionInfo{}, fmt.Errorf("OpenVPN 3 %s: %s", event.Name, event.Info)
			}
			if event.Name == "CONNECTED" {
				return c.ConnectionInfo()
			}
		case <-c.done:
			c.mu.Lock()
			err := c.connectErr
			c.mu.Unlock()
			if err == nil {
				return ConnectionInfo{}, errors.New("native session ended before CONNECTED")
			}
			return ConnectionInfo{}, err
		case <-ctx.Done():
			return ConnectionInfo{}, ctx.Err()
		}
	}
}

// ConnectionInfo reads state after CONNECTED from the controller goroutine,
// never reentering Core from its native event callback.
func (c *Client) ConnectionInfo() (ConnectionInfo, error) {
	var info ConnectionInfo
	raw := C.vpn_client_connection_info_json(c.handle)
	if raw == nil {
		return info, errors.New("connection info is unavailable for a null handle")
	}
	defer C.vpn_string_free(raw)
	if err := json.Unmarshal([]byte(C.GoString(raw)), &info); err != nil {
		return info, fmt.Errorf("decode native connection info: %w", err)
	}
	if !info.Defined {
		return info, errors.New("native session has no connection information")
	}
	return info, nil
}

// Close stops the native session, waits for connect() to return, then frees it.
func (c *Client) Close(ctx context.Context) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	started := c.started
	c.mu.Unlock()
	if !started {
		c.closeUnstarted()
		return nil
	}
	select {
	case <-c.done:
		c.closeUnstarted()
		return nil
	default:
	}
	if err := statusError(C.vpn_client_stop(c.handle)); err != nil {
		return err
	}
	select {
	case <-c.done:
		// The connection's error is reported by Connect. Done means the
		// handle can be freed even when that connection attempt failed.
		c.closeUnstarted()
		return nil
	case <-ctx.Done():
		return fmt.Errorf("wait for native stop: %w", ctx.Err())
	}
}

func (c *Client) closeUnstarted() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	registry.Delete(uint32(c.id))
	C.vpn_client_delete(c.handle)
	c.handle = nil
}
