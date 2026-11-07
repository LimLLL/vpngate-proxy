package gateway

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync/atomic"
	"time"

	"github.com/LimLLL/vpngate-proxy/go_backend/core"
)

type CandidateSource interface {
	Next(context.Context) (Candidate, error)
}

type NativeConfig struct {
	Source  CandidateSource
	Timeout time.Duration
	Backoff time.Duration
	TUNBase uint64
}

// NativeFactory returns one connected native tunnel per factory invocation.
// Caller controls its slot exclusivity; children do not share transport state.
type NativeFactory struct {
	config NativeConfig
	next   atomic.Uint64
}

func NewNativeFactory(config NativeConfig) (*NativeFactory, error) {
	if config.Source == nil {
		return nil, errors.New("native profile source is required")
	}
	if config.Timeout <= 0 {
		return nil, errors.New("native connect timeout must be positive")
	}
	return &NativeFactory{config: config}, nil
}

// Connect creates an isolated endpoint for probe or explicit node requests.
func (f *NativeFactory) Connect(ctx context.Context, candidate Candidate) (Endpoint, error) {
	return f.connect(ctx, candidate)
}

func (f *NativeFactory) Factory() EndpointFactory {
	return func(ctx context.Context) (Endpoint, error) {
		connectCtx, cancel := context.WithTimeout(ctx, f.config.Timeout)
		defer cancel()
		var errs []error
		for attempt := 0; attempt < 3; attempt++ {
			candidate, err := f.config.Source.Next(connectCtx)
			if err != nil {
				return nil, err
			}
			endpoint, err := f.connect(connectCtx, candidate)
			if err == nil {
				log.Printf("native connected %s on %s", endpoint.Device(), candidate.ID)
				return endpoint, nil
			}
			diagnostic := fmt.Errorf("candidate %s attempt %d: %w", candidate.ID, attempt+1, err)
			log.Printf("%v", diagnostic)
			errs = append(errs, diagnostic)
			if connectCtx.Err() != nil {
				break
			}
			if f.config.Backoff > 0 {
				select {
				case <-connectCtx.Done():
					continue
				case <-time.After(f.config.Backoff):
				}
			}
		}
		return nil, errors.Join(errs...)
	}
}

func (f *NativeFactory) connect(ctx context.Context, candidate Candidate) (Endpoint, error) {
	slot := f.next.Add(1) - 1
	device := fmt.Sprintf("tun%d", f.config.TUNBase+slot)
	profile := PrepareProfile(candidate.Profile, device)
	seconds := int(f.config.Timeout / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	client, err := core.NewClient(profile, "vpn", "vpn", seconds)
	if err != nil {
		return nil, err
	}
	client.OnEvent = func(event core.Event) {
		if event.Fatal || event.Error {
			log.Printf("%s %s: %s", device, event.Name, event.Info)
		}
	}
	info, err := client.Connect(ctx)
	if err != nil {
		closeClient(client)
		return nil, err
	}
	if !info.Defined || info.TUNName != device {
		closeClient(client)
		return nil, fmt.Errorf("native expected %s, got %q", device, info.TUNName)
	}
	cleanup, err := RouteInstall(device, slot)
	if err != nil {
		closeClient(client)
		return nil, err
	}
	return &nativeEndpoint{client: client, cleanup: cleanup, nodeID: candidate.ID}, nil
}

func closeClient(client *core.Client) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.Close(ctx); err != nil {
		log.Printf("close native client: %v", err)
	}
}
