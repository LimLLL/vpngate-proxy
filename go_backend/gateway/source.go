package gateway

import "github.com/LimLLL/vpngate-proxy/go_backend/nodes"

// Candidate and Source are shared by raw mirror validation and native clients.
type Candidate = nodes.Candidate
type Source = nodes.Source

var (
	FileSource            = nodes.FileSource
	RemoteSource          = nodes.RemoteSource
	NewSnapshotFileSource = nodes.NewSnapshotFileSource
	PrepareProfile        = nodes.PrepareProfile
	SafeProfile           = nodes.SafeProfile
)

func ParsePublicID(value string) string { return nodes.NodeID(value) }
