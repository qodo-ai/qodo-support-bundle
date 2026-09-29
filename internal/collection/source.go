// Package collection defines collection metadata and pure report assembly.
// Source collectors remain independent; this package consumes their results.
package collection

// Source identifies a supported data source in collection metadata.
type Source string

const (
	SourceKubernetes Source = "kubernetes"
	SourceZitadel    Source = "zitadel"
	SourceWorkload   Source = "workload"
	SourcePrometheus Source = "prometheus"
	SourcePhoenix    Source = "phoenix"
)

// String returns the source's wire representation.
func (source Source) String() string {
	return string(source)
}

// Valid reports whether source is supported.
func (source Source) Valid() bool {
	switch source {
	case SourceKubernetes, SourceZitadel, SourceWorkload, SourcePrometheus, SourcePhoenix:
		return true
	default:
		return false
	}
}

// SupportedSources returns all supported sources in protocol order.
// Each call returns a new slice that callers may safely modify.
func SupportedSources() []Source {
	return []Source{
		SourceKubernetes,
		SourceZitadel,
		SourceWorkload,
		SourcePrometheus,
		SourcePhoenix,
	}
}
