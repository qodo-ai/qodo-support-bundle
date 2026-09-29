package collection

import "time"

// CoverageState describes how fully a requested source was collected.
type CoverageState string

const (
	CoverageComplete     CoverageState = "complete"
	CoveragePartial      CoverageState = "partial"
	CoverageUnavailable  CoverageState = "unavailable"
	CoverageNotRequested CoverageState = "not_requested"
)

// String returns the coverage state's wire representation.
func (state CoverageState) String() string {
	return string(state)
}

// Valid reports whether state is part of the coverage protocol.
func (state CoverageState) Valid() bool {
	switch state {
	case CoverageComplete, CoveragePartial, CoverageUnavailable, CoverageNotRequested:
		return true
	default:
		return false
	}
}

// Coverage records the requested and retained range for a source.
type Coverage struct {
	State          CoverageState `json:"state"`
	RequestedStart *time.Time    `json:"requested_start,omitempty"`
	RequestedEnd   *time.Time    `json:"requested_end,omitempty"`
	ActualStart    *time.Time    `json:"actual_start,omitempty"`
	ActualEnd      *time.Time    `json:"actual_end,omitempty"`
	RetainedBytes  int64         `json:"retained_bytes"`
	RecordCount    int64         `json:"record_count"`
	Truncated      bool          `json:"truncated"`
	Reason         string        `json:"reason,omitempty"`
}

// InitializeCoverage returns independent coverage entries for every supported
// source. Requested sources start unavailable because no collection result
// exists yet; collectors replace that state with their final result. Invalid
// requested sources are ignored.
func InitializeCoverage(requested []Source) map[Source]Coverage {
	coverage := make(map[Source]Coverage, len(SupportedSources()))
	for _, source := range SupportedSources() {
		coverage[source] = Coverage{State: CoverageNotRequested}
	}
	for _, source := range requested {
		if source.Valid() {
			coverage[source] = Coverage{State: CoverageUnavailable}
		}
	}
	return coverage
}
