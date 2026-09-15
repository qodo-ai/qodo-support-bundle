package viewer

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestReadTimelineOrdersRecordsAcrossSources(t *testing.T) {
	t.Parallel()
	bundle := testExtractedBundle(t, map[string]string{
		"browser/network.jsonl": `{"@timestamp":"2026-09-15T07:02:00Z","duration_ms":125,"request":{"method":"GET","url":"https://example.com/auth/v1/oidc/userinfo"},"response":{"status":403}}
`,
		"kubernetes/logs/platform/main.log": `2026-09-15T07:01:00Z {"severity":"ERROR","message":"OIDC exchange failed"}
untimestamped diagnostic
`,
		"kubernetes/events.jsonl": `{"@timestamp":"2026-09-15T07:03:00Z","source":{"type":"kubernetes_event"},"type":"Warning","reason":"BackOff","kind":"Pod","name":"platform","message":"Restarting"}
`,
	})

	response, err := readTimeline(context.Background(), bundle, "", "all", 100)
	if err != nil {
		t.Fatal(err)
	}

	if len(response.Records) != 3 {
		t.Fatalf("unexpected records: %+v", response.Records)
	}
	if response.Records[0].Lane != "Backend logs" ||
		response.Records[1].Lane != "Browser" ||
		response.Records[2].Lane != "Kubernetes events" {
		t.Fatalf("records are not time ordered: %+v", response.Records)
	}
	if response.Records[1].Status != 403 ||
		response.Records[1].DurationMS != 125 {
		t.Fatalf("browser metadata is missing: %+v", response.Records[1])
	}
	if response.SkippedWithoutTime != 1 ||
		response.Earliest != "2026-09-15T07:01:00Z" ||
		response.Latest != "2026-09-15T07:03:00Z" {
		t.Fatalf("unexpected timeline summary: %+v", response)
	}
}

func TestReadTimelineKeepsLatestBoundedRecords(t *testing.T) {
	t.Parallel()
	bundle := testExtractedBundle(t, map[string]string{
		"kubernetes/logs/platform/main.log": `2026-09-15T07:01:00Z first
2026-09-15T07:02:00Z second
2026-09-15T07:03:00Z third
`,
	})

	response, err := readTimeline(context.Background(), bundle, "", "all", 2)
	if err != nil {
		t.Fatal(err)
	}

	if len(response.Records) != 2 ||
		response.Records[0].Timestamp != "2026-09-15T07:02:00Z" ||
		response.Records[1].Timestamp != "2026-09-15T07:03:00Z" {
		t.Fatalf("unexpected bounded records: %+v", response.Records)
	}
	if response.TotalMatches != 3 || !response.Truncated {
		t.Fatalf("unexpected bounded summary: %+v", response)
	}
}

func TestReadTimelineReservesCapacityAcrossLanes(t *testing.T) {
	t.Parallel()
	bundle := testExtractedBundle(t, map[string]string{
		"browser/network.jsonl": `{"@timestamp":"2026-09-15T07:01:00Z","request":{"method":"GET","url":"https://example.com"},"response":{"status":200}}` + "\n",
		"kubernetes/logs/platform/main.log": `2026-09-15T07:02:00Z second
2026-09-15T07:03:00Z third
`,
	})

	response, err := readTimeline(context.Background(), bundle, "", "all", 2)
	if err != nil {
		t.Fatal(err)
	}

	if len(response.Records) != 2 ||
		response.Records[0].Lane != "Browser" ||
		response.Records[1].Lane != "Backend logs" ||
		response.Records[1].Timestamp != "2026-09-15T07:03:00Z" {
		t.Fatalf("timeline lanes were crowded out: %+v", response.Records)
	}
}

func TestReadTimelineReservesCapacityAcrossContainerGroups(t *testing.T) {
	t.Parallel()
	bundle := testExtractedBundle(t, map[string]string{
		"kubernetes/logs/qodo/platform-1/main.log": `2026-09-15T07:01:00Z first
2026-09-15T07:03:00Z third
`,
		"kubernetes/logs/zitadel/zitadel-1/main.log": "2026-09-15T07:02:00Z second\n",
	})

	response, err := readTimeline(context.Background(), bundle, "", "all", 2)
	if err != nil {
		t.Fatal(err)
	}

	groups := map[string]bool{}
	for _, record := range response.Records {
		groups[record.Group] = true
	}
	if !groups["qodo / platform-1 / main"] ||
		!groups["zitadel / zitadel-1 / main"] {
		t.Fatalf("container group was crowded out: %+v", response.Records)
	}
}

func TestTimelineCandidateStoreBoundsUniqueHostGroups(t *testing.T) {
	t.Parallel()
	const limit = 100
	store := newTimelineCandidateStore(limit)
	baseTime := time.Date(2026, 9, 15, 7, 0, 0, 0, time.UTC)
	for index := 0; index < 50_000; index++ {
		store.add(timelineCandidate{
			record: TimelineRecord{
				Lane:  "Browser",
				Group: fmt.Sprintf("host-%d.example", index),
			},
			timestamp: baseTime.Add(time.Duration(index) * time.Second),
		})
	}

	if store.trackedGroups != limit {
		t.Fatalf("unexpected tracked group count: %d", store.trackedGroups)
	}
	if len(store.groups) > limit+1 {
		t.Fatalf("timeline group storage is unbounded: %d", len(store.groups))
	}
	if store.retained > store.maxCandidates {
		t.Fatalf(
			"timeline candidate storage exceeded its bound: %d > %d",
			store.retained,
			store.maxCandidates,
		)
	}
	totalCapacity := 0
	for _, candidates := range store.groups {
		totalCapacity += cap(*candidates)
	}
	if totalCapacity > store.maxCandidates {
		t.Fatalf(
			"timeline candidate capacity exceeded its bound: %d > %d",
			totalCapacity,
			store.maxCandidates,
		)
	}
	if selected := selectFairTimelineCandidates(store.groups, limit); len(selected) != limit {
		t.Fatalf("unexpected selected candidate count: %d", len(selected))
	}
}

func TestReadTimelineAppliesAuthenticationFilter(t *testing.T) {
	t.Parallel()
	bundle := testExtractedBundle(t, map[string]string{
		"browser/network.jsonl": `{"@timestamp":"2026-09-15T07:01:00Z","request":{"method":"GET","url":"https://example.com/health"},"response":{"status":200}}
{"@timestamp":"2026-09-15T07:02:00Z","request":{"method":"GET","url":"https://example.com/auth/v1/oidc/userinfo"},"response":{"status":200}}
{"@timestamp":"2026-09-15T07:03:00Z","request":{"method":"GET","url":"https://example.com/platform/v2/features?feature_ids=gitlab_token_auth"},"response":{"status":200}}
`,
		"kubernetes/logs/platform/main.log": `2026-09-15T07:04:00Z {"record":{"message":"Checking if multi-tenant portal is running","file":{"path":"/app/common/auth/tenant_redirect.py"},"extra":{"entry_point":"GET /platform/v2/users"}}}
`,
	})

	response, err := readTimeline(context.Background(), bundle, "", "auth", 100)
	if err != nil {
		t.Fatal(err)
	}

	if len(response.Records) != 1 ||
		response.Records[0].Summary !=
			"GET 200 https://example.com/auth/v1/oidc/userinfo" {
		t.Fatalf("unexpected auth timeline: %+v", response.Records)
	}
}

func TestReadTimelineStopsWhenContextIsCanceled(t *testing.T) {
	t.Parallel()
	bundle := testExtractedBundle(t, map[string]string{
		"kubernetes/logs/platform/main.log": "2026-09-15T07:01:00Z first\n",
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := readTimeline(ctx, bundle, "", "all", 100)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
}

func TestReadRecordAtLineReturnsFullDetails(t *testing.T) {
	t.Parallel()
	bundle := testExtractedBundle(t, map[string]string{
		"kubernetes/logs/platform/main.log": "first\n2026-09-15T07:02:00Z second\n",
	})

	record, err := readRecordAtLine(
		bundle,
		"kubernetes/logs/platform/main.log",
		2,
	)
	if err != nil {
		t.Fatal(err)
	}

	if record.Line != 2 ||
		record.Timestamp != "2026-09-15T07:02:00Z" ||
		record.Details != "2026-09-15T07:02:00Z second" {
		t.Fatalf("unexpected record: %+v", record)
	}
}

func TestContainsASCIIWordIgnoresConfigurationIdentifiers(t *testing.T) {
	t.Parallel()
	if !containsASCIIWord("token request received", "token") {
		t.Fatal("standalone token was not matched")
	}
	if containsASCIIWord("feature_ids=gitlab_token_auth", "token") {
		t.Fatal("token embedded in an identifier was matched")
	}
}
