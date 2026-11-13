package mcp

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"testing"

	"github.com/valon-technologies/gestalt/server/core"
	"github.com/valon-technologies/gestalt/server/core/catalog"
	coretesting "github.com/valon-technologies/gestalt/server/core/testing"
	"github.com/valon-technologies/gestalt/server/internal/testutil"
)

// A catalog shaped like the one the bug shows up in: an app whose name
// matches common queries, carrying the operation people actually want buried
// behind a pile of alphabetically-earlier ones, plus a second app so
// cross-app queries mean something.
func searchWorld(t *testing.T) Config {
	t.Helper()

	atlassianOps := []catalog.CatalogOperation{
		{ID: "createJiraIssue", Title: "Create Jira Issue", Description: "Create a new issue in a Jira project"},
		{ID: "getJiraIssue", Title: "Get Jira Issue", Description: "Fetch a Jira issue by key"},
	}
	// Noise that sorts before "createJiraIssue" and matches the app name only.
	// Without relevance ranking these fill a limit-20 page and truncate away
	// the operation the query described.
	for i := 0; i < 25; i++ {
		atlassianOps = append(atlassianOps, catalog.CatalogOperation{
			ID:    fmt.Sprintf("aaaBoard%02d", i),
			Title: fmt.Sprintf("Board %02d", i),
			// Mentions issues, so these genuinely compete for the issue
			// queries instead of scoring zero. Without that the truncation
			// test has nothing to be truncated by and tokenization alone
			// would pass it.
			Description: "An agile board tracking jira issues for a team",
		})
	}

	atlassian := &coretesting.StubIntegration{
		N: "atlassian", DN: "Atlassian", ConnMode: core.ConnectionModeNone,
		CatalogVal: &catalog.Catalog{Name: "atlassian", Operations: atlassianOps},
		ExecuteFn: func(_ context.Context, op string, _ map[string]any, _ string) (*core.OperationResult, error) {
			return &core.OperationResult{Status: http.StatusOK, Body: []byte(`{}`)}, nil
		},
	}
	slack := &coretesting.StubIntegration{
		N: "slack", DN: "Slack", ConnMode: core.ConnectionModeNone,
		CatalogVal: &catalog.Catalog{Name: "slack", Operations: []catalog.CatalogOperation{
			{ID: "slack_send_message", Title: "Send Message", Description: "Send a message to a Slack channel or user"},
			{ID: "slack_list_channels", Title: "List Channels", Description: "List channels in a workspace"},
		}},
		ExecuteFn: func(_ context.Context, op string, _ map[string]any, _ string) (*core.OperationResult, error) {
			return &core.OperationResult{Status: http.StatusOK, Body: []byte(`{}`)}, nil
		},
	}

	return Config{
		Invoker:          &listingInvoker{stub: atlassian},
		Providers:        testutil.NewProviderRegistry(t, atlassian, slack),
		AllowedProviders: []string{"atlassian", "slack"},
		IncludeREST:      map[string]bool{"atlassian": true, "slack": true},
	}
}

func searchOps(t *testing.T, query string, args ...map[string]any) []string {
	t.Helper()
	a := map[string]any{"query": query}
	if len(args) > 0 {
		for k, v := range args[0] {
			a[k] = v
		}
	}
	body := callSearch(t, searchWorld(t), listingTestPrincipal(), a)
	ops := make([]string, 0, len(body.Results))
	for _, r := range body.Results {
		ops = append(ops, r.Operation)
	}
	return ops
}

func contains(ops []string, want string) bool {
	for _, o := range ops {
		if o == want {
			return true
		}
	}
	return false
}

// The repro queries, run through the real search path rather than the scorer
// in isolation. Every one of these returned zero results before.
func TestSearchE2EReportedQueriesFindTheOperation(t *testing.T) {
	t.Parallel()

	for _, query := range []string{
		"jira issue",
		"find jira issue",
		"find a jira issue by key",
		"create issue",
		"issue create",
	} {
		ops := searchOps(t, query)
		if len(ops) == 0 {
			t.Errorf("query %q returned nothing", query)
			continue
		}
		if !contains(ops, "createJiraIssue") && !contains(ops, "getJiraIssue") {
			t.Errorf("query %q found %v, expected a jira issue operation", query, ops)
		}
	}

	ops := searchOps(t, "send message to slack channel")
	if !contains(ops, "slack_send_message") {
		t.Errorf(`"send message to slack channel" found %v, want slack_send_message`, ops)
	}
}

// The case the scorer alone cannot prove. 25 operations sort
// before createJiraIssue and match the app name, so alphabetical ordering
// filled the page with boards and truncated the issue operations away.
func TestSearchE2ERelevantOperationSurvivesTruncation(t *testing.T) {
	t.Parallel()

	// The query must NOT appear as a literal substring of any field, or the old
	// matcher finds it directly and the test proves nothing. "create jira issue"
	// is exactly the title, so it passes even unfixed; "find jira issue" does not
	// appear anywhere.
	ops := searchOps(t, "find jira issue", map[string]any{"limit": 5})
	if len(ops) == 0 {
		t.Fatal("no results")
	}
	// The 25 boards also match "jira" and "issue" in their descriptions and
	// sort first alphabetically, so relevance is the only thing that can put
	// the issue operations on a five-result page.
	if ops[0] != "createJiraIssue" && ops[0] != "getJiraIssue" {
		t.Errorf("first result = %q, want a jira issue operation; got page %v", ops[0], ops)
	}
	if !contains(ops, "createJiraIssue") || !contains(ops, "getJiraIssue") {
		t.Errorf("both issue operations should survive the limit; got %v", ops)
	}
}

// Word order must not change the result set.
func TestSearchE2EOrderIndependent(t *testing.T) {
	t.Parallel()

	forward := searchOps(t, "create issue")
	reverse := searchOps(t, "issue create")
	if len(forward) == 0 || len(reverse) == 0 {
		t.Fatalf("both orderings must return hits: forward=%v reverse=%v", forward, reverse)
	}
	if fmt.Sprint(forward) != fmt.Sprint(reverse) {
		t.Errorf("word order changed results:\n forward=%v\n reverse=%v", forward, reverse)
	}
}

// A bare app-name query still returns that app's operations. This is the case
// this change does NOT fix: every operation in the app matches the one
// term equally, and only in the app tier, so there is nothing to rank by and
// the page is still alphabetical and still truncated. It is a pagination
// problem, asserted here so the limitation is checked rather than described --
// if ranking ever starts reordering this page, that is a behaviour change and
// this test should be the thing that says so.
func TestSearchE2EBareAppQueryRemainsAlphabetical(t *testing.T) {
	t.Parallel()

	ops := searchOps(t, "atlassian", map[string]any{"limit": 5})
	if len(ops) == 0 {
		t.Fatal("an app-name query should return that app's operations")
	}
	if !sort.StringsAreSorted(ops) {
		t.Errorf("a bare app query has nothing to rank by, so the page should be alphabetical; got %v", ops)
	}
	if contains(ops, "createJiraIssue") {
		t.Errorf("createJiraIssue sorts after 25 aaaBoard* operations, so it cannot be on a 5-result alphabetical page; got %v", ops)
	}
}

// A query naming an app AND a thing must rank the thing first, rather than
// letting the app match flood the page.
func TestSearchE2EAppPlusTermRanksTheTerm(t *testing.T) {
	t.Parallel()

	ops := searchOps(t, "atlassian issue", map[string]any{"limit": 3})
	if len(ops) == 0 {
		t.Fatal("no results")
	}
	if !contains(ops[:min(2, len(ops))], "createJiraIssue") && !contains(ops[:min(2, len(ops))], "getJiraIssue") {
		t.Errorf("top results = %v, expected a jira issue operation in the top two", ops)
	}
}

// Cross-app: a query about one app must not be dominated by another.
func TestSearchE2ENoCrossAppFlood(t *testing.T) {
	t.Parallel()

	ops := searchOps(t, "slack message", map[string]any{"limit": 3})
	if len(ops) == 0 {
		t.Fatal("no results")
	}
	if ops[0] != "slack_send_message" {
		t.Errorf("first result = %q, want slack_send_message; page %v", ops[0], ops)
	}
}
