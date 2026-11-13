package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/valon-technologies/gestalt/server/core"
	coretesting "github.com/valon-technologies/gestalt/server/core/testing"
	"github.com/valon-technologies/gestalt/server/internal/testutil/metrictest"
	"github.com/valon-technologies/gestalt/server/services/identity/principal"
	"github.com/valon-technologies/gestalt/server/services/invocation"
	"github.com/valon-technologies/gestalt/server/services/observability/metricutil"
)

type failingTokenResolver struct {
	err error
}

func (r *failingTokenResolver) ResolveToken(ctx context.Context, _ *principal.Principal, _, _, _ string) (context.Context, string, error) {
	return ctx, "", r.err
}

// searchWithMetrics runs gestalt_search with a meter provider on the request
// context, so the test can read what the search recorded.
func searchWithMetrics(t *testing.T, cfg Config, args map[string]any) (SearchResult, *metrictest.ManualMeterProvider) {
	t.Helper()
	metrics := metrictest.NewManualMeterProvider(t)
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": SearchToolName, "arguments": args},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := metricutil.WithMeterProvider(req.Context(), metrics.Provider)
	req = req.WithContext(principal.WithPrincipal(ctx, listingTestPrincipal()))
	rec := httptest.NewRecorder()
	NewStatelessHTTPHandler(cfg).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("gestalt_search status = %d: %s", rec.Code, rec.Body.String())
	}
	var envelope map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode: %v", err)
	}
	result, err := DecodeSearchToolResult(envelope)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return result, metrics
}

func TestSearchRecordsUpstreamCatalogOutcome(t *testing.T) {
	t.Parallel()

	registrationErr := errors.New("registration endpoint returned 400: invalid_redirect_uri")
	cases := []struct {
		name       string
		err        error
		outcome    string
		errorCount int64
	}{
		{
			name:    "not connected",
			err:     fmt.Errorf("%w: no external credential stored for integration %q", invocation.ErrNoCredential, "sampleApp"),
			outcome: upstreamOutcomeNotConnected,
		},
		{
			// The caller has no credential only because nobody can get one.
			name: "cannot be connected",
			err: fmt.Errorf("%w: no external credential stored for integration %q, and connecting it is failing: %w: %w",
				invocation.ErrNoCredential, "sampleApp", invocation.ErrConnectionUnavailable, registrationErr),
			outcome:    upstreamOutcomeUnavailable,
			errorCount: 1,
		},
		{
			name:       "upstream error",
			err:        errors.New("dial tcp: i/o timeout"),
			outcome:    upstreamOutcomeUnavailable,
			errorCount: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			body, metrics := searchWithMetrics(t, instanceListingConfig(t, &failingTokenResolver{err: tc.err}), map[string]any{
				"app": "sampleApp",
			})
			if len(body.Unavailable) != 1 || body.Unavailable[0].App != "sampleApp" {
				t.Fatalf("unavailable = %+v, want sampleApp reported", body.Unavailable)
			}

			rm := metrictest.CollectMetrics(t, metrics.Reader)
			attrs := map[string]string{
				"gestalt.provider":         "sampleApp",
				"gestalt.upstream.outcome": tc.outcome,
			}
			metrictest.RequireInt64Sum(t, rm, "gestaltd.upstream.catalog.resolve.count", 1, attrs)
			if tc.errorCount > 0 {
				metrictest.RequireInt64Sum(t, rm, "gestaltd.upstream.catalog.resolve.error_count", tc.errorCount, attrs)
			} else {
				metrictest.RequireNoInt64Sum(t, rm, "gestaltd.upstream.catalog.resolve.error_count", attrs)
			}
		})
	}
}

func TestSearchUpstreamOutcome(t *testing.T) {
	t.Parallel()

	noAuth := &coretesting.StubIntegration{N: "noauth", ConnMode: core.ConnectionModeNone}
	perUser := &coretesting.StubIntegration{N: "peruser", ConnMode: core.ConnectionModeSubject}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	cases := []struct {
		name string
		ctx  context.Context
		prov core.Provider
		err  error
		want string
	}{
		{"ok", context.Background(), perUser, nil, upstreamOutcomeOK},
		{"not connected", context.Background(), perUser, fmt.Errorf("%w: none stored", invocation.ErrNoCredential), upstreamOutcomeNotConnected},
		{
			"cannot be connected",
			context.Background(), perUser,
			fmt.Errorf("%w: none stored: %w: %w", invocation.ErrNoCredential, invocation.ErrConnectionUnavailable, errors.New("registration 400")),
			upstreamOutcomeUnavailable,
		},
		{"own grant rejected", context.Background(), perUser, fmt.Errorf("%w: 401", invocation.ErrReconnectRequired), upstreamOutcomeReconnectRequired},
		{"no-auth app rejected", context.Background(), noAuth, fmt.Errorf("%w: 401", invocation.ErrReconnectRequired), upstreamOutcomeUnavailable},
		{"upstream error", context.Background(), perUser, errors.New("dial tcp: i/o timeout"), upstreamOutcomeUnavailable},
		{"caller went away", canceled, perUser, context.Canceled, upstreamOutcomeCanceled},
	}
	for _, tc := range cases {
		if got := searchUpstreamOutcome(tc.ctx, tc.prov, tc.err); got != tc.want {
			t.Errorf("%s: outcome = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// Without an app filter search reads only static catalogs, so it makes no
// upstream call and records no upstream outcome.
func TestSearchWithoutAppFilterRecordsNoUpstreamOutcome(t *testing.T) {
	t.Parallel()

	_, metrics := searchWithMetrics(t, instanceListingConfig(t, &failingTokenResolver{err: errors.New("unused")}), map[string]any{
		"query": "op",
	})
	rm := metrictest.CollectMetrics(t, metrics.Reader)
	metrictest.RequireNoMetric(t, rm, "gestaltd.upstream.catalog.resolve.count")
}
