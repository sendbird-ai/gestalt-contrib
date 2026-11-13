package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/valon-technologies/gestalt/server/core"
	coretesting "github.com/valon-technologies/gestalt/server/core/testing"
	"github.com/valon-technologies/gestalt/server/internal/bootstrap"
	"github.com/valon-technologies/gestalt/server/internal/config"
	"github.com/valon-technologies/gestalt/server/internal/server"
	"github.com/valon-technologies/gestalt/server/internal/testutil"
	providermanifestv1 "github.com/valon-technologies/gestalt/server/sdk/providermanifest/v1"
	"github.com/valon-technologies/gestalt/server/services/apps/mcpoauth"
)

const registrationTestProvider = "dcr-app"

type resettableHandler struct {
	testOAuthHandler
	key      string
	keyErr   error
	deleted  bool
	resetErr error
	resets   int
	gotKey   string
}

func (h *resettableHandler) ResetRegistration(_ context.Context, expectedKey string) (bool, error) {
	h.resets++
	h.gotKey = expectedKey
	return h.deleted, h.resetErr
}

func (h *resettableHandler) RegistrationKey(context.Context) (string, error) {
	if h.keyErr != nil {
		return "", h.keyErr
	}
	if h.key == "" {
		return "https://as.example.test\x00cb", nil
	}
	return h.key, nil
}

// staticClientHandler models a connection with a configured client_id.
type staticClientHandler struct{ resettableHandler }

func (h *staticClientHandler) RegistrationKey(context.Context) (string, error) { return "", nil }

func newRegistrationTestServer(t *testing.T, handler bootstrap.OAuthHandler) *httptest.Server {
	t.Helper()
	return newRegistrationTestServerWith(t, handler, nil)
}

// newRegistrationTestServerWith also registers extra OAuth connections, keyed
// "app/connection", alongside the main one.
func newRegistrationTestServerWith(t *testing.T, handler bootstrap.OAuthHandler, extra map[string]bootstrap.OAuthHandler) *httptest.Server {
	t.Helper()
	auth := map[string]map[string]bootstrap.OAuthHandler{
		registrationTestProvider: {testDefaultConnection: handler},
	}
	for name, h := range extra {
		app, conn, _ := strings.Cut(name, "/")
		if auth[app] == nil {
			auth[app] = map[string]bootstrap.OAuthHandler{}
		}
		auth[app][conn] = h
	}
	ts := newTestServer(t, func(cfg *server.Config) {
		cfg.Providers = testutil.NewProviderRegistry(t, &stubIntegrationWithAuthURL{
			StubIntegration: coretesting.StubIntegration{N: registrationTestProvider},
			authURL:         "https://idp.example.test/authorize",
		})
		cfg.DefaultConnection = map[string]string{registrationTestProvider: testDefaultConnection}
		cfg.AppDefs = map[string]*config.ProviderEntry{
			registrationTestProvider: {
				Connections: map[string]*config.ConnectionDef{
					testDefaultConnection: {
						Auth: config.ConnectionAuthDef{
							Type:             providermanifestv1.AuthTypeOAuth2,
							AuthorizationURL: "https://idp.example.test/authorize",
							TokenURL:         "https://idp.example.test/token",
						},
					},
				},
			},
		}
		cfg.ConnectionAuth = func() map[string]map[string]bootstrap.OAuthHandler { return auth }
		cfg.Services = testutil.NewStubServices(t)
	})
	testutil.CloseOnCleanup(t, ts)
	return ts
}

func postResetJSON(t *testing.T, url, body string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Post(url, "application/json", bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("POST %s: body is not JSON: %s", url, raw)
	}
	return resp.StatusCode, decoded
}

func TestAdminResetOAuthRegistration(t *testing.T) {
	t.Parallel()

	resetURL := func(ts *httptest.Server) string {
		return ts.URL + "/admin/api/v1/apps/" + registrationTestProvider + "/connections/" + testDefaultConnection + "/oauth-registration/reset"
	}

	t.Run("deletes the stored registration", func(t *testing.T) {
		t.Parallel()
		handler := &resettableHandler{deleted: true}
		ts := newRegistrationTestServer(t, handler)

		status, body := postResetJSON(t, resetURL(ts), `{}`)

		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200: %v", status, body)
		}
		if body["deleted"] != true || handler.resets != 1 {
			t.Fatalf("deleted = %v, resets = %d; want true, 1", body["deleted"], handler.resets)
		}
		if handler.gotKey == "" {
			t.Fatal("reset was not given the key the sharing check used")
		}
		if note, _ := body["note"].(string); !strings.Contains(note, "reconnect") {
			t.Fatalf("note = %q, want the reconnect warning", note)
		}
	})

	t.Run("nothing stored", func(t *testing.T) {
		t.Parallel()
		ts := newRegistrationTestServer(t, &resettableHandler{})

		status, body := postResetJSON(t, resetURL(ts), `{}`)

		if status != http.StatusOK || body["deleted"] != false {
			t.Fatalf("status = %d, deleted = %v; want 200, false", status, body["deleted"])
		}
	})

	t.Run("static client", func(t *testing.T) {
		t.Parallel()
		// RegistrationKey reports a configured client_id as an empty key.
		ts := newRegistrationTestServer(t, &staticClientHandler{})

		status, body := postResetJSON(t, resetURL(ts), `{}`)

		if status != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400: %v", status, body)
		}
	})

	t.Run("refuses a registration shared with another connection", func(t *testing.T) {
		t.Parallel()
		target := &resettableHandler{deleted: true, key: "shared-key"}
		sibling := &resettableHandler{key: "shared-key"}
		unrelated := &resettableHandler{key: "other-key"}
		ts := newRegistrationTestServerWith(t, target, map[string]bootstrap.OAuthHandler{
			"sibling-app/mcp":   sibling,
			"unrelated-app/mcp": unrelated,
		})

		status, body := postResetJSON(t, resetURL(ts), `{}`)

		if status != http.StatusConflict {
			t.Fatalf("status = %d, want 409: %v", status, body)
		}
		if body["code"] != "registration_shared" {
			t.Fatalf("code = %v, want registration_shared", body["code"])
		}
		shared, _ := body["sharedWith"].([]any)
		if len(shared) != 1 || shared[0] != "sibling-app/mcp" {
			t.Fatalf("sharedWith = %v, want [sibling-app/mcp]", body["sharedWith"])
		}
		if target.resets != 0 {
			t.Fatalf("resets = %d, want 0: a refused reset must delete nothing", target.resets)
		}
	})

	t.Run("include_shared resets a shared registration", func(t *testing.T) {
		t.Parallel()
		target := &resettableHandler{deleted: true, key: "shared-key"}
		sibling := &resettableHandler{key: "shared-key"}
		ts := newRegistrationTestServerWith(t, target, map[string]bootstrap.OAuthHandler{"sibling-app/mcp": sibling})

		status, body := postResetJSON(t, resetURL(ts)+"?include_shared=true", `{}`)

		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200: %v", status, body)
		}
		if target.resets != 1 || sibling.resets != 0 {
			t.Fatalf("target resets = %d, sibling resets = %d; want 1, 0", target.resets, sibling.resets)
		}
		if shared, _ := body["sharedWith"].([]any); len(shared) != 1 {
			t.Fatalf("sharedWith = %v, want the sibling named in the response", body["sharedWith"])
		}
	})

	t.Run("refuses when a sibling's sharing cannot be determined", func(t *testing.T) {
		t.Parallel()
		target := &resettableHandler{deleted: true, key: "shared-key"}
		down := &resettableHandler{keyErr: errors.New("discovery failed")}
		ts := newRegistrationTestServerWith(t, target, map[string]bootstrap.OAuthHandler{"down-app/mcp": down})

		status, body := postResetJSON(t, resetURL(ts), `{}`)

		if status != http.StatusConflict || body["code"] != "registration_sharing_unknown" {
			t.Fatalf("status = %d, code = %v; want 409 registration_sharing_unknown: %v", status, body["code"], body)
		}
		if unresolved, _ := body["unresolved"].([]any); len(unresolved) != 1 || unresolved[0] != "down-app/mcp" {
			t.Fatalf("unresolved = %v, want [down-app/mcp]", body["unresolved"])
		}
		if target.resets != 0 {
			t.Fatalf("resets = %d, want 0", target.resets)
		}
	})

	t.Run("skip_unresolved proceeds past an undeterminable sibling", func(t *testing.T) {
		t.Parallel()
		target := &resettableHandler{deleted: true, key: "shared-key"}
		down := &resettableHandler{keyErr: errors.New("discovery failed")}
		ts := newRegistrationTestServerWith(t, target, map[string]bootstrap.OAuthHandler{"down-app/mcp": down})

		status, body := postResetJSON(t, resetURL(ts)+"?skip_unresolved=true", `{}`)

		if status != http.StatusOK || target.resets != 1 {
			t.Fatalf("status = %d, resets = %d; want 200, 1: %v", status, target.resets, body)
		}
	})

	t.Run("a known sharer still needs include_shared alongside skip_unresolved", func(t *testing.T) {
		t.Parallel()
		target := &resettableHandler{deleted: true, key: "shared-key"}
		ts := newRegistrationTestServerWith(t, target, map[string]bootstrap.OAuthHandler{
			"down-app/mcp":    &resettableHandler{keyErr: errors.New("discovery failed")},
			"sibling-app/mcp": &resettableHandler{key: "shared-key"},
		})

		status, body := postResetJSON(t, resetURL(ts)+"?skip_unresolved=true", `{}`)

		if status != http.StatusConflict || body["code"] != "registration_shared" {
			t.Fatalf("status = %d, code = %v; want 409 registration_shared", status, body["code"])
		}
	})

	t.Run("an app that failed to load blocks the reset", func(t *testing.T) {
		t.Parallel()
		// Configured but absent from the provider registry: what a failed build
		// leaves behind. Its connections never reach connectionAuth.
		target := &resettableHandler{deleted: true}
		ts := newTestServer(t, func(cfg *server.Config) {
			cfg.Providers = testutil.NewProviderRegistry(t, &stubIntegrationWithAuthURL{
				StubIntegration: coretesting.StubIntegration{N: registrationTestProvider},
				authURL:         "https://idp.example.test/authorize",
			})
			cfg.DefaultConnection = map[string]string{registrationTestProvider: testDefaultConnection}
			cfg.AppDefs = map[string]*config.ProviderEntry{
				registrationTestProvider: {
					Connections: map[string]*config.ConnectionDef{
						testDefaultConnection: {Auth: config.ConnectionAuthDef{
							Type:             providermanifestv1.AuthTypeOAuth2,
							AuthorizationURL: "https://idp.example.test/authorize",
							TokenURL:         "https://idp.example.test/token",
						}},
					},
				},
				"broken-app": {},
			}
			cfg.ConnectionAuth = testConnectionAuth(registrationTestProvider, target)
			cfg.Services = testutil.NewStubServices(t)
		})
		testutil.CloseOnCleanup(t, ts)

		status, body := postResetJSON(t, resetURL(ts), `{}`)
		if status != http.StatusConflict || body["code"] != "registration_sharing_unknown" {
			t.Fatalf("status = %d, code = %v; want 409 registration_sharing_unknown: %v", status, body["code"], body)
		}
		if unresolved, _ := body["unresolved"].([]any); len(unresolved) != 1 || unresolved[0] != "broken-app (failed to load)" {
			t.Fatalf("unresolved = %v, want [broken-app (failed to load)]", body["unresolved"])
		}
		if target.resets != 0 {
			t.Fatalf("resets = %d, want 0", target.resets)
		}

		if status, body := postResetJSON(t, resetURL(ts)+"?skip_unresolved=true", `{}`); status != http.StatusOK || target.resets != 1 {
			t.Fatalf("with skip_unresolved: status = %d, resets = %d; want 200, 1: %v", status, target.resets, body)
		}
	})

	t.Run("refuses when the registration moved during the check", func(t *testing.T) {
		t.Parallel()
		ts := newRegistrationTestServer(t, &resettableHandler{resetErr: mcpoauth.ErrRegistrationKeyChanged})

		status, body := postResetJSON(t, resetURL(ts), `{}`)

		if status != http.StatusConflict || body["code"] != "registration_changed" {
			t.Fatalf("status = %d, code = %v; want 409 registration_changed", status, body["code"])
		}
	})

	t.Run("refuses when the upstream can no longer register", func(t *testing.T) {
		t.Parallel()
		ts := newRegistrationTestServer(t, &resettableHandler{resetErr: mcpoauth.ErrNoRegistrationEndpoint})

		status, body := postResetJSON(t, resetURL(ts), `{}`)

		if status != http.StatusConflict || body["code"] != "registration_unavailable" {
			t.Fatalf("status = %d, code = %v; want 409 registration_unavailable", status, body["code"])
		}
	})

	t.Run("connection without dynamic registration", func(t *testing.T) {
		t.Parallel()
		ts := newRegistrationTestServer(t, &testOAuthHandler{})

		status, body := postResetJSON(t, resetURL(ts), `{}`)

		if status != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400: %v", status, body)
		}
	})

	t.Run("unknown app", func(t *testing.T) {
		t.Parallel()
		ts := newRegistrationTestServer(t, &resettableHandler{})

		status, _ := postResetJSON(t, ts.URL+"/admin/api/v1/apps/nope/connections/default/oauth-registration/reset", `{}`)

		if status != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", status)
		}
	})

	t.Run("upstream failure", func(t *testing.T) {
		t.Parallel()
		ts := newRegistrationTestServer(t, &resettableHandler{resetErr: core.ErrNotFound})

		status, _ := postResetJSON(t, resetURL(ts), `{}`)

		if status != http.StatusBadGateway {
			t.Fatalf("status = %d, want 502", status)
		}
	})
}
