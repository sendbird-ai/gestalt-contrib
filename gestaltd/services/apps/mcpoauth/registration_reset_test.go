package mcpoauth_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	coretesting "github.com/valon-technologies/gestalt/server/core/testing"
	"github.com/valon-technologies/gestalt/server/internal/testutil"
	"github.com/valon-technologies/gestalt/server/services/apps/mcpoauth"
)

// A vendor forgets the client the gateway registered, so the stored one has to
// be replaced. After a reset the next connect must register a new client and
// present it, not the stored one.
func TestResetRegistrationReplacesTheStoredClient(t *testing.T) {
	t.Parallel()

	as := newFakeAuthServer(t, false)
	creds := coretesting.NewStubExternalCredentialProvider()
	handler := newHandler(as, creds)

	authURL, _ := handler.StartOAuth("state", nil)
	if got := clientIDOf(t, authURL); got != "client-001" {
		t.Fatalf("first client_id = %q, want client-001", got)
	}

	deleted, err := handler.ResetRegistration(context.Background(), "")
	if err != nil {
		t.Fatalf("ResetRegistration: %v", err)
	}
	if !deleted {
		t.Fatal("ResetRegistration reported nothing deleted; want the stored client removed")
	}

	authURL, _ = handler.StartOAuth("state", nil)
	if got := clientIDOf(t, authURL); got != "client-002" {
		t.Fatalf("client_id after reset = %q, want a newly registered client-002", got)
	}
	if got := storedClientInfo(t, creds, as.srv.URL).ClientID; got != "client-002" {
		t.Fatalf("stored client_id after reset = %q, want client-002", got)
	}
	if as.dcrCount != 2 {
		t.Fatalf("DCR count = %d, want 2", as.dcrCount)
	}

	// The refresh path must not keep serving the deleted client.
	cfg, err := handler.AuthConfig(context.Background())
	if err != nil {
		t.Fatalf("AuthConfig: %v", err)
	}
	if cfg.ClientID != "client-002" {
		t.Fatalf("AuthConfig client_id = %q, want client-002", cfg.ClientID)
	}
}

func TestResetRegistrationWithNothingStored(t *testing.T) {
	t.Parallel()

	as := newFakeAuthServer(t, false)
	handler := newHandler(as, coretesting.NewStubExternalCredentialProvider())

	deleted, err := handler.ResetRegistration(context.Background(), "")
	if err != nil {
		t.Fatalf("ResetRegistration: %v", err)
	}
	if deleted {
		t.Fatal("ResetRegistration reported a deletion with nothing stored")
	}
	if as.dcrCount != 0 {
		t.Fatalf("DCR count = %d, want 0: a reset must not register", as.dcrCount)
	}
}

func TestResetRegistrationRefusesAStaticClient(t *testing.T) {
	t.Parallel()

	as := newFakeAuthServer(t, false)
	handler := mcpoauth.NewHandler(mcpoauth.HandlerConfig{
		MCPURL:      as.mcpURL(),
		Credentials: coretesting.NewStubExternalCredentialProvider(),
		RedirectURL: testRedirectURL,
		ClientID:    "configured-client",
	})

	if _, err := handler.ResetRegistration(context.Background(), ""); !errors.Is(err, mcpoauth.ErrStaticClient) {
		t.Fatalf("ResetRegistration error = %v, want ErrStaticClient", err)
	}
}

// An upstream that stops advertising registration keeps its stored client in
// use, so a reset must keep it too rather than strand the connection.
func TestResetRegistrationKeepsTheClientWhenRegistrationIsGone(t *testing.T) {
	t.Parallel()

	var offerRegistration atomic.Bool
	offerRegistration.Store(true)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /mcp", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		writeJSON(w, 0, map[string]any{"resource": base + "/mcp", "authorization_servers": []string{base}})
	})
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		md := map[string]any{
			"issuer":                                base,
			"authorization_endpoint":                base + "/oauth/authorize",
			"token_endpoint":                        base + "/oauth/token",
			"code_challenge_methods_supported":      []string{"S256"},
			"token_endpoint_auth_methods_supported": []string{"none"},
		}
		if offerRegistration.Load() {
			md["registration_endpoint"] = base + "/oauth/register"
		}
		writeJSON(w, 0, md)
	})
	mux.HandleFunc("POST /oauth/register", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusCreated, map[string]any{"client_id": "kept-client"})
	})
	srv := httptest.NewServer(mux)
	testutil.CloseOnCleanup(t, srv)

	creds := coretesting.NewStubExternalCredentialProvider()
	handler := mcpoauth.NewHandler(mcpoauth.HandlerConfig{MCPURL: srv.URL + "/mcp", Credentials: creds, RedirectURL: testRedirectURL})
	if authURL, _ := handler.StartOAuth("state", nil); clientIDOf(t, authURL) != "kept-client" {
		t.Fatalf("setup: client_id = %q, want kept-client", clientIDOf(t, authURL))
	}

	offerRegistration.Store(false)
	deleted, err := handler.ResetRegistration(context.Background(), "")
	if !errors.Is(err, mcpoauth.ErrNoRegistrationEndpoint) {
		t.Fatalf("ResetRegistration = (%v, %v), want ErrNoRegistrationEndpoint", deleted, err)
	}
	if got := storedClientInfo(t, creds, srv.URL).ClientID; got != "kept-client" {
		t.Fatalf("stored client_id = %q, want kept-client left in place", got)
	}
	if authURL, _ := handler.StartOAuth("state", nil); clientIDOf(t, authURL) != "kept-client" {
		t.Fatalf("connect after refused reset uses %q, want kept-client", clientIDOf(t, authURL))
	}
}

// Connections on one authorization server share a registration key, so the
// admin reset can find them; different servers don't.
func TestRegistrationKeyIdentifiesSharedRegistrations(t *testing.T) {
	t.Parallel()

	as := newFakeAuthServer(t, false)
	other := newFakeAuthServer(t, false)
	creds := coretesting.NewStubExternalCredentialProvider()

	keyOf := func(h *mcpoauth.Handler) string {
		t.Helper()
		key, err := h.RegistrationKey(context.Background())
		if err != nil {
			t.Fatalf("RegistrationKey: %v", err)
		}
		return key
	}
	a, b, c := keyOf(newHandler(as, creds)), keyOf(newHandler(as, creds)), keyOf(newHandler(other, creds))
	if a == "" || a != b {
		t.Fatalf("same authorization server: keys %q and %q, want equal and non-empty", a, b)
	}
	if a == c {
		t.Fatalf("different authorization servers share key %q", a)
	}
	// Computing a key must not register. These connections have never
	// connected, so resolving their clients would provision one at each vendor.
	if as.dcrCount != 0 || other.dcrCount != 0 {
		t.Fatalf("DCR count = %d, %d; want 0, 0: RegistrationKey must use discovery only", as.dcrCount, other.dcrCount)
	}

	static := mcpoauth.NewHandler(mcpoauth.HandlerConfig{MCPURL: as.mcpURL(), Credentials: creds, RedirectURL: testRedirectURL, ClientID: "configured"})
	if key := keyOf(static); key != "" {
		t.Fatalf("static client key = %q, want empty", key)
	}
}

// The admin reset computes the target's key before resetting. For a
// never-connected connection that sequence must leave the vendor untouched.
func TestResettingANeverConnectedConnectionRegistersNothing(t *testing.T) {
	t.Parallel()

	as := newFakeAuthServer(t, false)
	creds := coretesting.NewStubExternalCredentialProvider()
	handler := newHandler(as, creds)

	if _, err := handler.RegistrationKey(context.Background()); err != nil {
		t.Fatalf("RegistrationKey: %v", err)
	}
	deleted, err := handler.ResetRegistration(context.Background(), "")
	if err != nil || deleted {
		t.Fatalf("ResetRegistration = (%v, %v), want (false, nil)", deleted, err)
	}
	if as.dcrCount != 0 {
		t.Fatalf("DCR count = %d, want 0: nothing was connected, so nothing should be registered", as.dcrCount)
	}
}

// With nothing stored and no registration endpoint the connection cannot get a
// client at all, so the reset must say so rather than report a harmless no-op.
func TestResetRegistrationReportsNoEndpointWithNothingStored(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /mcp", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		writeJSON(w, 0, map[string]any{"resource": base + "/mcp", "authorization_servers": []string{base}})
	})
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		writeJSON(w, 0, map[string]any{
			"issuer":                           base,
			"authorization_endpoint":           base + "/oauth/authorize",
			"token_endpoint":                   base + "/oauth/token",
			"code_challenge_methods_supported": []string{"S256"},
		})
	})
	srv := httptest.NewServer(mux)
	testutil.CloseOnCleanup(t, srv)

	handler := mcpoauth.NewHandler(mcpoauth.HandlerConfig{
		MCPURL: srv.URL + "/mcp", Credentials: coretesting.NewStubExternalCredentialProvider(), RedirectURL: testRedirectURL,
	})
	deleted, err := handler.ResetRegistration(context.Background(), "")
	if deleted || !errors.Is(err, mcpoauth.ErrNoRegistrationEndpoint) {
		t.Fatalf("ResetRegistration = (%v, %v), want (false, ErrNoRegistrationEndpoint)", deleted, err)
	}
}

// The reset must act on the registration the caller checked for sharing. If the upstream moves authorization servers in between,
// it refuses rather than delete a registration nobody checked.
func TestResetRegistrationRefusesWhenTheKeyChanged(t *testing.T) {
	t.Parallel()

	first := newFakeAuthServer(t, false)
	second := newFakeAuthServer(t, false)
	var current atomic.Value
	current.Store(first.srv.URL)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="http://`+r.Host+`/.well-known/oauth-protected-resource/mcp"`)
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 0, map[string]any{
			"resource":              "http://" + r.Host + "/mcp",
			"authorization_servers": []string{current.Load().(string)},
		})
	})
	resource := httptest.NewServer(mux)
	testutil.CloseOnCleanup(t, resource)

	creds := coretesting.NewStubExternalCredentialProvider()
	handler := mcpoauth.NewHandler(mcpoauth.HandlerConfig{MCPURL: resource.URL + "/mcp", Credentials: creds, RedirectURL: testRedirectURL})
	if authURL, _ := handler.StartOAuth("state", nil); clientIDOf(t, authURL) == "" {
		t.Fatal("setup: no client registered with the first authorization server")
	}
	// Register with the second server too, so a wrong delete would have a target.
	current.Store(second.srv.URL)
	if authURL, _ := handler.StartOAuth("state", nil); clientIDOf(t, authURL) == "" {
		t.Fatal("setup: no client registered with the second authorization server")
	}
	current.Store(first.srv.URL)

	checked, err := handler.RegistrationKey(context.Background())
	if err != nil {
		t.Fatalf("RegistrationKey: %v", err)
	}
	current.Store(second.srv.URL)

	deleted, err := handler.ResetRegistration(context.Background(), checked)
	if deleted || !errors.Is(err, mcpoauth.ErrRegistrationKeyChanged) {
		t.Fatalf("ResetRegistration = (%v, %v), want (false, ErrRegistrationKeyChanged)", deleted, err)
	}
	if got := storedClientInfo(t, creds, second.srv.URL).ClientID; got == "" {
		t.Fatal("the second server's registration was deleted although only the first was checked")
	}

	// Checked against what discovery now says, the reset proceeds.
	checked, err = handler.RegistrationKey(context.Background())
	if err != nil {
		t.Fatalf("RegistrationKey: %v", err)
	}
	if deleted, err := handler.ResetRegistration(context.Background(), checked); err != nil || !deleted {
		t.Fatalf("ResetRegistration with a current key = (%v, %v), want (true, nil)", deleted, err)
	}
}
