package mcpoauth_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/valon-technologies/gestalt/server/core"
	coretesting "github.com/valon-technologies/gestalt/server/core/testing"
	"github.com/valon-technologies/gestalt/server/internal/testutil"
	"github.com/valon-technologies/gestalt/server/services/apps/mcpoauth"
)

const testRedirectURL = "http://localhost:9999/callback"

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	if status != 0 {
		w.WriteHeader(status)
	}
	_ = json.NewEncoder(w).Encode(v)
}

// fakeAuthServer is an MCP resource plus OAuth authorization server with DCR.
// direct=false advertises the AS via RFC 9728 WWW-Authenticate indirection;
// direct=true embeds the endpoints in the resource metadata (ClickHouse style).
type fakeAuthServer struct {
	srv *httptest.Server

	mu             sync.Mutex
	dcrCount       int
	dcrGrantTypes  []any
	tokenClientIDs []string
	tokenVerifiers []string
	tokenResources []string
	// newClientID names the nth registered client; default is client-00n.
	newClientID func(n int) string
}

func newFakeAuthServer(t *testing.T, direct bool) *fakeAuthServer {
	t.Helper()
	as := &fakeAuthServer{newClientID: func(n int) string { return fmt.Sprintf("client-%03d", n) }}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /mcp", func(w http.ResponseWriter, r *http.Request) {
		if !direct {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(
				`Bearer resource_metadata="http://%s/.well-known/oauth-protected-resource/mcp"`, r.Host))
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		baseURL := "http://" + r.Host
		if direct {
			writeJSON(w, 0, map[string]any{
				"authorization_endpoint":                baseURL + "/oauth/authorize",
				"token_endpoint":                        baseURL + "/oauth/token",
				"registration_endpoint":                 baseURL + "/oauth/register",
				"scopes_supported":                      []string{"query"},
				"code_challenge_methods_supported":      []string{"S256"},
				"token_endpoint_auth_methods_supported": []string{"none"},
			})
			return
		}
		writeJSON(w, 0, map[string]any{
			"resource":              baseURL + "/mcp",
			"authorization_servers": []string{baseURL},
			"scopes_supported":      []string{"read", "write"},
		})
	})
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		baseURL := "http://" + r.Host
		writeJSON(w, 0, map[string]any{
			"issuer":                                baseURL,
			"authorization_endpoint":                baseURL + "/oauth/authorize",
			"token_endpoint":                        baseURL + "/oauth/token",
			"registration_endpoint":                 baseURL + "/oauth/register",
			"scopes_supported":                      []string{"read", "write"},
			"code_challenge_methods_supported":      []string{"S256"},
			"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post"},
		})
	})
	mux.HandleFunc("POST /oauth/register", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		as.mu.Lock()
		as.dcrCount++
		n := as.dcrCount
		as.dcrGrantTypes, _ = body["grant_types"].([]any)
		as.mu.Unlock()
		// Outside the lock: newClientID may block on a test barrier.
		writeJSON(w, http.StatusCreated, map[string]any{"client_id": as.newClientID(n)})
	})
	mux.HandleFunc("POST /oauth/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") == "" {
			http.Error(w, "bad token request", http.StatusBadRequest)
			return
		}
		as.mu.Lock()
		as.tokenClientIDs = append(as.tokenClientIDs, r.Form.Get("client_id"))
		as.tokenVerifiers = append(as.tokenVerifiers, r.Form.Get("code_verifier"))
		as.tokenResources = append(as.tokenResources, r.Form.Get("resource"))
		as.mu.Unlock()
		writeJSON(w, 0, map[string]any{
			"access_token":  "access-tok-123",
			"refresh_token": "refresh-tok-456",
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	})

	as.srv = httptest.NewServer(mux)
	testutil.CloseOnCleanup(t, as.srv)
	return as
}

func (as *fakeAuthServer) mcpURL() string { return as.srv.URL + "/mcp" }

func newHandler(as *fakeAuthServer, creds core.ExternalCredentialProvider) *mcpoauth.Handler {
	return mcpoauth.NewHandler(mcpoauth.HandlerConfig{
		MCPURL:      as.mcpURL(),
		Credentials: creds,
		RedirectURL: testRedirectURL,
	})
}

func storedClientInfo(t *testing.T, creds core.ExternalCredentialProvider, authServerURL string) *core.ExternalCredentialClientInfo {
	t.Helper()
	credential, err := creds.GetCredential(context.Background(), core.GestaltdSubjectID, authServerURL, testRedirectURL)
	if err != nil {
		t.Fatalf("GetCredential(%s, %s, %s): %v", core.GestaltdSubjectID, authServerURL, testRedirectURL, err)
	}
	if credential.Client == nil {
		t.Fatalf("stored credential = %+v, want ClientInfo kind", credential)
	}
	return credential.Client
}

func clientIDOf(t *testing.T, authURL string) string {
	t.Helper()
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parsing auth URL %q: %v", authURL, err)
	}
	return parsed.Query().Get("client_id")
}

func TestMCPOAuthFlow(t *testing.T) {
	t.Parallel()

	// The production topology: the OAuth start and the callback are served by
	// different instances that share only the external credentials provider.
	// The exchange must present the same client_id the authorize URL carried.
	t.Run("RFC9728CrossInstance", func(t *testing.T) {
		t.Parallel()

		as := newFakeAuthServer(t, false)
		creds := coretesting.NewStubExternalCredentialProvider()
		instanceA := newHandler(as, creds)
		instanceB := newHandler(as, creds)

		authURL, verifier := instanceA.StartOAuth("test-state", nil)
		if authURL == "" || verifier == "" {
			t.Fatalf("StartOAuth = (%q, %q), want non-empty auth URL and PKCE verifier", authURL, verifier)
		}
		parsed, err := url.Parse(authURL)
		if err != nil {
			t.Fatalf("parsing auth URL: %v", err)
		}
		if !strings.HasPrefix(parsed.Path, "/oauth/authorize") {
			t.Errorf("auth URL path = %q, want /oauth/authorize prefix", parsed.Path)
		}
		if got := parsed.Query().Get("client_id"); got != "client-001" {
			t.Errorf("client_id = %q, want client-001", got)
		}
		if got := parsed.Query().Get("code_challenge_method"); got != "S256" {
			t.Errorf("code_challenge_method = %q, want S256", got)
		}
		if got := parsed.Query().Get("resource"); got != as.mcpURL() {
			t.Errorf("authorize resource = %q, want %q (RFC 8707)", got, as.mcpURL())
		}
		if len(as.dcrGrantTypes) != 2 || as.dcrGrantTypes[0] != "authorization_code" || as.dcrGrantTypes[1] != "refresh_token" {
			t.Errorf("DCR grant_types = %v, want [authorization_code, refresh_token]", as.dcrGrantTypes)
		}

		if got := storedClientInfo(t, creds, as.srv.URL).ClientID; got != "client-001" {
			t.Errorf("stored client_id = %q, want client-001", got)
		}

		tokenResp, err := instanceB.ExchangeCodeWithVerifier(context.Background(), "auth-code-xyz", verifier)
		if err != nil {
			t.Fatalf("ExchangeCodeWithVerifier: %v", err)
		}
		if tokenResp.AccessToken != "access-tok-123" || tokenResp.RefreshToken != "refresh-tok-456" {
			t.Errorf("token response = (%q, %q), want (access-tok-123, refresh-tok-456)", tokenResp.AccessToken, tokenResp.RefreshToken)
		}
		if as.dcrCount != 1 {
			t.Errorf("DCR calls = %d, want 1 (instance B must reuse instance A's client)", as.dcrCount)
		}
		if len(as.tokenClientIDs) != 1 || as.tokenClientIDs[0] != "client-001" {
			t.Errorf("token exchange client_ids = %v, want [client-001]", as.tokenClientIDs)
		}
		if len(as.tokenVerifiers) != 1 || as.tokenVerifiers[0] != verifier {
			t.Errorf("token exchange verifier not forwarded")
		}
		if len(as.tokenResources) != 1 || as.tokenResources[0] != as.mcpURL() {
			t.Errorf("token exchange resource = %v, want [%q] (RFC 8707)", as.tokenResources, as.mcpURL())
		}
	})

	t.Run("DirectEndpoints", func(t *testing.T) {
		t.Parallel()

		as := newFakeAuthServer(t, true)
		handler := newHandler(as, coretesting.NewStubExternalCredentialProvider())

		authURL, verifier := handler.StartOAuth("test-state", nil)
		if got := clientIDOf(t, authURL); got != "client-001" {
			t.Errorf("client_id = %q, want client-001", got)
		}
		tokenResp, err := handler.ExchangeCodeWithVerifier(context.Background(), "test-code", verifier)
		if err != nil {
			t.Fatalf("ExchangeCodeWithVerifier: %v", err)
		}
		if tokenResp.AccessToken != "access-tok-123" {
			t.Errorf("access_token = %q, want access-tok-123", tokenResp.AccessToken)
		}
		// Direct-endpoint metadata omits the resource field; the MCP URL is
		// the canonical resource URI.
		if len(as.tokenResources) != 1 || as.tokenResources[0] != as.mcpURL() {
			t.Errorf("token exchange resource = %v, want [%q] (RFC 8707)", as.tokenResources, as.mcpURL())
		}
	})

	t.Run("ConcurrentDCRFirstWriterWins", func(t *testing.T) {
		t.Parallel()

		as := newFakeAuthServer(t, false)
		barrier := make(chan struct{})
		release := sync.OnceFunc(func() { close(barrier) })
		as.newClientID = func(n int) string {
			// Hold the first registration until the second arrives so both
			// instances register before either stores its client.
			if n == 1 {
				<-barrier
			} else {
				release()
			}
			return fmt.Sprintf("client-%03d", n)
		}
		creds := coretesting.NewStubExternalCredentialProvider()
		handlers := []*mcpoauth.Handler{newHandler(as, creds), newHandler(as, creds)}

		urls := make([]string, len(handlers))
		var wg sync.WaitGroup
		for i, h := range handlers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				urls[i], _ = h.StartOAuth(fmt.Sprintf("s%d", i), nil)
			}()
		}
		wg.Wait()
		release()

		clientA, clientB := clientIDOf(t, urls[0]), clientIDOf(t, urls[1])
		if clientA == "" || clientA != clientB {
			t.Fatalf("authorize client_ids = (%q, %q), want both equal to the race winner", clientA, clientB)
		}
		if got := storedClientInfo(t, creds, as.srv.URL).ClientID; got != clientA {
			t.Errorf("stored client_id = %q, want %q", got, clientA)
		}
	})

	t.Run("ExpiredRegistrationReRegisters", func(t *testing.T) {
		t.Parallel()

		as := newFakeAuthServer(t, false)
		creds := coretesting.NewStubExternalCredentialProvider()
		expired := time.Now().Add(-time.Hour)
		err := creds.UpsertCredential(context.Background(), &core.ExternalCredential{
			Subject:   core.GestaltdSubjectID,
			Audience:  as.srv.URL,
			Qualifier: testRedirectURL,
			Client: &core.ExternalCredentialClientInfo{
				ClientID:              "stale-client",
				ClientSecretExpiresAt: &expired,
			},
		})
		if err != nil {
			t.Fatalf("seeding expired registration: %v", err)
		}

		authURL, _ := newHandler(as, creds).StartOAuth("s1", nil)
		if got := clientIDOf(t, authURL); got != "client-001" {
			t.Errorf("client_id = %q, want re-registered client-001", got)
		}
		if got := storedClientInfo(t, creds, as.srv.URL).ClientID; got != "client-001" {
			t.Errorf("stored client_id = %q, want replaced registration client-001", got)
		}
	})

	t.Run("AuthConfigCarriesRegisteredClient", func(t *testing.T) {
		t.Parallel()

		as := newFakeAuthServer(t, false)
		creds := coretesting.NewStubExternalCredentialProvider()
		handler := newHandler(as, creds)

		authConfig, err := handler.AuthConfig(context.Background())
		if err != nil {
			t.Fatalf("AuthConfig: %v", err)
		}
		if authConfig.Type != "oauth2" {
			t.Errorf("auth type = %q, want oauth2", authConfig.Type)
		}
		if want := as.srv.URL + "/oauth/token"; authConfig.TokenURL != want {
			t.Errorf("token URL = %q, want %q", authConfig.TokenURL, want)
		}
		if authConfig.ClientID != "client-001" {
			t.Errorf("client_id = %q, want client-001", authConfig.ClientID)
		}
		if got := authConfig.RefreshParams["resource"]; got != as.mcpURL() {
			t.Errorf("refresh resource param = %q, want %q (RFC 8707)", got, as.mcpURL())
		}
		if got := storedClientInfo(t, creds, as.srv.URL).ClientID; got != "client-001" {
			t.Errorf("stored client_id = %q, want client-001 (AuthConfig registers when absent)", got)
		}
	})

	t.Run("IsolatedFromDefaultTransportCloseIdleConnections", func(t *testing.T) {
		t.Parallel()

		as := newFakeAuthServer(t, false)
		handler := newHandler(as, coretesting.NewStubExternalCredentialProvider())

		defaultTransport, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			t.Fatalf("http.DefaultTransport = %T, want *http.Transport", http.DefaultTransport)
		}

		stop := make(chan struct{})
		done := make(chan struct{})
		go func() {
			defer close(done)
			for {
				select {
				case <-stop:
					return
				default:
					defaultTransport.CloseIdleConnections()
				}
			}
		}()
		t.Cleanup(func() {
			close(stop)
			<-done
		})

		for i := range 5 {
			authURL, verifier := handler.StartOAuth(fmt.Sprintf("s%d", i+1), nil)
			if authURL == "" || verifier == "" {
				t.Fatalf("StartOAuth #%d = (%q, %q), want non-empty", i+1, authURL, verifier)
			}
			if got := clientIDOf(t, authURL); got != "client-001" {
				t.Fatalf("client_id #%d = %q, want client-001", i+1, got)
			}
		}
	})
}

// newPublicOnlyAuthServer models mcp.vercel.com: the authorization server the
// RFC 9728 chain leads to advertises only confidential methods, but
// registration accepts nothing except a public client. It answers any other
// method with invalid_redirect_uri, which is what Vercel actually returns. Its
// token endpoint rejects a request that carries a client_secret at all.
// registerStatus, when set, overrides the rejection status for confidential
// registrations, and noPKCE advertises no S256, so the no-retry paths can be
// exercised.
type publicOnlyAuthServer struct {
	srv            *httptest.Server
	mu             sync.Mutex
	dcrMethods     []string
	tokenHadSecret []bool
	registerStatus int
	noPKCE         bool
}

func (as *publicOnlyAuthServer) challengeMethods() []string {
	if as.noPKCE {
		return []string{"plain"}
	}
	return []string{"S256"}
}

func newPublicOnlyAuthServer(t *testing.T) *publicOnlyAuthServer {
	t.Helper()
	as := &publicOnlyAuthServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+as.srv.URL+`/.well-known/oauth-protected-resource"`)
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"resource":              as.srv.URL + "/mcp",
			"authorization_servers": []string{as.srv.URL + "/as"},
		})
	})
	mux.HandleFunc("GET /.well-known/oauth-authorization-server/as", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"issuer":                                as.srv.URL + "/as",
			"authorization_endpoint":                as.srv.URL + "/as/authorize",
			"token_endpoint":                        as.srv.URL + "/as/token",
			"registration_endpoint":                 as.srv.URL + "/as/register",
			"code_challenge_methods_supported":      as.challengeMethods(),
			"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		})
	})
	mux.HandleFunc("POST /as/register", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Method string `json:"token_endpoint_auth_method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		as.mu.Lock()
		as.dcrMethods = append(as.dcrMethods, body.Method)
		status := as.registerStatus
		as.mu.Unlock()
		if body.Method != "none" {
			if status == 0 {
				status = http.StatusBadRequest
			}
			writeJSON(w, status, map[string]any{"error": "invalid_redirect_uri"})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"client_id": "public-001", "token_endpoint_auth_method": "none"})
	})
	mux.HandleFunc("POST /as/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		_, hadSecret := r.PostForm["client_secret"]
		as.mu.Lock()
		as.tokenHadSecret = append(as.tokenHadSecret, hadSecret)
		as.mu.Unlock()
		if hadSecret {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_client", "error_description": "Unsupported client authentication method."})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"access_token": "access-public", "token_type": "Bearer", "refresh_token": "refresh-public", "expires_in": 3600})
	})
	as.srv = httptest.NewServer(mux)
	testutil.CloseOnCleanup(t, as.srv)
	return as
}

func TestRegistrationFallsBackToPublicClient(t *testing.T) {
	t.Parallel()

	as := newPublicOnlyAuthServer(t)
	handler := mcpoauth.NewHandler(mcpoauth.HandlerConfig{
		MCPURL:      as.srv.URL + "/mcp",
		Credentials: coretesting.NewStubExternalCredentialProvider(),
		RedirectURL: testRedirectURL,
	})

	authURL, verifier := handler.StartOAuth("state", nil)
	if got := clientIDOf(t, authURL); got != "public-001" {
		t.Fatalf("client_id = %q, want public-001 from the public-client retry (auth URL %q)", got, authURL)
	}
	if want := []string{"client_secret_post", "none"}; !slices.Equal(as.dcrMethods, want) {
		t.Errorf("DCR methods = %v, want %v: the advertised method first, then one public retry", as.dcrMethods, want)
	}

	tokenResp, err := handler.ExchangeCodeWithVerifier(context.Background(), "code", verifier)
	if err != nil {
		t.Fatalf("ExchangeCodeWithVerifier: %v", err)
	}
	if tokenResp.AccessToken != "access-public" {
		t.Errorf("access_token = %q, want access-public", tokenResp.AccessToken)
	}
	// A secretless client must not send client_secret, even empty, however
	// the metadata advertised: that is the request this server rejects.
	if len(as.tokenHadSecret) != 1 || as.tokenHadSecret[0] {
		t.Errorf("token exchange carried client_secret = %v, want [false]", as.tokenHadSecret)
	}
}

func TestRegistrationRetriesOnlyMetadataRejections(t *testing.T) {
	t.Parallel()

	// Only a 400 is a statement about client metadata (RFC 7591 3.2.2). A
	// token-gated registration, a throttled one or a server fault must not be
	// answered with a second registration under a different auth method.
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			t.Parallel()
			as := newPublicOnlyAuthServer(t)
			as.registerStatus = status
			handler := mcpoauth.NewHandler(mcpoauth.HandlerConfig{
				MCPURL:      as.srv.URL + "/mcp",
				Credentials: coretesting.NewStubExternalCredentialProvider(),
				RedirectURL: testRedirectURL,
			})

			if authURL, _ := handler.StartOAuth("state", nil); authURL != "" {
				t.Fatalf("StartOAuth = %q, want failure on a %d registration", authURL, status)
			}
			if want := []string{"client_secret_post"}; !slices.Equal(as.dcrMethods, want) {
				t.Errorf("DCR methods = %v, want %v (no retry on %d)", as.dcrMethods, want, status)
			}
		})
	}
}

func TestRegistrationDoesNotFallBackWithoutPKCE(t *testing.T) {
	t.Parallel()

	// A public client without PKCE has nothing binding the code to the
	// gateway, so a server that advertises no S256 does not get one.
	as := newPublicOnlyAuthServer(t)
	as.noPKCE = true
	handler := mcpoauth.NewHandler(mcpoauth.HandlerConfig{
		MCPURL:      as.srv.URL + "/mcp",
		Credentials: coretesting.NewStubExternalCredentialProvider(),
		RedirectURL: testRedirectURL,
	})

	if authURL, _ := handler.StartOAuth("state", nil); authURL != "" {
		t.Fatalf("StartOAuth = %q, want failure: no public fallback without PKCE", authURL)
	}
	if want := []string{"client_secret_post"}; !slices.Equal(as.dcrMethods, want) {
		t.Errorf("DCR methods = %v, want %v", as.dcrMethods, want)
	}
}
