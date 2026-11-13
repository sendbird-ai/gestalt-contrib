package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/go-chi/chi/v5"
	"github.com/valon-technologies/gestalt/server/services/apps/mcpoauth"
)

// oauthRegistrationResetter is implemented by OAuth handlers that hold a
// gateway-owned dynamic client registration.
type oauthRegistrationResetter interface {
	// ResetRegistration refuses if the registration no longer matches
	// expectedKey, the key the sharing check was made against.
	ResetRegistration(ctx context.Context, expectedKey string) (bool, error)
	// RegistrationKey identifies the stored registration; connections with
	// equal non-empty keys share one.
	RegistrationKey(ctx context.Context) (string, error)
}

type adminOAuthRegistrationResetResponse struct {
	App        string   `json:"app"`
	Connection string   `json:"connection"`
	Deleted    bool     `json:"deleted"`
	SharedWith []string `json:"sharedWith,omitempty"`
	Note       string   `json:"note"`
}

type adminOAuthRegistrationSharedResponse struct {
	Error      string   `json:"error"`
	Code       string   `json:"code"`
	SharedWith []string `json:"sharedWith,omitempty"`
	Unresolved []string `json:"unresolved,omitempty"`
}

func (s *Server) mountAdminOAuthRegistrationRoutes(r chi.Router) {
	r.Post("/apps/{app}/connections/{connection}/oauth-registration/reset", s.resetAdminOAuthRegistration)
}

// resetAdminOAuthRegistration deletes the gateway's stored dynamic client
// registration for one app connection, so the next connect registers a new
// client. It is the operator's answer to a vendor that has forgotten or
// revoked the client: the gateway cannot detect that itself, because the
// rejection happens on the vendor's authorize page in the user's browser.
//
// A registration is stored per authorization server and callback, so other
// connections can share it, and deleting it signs their users out of refresh
// too. Those connections are named and the reset refused unless the caller
// passes include_shared=true. A connection whose key cannot be resolved right
// now might share it, so it too refuses the reset, unless the caller has
// checked and passes skip_unresolved=true.
func (s *Server) resetAdminOAuthRegistration(w http.ResponseWriter, r *http.Request) {
	app := chi.URLParam(r, "app")
	connection := chi.URLParam(r, "connection")
	auditAllowed := false
	auditErr := errors.New("oauth registration reset failed")
	defer func() {
		s.auditHTTPEventWithTarget(r.Context(), PrincipalFromContext(r.Context()), app,
			"connection.oauth.registration.reset", auditAllowed, auditErr,
			connectionAuditTarget(app, connection, ""))
	}()

	handler, ok := s.requireOAuthHandler(w, app, connection)
	if !ok {
		auditErr = errors.New("oauth is not configured")
		return
	}
	resetter, ok := handler.(oauthRegistrationResetter)
	if !ok {
		auditErr = errors.New("connection has no dynamic client registration")
		writeError(w, http.StatusBadRequest,
			fmt.Sprintf("connection %q on app %q does not use dynamic client registration", connection, app))
		return
	}

	key, err := resetter.RegistrationKey(r.Context())
	switch {
	case err != nil:
		auditErr = err
		writeError(w, http.StatusBadGateway, fmt.Sprintf("reset failed for %q: %v", app, err))
		return
	case key == "":
		auditErr = mcpoauth.ErrStaticClient
		writeError(w, http.StatusBadRequest,
			fmt.Sprintf("connection %q on app %q uses a configured client_id; there is no registration to reset", connection, app))
		return
	}

	shared, unresolved := s.connectionsSharingRegistration(r.Context(), app, connection, key)
	if len(unresolved) > 0 && r.URL.Query().Get("skip_unresolved") != "true" {
		auditErr = errors.New("registration sharing could not be determined")
		writeJSON(w, http.StatusConflict, adminOAuthRegistrationSharedResponse{
			Error: fmt.Sprintf("could not tell whether %s share the registration for %s/%s: their upstreams did not resolve. "+
				"If they do share it, resetting signs their users out of refresh once they recover. "+
				"Retry when they resolve, or with skip_unresolved=true once you have checked.",
				strings.Join(unresolved, ", "), app, connection),
			Code:       "registration_sharing_unknown",
			SharedWith: shared,
			Unresolved: unresolved,
		})
		return
	}
	if len(shared) > 0 && r.URL.Query().Get("include_shared") != "true" {
		auditErr = errors.New("registration is shared with other connections")
		writeJSON(w, http.StatusConflict, adminOAuthRegistrationSharedResponse{
			Error: fmt.Sprintf("the registration for %s/%s is shared with %s; resetting it replaces the client for all of them, "+
				"and their users must reconnect. Retry with include_shared=true to proceed.",
				app, connection, strings.Join(shared, ", ")),
			Code:       "registration_shared",
			SharedWith: shared,
		})
		return
	}

	deleted, err := resetter.ResetRegistration(r.Context(), key)
	switch {
	case errors.Is(err, mcpoauth.ErrStaticClient):
		auditErr = err
		writeError(w, http.StatusBadRequest,
			fmt.Sprintf("connection %q on app %q uses a configured client_id; there is no registration to reset", connection, app))
		return
	case errors.Is(err, mcpoauth.ErrRegistrationKeyChanged):
		auditErr = err
		writeTypedError(w, http.StatusConflict, "registration_changed", app,
			fmt.Sprintf("%q moved authorization servers while the reset was checking for shared registrations, so nothing was deleted; retry", app))
		return
	case errors.Is(err, mcpoauth.ErrNoRegistrationEndpoint):
		auditErr = err
		writeTypedError(w, http.StatusConflict, "registration_unavailable", app,
			fmt.Sprintf("%q advertises no client registration endpoint, so nothing was deleted: a new client could not be registered to replace it", app))
		return
	case err != nil:
		auditErr = err
		slog.ErrorContext(r.Context(), "oauth registration reset failed", "provider", app, "connection", connection, "error", err)
		writeError(w, http.StatusBadGateway, fmt.Sprintf("reset failed for %q: %v", app, err))
		return
	}
	auditAllowed = true
	auditErr = nil
	slog.InfoContext(r.Context(), "oauth registration reset", "provider", app, "connection", connection,
		"deleted", deleted, "shared_with", shared, "skipped_unresolved", unresolved)
	note := "no stored registration; the next connect registers a client"
	if deleted {
		note = "deleted; the next connect registers a new client, and users connected with the old client must reconnect"
	}
	writeJSON(w, http.StatusOK, adminOAuthRegistrationResetResponse{
		App:        app,
		Connection: connection,
		Deleted:    deleted,
		SharedWith: shared,
		Note:       note,
	})
}

// connectionsSharingRegistration returns every other connection whose
// registration key equals key, and the names of those whose key could not be
// resolved, both as "app/connection". Keys come from live discovery, in
// parallel. An unresolved connection is not assumed to be unrelated: its users' grants may belong to this very
// client, so the caller decides what to do about it.
//
// The scan can only see apps that loaded. An app whose build failed is removed
// from the provider registry and never reaches connectionAuth, so its
// connections, and whether any of them shares this registration, are unknown.
// Each configured app missing from the registry is therefore reported as
// unresolved too. That can over-report (a frontend-only dev app has no backend
// and no OAuth), which costs a skip_unresolved, never a wrong delete.
//
// Known gap: a runtime app restart registers the provider before it publishes
// the app's connection-auth handlers. A reset in that window sees the app as
// loaded yet finds none of its connections, so a registration it shares could
// be deleted without either override.
func (s *Server) connectionsSharingRegistration(ctx context.Context, app, connection, key string) ([]string, []string) {
	if s.connectionAuth == nil {
		return nil, nil
	}
	var (
		mu         sync.Mutex
		wg         sync.WaitGroup
		shared     []string
		unresolved []string
	)
	for otherApp, conns := range s.connectionAuth() {
		for otherConn, h := range conns {
			if otherApp == app && otherConn == connection {
				continue
			}
			other, ok := h.(oauthRegistrationResetter)
			if !ok {
				continue
			}
			wg.Add(1)
			go func(name string, other oauthRegistrationResetter) {
				defer wg.Done()
				otherKey, err := other.RegistrationKey(ctx)
				if err != nil {
					slog.WarnContext(ctx, "oauth registration reset: could not resolve a connection's registration key",
						"connection", name, "error", err)
					mu.Lock()
					unresolved = append(unresolved, name)
					mu.Unlock()
					return
				}
				if otherKey == key {
					mu.Lock()
					shared = append(shared, name)
					mu.Unlock()
				}
			}(otherApp+"/"+otherConn, other)
		}
	}
	wg.Wait()
	unresolved = append(unresolved, s.configuredAppsNotLoaded()...)
	sort.Strings(shared)
	sort.Strings(unresolved)
	return shared, unresolved
}

// configuredAppsNotLoaded names each configured app that is not in the provider
// registry, which is where a failed build leaves it.
func (s *Server) configuredAppsNotLoaded() []string {
	if s.providers == nil {
		return nil
	}
	loaded := make(map[string]bool)
	for _, name := range s.providers.List() {
		loaded[name] = true
	}
	var missing []string
	for name := range s.pluginDefs {
		if !loaded[name] {
			missing = append(missing, name+" (failed to load)")
		}
	}
	return missing
}
