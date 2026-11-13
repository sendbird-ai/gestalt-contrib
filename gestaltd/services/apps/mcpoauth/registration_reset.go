package mcpoauth

import (
	"context"
	"errors"
	"fmt"

	"github.com/valon-technologies/gestalt/server/core"
)

// ErrStaticClient is returned by ResetRegistration for a connection configured
// with its own client_id: there is no gateway registration to replace.
var ErrStaticClient = errors.New("mcp oauth: connection uses a configured client_id, not a dynamic registration")

// ErrNoRegistrationEndpoint is returned by ResetRegistration, deleting nothing,
// when the upstream advertises no registration endpoint. resolveRegistration
// keeps using a stored client in that case, so deleting it would leave nothing
// to connect with; and with nothing stored, no client can be had at all.
var ErrNoRegistrationEndpoint = errors.New("mcp oauth: upstream advertises no registration endpoint, so no new client can be registered")

// ErrRegistrationKeyChanged is returned by ResetRegistration, deleting nothing,
// when the registration the caller checked is no longer the one discovery
// resolves to: the upstream moved authorization servers in between, so any
// sharing check the caller made applies to a different registration.
var ErrRegistrationKeyChanged = errors.New("mcp oauth: the upstream's registration changed since it was checked; check again")

// RegistrationKey identifies the stored registration this connection uses.
// Registrations are stored per authorization server and callback, not per
// connection, so two connections whose MCP servers share an authorization
// server share one registration; equal keys mean exactly that. It is empty for
// a connection with a configured client_id, which stores no registration.
//
// It needs only discovery, never registration: resolving the client would run
// DCR for any connection with nothing stored, so a reset's scan across every
// connection would provision a client at each vendor for every
// never-connected connection, and resetting a never-connected target would
// register a client only to delete the gateway's record of it.
func (h *Handler) RegistrationKey(ctx context.Context) (string, error) {
	if h.cfg.ClientID != "" {
		return "", nil
	}
	ctx, cancel := context.WithTimeout(ctx, ensureTimeout)
	defer cancel()
	md, err := Discover(ctx, h.cfg.MCPURL)
	if err != nil {
		return "", fmt.Errorf("mcp oauth discovery failed for %s: %w", h.cfg.MCPURL, err)
	}
	return h.registrationKey(md), nil
}

// registrationKey mirrors the lookup in storedRegistration.
func (h *Handler) registrationKey(md *DiscoveredMetadata) string {
	return md.AuthServerURL + "\x00" + h.cfg.RedirectURL
}

// ResetRegistration deletes this upstream's stored dynamic client registration,
// so the next connect registers a new client. It reports whether there was one.
//
// A registration is otherwise kept until the expiry the server gave it, and
// many servers give none. When a server forgets or revokes the client, the
// gateway keeps presenting it, and the failure happens on the vendor's
// authorize page in the user's browser, where the gateway never sees it.
//
// The registration belongs to the authorization server and callback, not to
// this connection (see RegistrationKey), so a reset replaces it for every
// connection sharing it; the admin handler checks for those first. Grants users
// already hold were issued to the old client, so their refresh will fail after
// a reset and they will need to reconnect. It refuses, deleting nothing, when
// the upstream no longer offers registration.
//
// expectedKey, when non-empty, is the RegistrationKey the caller checked for
// sharing; the reset refuses with ErrRegistrationKeyChanged if fresh discovery
// now resolves to a different one.
func (h *Handler) ResetRegistration(ctx context.Context, expectedKey string) (bool, error) {
	if h.cfg.ClientID != "" {
		return false, ErrStaticClient
	}
	ctx, cancel := context.WithTimeout(ctx, ensureTimeout)
	defer cancel()

	md, err := Discover(ctx, h.cfg.MCPURL)
	if err != nil {
		return false, fmt.Errorf("mcp oauth discovery failed for %s: %w", h.cfg.MCPURL, err)
	}
	if expectedKey != "" && h.registrationKey(md) != expectedKey {
		return false, ErrRegistrationKeyChanged
	}
	id, existing, err := h.storedRegistration(ctx, md)
	if err != nil {
		return false, err
	}
	// Checked before the nothing-stored return too: with no stored client and no
	// endpoint the next connect cannot get a client at all, and reporting
	// success would say otherwise.
	if md.RegistrationEndpoint == "" {
		return false, ErrNoRegistrationEndpoint
	}
	if existing == nil {
		return false, nil
	}
	if err := h.cfg.Credentials.DeleteCredential(ctx, id); err != nil && !errors.Is(err, core.ErrNotFound) {
		return false, err
	}
	return true, nil
}
