package invocation

import (
	"context"
	"errors"
	"testing"

	"github.com/valon-technologies/gestalt/server/core"
	coretesting "github.com/valon-technologies/gestalt/server/core/testing"
	"github.com/valon-technologies/gestalt/server/internal/testutil"
	"github.com/valon-technologies/gestalt/server/services/identity/principal"
)

func TestNoCredentialErrorCarriesWhyConnectingFails(t *testing.T) {
	t.Parallel()

	registrationErr := errors.New("registration endpoint returned 400: invalid_redirect_uri")
	err := noCredentialError(`no external credential stored for integration "example"`, registrationErr)

	// Still a missing credential to anything that only asks that...
	if !errors.Is(err, ErrNoCredential) {
		t.Fatalf("err = %v, want it to remain ErrNoCredential", err)
	}
	// ...but distinguishable from "not connected yet", with the cause kept.
	if !errors.Is(err, ErrConnectionUnavailable) {
		t.Fatalf("err = %v, want ErrConnectionUnavailable", err)
	}
	if !errors.Is(err, registrationErr) {
		t.Fatalf("err = %v, want the resolver error wrapped", err)
	}

	plain := noCredentialError(`no external credential stored for integration "example"`, nil)
	if !errors.Is(plain, ErrNoCredential) || errors.Is(plain, ErrConnectionUnavailable) {
		t.Fatalf("plain = %v, want only ErrNoCredential when the connection can be made", plain)
	}
}

func TestBrokerResolveToken_ReportsWhyAConnectionCannotBeMade(t *testing.T) {
	t.Parallel()

	registrationErr := errors.New("registration endpoint returned 400: invalid_redirect_uri")
	for _, tc := range []struct {
		name            string
		resolverErr     error
		wantUnavailable bool
	}{
		{name: "auth config resolves", resolverErr: nil, wantUnavailable: false},
		{name: "auth config fails", resolverErr: registrationErr, wantUnavailable: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			svc := testutil.NewStubServices(t)
			broker := NewBroker(
				testutil.NewProviderRegistry(t, &coretesting.StubIntegration{
					N:        "example",
					ConnMode: core.ConnectionModeSubject,
				}),
				svc.Users,
				svc.ExternalCredentials,
				WithConnectionRuntime(func(string, string) (ConnectionRuntimeInfo, bool) {
					return ConnectionRuntimeInfo{
						Mode: core.ConnectionModeSubject,
						AuthConfigResolver: func(context.Context) (core.ExternalCredentialAuthConfig, error) {
							return core.ExternalCredentialAuthConfig{}, tc.resolverErr
						},
					}, true
				}),
			)

			_, _, err := broker.ResolveToken(context.Background(), &principal.Principal{
				SubjectID: principal.UserSubjectID("user-1"),
				UserID:    "user-1",
				Kind:      principal.KindUser,
			}, "example", "", "")
			if !errors.Is(err, ErrNoCredential) {
				t.Fatalf("err = %v, want ErrNoCredential", err)
			}
			if got := errors.Is(err, ErrConnectionUnavailable); got != tc.wantUnavailable {
				t.Fatalf("errors.Is(err, ErrConnectionUnavailable) = %v, want %v (err = %v)", got, tc.wantUnavailable, err)
			}
			if tc.wantUnavailable && !errors.Is(err, registrationErr) {
				t.Fatalf("err = %v, want the resolver error wrapped", err)
			}
		})
	}
}
