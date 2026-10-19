/*
 * Teleport
 * Copyright (C) 2026  GreyOrange Pte Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

// Unit tests for the pure claim/trait-mapping helpers in oidc_service.go.
// These are the parts of the OIDC relying-party implementation that don't
// need a live IdP (Keycloak) or network access to exercise -- the OAuth2
// exchange and ID-token verification themselves are covered by the
// end-to-end checks in GOOGLE_SSO_PLAN.md's Verification section
// (`tctl sso test`, a real browser login) instead.
package auth

import (
	"testing"

	zoidc "github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/constants"
	"github.com/gravitational/teleport/api/types"
)

func TestOIDCClaimsToTraits(t *testing.T) {
	claims := map[string]any{
		"email":          "alice@example.com",
		"email_verified": true,
		"groups":         []any{"dev", "ops", 42},
		"hd":             "example.com",
		"sub":            "12345",
		"aud":            []any{"teleport"},
		"nested":         map[string]any{"unsupported": "value"},
		"empty_string":   "",
	}

	traits := oidcClaimsToTraits(claims, "alice@example.com")

	require.Equal(t, []string{"alice@example.com"}, traits[constants.TraitLogins],
		"logins trait must always be the computed username, not the raw email claim")
	require.Equal(t, []string{"alice@example.com"}, traits["email"])
	require.ElementsMatch(t, []string{"dev", "ops"}, traits["groups"],
		"non-string entries in a claim's array must be dropped, not stringified into garbage")
	require.Equal(t, []string{"example.com"}, traits["hd"])
	require.Equal(t, []string{"true"}, traits["email_verified"])
	require.NotContains(t, traits, "nested", "claims that don't reduce to strings must be dropped, not guessed at")
	require.NotContains(t, traits, "empty_string", "empty string claims must not produce an empty trait")
}

func TestOIDCClaimsToTraits_GroupsClaimIsWhatEverythingElseKeysOff(t *testing.T) {
	// This is the specific claim Keycloak is configured to emit (see
	// GOOGLE_SSO_PLAN.md); a regression here silently breaks every
	// claims_to_roles mapping in the fleet.
	traits := oidcClaimsToTraits(map[string]any{"groups": []any{"greyorange-eng"}}, "bob@example.com")
	require.Equal(t, []string{"greyorange-eng"}, traits["groups"])
}

func TestStringClaim(t *testing.T) {
	claims := map[string]any{
		"email": "alice@example.com",
		"count": 3,
	}

	v, err := stringClaim(claims, "email")
	require.NoError(t, err)
	require.Equal(t, "alice@example.com", v)

	_, err = stringClaim(claims, "missing")
	require.Error(t, err, "a missing claim must be an error, never treated as an empty match")

	_, err = stringClaim(claims, "count")
	require.Error(t, err, "a non-string claim value must be rejected rather than coerced")
}

func TestOIDCUsernameAndIdentity(t *testing.T) {
	connector, err := newTestOIDCConnector(t, "")
	require.NoError(t, err)

	t.Run("default username claim is email, verified", func(t *testing.T) {
		claims := &zoidc.IDTokenClaims{
			TokenClaims:   zoidc.TokenClaims{Subject: "sub-1"},
			UserInfoEmail: zoidc.UserInfoEmail{Email: "alice@example.com", EmailVerified: true},
		}
		claims.Claims = map[string]any{"email": "alice@example.com"}

		username, identity, err := oidcUsernameAndIdentity(connector, claims)
		require.NoError(t, err)
		require.Equal(t, "alice@example.com", username)
		require.Equal(t, "sub-1", identity.ID)
		require.Equal(t, "alice@example.com", identity.Email)
	})

	t.Run("unverified email is rejected by default", func(t *testing.T) {
		claims := &zoidc.IDTokenClaims{
			TokenClaims:   zoidc.TokenClaims{Subject: "sub-2"},
			UserInfoEmail: zoidc.UserInfoEmail{Email: "mallory@example.com", EmailVerified: false},
		}
		claims.Claims = map[string]any{"email": "mallory@example.com"}

		_, _, err := oidcUsernameAndIdentity(connector, claims)
		require.Error(t, err, "an unverified email must never become the Teleport username unless allow_unverified_email is set")
	})

	t.Run("missing username claim fails closed", func(t *testing.T) {
		claims := &zoidc.IDTokenClaims{TokenClaims: zoidc.TokenClaims{Subject: "sub-3"}}
		claims.Claims = map[string]any{}

		_, _, err := oidcUsernameAndIdentity(connector, claims)
		require.Error(t, err)
	})

	t.Run("allow_unverified_email opts out of the check", func(t *testing.T) {
		lenientConnector, err := newTestOIDCConnector(t, "")
		require.NoError(t, err)
		lenientConnector.Spec.AllowUnverifiedEmail = true

		claims := &zoidc.IDTokenClaims{
			TokenClaims:   zoidc.TokenClaims{Subject: "sub-4"},
			UserInfoEmail: zoidc.UserInfoEmail{Email: "trusted@example.com", EmailVerified: false},
		}
		claims.Claims = map[string]any{"email": "trusted@example.com"}

		username, _, err := oidcUsernameAndIdentity(lenientConnector, claims)
		require.NoError(t, err)
		require.Equal(t, "trusted@example.com", username)
	})

	t.Run("custom username_claim bypasses the email-verified check", func(t *testing.T) {
		byPreferredUsername, err := newTestOIDCConnector(t, "preferred_username")
		require.NoError(t, err)

		claims := &zoidc.IDTokenClaims{TokenClaims: zoidc.TokenClaims{Subject: "sub-5"}}
		claims.Claims = map[string]any{"preferred_username": "svc-account"}

		username, _, err := oidcUsernameAndIdentity(byPreferredUsername, claims)
		require.NoError(t, err)
		require.Equal(t, "svc-account", username)
	})
}

// newTestOIDCConnector builds a minimal, valid OIDC connector for the pure
// claim-mapping tests above -- no network access, no real Keycloak/Google
// endpoints involved.
func newTestOIDCConnector(t *testing.T, usernameClaim string) (*types.OIDCConnectorV3, error) {
	t.Helper()
	connector, err := types.NewOIDCConnector("test", types.OIDCConnectorSpecV3{
		IssuerURL:    "https://keycloak.example.com/realms/greyorange",
		ClientID:     "teleport",
		ClientSecret: "secret",
		RedirectURLs: []string{"https://teleport.example.com/v1/webapi/oidc/callback"},
		ClaimsToRoles: []types.ClaimMapping{
			{Claim: "groups", Value: "greyorange-eng", Roles: []string{"access"}},
		},
		UsernameClaim: usernameClaim,
	})
	if err != nil {
		return nil, err
	}
	return connector.(*types.OIDCConnectorV3), nil
}
