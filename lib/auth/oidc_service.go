/*
 * Teleport
 * Copyright (C) 2026  GreyOrange Pte Ltd
 *
 * This file adds a generic OpenID Connect relying-party implementation to
 * Teleport Community Edition, which does not ship one -- see the
 * errOIDCNotImplemented sentinel in oidc.go. The equivalent implementation in
 * Gravitational's own tree lives in the private `e/` (Enterprise) submodule,
 * which is empty in this checkout and requires a commercial license to
 * obtain. This file is our own implementation, written from scratch against
 * the public OSS interfaces and modeled structurally on the OSS GitHub
 * connector (github.go) for consistency with upstream. See GOOGLE_SSO_PLAN.md
 * in the repository root for the full design and rationale.
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

package auth

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/gravitational/trace"
	oidcclient "github.com/zitadel/oidc/v3/pkg/client"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	zoidc "github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/oauth2"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/constants"
	apidefaults "github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	apiutils "github.com/gravitational/teleport/api/utils"
	"github.com/gravitational/teleport/api/utils/keys/hardwarekey"
	"github.com/gravitational/teleport/lib/auth/authclient"
	"github.com/gravitational/teleport/lib/authz"
	"github.com/gravitational/teleport/lib/client/sso"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/loginrule"
	teleoidc "github.com/gravitational/teleport/lib/oidc"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils"
)

// ErrOIDCNoRoles results from an OIDC user not being assigned any Teleport
// roles by the connector's claims_to_roles mapping. This is the fail-closed
// behavior for a missing or empty "groups" (or other mapped) claim too --
// there is no separate special case for it. A login that would otherwise map
// to zero roles is refused outright rather than silently succeeding with no
// access.
var ErrOIDCNoRoles = trace.AccessDenied("user does not have any roles mapped from claims_to_roles; check the connector configuration and the user's group membership at the identity provider")

// oidcRelyingParty implements OIDCService (see oidc.go) using Teleport's own
// generic OIDC relying-party flow, backed by the given Auth Server.
type oidcRelyingParty struct {
	a *Server
}

// NewOIDCService returns an OIDCService implementation backed by the given
// Auth Server. Wire it in via Server.SetOIDCService during server startup
// (lib/service/service.go), which is the same injection point Enterprise
// uses for its own OIDC implementation.
func NewOIDCService(a *Server) OIDCService {
	return &oidcRelyingParty{a: a}
}

// CreateOIDCAuthRequest creates a new request for the OIDC authorization code
// flow.
func (o *oidcRelyingParty) CreateOIDCAuthRequest(ctx context.Context, req types.OIDCAuthRequest) (*types.OIDCAuthRequest, error) {
	return o.a.createOIDCAuthRequest(ctx, req)
}

// CreateOIDCAuthRequestForMFA creates a new request for verifying an existing
// user's identity via their OIDC connector, for SSO MFA checks. This deployment
// does not enable SSO MFA (Teleport-registered WebAuthn devices are used for
// per-session MFA instead, see GOOGLE_SSO_PLAN.md), but this method is still
// reachable via BeginSSOMFAChallenge (lib/auth/sso_mfa.go) if a connector's
// mfa_settings are ever enabled, so it is implemented rather than left to
// panic or return an error unconditionally.
func (o *oidcRelyingParty) CreateOIDCAuthRequestForMFA(ctx context.Context, req types.OIDCAuthRequest) (*types.OIDCAuthRequest, error) {
	req.CheckUser = true
	return o.a.createOIDCAuthRequest(ctx, req)
}

// ValidateOIDCAuthCallback validates the callback redirect from the OIDC
// provider (via Keycloak, in this deployment) and, on success, either
// completes a login (issuing a web session and/or certificates) or, for
// SSO MFA requests, verifies the existing user's identity.
func (o *oidcRelyingParty) ValidateOIDCAuthCallback(ctx context.Context, q url.Values) (*authclient.OIDCAuthResponse, error) {
	diagCtx := NewSSODiagContext(types.KindOIDC, o.a)
	return validateOIDCAuthCallbackHelper(ctx, o.a, diagCtx, q, o.a.emitter, o.a.logger)
}

// oidcManager is the subset of *Server needed by validateOIDCAuthCallbackHelper,
// split out (mirroring githubManager in github.go) so the audit-event wrapper
// can be exercised independently of the full callback implementation.
type oidcManager interface {
	ValidateOIDCAuthRedirect(ctx context.Context, diagCtx *SSODiagContext, q url.Values) (*authclient.OIDCAuthResponse, error)
}

func validateOIDCAuthCallbackHelper(ctx context.Context, m oidcManager, diagCtx *SSODiagContext, q url.Values, emitter apievents.Emitter, logger *slog.Logger) (*authclient.OIDCAuthResponse, error) {
	event := &apievents.UserLogin{
		Metadata: apievents.Metadata{
			Type: events.UserLoginEvent,
		},
		Method:             events.LoginMethodOIDC,
		ConnectionMetadata: authz.ConnectionMetadata(ctx),
	}

	authResp, err := m.ValidateOIDCAuthRedirect(ctx, diagCtx, q)
	diagCtx.Info.Error = trace.UserMessage(err)
	event.AppliedLoginRules = diagCtx.Info.AppliedLoginRules

	diagCtx.WriteToBackend(ctx)

	if claims := diagCtx.Info.OIDCClaims; claims != nil {
		attributes, encErr := apievents.EncodeMap(claims)
		if encErr != nil {
			event.Status.UserMessage = fmt.Sprintf("Failed to encode identity attributes: %v", encErr.Error())
			logger.DebugContext(ctx, "Failed to encode identity attributes", "error", encErr)
		} else {
			event.IdentityAttributes = attributes
		}
	}

	if err != nil {
		event.Code = events.UserSSOLoginFailureCode
		if diagCtx.Info.TestFlow {
			event.Code = events.UserSSOTestFlowLoginFailureCode
		}
		event.Status.Success = false
		event.Status.Error = trace.Unwrap(err).Error()
		event.Status.UserMessage = err.Error()

		if emitErr := emitter.EmitAuditEvent(ctx, event); emitErr != nil {
			logger.WarnContext(ctx, "Failed to emit OIDC login failed event", "error", emitErr)
		}
		return nil, trace.Wrap(err)
	}

	event.Code = events.UserSSOLoginCode
	if diagCtx.Info.TestFlow {
		event.Code = events.UserSSOTestFlowLoginCode
	}
	event.Status.Success = true
	event.User = authResp.Username

	if emitErr := emitter.EmitAuditEvent(ctx, event); emitErr != nil {
		logger.WarnContext(ctx, "Failed to emit OIDC login event", "error", emitErr)
	}

	return authResp, nil
}

// getOIDCConnector resolves the connector for an auth request, handling the
// SSOTestFlow stateless-spec branch used by `tctl sso test`.
func (a *Server) getOIDCConnector(ctx context.Context, request types.OIDCAuthRequest) (types.OIDCConnector, error) {
	if request.SSOTestFlow {
		if request.ConnectorSpec == nil {
			return nil, trace.BadParameter("ConnectorSpec cannot be nil for SSOTestFlow")
		}
		if request.ConnectorID == "" {
			return nil, trace.BadParameter("ConnectorID cannot be empty")
		}

		// Stateless test flow: build an ephemeral connector from the spec
		// embedded in the request instead of reading a stored resource.
		connector, err := types.NewOIDCConnector(request.ConnectorID, *request.ConnectorSpec)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		return connector, nil
	}

	// Regular execution flow. GetOIDCConnector is promoted from the embedded
	// *Services, same as GetGithubConnector is for the GitHub connector.
	connector, err := a.GetOIDCConnector(ctx, request.ConnectorID, true)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return connector, nil
}

// createOIDCAuthRequest builds the authorization-code redirect URL for the
// given request and persists it, keyed by a freshly generated state token.
func (a *Server) createOIDCAuthRequest(ctx context.Context, req types.OIDCAuthRequest) (*types.OIDCAuthRequest, error) {
	connector, err := a.getOIDCConnector(ctx, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Requests for a web session originate from the proxy and are trusted;
	// requests for a client session (tsh login) must be checked, since they
	// point the browser away from the IdP or the web UI once authentication
	// completes. Mirrors CreateGithubAuthRequest exactly.
	if !req.CreateWebSession {
		ceremonyType := sso.CeremonyTypeLogin
		if req.SSOTestFlow {
			ceremonyType = sso.CeremonyTypeTest
		}
		if err := sso.ValidateClientRedirect(req.ClientRedirectURL, ceremonyType, connector.GetClientRedirectSettings()); err != nil {
			return nil, trace.Wrap(err, InvalidClientRedirectErrorMessage)
		}
	}

	req.StateToken, err = utils.CryptoRandomHex(defaults.TokenLenBytes)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// PKCE is used unconditionally, regardless of the connector's PKCEMode
	// setting -- that field has no consumer anywhere in this implementation.
	// The console/tester client generates its own verifier and supplies it on
	// the request; the web flow has no client-side OAuth2 code to do that, so
	// the auth service generates one here instead.
	if req.PkceVerifier == "" {
		req.PkceVerifier = oauth2.GenerateVerifier()
	}

	redirectURL, err := services.GetRedirectURL(connector, req.ProxyAddress)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	discovery, err := discoverOIDCProvider(ctx, connector.GetIssuerURL())
	if err != nil {
		return nil, trace.Wrap(err, "discovering OIDC provider configuration")
	}

	oauthCfg := newOIDCOAuth2Config(connector, discovery, redirectURL)

	authCodeOpts := []oauth2.AuthCodeOption{
		oauth2.S256ChallengeOption(req.PkceVerifier),
		// The state token doubles as the OIDC nonce. It is already a
		// single-use, cryptographically random value bound to exactly one
		// stored auth request, which gives the same replay protection a
		// dedicated nonce field would -- types.OIDCAuthRequest has no
		// separate Nonce field, and adding one would mean hand-editing
		// generated protobuf code for a property with an existing equivalent.
		oauth2.SetAuthURLParam("nonce", req.StateToken),
	}
	if prompt := connector.GetPrompt(); prompt != "" {
		authCodeOpts = append(authCodeOpts, oauth2.SetAuthURLParam("prompt", prompt))
	}
	if acr := connector.GetACR(); acr != "" {
		authCodeOpts = append(authCodeOpts, oauth2.SetAuthURLParam("acr_values", acr))
	}
	if req.LoginHint != "" {
		authCodeOpts = append(authCodeOpts, oauth2.SetAuthURLParam("login_hint", req.LoginHint))
	}

	req.RedirectURL = oauthCfg.AuthCodeURL(req.StateToken, authCodeOpts...)

	a.logger.DebugContext(ctx, "Creating OIDC auth request", "redirect_url", req.RedirectURL)

	if err := a.Services.CreateOIDCAuthRequest(ctx, req, defaults.OIDCAuthRequestTTL); err != nil {
		return nil, trace.Wrap(err)
	}
	return &req, nil
}

// discoverOIDCProvider fetches the provider's OpenID Connect discovery
// document (issuer + "/.well-known/openid-configuration").
func discoverOIDCProvider(ctx context.Context, issuerURL string) (*zoidc.DiscoveryConfiguration, error) {
	ctx, cancel := context.WithTimeout(ctx, defaults.HTTPRequestTimeout)
	defer cancel()
	dc, err := oidcclient.Discover(ctx, issuerURL, http.DefaultClient)
	return dc, trace.Wrap(err)
}

// newOIDCOAuth2Config builds the OAuth2 client config for a connector from
// its own settings plus the provider's discovered endpoints.
func newOIDCOAuth2Config(connector types.OIDCConnector, discovery *zoidc.DiscoveryConfiguration, redirectURL string) oauth2.Config {
	scopes := apiutils.Deduplicate(append([]string{zoidc.ScopeOpenID, zoidc.ScopeEmail, zoidc.ScopeProfile}, connector.GetScope()...))
	return oauth2.Config{
		ClientID:     connector.GetClientID(),
		ClientSecret: connector.GetClientSecret(),
		RedirectURL:  redirectURL,
		Scopes:       scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  discovery.AuthorizationEndpoint,
			TokenURL: discovery.TokenEndpoint,
		},
	}
}

// ValidateOIDCAuthRedirect validates the OIDC callback redirect: exchanges
// the authorization code for a verified ID token, computes the Teleport
// username/traits/roles from its claims, and either verifies an existing
// user's identity (SSO MFA) or creates/updates the user and issues a session
// and/or certificates. Mirrors ValidateGithubAuthRedirect's structure.
func (a *Server) ValidateOIDCAuthRedirect(ctx context.Context, diagCtx *SSODiagContext, q url.Values) (*authclient.OIDCAuthResponse, error) {
	if errParam := q.Get("error"); errParam != "" {
		// Try to find the request so the error gets logged against it.
		if state := q.Get("state"); state != "" {
			diagCtx.RequestID = state
			if req, err := a.Services.GetOIDCAuthRequest(ctx, state); err == nil {
				diagCtx.Info.TestFlow = req.SSOTestFlow
			}
		}

		errDesc := q.Get("error_description")
		oauthErr := trace.OAuth2("invalid_request", errParam, q)
		return nil, trace.WithUserMessage(oauthErr, "Identity provider returned error: %v [%v]", errDesc, errParam)
	}

	code := q.Get("code")
	if code == "" {
		oauthErr := trace.OAuth2("invalid_request", "code query param must be set", q)
		return nil, trace.WithUserMessage(oauthErr, "Invalid parameters received from the identity provider.")
	}

	stateToken := q.Get("state")
	if stateToken == "" {
		oauthErr := trace.OAuth2("invalid_request", "missing state query param", q)
		return nil, trace.WithUserMessage(oauthErr, "Invalid parameters received from the identity provider.")
	}
	diagCtx.RequestID = stateToken

	req, err := a.Services.GetOIDCAuthRequest(ctx, stateToken)
	if err != nil {
		return nil, trace.Wrap(err, "Failed to get OIDC Auth Request.")
	}
	diagCtx.Info.TestFlow = req.SSOTestFlow

	connector, err := a.getOIDCConnector(ctx, *req)
	if err != nil {
		return nil, trace.Wrap(err, "Failed to get OIDC connector.")
	}
	diagCtx.Info.OIDCConnectorTraitMapping = connector.GetTraitMappings()
	a.logger.DebugContext(ctx, "OIDC connector found", "connector", connector.GetName())

	redirectURL, err := services.GetRedirectURL(connector, req.ProxyAddress)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	claims, err := a.exchangeOIDCCode(ctx, connector, redirectURL, code, req.PkceVerifier, req.StateToken)
	if err != nil {
		return nil, trace.Wrap(err, "Failed to exchange OIDC code for identity.")
	}
	diagCtx.Info.OIDCClaims = types.OIDCClaims(claims.Claims)

	params, identity, err := a.calculateOIDCUser(ctx, diagCtx, connector, claims, req)
	if err != nil {
		return nil, trace.Wrap(err, "Failed to calculate user attributes.")
	}
	diagCtx.Info.OIDCIdentity = &identity

	diagCtx.Info.CreateUserParams = &types.CreateUserParams{
		ConnectorName: params.ConnectorName,
		Username:      params.Username,
		Roles:         params.Roles,
		Traits:        params.Traits,
		SessionTTL:    types.Duration(params.SessionTTL),
	}

	// SSO MFA verification: do not create or update the user, just confirm
	// they already exist and that this identity belongs to them. See the
	// CreateOIDCAuthRequestForMFA doc comment -- this path is not exercised
	// by this deployment's supported configuration.
	if req.CheckUser {
		return a.makeOIDCAuthResponseForMFA(ctx, req, params.Username, identity)
	}

	user, err := a.createOIDCUser(ctx, params, req.SSOTestFlow)
	if err != nil {
		return nil, trace.Wrap(err, "Failed to create user from provided parameters.")
	}

	if err := a.CallLoginHooks(ctx, user); err != nil {
		return nil, trace.Wrap(err)
	}

	userState, err := a.GetUserOrLoginState(ctx, user.GetName())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// In test flow, skip signing and creating web sessions.
	if req.SSOTestFlow {
		diagCtx.Info.Success = true
		return &authclient.OIDCAuthResponse{
			Req:      OIDCAuthRequestFromProto(req),
			Identity: oidcExternalIdentity(params.ConnectorName, params.Username, identity),
			Username: params.Username,
		}, nil
	}

	return a.makeOIDCAuthResponse(ctx, req, userState, identity, params.SessionTTL)
}

// exchangeOIDCCode exchanges the authorization code for a token and returns
// the verified ID token claims.
func (a *Server) exchangeOIDCCode(ctx context.Context, connector types.OIDCConnector, redirectURL, code, pkceVerifier, nonce string) (*zoidc.IDTokenClaims, error) {
	discovery, err := discoverOIDCProvider(ctx, connector.GetIssuerURL())
	if err != nil {
		return nil, trace.Wrap(err, "discovering OIDC provider configuration")
	}

	oauthCfg := newOIDCOAuth2Config(connector, discovery, redirectURL)

	token, err := oauthCfg.Exchange(ctx, code, oauth2.VerifierOption(pkceVerifier))
	if err != nil {
		return nil, trace.Wrap(err, "exchanging authorization code for a token")
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, trace.BadParameter("identity provider's token response did not include an id_token")
	}

	claims, err := teleoidc.ValidateToken[*zoidc.IDTokenClaims](
		ctx, connector.GetIssuerURL(), connector.GetClientID(), rawIDToken,
		rp.WithNonce(func(context.Context) string { return nonce }),
	)
	if err != nil {
		return nil, trace.Wrap(err, "verifying id_token")
	}

	if claims.Claims == nil {
		claims.Claims = make(map[string]any)
	}

	return claims, nil
}

// calculateOIDCUser figures out the username, roles, traits and session TTL
// for a user from their verified ID token claims, and creates the user in
// the backend. Mirrors calculateGithubUser.
func (a *Server) calculateOIDCUser(ctx context.Context, diagCtx *SSODiagContext, connector types.OIDCConnector, claims *zoidc.IDTokenClaims, request *types.OIDCAuthRequest) (*CreateUserParams, types.OIDCIdentity, error) {
	username, identity, err := oidcUsernameAndIdentity(connector, claims)
	if err != nil {
		return nil, types.OIDCIdentity{}, trace.Wrap(err)
	}

	p := CreateUserParams{
		ConnectorName: connector.GetName(),
		Username:      username,
		UserID:        identity.ID,
	}

	// Every claim in the verified ID token becomes a trait (e.g. Keycloak's
	// "groups" claim), plus the standard "logins" trait bound to the
	// computed username. There is no Login Rules equivalent available in
	// Teleport Community Edition to reshape claims after this point
	// (lib/auth/loginrule returns ErrRequiresEnterprise for every RPC in
	// OSS), so this is the only place traits are ever set.
	p.Traits = oidcClaimsToTraits(claims.Claims, username)

	evaluationInput := &loginrule.EvaluationInput{Traits: p.Traits}
	evaluationOutput, err := a.GetLoginRuleEvaluator().Evaluate(ctx, evaluationInput)
	if err != nil {
		return nil, types.OIDCIdentity{}, trace.Wrap(err)
	}
	p.Traits = evaluationOutput.Traits
	diagCtx.Info.AppliedLoginRules = evaluationOutput.AppliedRules
	diagCtx.Info.OIDCTraitsFromClaims = p.Traits

	mappings := connector.GetTraitMappings()
	diagCtx.Info.OIDCClaimsToRoles = connector.GetClaimsToRoles()

	warnings, roles := services.TraitsToRoles(mappings, p.Traits)
	if len(warnings) > 0 {
		diagCtx.Info.OIDCClaimsToRolesWarnings = &types.SSOWarnings{
			Message:  "Some claims_to_roles mappings did not match any of the user's claims",
			Warnings: warnings,
		}
	}
	if len(roles) == 0 {
		return nil, types.OIDCIdentity{}, trace.Wrap(ErrOIDCNoRoles)
	}
	p.Roles = roles

	roleSet, err := services.FetchRolesWithContext(p.Roles, a, services.RoleTemplateContext{
		Username: p.Username,
		Traits:   p.Traits,
	})
	if err != nil {
		return nil, types.OIDCIdentity{}, trace.Wrap(err)
	}
	roleTTL := roleSet.AdjustSessionTTL(apidefaults.MaxCertDuration)
	p.SessionTTL = utils.MinTTL(roleTTL, request.CertTTL)

	return &p, identity, nil
}

// oidcUsernameAndIdentity derives the Teleport username and the external
// identity record from a verified ID token's claims.
func oidcUsernameAndIdentity(connector types.OIDCConnector, claims *zoidc.IDTokenClaims) (string, types.OIDCIdentity, error) {
	usernameClaim := connector.GetUsernameClaim()
	if usernameClaim == "" {
		usernameClaim = "email"
	}

	username, err := stringClaim(claims.Claims, usernameClaim)
	if err != nil || username == "" {
		return "", types.OIDCIdentity{}, trace.AccessDenied(
			"claim %q is not present (or is empty) in the identity provider's response; cannot determine username", usernameClaim)
	}

	// Guard against spoofed/unverified email addresses being used as the
	// Teleport username, unless the connector has explicitly opted out.
	if usernameClaim == "email" && !connector.GetAllowUnverifiedEmail() && !bool(claims.EmailVerified) {
		return "", types.OIDCIdentity{}, trace.AccessDenied(
			"email %q is not marked as verified by the identity provider; set allow_unverified_email on the connector to bypass this check", claims.Email)
	}

	identity := types.OIDCIdentity{
		ID:        claims.Subject,
		Email:     claims.Email,
		ExpiresAt: claims.GetExpiration(),
	}

	return username, identity, nil
}

// stringClaim reads a named claim as a string.
func stringClaim(claims map[string]any, name string) (string, error) {
	v, ok := claims[name]
	if !ok {
		return "", trace.NotFound("claim %q not present", name)
	}
	s, ok := v.(string)
	if !ok {
		return "", trace.BadParameter("claim %q is not a string (got %T)", name, v)
	}
	return s, nil
}

// oidcClaimsToTraits converts every claim in a verified ID token into a
// Teleport trait, so that claims_to_roles, request.claims_to_roles, and
// {{external.<trait>}} interpolation can all key off any claim the identity
// provider sends -- notably Keycloak's "groups" claim. The "logins" trait is
// always set explicitly to the computed username, matching every other
// Teleport connector.
func oidcClaimsToTraits(claims map[string]any, username string) map[string][]string {
	traits := make(map[string][]string, len(claims)+1)
	for name, value := range claims {
		if vs := claimValueToStrings(value); len(vs) > 0 {
			traits[name] = vs
		}
	}
	traits[constants.TraitLogins] = []string{username}
	return traits
}

// claimValueToStrings converts a single claim's decoded JSON value into
// trait values. Claims that don't reduce sensibly to strings (nested
// objects) are dropped rather than guessed at.
func claimValueToStrings(value any) []string {
	switch v := value.(type) {
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case bool:
		return []string{strconv.FormatBool(v)}
	case float64:
		return []string{strconv.FormatFloat(v, 'f', -1, 64)}
	default:
		return nil
	}
}

// createOIDCUser creates or updates the Teleport user for a successful OIDC
// login. Mirrors createGithubUser exactly, substituting OIDCIdentities and
// constants.OIDC for their GitHub equivalents.
func (a *Server) createOIDCUser(ctx context.Context, p *CreateUserParams, dryRun bool) (types.User, error) {
	a.logger.DebugContext(ctx, "Generating dynamic OIDC identity",
		"connector_name", p.ConnectorName,
		"user_name", p.Username,
		"role", p.Roles,
		"dry_run", dryRun,
	)

	expires := a.GetClock().Now().UTC().Add(p.SessionTTL)

	user := &types.UserV2{
		Kind:    types.KindUser,
		Version: types.V2,
		Metadata: types.Metadata{
			Name:      p.Username,
			Namespace: apidefaults.Namespace,
			Expires:   &expires,
		},
		Spec: types.UserSpecV2{
			Roles:  p.Roles,
			Traits: p.Traits,
			OIDCIdentities: []types.ExternalIdentity{{
				ConnectorID: p.ConnectorName,
				Username:    p.Username,
				UserID:      p.UserID,
			}},
			CreatedBy: types.CreatedBy{
				User: types.UserRef{Name: teleport.UserSystem},
				Time: a.GetClock().Now().UTC(),
				Connector: &types.ConnectorRef{
					Type:     constants.OIDC,
					ID:       p.ConnectorName,
					Identity: p.Username,
				},
			},
		},
	}

	if dryRun {
		return user, nil
	}

	existingUser, err := a.Services.GetUser(ctx, p.Username, false)
	if err != nil && !trace.IsNotFound(err) {
		return nil, trace.Wrap(err)
	}

	if existingUser != nil {
		ref := user.GetCreatedBy().Connector
		if !ref.IsSameProvider(existingUser.GetCreatedBy().Connector) {
			return nil, trace.AlreadyExists("local user %q already exists and is not an OIDC user",
				existingUser.GetName())
		}

		user.SetRevision(existingUser.GetRevision())
		if _, err := a.UpdateUser(ctx, user); err != nil {
			return nil, trace.Wrap(err)
		}
	} else {
		if _, err := a.CreateUser(ctx, user); err != nil {
			return nil, trace.Wrap(err)
		}
	}

	return user, nil
}

// makeOIDCAuthResponse builds the final response for a successful login:
// a web session (browser flow) and/or issued certificates (console flow).
// Mirrors makeGithubAuthResponse.
func (a *Server) makeOIDCAuthResponse(
	ctx context.Context,
	req *types.OIDCAuthRequest,
	userState services.UserState,
	identity types.OIDCIdentity,
	sessionTTL time.Duration,
) (*authclient.OIDCAuthResponse, error) {
	resp := authclient.OIDCAuthResponse{
		Req:      OIDCAuthRequestFromProto(req),
		Identity: oidcExternalIdentity(req.ConnectorID, userState.GetName(), identity),
		Username: userState.GetName(),
	}

	// If the request is coming from a browser, create a web session.
	if req.CreateWebSession {
		session, err := a.CreateWebSessionFromReq(ctx, NewWebSessionRequest{
			User:                 userState.GetName(),
			Roles:                userState.GetRoles(),
			Traits:               userState.GetTraits(),
			SessionTTL:           sessionTTL,
			LoginTime:            a.clock.Now().UTC(),
			LoginIP:              req.ClientLoginIP,
			LoginUserAgent:       req.ClientUserAgent,
			AttestWebSession:     true,
			CreateDeviceWebToken: true,
			Scope:                req.Scope,
		})
		if err != nil {
			return nil, trace.Wrap(err, "Failed to create web session.")
		}
		resp.Session = session
	}

	// If a public key was provided, sign it and return a certificate.
	if len(req.SshPublicKey) != 0 || len(req.TlsPublicKey) != 0 {
		sshCert, tlsCert, err := a.CreateSessionCerts(ctx, &SessionCertsRequest{
			UserState:               userState,
			SessionTTL:              sessionTTL,
			SSHPubKey:               req.SshPublicKey,
			TLSPubKey:               req.TlsPublicKey,
			SSHAttestationStatement: hardwarekey.AttestationStatementFromProto(req.SshAttestationStatement),
			TLSAttestationStatement: hardwarekey.AttestationStatementFromProto(req.TlsAttestationStatement),
			Compatibility:           req.Compatibility,
			RouteToCluster:          req.RouteToCluster,
			KubernetesCluster:       req.KubernetesCluster,
			LoginIP:                 req.ClientLoginIP,
			Scope:                   req.Scope,
		})
		if err != nil {
			return nil, trace.Wrap(err, "Failed to create session certificate.")
		}

		clusterName, err := a.GetClusterName(ctx)
		if err != nil {
			return nil, trace.Wrap(err, "Failed to obtain cluster name.")
		}

		resp.Cert = sshCert
		resp.TLSCert = tlsCert

		// Return the host CA for this cluster only.
		authority, err := a.GetCertAuthority(ctx, types.CertAuthID{
			Type:       types.HostCA,
			DomainName: clusterName.GetClusterName(),
		}, false)
		if err != nil {
			return nil, trace.Wrap(err, "Failed to obtain cluster's host CA.")
		}
		resp.HostSigners = append(resp.HostSigners, authority)
	}

	if o, err := a.ClientOptionsForLogin(userState); err == nil {
		resp.ClientOptions = o
	} else {
		a.logger.WarnContext(ctx, "Failed to calculate client options for OIDC login", "username", userState.GetName(), "error", err)
	}

	return &resp, nil
}

// makeOIDCAuthResponseForMFA verifies an existing user's identity for an SSO
// MFA challenge (see BeginSSOMFAChallenge in sso_mfa.go) without creating or
// updating the user or issuing a session/certificate, and mints the MFA
// token that VerifySSOMFASession checks. This path is not exercised by this
// deployment's supported configuration -- see the doc comment on
// CreateOIDCAuthRequestForMFA.
func (a *Server) makeOIDCAuthResponseForMFA(ctx context.Context, req *types.OIDCAuthRequest, username string, identity types.OIDCIdentity) (*authclient.OIDCAuthResponse, error) {
	existingUser, err := a.Services.GetUser(ctx, username, false)
	if err != nil {
		return nil, trace.Wrap(err, "MFA verification failed: user %q not found", username)
	}

	sessionData, err := a.GetMFASessionData(ctx, req.StateToken)
	if err != nil {
		return nil, trace.Wrap(err, "MFA verification failed: no pending MFA session")
	}
	if sessionData.Username != username {
		return nil, trace.AccessDenied("MFA verification failed: identity provider identity does not match the user who requested the challenge")
	}

	token, err := utils.CryptoRandomHex(defaults.TokenLenBytes)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	sessionData.Token = token
	if err := a.UpsertMFASessionData(ctx, sessionData); err != nil {
		return nil, trace.Wrap(err)
	}

	return &authclient.OIDCAuthResponse{
		Req:      OIDCAuthRequestFromProto(req),
		Identity: oidcExternalIdentity(req.ConnectorID, username, identity),
		Username: existingUser.GetName(),
		MFAToken: token,
	}, nil
}

// OIDCAuthRequestFromProto converts the types.OIDCAuthRequest to the
// client-facing authclient.OIDCAuthRequest. Mirrors GithubAuthRequestFromProto.
func OIDCAuthRequestFromProto(req *types.OIDCAuthRequest) authclient.OIDCAuthRequest {
	return authclient.OIDCAuthRequest{
		ConnectorID:       req.ConnectorID,
		SSHPubKey:         req.SshPublicKey,
		TLSPubKey:         req.TlsPublicKey,
		CSRFToken:         req.CSRFToken,
		CreateWebSession:  req.CreateWebSession,
		ClientRedirectURL: req.ClientRedirectURL,
	}
}

// oidcExternalIdentity builds the ExternalIdentity record stored on the user
// and returned to the caller.
func oidcExternalIdentity(connectorID, username string, identity types.OIDCIdentity) types.ExternalIdentity {
	return types.ExternalIdentity{
		ConnectorID: connectorID,
		Username:    username,
		UserID:      identity.ID,
	}
}
