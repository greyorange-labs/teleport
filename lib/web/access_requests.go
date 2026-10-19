// Teleport
// Copyright (C) 2026  GreyOrange
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package web

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gravitational/trace"
	"github.com/julienschmidt/httprouter"

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/httplib"
	"github.com/gravitational/teleport/lib/reversetunnelclient"
	"github.com/gravitational/teleport/lib/web/ui"
)

// The access request endpoints are served from the open source proxy. The
// community web UI only ships a locked placeholder for access requests, the
// real handlers are normally provided by the enterprise plugin.

// accessRequestResourceID identifies a resource in an access request create request.
type accessRequestResourceID struct {
	Kind            string `json:"kind"`
	Name            string `json:"name"`
	ClusterName     string `json:"clusterName"`
	SubResourceName string `json:"subResourceName,omitempty"`
}

// createAccessRequestRequest is the body of the create access request endpoint.
type createAccessRequestRequest struct {
	// Roles are the roles being requested.
	Roles []string `json:"roles"`
	// Resources are the resources being requested.
	Resources []accessRequestResourceID `json:"resources"`
	// Reason is the reason for the request.
	Reason string `json:"reason"`
	// SuggestedReviewers are users suggested to review the request.
	SuggestedReviewers []string `json:"suggestedReviewers"`
	// MaxDuration optionally limits how long access lasts after approval.
	MaxDuration *time.Time `json:"maxDuration"`
	// AssumeStartTime optionally delays when the access can be assumed.
	AssumeStartTime *time.Time `json:"assumeStartTime"`
	// DryRun validates the request without storing it.
	DryRun bool `json:"dryRun"`
}

// reviewAccessRequestRequest is the body of the review access request endpoint.
type reviewAccessRequestRequest struct {
	// State is either APPROVED or DENIED.
	State string `json:"state"`
	// Reason is an optional message that is attached to the review.
	Reason string `json:"reason"`
	// Roles optionally restricts which of the requested roles are approved.
	Roles []string `json:"roles"`
	// AssumeStartTime optionally overrides the requested assume start time.
	AssumeStartTime *time.Time `json:"assumeStartTime"`
}

// accessCapabilitiesRequest is the body of the access capabilities endpoint.
type accessCapabilitiesRequest struct {
	// Resources are the resources the user wants to request.
	Resources []accessRequestResourceID `json:"resources"`
}

// listAccessRequestsResponse is the response of the list access requests endpoint.
type listAccessRequestsResponse struct {
	Requests []ui.AccessRequest `json:"requests"`
	StartKey string             `json:"startKey"`
}

// accessCapabilitiesResponse is the response of the access capabilities endpoint.
type accessCapabilitiesResponse struct {
	RequestableRoles   []string `json:"requestableRoles"`
	ApplicableRoles    []string `json:"applicableRoles"`
	SuggestedReviewers []string `json:"suggestedReviewers"`
	RequestPrompt      string   `json:"requestPrompt"`
	RequireReason      bool     `json:"requireReason"`
	AutoRequest        bool     `json:"autoRequest"`
}

func toResourceIDs(in []accessRequestResourceID) []types.ResourceID {
	out := make([]types.ResourceID, 0, len(in))
	for _, r := range in {
		out = append(out, types.ResourceID{
			ClusterName:     r.ClusterName,
			Kind:            r.Kind,
			Name:            r.Name,
			SubResourceName: r.SubResourceName,
		})
	}
	return out
}

// accessRequestScope converts the `scope` query parameter to a request scope.
func accessRequestScope(v string) (types.AccessRequestScope, error) {
	switch v {
	case "", "default":
		return types.AccessRequestScope_DEFAULT, nil
	case "myRequests":
		return types.AccessRequestScope_MY_REQUESTS, nil
	case "needsReview":
		return types.AccessRequestScope_NEEDS_REVIEW, nil
	case "reviewed":
		return types.AccessRequestScope_REVIEWED, nil
	default:
		return 0, trace.BadParameter("unknown access request scope %q", v)
	}
}

// listAccessRequests returns a page of access requests visible to the user.
//
// GET /webapi/sites/:site/accessrequests?scope=myRequests|needsReview|reviewed&limit=&startKey=&search=
func (h *Handler) listAccessRequests(w http.ResponseWriter, r *http.Request, p httprouter.Params, sctx *SessionContext, site reversetunnelclient.Cluster) (any, error) {
	clt, err := sctx.GetUserClient(r.Context(), site)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	values := r.URL.Query()
	scope, err := accessRequestScope(values.Get("scope"))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	limit, err := QueryLimitAsInt32(values, "limit", defaults.MaxIterationLimit)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	resp, err := clt.ListAccessRequests(r.Context(), &proto.ListAccessRequestsRequest{
		Filter: &types.AccessRequestFilter{
			Scope:          scope,
			SearchKeywords: client.ParseSearchKeywords(values.Get("search"), ' '),
		},
		Sort:       proto.AccessRequestSort_CREATED,
		Descending: true,
		Limit:      limit,
		StartKey:   values.Get("startKey"),
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	requests := make([]ui.AccessRequest, 0, len(resp.AccessRequests))
	for _, req := range resp.AccessRequests {
		requests = append(requests, ui.MakeAccessRequest(req))
	}
	return listAccessRequestsResponse{Requests: requests, StartKey: resp.NextKey}, nil
}

// getAccessRequest returns a single access request.
//
// GET /webapi/sites/:site/accessrequests/:id
func (h *Handler) getAccessRequest(w http.ResponseWriter, r *http.Request, p httprouter.Params, sctx *SessionContext, site reversetunnelclient.Cluster) (any, error) {
	clt, err := sctx.GetUserClient(r.Context(), site)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	req, err := getAccessRequestByID(r, clt, p.ByName("id"))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return ui.MakeAccessRequest(req), nil
}

// createAccessRequest creates an access request, or validates it if dryRun is set.
//
// POST /webapi/sites/:site/accessrequests
func (h *Handler) createAccessRequest(w http.ResponseWriter, r *http.Request, p httprouter.Params, sctx *SessionContext, site reversetunnelclient.Cluster) (any, error) {
	var body createAccessRequestRequest
	if err := httplib.ReadResourceJSON(r, &body); err != nil {
		return nil, trace.Wrap(err)
	}
	if len(body.Roles) == 0 && len(body.Resources) == 0 {
		return nil, trace.BadParameter("at least one role or resource is required")
	}

	clt, err := sctx.GetUserClient(r.Context(), site)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	req, err := types.NewAccessRequestWithResources(
		uuid.NewString(), sctx.GetUser(), body.Roles, wrapResourceAccessIDs(toResourceIDs(body.Resources)),
	)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	req.SetRequestReason(body.Reason)
	req.SetSuggestedReviewers(body.SuggestedReviewers)
	if body.MaxDuration != nil {
		req.SetMaxDuration(*body.MaxDuration)
	}
	if body.AssumeStartTime != nil {
		req.SetAssumeStartTime(*body.AssumeStartTime)
	}
	req.SetDryRun(body.DryRun)

	created, err := clt.CreateAccessRequestV2(r.Context(), req)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return ui.MakeAccessRequest(created), nil
}

// deleteAccessRequest deletes an access request.
//
// DELETE /webapi/sites/:site/accessrequests/:id
func (h *Handler) deleteAccessRequest(w http.ResponseWriter, r *http.Request, p httprouter.Params, sctx *SessionContext, site reversetunnelclient.Cluster) (any, error) {
	clt, err := sctx.GetUserClient(r.Context(), site)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err := clt.DeleteAccessRequest(r.Context(), p.ByName("id")); err != nil {
		return nil, trace.Wrap(err)
	}
	return OK(), nil
}

// reviewAccessRequest approves or denies an access request. The auth server
// requires admin action MFA for reviews, the MFA response is taken from the
// request header by the web authentication layer.
//
// POST /webapi/sites/:site/accessrequests/:id/review
func (h *Handler) reviewAccessRequest(w http.ResponseWriter, r *http.Request, p httprouter.Params, sctx *SessionContext, site reversetunnelclient.Cluster) (any, error) {
	var body reviewAccessRequestRequest
	if err := httplib.ReadResourceJSON(r, &body); err != nil {
		return nil, trace.Wrap(err)
	}

	var state types.RequestState
	switch body.State {
	case types.RequestState_APPROVED.String():
		state = types.RequestState_APPROVED
	case types.RequestState_DENIED.String():
		state = types.RequestState_DENIED
	default:
		return nil, trace.BadParameter("review state must be %s or %s",
			types.RequestState_APPROVED, types.RequestState_DENIED)
	}

	clt, err := sctx.GetUserClient(r.Context(), site)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	updated, err := clt.SubmitAccessReview(r.Context(), types.AccessReviewSubmission{
		RequestID: p.ByName("id"),
		Review: types.AccessReview{
			Author:          sctx.GetUser(),
			ProposedState:   state,
			Reason:          body.Reason,
			Roles:           body.Roles,
			AssumeStartTime: body.AssumeStartTime,
		},
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return ui.MakeAccessRequest(updated), nil
}

// getAccessCapabilities returns the roles and reviewers the user can use
// to build an access request.
//
// POST /webapi/sites/:site/accesscapabilities
func (h *Handler) getAccessCapabilities(w http.ResponseWriter, r *http.Request, p httprouter.Params, sctx *SessionContext, site reversetunnelclient.Cluster) (any, error) {
	var body accessCapabilitiesRequest
	if err := httplib.ReadResourceJSON(r, &body); err != nil {
		return nil, trace.Wrap(err)
	}

	clt, err := sctx.GetUserClient(r.Context(), site)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	resourceIDs := toResourceIDs(body.Resources)
	caps, err := clt.GetAccessCapabilities(r.Context(), types.AccessCapabilitiesRequest{
		User:                             sctx.GetUser(),
		RequestableRoles:                 true,
		SuggestedReviewers:               true,
		ResourceIDs:                      resourceIDs,
		FilterRequestableRolesByResource: len(resourceIDs) > 0,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return accessCapabilitiesResponse{
		RequestableRoles:   nonNilStrings(caps.RequestableRoles),
		ApplicableRoles:    nonNilStrings(caps.ApplicableRolesForResources),
		SuggestedReviewers: nonNilStrings(caps.SuggestedReviewers),
		RequestPrompt:      caps.RequestPrompt,
		RequireReason:      caps.RequireReason,
		AutoRequest:        caps.AutoRequest,
	}, nil
}

func getAccessRequestByID(r *http.Request, clt interface {
	GetAccessRequests(ctx context.Context, filter types.AccessRequestFilter) ([]types.AccessRequest, error)
}, id string) (types.AccessRequest, error) {
	reqs, err := clt.GetAccessRequests(r.Context(), types.AccessRequestFilter{ID: id})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if len(reqs) != 1 {
		return nil, trace.NotFound("access request %q not found", id)
	}
	return reqs[0], nil
}

func wrapResourceAccessIDs(ids []types.ResourceID) []types.ResourceAccessID {
	out := make([]types.ResourceAccessID, 0, len(ids))
	for _, id := range ids {
		out = append(out, types.ResourceAccessID{Id: id})
	}
	return out
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
