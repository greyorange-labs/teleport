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
	"encoding/json"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/web/ui"
)

func TestAccessRequestEndpoints(t *testing.T) {
	ctx := t.Context()
	env := newWebPack(t, 1)
	proxy := env.proxies[0]

	grantRole, err := types.NewRole("gor-node-access", types.RoleSpecV6{
		Allow: types.RoleConditions{Logins: []string{"root"}},
	})
	require.NoError(t, err)

	requesterRole, err := types.NewRole("gor-requester", types.RoleSpecV6{
		Options: types.RoleOptions{RequestAccess: types.RequestStrategyReason},
		Allow: types.RoleConditions{
			Request: &types.AccessRequestConditions{Roles: []string{"gor-node-access"}},
		},
	})
	require.NoError(t, err)

	approverRole, err := types.NewRole("gor-approver", types.RoleSpecV6{
		Allow: types.RoleConditions{
			ReviewRequests: &types.AccessReviewConditions{Roles: []string{"gor-node-access"}},
		},
	})
	require.NoError(t, err)

	for _, role := range []types.Role{grantRole, requesterRole, approverRole} {
		_, err = env.server.Auth().UpsertRole(ctx, role)
		require.NoError(t, err)
	}

	requester := proxy.authPack(t, "requester", []types.Role{requesterRole})
	approver := proxy.authPack(t, "approver", []types.Role{approverRole})
	site := env.server.ClusterName()
	listEndpoint := requester.clt.Endpoint("webapi", "sites", site, "accessrequests")

	// The requester creates a request for the grant role.
	resp, err := requester.clt.PostJSON(ctx, listEndpoint, createAccessRequestRequest{
		Roles:  []string{"gor-node-access"},
		Reason: "need to debug node",
	})
	require.NoError(t, err)
	var created ui.AccessRequest
	require.NoError(t, json.Unmarshal(resp.Bytes(), &created))
	require.NotEmpty(t, created.ID)
	require.Equal(t, "requester", created.User)
	require.Equal(t, "PENDING", created.State)
	require.Equal(t, []string{"gor-node-access"}, created.Roles)
	require.Equal(t, "need to debug node", created.RequestReason)

	// A request without any role or resource is rejected.
	_, err = requester.clt.PostJSON(ctx, listEndpoint, createAccessRequestRequest{Reason: "nothing"})
	require.Error(t, err)

	listRequests := func(pack *authPack, scope string) []ui.AccessRequest {
		t.Helper()
		resp, err := pack.clt.Get(ctx, listEndpoint, url.Values{"scope": []string{scope}})
		require.NoError(t, err)
		var out listAccessRequestsResponse
		require.NoError(t, json.Unmarshal(resp.Bytes(), &out))
		return out.Requests
	}

	// The request shows up for the requester and for the approver's review queue.
	require.Len(t, listRequests(requester, "myRequests"), 1)
	needsReview := listRequests(approver, "needsReview")
	require.Len(t, needsReview, 1)
	require.Equal(t, created.ID, needsReview[0].ID)

	// The requester cannot review requests.
	reviewEndpoint := requester.clt.Endpoint("webapi", "sites", site, "accessrequests", created.ID, "review")
	_, err = requester.clt.PostJSON(ctx, reviewEndpoint, reviewAccessRequestRequest{State: "APPROVED"})
	require.Error(t, err)

	// An invalid review state is rejected before reaching the auth server.
	_, err = approver.clt.PostJSON(ctx, reviewEndpoint, reviewAccessRequestRequest{State: "PENDING"})
	require.Error(t, err)

	// The approver approves the request.
	resp, err = approver.clt.PostJSON(ctx, reviewEndpoint, reviewAccessRequestRequest{State: "APPROVED", Reason: "ok"})
	require.NoError(t, err)
	var approved ui.AccessRequest
	require.NoError(t, json.Unmarshal(resp.Bytes(), &approved))
	require.Equal(t, "APPROVED", approved.State)
	require.Len(t, approved.Reviews, 1)
	require.Equal(t, "approver", approved.Reviews[0].Author)

	// The requester can fetch the resolved request.
	resp, err = requester.clt.Get(ctx, requester.clt.Endpoint("webapi", "sites", site, "accessrequests", created.ID), url.Values{})
	require.NoError(t, err)
	var got ui.AccessRequest
	require.NoError(t, json.Unmarshal(resp.Bytes(), &got))
	require.Equal(t, "APPROVED", got.State)
}
