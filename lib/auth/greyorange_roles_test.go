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

package auth_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/modules"
	"github.com/gravitational/teleport/lib/modules/modulestest"
)

// TestRoleFeatureSupportAccessRequests verifies that the access request role
// fields that the community build used to reject are accepted by default, and
// are still rejected when the workflow features are explicitly disabled.
func TestRoleFeatureSupportAccessRequests(t *testing.T) {
	t.Parallel()

	approver, err := types.NewRole("gor-approver", types.RoleSpecV6{
		Allow: types.RoleConditions{
			ReviewRequests: &types.AccessReviewConditions{Roles: []string{"gor-*-access"}},
		},
	})
	require.NoError(t, err)

	requester, err := types.NewRole("gor-requester", types.RoleSpecV6{
		Options: types.RoleOptions{RequestAccess: types.RequestStrategyReason},
		Allow: types.RoleConditions{
			Request: &types.AccessRequestConditions{
				Roles:         []string{"gor-node-access"},
				SearchAsRoles: []string{"gor-node-access"},
			},
		},
	})
	require.NoError(t, err)

	t.Run("default community modules", func(t *testing.T) {
		mod := modules.GetModules()
		require.Equal(t, modules.BuildOSS, mod.BuildType())
		require.NoError(t, auth.CheckRoleFeatureSupport(mod, approver))
		require.NoError(t, auth.CheckRoleFeatureSupport(mod, requester))
	})

	t.Run("features disabled", func(t *testing.T) {
		mod := &modulestest.Modules{TestBuildType: modules.BuildOSS}
		require.Error(t, auth.CheckRoleFeatureSupport(mod, approver))
		require.Error(t, auth.CheckRoleFeatureSupport(mod, requester))
	})
}
