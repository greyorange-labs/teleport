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

package modules

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/entitlements"
)

// TestDefaultModulesEnableAccessRequests verifies that the default (community)
// modules enable the access request workflow features, with no monthly limit.
func TestDefaultModulesEnableAccessRequests(t *testing.T) {
	t.Parallel()

	features := (&defaultModules{}).Features()

	require.True(t, features.AdvancedAccessWorkflows)
	require.Equal(t,
		EntitlementInfo{Enabled: true, Limit: 0},
		features.Entitlements[entitlements.AccessRequests],
	)
	// Unrelated enterprise features stay off.
	require.False(t, features.Entitlements[entitlements.OIDC].Enabled)
	require.False(t, features.Entitlements[entitlements.SAML].Enabled)
}
