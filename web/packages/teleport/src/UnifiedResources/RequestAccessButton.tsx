/**
 * Teleport
 * Copyright (C) 2026  GreyOrange
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

import { useNavigate } from 'react-router';

import { ButtonBorder } from 'design';

import cfg from 'teleport/config';
import { UnifiedResource } from 'teleport/services/agents';

/** Returns the name that identifies the resource in an access request. */
export function getRequestableResourceName(
  resource: UnifiedResource
): string | undefined {
  switch (resource.kind) {
    case 'node':
      return resource.id;
    case 'app':
    case 'db':
    case 'kube_cluster':
    case 'windows_desktop':
    case 'linux_desktop':
      return resource.name;
    default:
      return undefined;
  }
}

/** Whether the resource is visible to the user only through a request. */
export function needsAccessRequest(resource: UnifiedResource): boolean {
  return (
    'requiresRequest' in resource &&
    !!resource.requiresRequest &&
    getRequestableResourceName(resource) !== undefined
  );
}

/** RequestAccessButton opens the new access request page for a resource. */
export function RequestAccessButton({
  resource,
}: {
  resource: UnifiedResource;
}) {
  const navigate = useNavigate();
  const name = getRequestableResourceName(resource);
  if (!name) {
    return null;
  }

  const params = new URLSearchParams({ kind: resource.kind, name });
  return (
    <ButtonBorder
      size="small"
      onClick={() => navigate(`${cfg.routes.newAccessRequest}?${params}`)}
    >
      Request Access
    </ButtonBorder>
  );
}
