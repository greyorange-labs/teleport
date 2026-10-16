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

import { UnifiedResource } from 'teleport/services/agents';

import {
  getRequestableResourceName,
  needsAccessRequest,
} from './RequestAccessButton';

const node = {
  kind: 'node',
  id: 'node-uuid',
  hostname: 'host-1',
  requiresRequest: true,
} as UnifiedResource;

const desktop = {
  kind: 'linux_desktop',
  name: 'desktop-uuid',
  requiresRequest: true,
} as UnifiedResource;

describe('RequestAccessButton helpers', () => {
  it('identifies nodes by id and other resources by name', () => {
    expect(getRequestableResourceName(node)).toBe('node-uuid');
    expect(getRequestableResourceName(desktop)).toBe('desktop-uuid');
  });

  it('only asks for a request when the resource requires one', () => {
    expect(needsAccessRequest(node)).toBe(true);
    expect(needsAccessRequest(desktop)).toBe(true);
    expect(
      needsAccessRequest({ ...node, requiresRequest: false } as UnifiedResource)
    ).toBe(false);
    expect(
      needsAccessRequest({ kind: 'user_group', name: 'g' } as UnifiedResource)
    ).toBe(false);
  });
});
