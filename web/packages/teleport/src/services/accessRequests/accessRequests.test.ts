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

import { http, HttpResponse } from 'msw';

import { enableMswServer, server } from 'design/utils/testing';

import cfg from 'teleport/config';

import { accessRequestsService } from './accessRequests';

enableMswServer();

const apiRequest = {
  id: 'req-1',
  state: 'PENDING',
  user: 'requester',
  userInfo: { username: 'requester' },
  created: '2026-10-16T10:00:00Z',
  expires: '2026-10-16T18:00:00Z',
  roles: ['gor-node-access'],
  requestReason: 'debug node',
  reviews: [],
  suggestedReviewersInfo: [],
  resources: [],
};

describe('accessRequestsService', () => {
  it('lists requests for a scope', async () => {
    let scope: string | null = null;
    server.use(
      http.get(cfg.getAccessRequestsUrl('im-a-cluster'), ({ request }) => {
        scope = new URL(request.url).searchParams.get('scope');
        return HttpResponse.json({ requests: [apiRequest], startKey: '' });
      })
    );

    const requests = await accessRequestsService.list(
      'im-a-cluster',
      'needsReview'
    );

    expect(scope).toBe('needsReview');
    expect(requests).toHaveLength(1);
    expect(requests[0]).toMatchObject({
      id: 'req-1',
      user: 'requester',
      roles: ['gor-node-access'],
      requestReason: 'debug node',
    });
  });

  it('creates a request with roles and a resource', async () => {
    let body: any;
    server.use(
      http.post(
        cfg.getAccessRequestsUrl('im-a-cluster'),
        async ({ request }) => {
          body = await request.json();
          return HttpResponse.json(apiRequest);
        }
      )
    );

    const created = await accessRequestsService.create('im-a-cluster', {
      roles: ['gor-node-access'],
      resources: [
        { kind: 'node', name: 'node-uuid', clusterName: 'im-a-cluster' },
      ],
      reason: 'debug node',
    });

    expect(created.id).toBe('req-1');
    expect(body).toMatchObject({
      roles: ['gor-node-access'],
      reason: 'debug node',
      dryRun: false,
      resources: [
        { kind: 'node', name: 'node-uuid', clusterName: 'im-a-cluster' },
      ],
    });
  });

  it('submits a review', async () => {
    let body: any;
    server.use(
      http.post(
        cfg.getAccessRequestReviewUrl('im-a-cluster', 'req-1'),
        async ({ request }) => {
          body = await request.json();
          return HttpResponse.json({ ...apiRequest, state: 'APPROVED' });
        }
      )
    );

    const reviewed = await accessRequestsService.review(
      'im-a-cluster',
      'req-1',
      { state: 'APPROVED', reason: 'ok' }
    );

    expect(reviewed.state).toBe('APPROVED');
    expect(body).toMatchObject({ state: 'APPROVED', reason: 'ok' });
  });
});
