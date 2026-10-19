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

import { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router';

import { Alert, ButtonPrimary, ButtonSecondary, Flex } from 'design';
import Table, { Cell } from 'design/DataTable';
import { displayDateTime } from 'design/datetime';
import {
  renderIdCell,
  renderStatusCell,
  renderUserCell,
} from 'shared/components/AccessRequests/ReviewRequests';
import { getResourcesOrRolesFromRequest } from 'shared/components/AccessRequests/Shared/Shared';
// eslint-disable-next-line no-restricted-imports -- RequestView and the shared access request components take useAsync Attempts
import { useAsync } from 'shared/hooks/useAsync';
import { AccessRequest } from 'shared/services/accessRequests';

import {
  FeatureBox,
  FeatureHeader,
  FeatureHeaderTitle,
} from 'teleport/components/Layout';
import cfg from 'teleport/config';
import {
  AccessRequestScope,
  accessRequestsService,
} from 'teleport/services/accessRequests';
import useStickyClusterId from 'teleport/useStickyClusterId';
import useTeleport from 'teleport/useTeleport';

const scopes: { scope: AccessRequestScope; title: string }[] = [
  { scope: 'myRequests', title: 'My Requests' },
  { scope: 'needsReview', title: 'Needs My Review' },
  { scope: 'reviewed', title: 'Reviewed By Me' },
];

export function AccessRequestsList() {
  const ctx = useTeleport();
  const navigate = useNavigate();
  const { clusterId } = useStickyClusterId();
  const canReview = ctx.storeUser.state.acl.reviewRequests;
  const [scope, setScope] = useState<AccessRequestScope>('myRequests');

  const [attempt, run] = useAsync(
    useCallback(
      (s: AccessRequestScope) => accessRequestsService.list(clusterId, s),
      [clusterId]
    )
  );

  useEffect(() => {
    run(scope);
  }, [run, scope]);

  const visibleScopes = scopes.filter(
    s => canReview || s.scope === 'myRequests'
  );

  return (
    <FeatureBox>
      <FeatureHeader alignItems="center" justifyContent="space-between">
        <FeatureHeaderTitle>Access Requests</FeatureHeaderTitle>
        <ButtonPrimary
          as="a"
          onClick={() => navigate(cfg.routes.newAccessRequest)}
        >
          New Request
        </ButtonPrimary>
      </FeatureHeader>
      {attempt.status === 'error' && (
        <Alert kind="danger" details={attempt.statusText}>
          Could not fetch access requests
        </Alert>
      )}
      <Flex gap={2} mb={3}>
        {visibleScopes.map(s =>
          s.scope === scope ? (
            <ButtonPrimary key={s.scope} size="small">
              {s.title}
            </ButtonPrimary>
          ) : (
            <ButtonSecondary
              key={s.scope}
              size="small"
              onClick={() => setScope(s.scope)}
            >
              {s.title}
            </ButtonSecondary>
          )
        )}
        <ButtonSecondary
          size="small"
          ml="auto"
          disabled={attempt.status === 'processing'}
          onClick={() => run(scope)}
        >
          Refresh
        </ButtonSecondary>
      </Flex>
      <Table<AccessRequest>
        data={attempt.data ?? []}
        columns={[
          {
            key: 'id',
            headerText: 'Id',
            isSortable: true,
            render: renderIdCell,
          },
          {
            key: 'state',
            headerText: 'Status',
            isSortable: true,
            render: renderStatusCell,
          },
          {
            key: 'user',
            headerText: 'User',
            isSortable: true,
            render: renderUserCell,
          },
          {
            key: 'roles',
            headerText: 'Requested',
            render: request => (
              <Cell>
                {getResourcesOrRolesFromRequest(request)
                  .map(r => r.name)
                  .join(', ')}
              </Cell>
            ),
          },
          { key: 'resources', isNonRender: true },
          {
            key: 'created',
            headerText: 'Created',
            isSortable: true,
            render: ({ createdDuration, created }) => (
              <Cell title={displayDateTime(created)}>{createdDuration}</Cell>
            ),
          },
          {
            altKey: 'view-btn',
            render: request => (
              <Cell align="right">
                <ButtonSecondary
                  size="small"
                  onClick={() =>
                    navigate(cfg.getAccessRequestRoute(request.id))
                  }
                >
                  View
                </ButtonSecondary>
              </Cell>
            ),
          },
        ]}
        emptyText="No Requests Found"
        isSearchable
        pagination={{ pageSize: 20 }}
        initialSort={{ key: 'created', dir: 'DESC' }}
      />
    </FeatureBox>
  );
}
