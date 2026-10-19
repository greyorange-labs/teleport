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

import { Alert, Flex, Text } from 'design';
import { ArrowBack } from 'design/Icon';
import {
  RequestDelete,
  RequestView,
} from 'shared/components/AccessRequests/ReviewRequests';
import type {
  RequestFlags,
  SubmitReview,
} from 'shared/components/AccessRequests/ReviewRequests/RequestView/types';
// eslint-disable-next-line no-restricted-imports -- RequestView and the shared access request components take useAsync Attempts
import { makeSuccessAttempt, useAsync } from 'shared/hooks/useAsync';
import { AccessRequest } from 'shared/services/accessRequests';

import { FeatureBox } from 'teleport/components/Layout';
import { useParams } from 'teleport/components/Router';
import cfg from 'teleport/config';
import { accessRequestsService } from 'teleport/services/accessRequests';
import useStickyClusterId from 'teleport/useStickyClusterId';
import useTeleport from 'teleport/useTeleport';

export function AccessRequestDetail() {
  const ctx = useTeleport();
  const navigate = useNavigate();
  const { clusterId } = useStickyClusterId();
  const { requestId } = useParams<{ requestId: string }>();
  const { username, acl, accessRequestId } = ctx.storeUser.state;
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);

  const [fetchAttempt, runFetch] = useAsync(
    useCallback(
      () => accessRequestsService.get(clusterId, requestId),
      [clusterId, requestId]
    )
  );
  const [reviewAttempt, runReview] = useAsync((review: SubmitReview) => {
    if (review.state !== 'APPROVED' && review.state !== 'DENIED') {
      throw new Error(`Unsupported review state ${review.state}`);
    }
    return accessRequestsService.review(clusterId, requestId, {
      state: review.state,
      reason: review.reason,
      roles: fetchAttempt.data?.roles,
      assumeStartTime: review.assumeStartTime,
    });
  });
  const [deleteAttempt, runDelete] = useAsync(
    useCallback(
      () => accessRequestsService.delete(clusterId, requestId),
      [clusterId, requestId]
    )
  );
  const [assumeAttempt, runAssume] = useAsync(async () => {
    await accessRequestsService.assume(requestId);
    // Reload so that the web UI picks up the newly assumed roles.
    window.location.reload();
  });

  useEffect(() => {
    runFetch();
  }, [runFetch]);

  function getFlags(request: AccessRequest): RequestFlags {
    const ownRequest = request.user === username;
    const reviewed = request.reviews.find(r => r.author === username);
    const isPending = reviewed
      ? reviewed.state === 'PENDING'
      : request.state === 'PENDING';
    return {
      canAssume: ownRequest && request.state === 'APPROVED',
      isAssumed: request.id === accessRequestId,
      canDelete: true,
      canReview: !ownRequest && isPending && acl.reviewRequests,
      isPromoted: false,
      ownRequest,
    };
  }

  async function deleteRequest() {
    const [, error] = await runDelete();
    if (!error) {
      navigate(cfg.routes.accessRequest);
    }
  }

  const request =
    reviewAttempt.status === 'success' ? reviewAttempt.data : fetchAttempt.data;

  return (
    <FeatureBox>
      <Flex alignItems="center" mb={3}>
        <ArrowBack
          mr={2}
          size="large"
          onClick={() => navigate(cfg.routes.accessRequest)}
          style={{ cursor: 'pointer' }}
        />
        <Text typography="h1">{`Request: ${requestId}`}</Text>
      </Flex>
      {assumeAttempt.status === 'error' && (
        <Alert kind="danger" details={assumeAttempt.statusText}>
          Could not assume the roles
        </Alert>
      )}
      <RequestView
        user={username}
        fetchRequestAttempt={fetchAttempt}
        fetchSuggestedAccessListsAttempt={makeSuccessAttempt([])}
        getFlags={getFlags}
        confirmDelete={false}
        toggleConfirmDelete={() => setDeleteDialogOpen(true)}
        submitReview={runReview}
        submitReviewAttempt={reviewAttempt}
        assumeRole={() => runAssume()}
        assumeRoleAttempt={assumeAttempt}
        assumeAccessList={() => undefined}
        deleteRequestAttempt={deleteAttempt}
        deleteRequest={deleteRequest}
      />
      {deleteDialogOpen && request && (
        <RequestDelete
          deleteRequestAttempt={deleteAttempt}
          user={request.user}
          roles={request.roles}
          requestId={request.id}
          requestState={request.state}
          onClose={() => setDeleteDialogOpen(false)}
          onDelete={deleteRequest}
        />
      )}
    </FeatureBox>
  );
}
