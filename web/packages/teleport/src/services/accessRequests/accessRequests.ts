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

import {
  AccessRequest,
  makeAccessRequest,
  RequestState,
  ResourceId,
} from 'shared/services/accessRequests';

import cfg from 'teleport/config';
import api from 'teleport/services/api';
import session from 'teleport/services/websession';

export type AccessRequestScope = 'myRequests' | 'needsReview' | 'reviewed';

export type CreateAccessRequestParams = {
  roles: string[];
  resources?: ResourceId[];
  reason?: string;
  suggestedReviewers?: string[];
  maxDuration?: Date;
  assumeStartTime?: Date;
  dryRun?: boolean;
};

export type ReviewAccessRequestParams = {
  state: Extract<RequestState, 'APPROVED' | 'DENIED'>;
  reason?: string;
  roles?: string[];
  assumeStartTime?: Date;
};

export type AccessCapabilities = {
  requestableRoles: string[];
  applicableRoles: string[];
  suggestedReviewers: string[];
  requestPrompt: string;
  requireReason: boolean;
  autoRequest: boolean;
};

export const accessRequestsService = {
  async list(
    clusterId: string,
    scope: AccessRequestScope,
    signal?: AbortSignal
  ): Promise<AccessRequest[]> {
    const url = `${cfg.getAccessRequestsUrl(clusterId)}?scope=${scope}`;
    const json = await api.get(url, signal);
    return (json?.requests ?? []).map(makeAccessRequest);
  },

  async get(
    clusterId: string,
    requestId: string,
    signal?: AbortSignal
  ): Promise<AccessRequest> {
    const json = await api.get(
      cfg.getAccessRequestsUrl(clusterId, requestId),
      signal
    );
    return makeAccessRequest(json);
  },

  async create(
    clusterId: string,
    params: CreateAccessRequestParams
  ): Promise<AccessRequest> {
    const json = await api.post(cfg.getAccessRequestsUrl(clusterId), {
      roles: params.roles,
      resources: params.resources ?? [],
      reason: params.reason ?? '',
      suggestedReviewers: params.suggestedReviewers ?? [],
      maxDuration: params.maxDuration?.toISOString(),
      assumeStartTime: params.assumeStartTime?.toISOString(),
      dryRun: params.dryRun ?? false,
    });
    return makeAccessRequest(json);
  },

  async delete(clusterId: string, requestId: string): Promise<void> {
    await api.delete(cfg.getAccessRequestsUrl(clusterId, requestId));
  },

  /**
   * Submits a review. The admin action MFA that the auth server requires for
   * reviews is handled by the shared api layer.
   */
  async review(
    clusterId: string,
    requestId: string,
    params: ReviewAccessRequestParams
  ): Promise<AccessRequest> {
    const json = await api.post(
      cfg.getAccessRequestReviewUrl(clusterId, requestId),
      {
        state: params.state,
        reason: params.reason ?? '',
        roles: params.roles,
        assumeStartTime: params.assumeStartTime?.toISOString(),
      }
    );
    return makeAccessRequest(json);
  },

  async getCapabilities(
    clusterId: string,
    resources: ResourceId[] = [],
    signal?: AbortSignal
  ): Promise<AccessCapabilities> {
    return api.post(
      cfg.getAccessCapabilitiesUrl(clusterId),
      { resources },
      signal
    );
  },

  /**
   * Assumes the roles of an approved request by renewing the web session.
   */
  async assume(requestId: string): Promise<void> {
    await session.renewSession({ requestId });
  },
};
