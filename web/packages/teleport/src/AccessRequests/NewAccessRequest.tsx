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

import {
  Alert,
  Box,
  ButtonPrimary,
  ButtonSecondary,
  Flex,
  Indicator,
  Text,
} from 'design';
import { FieldCheckbox } from 'shared/components/FieldCheckbox';
import { FieldTextArea } from 'shared/components/FieldTextArea';
// eslint-disable-next-line no-restricted-imports -- RequestView and the shared access request components take useAsync Attempts
import { useAsync } from 'shared/hooks/useAsync';
import { ResourceId } from 'shared/services/accessRequests';

import {
  FeatureBox,
  FeatureHeader,
  FeatureHeaderTitle,
} from 'teleport/components/Layout';
import { useLocation } from 'teleport/components/Router';
import cfg from 'teleport/config';
import { accessRequestsService } from 'teleport/services/accessRequests';
import useStickyClusterId from 'teleport/useStickyClusterId';

/**
 * NewAccessRequest creates an access request for roles, or for a single
 * resource when the `kind` and `name` query parameters are present (the
 * "Request access" action on a resource links here).
 */
export function NewAccessRequest() {
  const navigate = useNavigate();
  const { search } = useLocation();
  const { clusterId } = useStickyClusterId();

  const resource = parseResource(search, clusterId);
  const [selected, setSelected] = useState<string[]>([]);
  const [reason, setReason] = useState('');

  const [capsAttempt, runCaps] = useAsync(
    useCallback(
      () =>
        accessRequestsService.getCapabilities(
          clusterId,
          resource ? [resource] : []
        ),
      // eslint-disable-next-line react-hooks/exhaustive-deps -- resource is derived from search
      [clusterId, search]
    )
  );
  const [createAttempt, runCreate] = useAsync(() =>
    accessRequestsService.create(clusterId, {
      roles: selected,
      resources: resource ? [resource] : [],
      reason,
    })
  );

  useEffect(() => {
    runCaps();
  }, [runCaps]);

  const caps = capsAttempt.data;
  const roles = resource
    ? (caps?.applicableRoles ?? [])
    : (caps?.requestableRoles ?? []);
  const reasonRequired = !!caps?.requireReason;
  const canSubmit =
    selected.length > 0 &&
    (!reasonRequired || reason.trim() !== '') &&
    createAttempt.status !== 'processing';

  function toggle(role: string) {
    setSelected(prev =>
      prev.includes(role) ? prev.filter(r => r !== role) : [...prev, role]
    );
  }

  async function submit() {
    const [request, error] = await runCreate();
    if (!error && request) {
      navigate(cfg.getAccessRequestRoute(request.id));
    }
  }

  return (
    <FeatureBox>
      <FeatureHeader>
        <FeatureHeaderTitle>New Access Request</FeatureHeaderTitle>
      </FeatureHeader>
      {capsAttempt.status === 'processing' && (
        <Box textAlign="center" m={10}>
          <Indicator />
        </Box>
      )}
      {capsAttempt.status === 'error' && (
        <Alert kind="danger" details={capsAttempt.statusText}>
          Could not load requestable roles
        </Alert>
      )}
      {createAttempt.status === 'error' && (
        <Alert kind="danger" details={createAttempt.statusText}>
          Could not create the access request
        </Alert>
      )}
      {capsAttempt.status === 'success' && (
        <Box maxWidth="640px">
          {resource && (
            <Text mb={3}>
              Requesting access to <b>{resource.kind}</b> <b>{resource.name}</b>
            </Text>
          )}
          <Text bold mb={2}>
            {resource ? 'Roles that grant access' : 'Select roles to request'}
          </Text>
          {roles.length === 0 && (
            <Text color="text.slightlyMuted" mb={3}>
              There are no roles you can request.
            </Text>
          )}
          {roles.map(role => (
            <FieldCheckbox
              key={role}
              label={role}
              checked={selected.includes(role)}
              onChange={() => toggle(role)}
            />
          ))}
          <FieldTextArea
            mt={3}
            label={reasonRequired ? 'Reason' : 'Reason (optional)'}
            placeholder={caps.requestPrompt || 'Why do you need this access?'}
            value={reason}
            onChange={e => setReason(e.target.value)}
          />
          <Flex gap={3} mt={3}>
            <ButtonPrimary disabled={!canSubmit} onClick={submit}>
              Submit Request
            </ButtonPrimary>
            <ButtonSecondary onClick={() => navigate(-1)}>
              Cancel
            </ButtonSecondary>
          </Flex>
        </Box>
      )}
    </FeatureBox>
  );
}

function parseResource(search: string, clusterId: string): ResourceId | null {
  const params = new URLSearchParams(search);
  const kind = params.get('kind');
  const name = params.get('name');
  if (!kind || !name) {
    return null;
  }
  return {
    kind: kind as ResourceId['kind'],
    name,
    clusterName: params.get('cluster') || clusterId,
  };
}
