# PAM access requests in the community build

This fork of Teleport adds a just-in-time access request and approval workflow
that the open source (community) build does not offer. This page explains what
was changed, why, and how to use and maintain it.

Part of GM-308639, "PAM (Teleport) Phase 1".

## Goal

Users sign in with Google SSO. By default they have no access to nodes or
desktops. A user can request access to a role, or to a single resource, and
someone in a privileged group (for example engineering leadership) approves or
denies the request. This works from the proxy web UI and from the command line
(`tsh`, `tctl`).

## Why code changes were needed

The community build blocks most of the access request feature set. The code that
implements it lives in the closed `teleport.e` repository, which is empty in
this tree (`e/`). Specifically:

| Area | Community build | Result |
|------|-----------------|--------|
| Roles with `allow.review_requests`, `allow.request.thresholds`, `request_access: reason` | Rejected when the role is saved | Nobody can be given review permission |
| Roles with `allow.request.search_as_roles` | Rejected | Resource requests are impossible |
| Certificates for approved resource requests | Refused | Approved resource requests cannot be used |
| Web API for access requests | Missing (served by the enterprise plugin) | No web UI flow |
| Web UI for access requests | A locked placeholder page | Nothing to click |

The request logic itself (creating, reviewing, assuming) is open source and
works. The changes below remove the gates and add the missing web API and UI.

## What changed

### 1. Feature gates (`lib/modules`, `lib/auth`)

- `lib/modules/greyorange.go` turns on `AdvancedAccessWorkflows` and an unlimited
  `AccessRequests` entitlement in the default modules. This clears the role
  checks for review, thresholds and `request_access: reason`, and tells the web UI
  that access requests are available.
- `lib/auth/auth_with_roles.go`: `search_as_roles` is accepted when the feature is
  on.
- `lib/auth/auth.go`: certificates for approved resource requests are issued when
  the feature is on.

Enterprise builds behave as before. The build type is deliberately not changed,
because that would switch on many unrelated enterprise checks.

### 2. Web API (`lib/web/access_requests.go`)

All endpoints are under `/webapi/sites/:site/` and use the caller's own identity.

| Method and path | Purpose |
|-----------------|---------|
| `GET accessrequests?scope=myRequests\|needsReview\|reviewed` | List requests |
| `POST accessrequests` | Create a request for roles and/or resources (`dryRun` supported) |
| `GET accessrequests/:id` | Get one request |
| `DELETE accessrequests/:id` | Delete a request |
| `POST accessrequests/:id/review` | Approve or deny (`state`: `APPROVED` or `DENIED`) |
| `POST accesscapabilities` | Roles the user can request, and the roles that grant given resources |

`lib/web/ui/access_request.go` converts a request to the JSON shape that the
existing web UI parser (`makeAccessRequest`) expects. Reviews require admin
action MFA on the auth server, and the web client handles that through the
standard MFA prompt.

### 3. Web UI (`web/packages/teleport/src`)

- `services/accessRequests`: client for the API above.
- `AccessRequests/`: a list page (my requests, needs my review, reviewed by me), a
  detail and review page (reuses the shared `RequestView`), and a new request page
  for roles or for one resource.
- `UnifiedResources/`: a "Request Access" button on resources the user cannot
  access yet, and requestable resources become visible to users with
  `search_as_roles`.
- `features.tsx` and `config.ts`: the locked placeholder is replaced by these pages.

### 4. Example roles (`examples/greyorange/pam`)

| Role | Given to | Purpose |
|------|----------|---------|
| `gor-base` | Every user | No standing access. Can request `gor-*-access` roles and resources. A reason is required. |
| `gor-approver` | Privileged Google groups | Can approve or deny requests for `gor-*-access` roles. |
| `gor-node-access` | Approved requests | SSH access to nodes. |
| `gor-linux-desktop-access` | Approved requests | Linux desktop access. |

Apply them with `tctl create -f examples/greyorange/pam/roles.yaml`. A Go test
checks that they parse and are accepted by the default modules.

## Using it

Command line:

```bash
# requester
tsh request search --kind=node
tsh request create --roles=gor-node-access --reason "debug node"

# approver
tctl requests ls
tsh request review --approve --reason ok <request-id>

# requester, after approval
tsh login --request-id=<request-id>
```

Web UI: Access Requests in the navigation, or "Request Access" on a resource.

## Google SSO

OIDC login is also an enterprise feature. It is developed on its own branch
(`feature/google-sso`) and is not part of this change. Until it is merged, test
with local users, for example:

```bash
tctl users add requester --roles=gor-base
tctl users add approver --roles=gor-base,gor-approver
```

Once SSO is in, map the privileged Google groups to `gor-approver`, and everyone
to `gor-base`, with `claims_to_roles` on the connector. Group membership is read
at login, so a group change applies on the next login.

## Testing

- Go: `go test ./lib/modules/... ./lib/services/ -run 'AccessRequest|Role'`,
  `go test ./lib/auth/ -run 'AccessRequest|RoleFeatureSupport|GreyOrange'`,
  `go test ./lib/web/ -run AccessRequest`.
- Web: `pnpm type-check`, `pnpm oxlint`, `pnpm format-check`, `pnpm test`.

## Known limitations

- The new request page handles one resource at a time. There is no multi-resource
  cart.
- The resource request flow in the web UI has not been checked against a running
  cluster. In particular, confirm that requestable resources appear in the
  resources list and that Linux desktops can be requested.
- Manager-hierarchy routing, Butler or GoPulse approval integration, notification
  plugins and approval thresholds are not part of this change.
- Long-term requests and access list promotion stay unavailable (they need the
  enterprise implementation).

## Keeping up with upstream

The changes touch few upstream files: `lib/modules/modules.go`,
`lib/auth/auth.go`, `lib/auth/auth_with_roles.go`, `lib/web/apiserver.go`, and in
the web package `features.tsx`, `config.ts`, `UnifiedResources.tsx` and
`AccessRequests/index.ts`. Everything else is new files. When upstream adds a
real `branch/v19`, move the commits onto it.

## CI

`.github/workflows/greyorange-ci.yaml` runs on standard GitHub runners. The
upstream workflows need larger runners and Gravitational credentials, so they are
disabled in this fork. The `CI result` job is the single check to require on
`develop`.

Notes:

- The `go.mod` tidy check covers only the root and `api` modules. Other modules,
  for example `e2e/runner`, are untidy upstream and are not checked.
- The golangci-lint steps are non-blocking (`continue-on-error`). The released
  linter crashes with "file requires newer Go version go1.27" on this code base.
  Remove `continue-on-error` once the linter and the Go toolchain agree.
