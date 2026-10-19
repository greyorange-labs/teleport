# GreyOrange PAM roles

Roles for the just-in-time access request workflow.

| Role | Granted | Purpose |
|------|---------|---------|
| `gor-base` | every SSO user | No standing access. Can request `gor-*-access` roles and individual resources. |
| `gor-approver` | privileged Google groups | Can approve or deny requests for `gor-*-access` roles. |
| `gor-node-access` | approved request | SSH to nodes. |
| `gor-linux-desktop-access` | approved request | Linux desktop access. |

```bash
tctl create -f examples/greyorange/pam/roles.yaml
```

## Local testing without Google SSO

```bash
tctl users add requester --roles=gor-base
tctl users add approver --roles=gor-base,gor-approver
```

Both users need an MFA device: reviewing a request requires MFA.

## CLI flow

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

The same flow is available in the web UI under Access Requests, and from
"Request Access" on a resource that the user cannot access yet.

## Google SSO

When Google SSO is merged, map the privileged Google groups to
`gor-approver` (and `gor-base` for everyone) with `claims_to_roles` on the
connector. Group membership is read at login, so a group change takes effect
on the next login.
