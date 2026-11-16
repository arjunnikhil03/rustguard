# Debugging the RustGuard <-> Redmine integration

Run these `curl` checks **before** running `rustguard --report-to-redmine`,
in order. Each one isolates a specific failure mode. Stop at the first one
that fails — that tells you exactly where the problem is.

## 1. Is the API key valid at all?

```bash
curl -s -o /dev/null -w "%{http_code}\n" \
  -H "X-Redmine-API-Key: $RUSTGUARD_REDMINE_API_KEY" \
  "$RUSTGUARD_REDMINE_URL/users/current.json"
```
- `200` → key is valid, move to step 2.
- `401` → key is wrong, revoked, or REST API access is disabled instance-wide.
  Check: Administration -> Settings -> API -> "Enable REST web service" is
  checked, and the key matches the one on your Redmine account page
  (My account -> API access key -> Show).
- `403` → key is valid but something about the endpoint is forbidden
  (rare for this specific endpoint — usually means the account is locked
  or REST API is restricted further by a plugin).

## 2. Can this key see the target project?

```bash
curl -s -w "\n%{http_code}\n" \
  -H "X-Redmine-API-Key: $RUSTGUARD_REDMINE_API_KEY" \
  "$RUSTGUARD_REDMINE_URL/projects/$RUSTGUARD_REDMINE_PROJECT.json"
```
- `200` with project JSON → good, move to step 3.
- `404` → the project identifier is wrong (this must be the URL-slug
  identifier, e.g. `my-project`, not the display name or numeric ID — unless
  you deliberately want the numeric ID, which also works), OR the project
  is archived, OR this user genuinely doesn't have "View project" access.
- `403` → the user has an account but isn't a member of this project (or
  isn't a member with sufficient role — check Project Settings -> Members).

## 3. Can this key list issues in the project? (what RustGuard's dedup step does)

```bash
curl -s -w "\n%{http_code}\n" \
  -H "X-Redmine-API-Key: $RUSTGUARD_REDMINE_API_KEY" \
  "$RUSTGUARD_REDMINE_URL/issues.json?project_id=$RUSTGUARD_REDMINE_PROJECT&status_id=open&limit=5"
```
- `200` with an `"issues": [...]` array (even if empty) → dedup will work.
- `403` → this account can see the project but lacks "View issues"
  permission on it (Project Settings -> Members -> check the role's
  permissions, or Administration -> Roles and permissions).

## 4. Can this key actually CREATE an issue? (what filing a defect does)

This one has a side effect — it really creates a test issue — so only run
it once you're ready, and delete/close the resulting issue afterward.

```bash
curl -s -w "\n%{http_code}\n" \
  -X POST \
  -H "Content-Type: application/json" \
  -H "X-Redmine-API-Key: $RUSTGUARD_REDMINE_API_KEY" \
  -d '{"issue": {"project_id": "'"$RUSTGUARD_REDMINE_PROJECT"'", "subject": "RustGuard connectivity test - safe to delete"}}' \
  "$RUSTGUARD_REDMINE_URL/issues.json"
```
- `201 Created` with the new issue's JSON → everything works, RustGuard
  should work too. Delete this test issue.
- `422 Unprocessable Entity` with an `"errors": [...]` array → read the
  errors array carefully. The most common cause: **the project's default
  tracker requires a field RustGuard doesn't send** (e.g. a required custom
  field, or "Tracker can't be blank" if the project has no default
  tracker configured). If you see this, pass `--redmine-tracker-id <id>`
  explicitly (find valid tracker IDs via
  `curl -H "X-Redmine-API-Key: $KEY" "$URL/trackers.json"`).
- `403` → this account can view the project/issues but lacks "Add issues"
  permission specifically (a separate permission from "View issues" in
  Redmine's role configuration).

## 5. Once all four succeed manually, run RustGuard itself

```bash
rustguard scan . --rules ./rules \
  --report-to-redmine \
  --redmine-url "$RUSTGUARD_REDMINE_URL" \
  --redmine-project "$RUSTGUARD_REDMINE_PROJECT" \
  --redmine-dry-run
```

`--redmine-dry-run` (see CHANGES below) runs the full fetch-and-dedup logic
and prints exactly what it *would* create or skip, without actually POSTing
any new issues — use this to confirm RustGuard's fingerprint/dedup
behavior looks right before letting it file real tickets.

## If it still doesn't work after all of the above pass

The remaining possibilities are narrower:
- **TLS/certificate issues** (self-signed cert, internal CA) — RustGuard
  uses `rustls` with the standard `webpki-roots` trust store, which will
  reject a self-signed or internally-issued certificate that curl might
  accept via your system's trust store. If curl works but RustGuard's HTTP
  calls fail with a certificate error, this is almost certainly why —
  worth flagging as a fix needed in `rustguard-redmine`/`rustguard-external`
  if you hit this (adding a way to trust a custom CA bundle).
- **A corporate proxy** between the CI runner and Redmine that `curl` is
  configured for (via `~/.curlrc` or system proxy env vars) but that
  RustGuard's HTTP client isn't picking up.
- **Network policy** on the GitLab runner itself blocking the destination
  — check with your platform/infra team if `curl` from your laptop works
  but the same call from within a CI job doesn't.
