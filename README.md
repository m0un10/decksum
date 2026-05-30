# decksum

A tiny CLI that summarises a Kong [decK](https://github.com/Kong/deck) declarative config: entity counts, plugin usage by scope, a service → route tree with effective auth, and a few sanity checks.

decK itself can validate, lint, diff and transform state files, but has no "what's in this file?" command. This is an experiment to fill that gap.

## Install

```bash
go install github.com/m0un10/decksum@latest
```

## Usage

```bash
# straight from a running gateway
deck gateway dump -o - | decksum

# from a file (YAML or JSON)
decksum kong.yaml

# markdown for a PR comment or GitHub Actions job summary
decksum kong.yaml -f markdown >> "$GITHUB_STEP_SUMMARY"

# machine-readable
decksum kong.yaml -f json | jq '.findings'

# CI gate: exit 2 if any warnings are found
decksum kong.yaml --fail-on-warn
```

| Flag | |
|---|---|
| `-f, --format` | `text` (default), `markdown`, `json` |
| `--no-tree` | skip the per-service route tree |
| `--no-color` | plain text output (also honours `NO_COLOR`) |
| `--fail-on-warn` | exit status 2 when any `warn` finding is present |

## Example

```
$ decksum testdata/kong.yaml --no-color
decK config summary
format 3.0 · workspace default · select_tags team-payments

ENTITIES
  services         4
  routes           8
  plugins          9  (2 global, 2 service, 4 route, 1 consumer)
  consumers        2  (4 credentials)
  upstreams        1  (2 targets)
  certificates     1  (1 SNI)
  vaults           1

PLUGINS
  NAME                 TOTAL  GLOBAL  SERVICE  ROUTE  CONSUMER  DISABLED
  rate-limiting        3      ·       1        1      1         ·
  acl                  1      ·       ·        1      ·         ·
  ...

SERVICES
  orders → https://orders.internal:8443  [key-auth, rate-limiting]
    ├─ orders-api    GET,POST    /orders        auth: key-auth
    ├─ orders-admin  GET,DELETE  /orders/admin  auth: key-auth [acl]
    └─ healthz       ANY         /healthz       auth: key-auth
  payments → http://payments.internal:80
    ├─ checkout         ANY  api.example.com /checkout  auth: openid-connect [openid-connect]
    └─ legacy-checkout  ANY  /v0/checkout               no auth [request-transformer (disabled), rate-limiting]
  ...

FINDINGS
  warn  4 of 8 routes have no auth plugin (global, service or route): ...
  warn  path /docs is defined on multiple routes with the same hosts/methods: docs/public-docs, docs/docs-mirror
  warn  route stray references service "billing", which is not in this file
  info  1 service has no routes: reporting
  info  2 services use a plain http upstream: payments, docs
  ...
```

## What it understands

- Routes nested under services **and** top-level routes that reference a service by name or id.
- Plugins at every scope: global, service, route, consumer, consumer group — nested or top-level with a `service`/`route`/`consumer` reference.
- **Effective auth** per route: an enabled auth plugin (`key-auth`, `jwt`, `openid-connect`, `basic-auth`, `oauth2`, `hmac-auth`, `ldap-auth`, `mtls-auth`, …) at global, service or route level. Consumer-scoped plugins don't count.
- Any other top-level list (vaults, key_sets, partials, …) is counted generically.

### Findings

| Level | Check |
|---|---|
| warn | routes with no effective auth plugin |
| warn | the same path + hosts + methods on more than one route |
| warn | route referencing a service not in the file |
| info | services with no routes |
| info | services with a plain `http://` upstream |
| info | routes accepting plain http (protocols unset or include `http`) |
| info | disabled plugins |

## Limitations

This is a single-file, read-only summariser: it doesn't merge multiple state files, resolve `{vault://…}` references, or know about plugin ordering or Konnect-specific entities beyond counting them. Route matching for the duplicate check is exact string comparison, not Kong's router semantics.

## License

MIT, see [LICENSE](LICENSE).
