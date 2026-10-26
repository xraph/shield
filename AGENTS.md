# AGENTS.md

Shield is a Go library for AI safety: instincts, awareness detectors, boundaries, values, judgments, reflexes, safety profiles and policies, stored per tenant and app, plus scan records, PII tokens and compliance reports. `engine.ScanInput`, `ScanOutput` and `ScanToolCall` evaluate a tenant's profile through all six layers and its policies, with deterministic detectors and an optional model judge that can only raise risk. It comes with a Forge extension and an authenticated Forge dashboard contract. The module path is `github.com/xraph/shield`.

There's no `cmd/` and no binary. The repo holds two modules: `github.com/xraph/shield` at the root, and `github.com/xraph/shield/integrations/nexusguard` in `integrations/nexusguard`, which depends on nexus so the root module doesn't have to.

## Commands

Run everything from the repo root. CI has no `go.work`, so build with `GOWORK=off` to get exactly what `go.mod` pins.

| What | Command |
|---|---|
| Build | `GOWORK=off go build ./...` |
| Test, as CI runs it | `make test` (`go test -v ./...`) |
| Race tests, as release runs them | `go test -race -count=1 ./...` (or `make test-race`) |
| Vet | `make vet` |
| Lint | `make lint` (`golangci-lint run --allow-serial-runners ./...`) |
| Format | `make fmt` (`gofmt -s -w .`, then `goimports -w -local github.com/xraph/shield .`) |
| Format, vet and lint together | `make check` |
| Coverage | `make coverage` |
| Docs site | `make docs` or `make docs-build` (pnpm, inside `docs/`) |
| nexusguard tests | `cd integrations/nexusguard && go test -race -count=1 ./...` (needs the workspace, see below) |

`make build`, `make run`, `make dev`, `make install` and `make all` go through `./cmd/shield`. That directory does not exist, so they fail.

`.github/workflows/ci.yml` calls the shared `xraph/workflows/.github/workflows/go-ci.yml@v1` on Go 1.26 (setup-go resolves the newest patch) and adds a Format job and a Docs job. CI runs `make test`, a race-enabled coverage run, golangci-lint at the version go-ci.yml pins, `gofmt -l .`, `make vet`, a `go mod tidy` diff check, gosec and govulncheck (both fail on findings), `goimports -l -local github.com/xraph/shield .`, and the `pnpm types:check`, `pnpm lint` and `pnpm build` steps in `docs/`.

The nexusguard job builds `integrations/nexusguard` against this checkout of shield. It runs `go work init . ./integrations/nexusguard` to make a workspace, then `go vet ./...`, `go test -race -count=1 ./...` and golangci-lint (v2.12.2) inside `integrations/nexusguard`. Its `go.mod` pins the last released shield, which lacks the new APIs until the next tag, so the module only builds through a workspace. Locally, keep the same `go.work` at the repo root (`go 1.26.3`, `use (. ./integrations/nexusguard)`). `.gitignore` excludes it, so it stays untracked; never commit it. The root module's commands above all run with `GOWORK=off`, so the workspace doesn't change them.

The Security job runs gosec by itself, with only `-exclude=G115`, and it does not read `.golangci.yml`. The G104, G117, G304, G402 and G704 excludes in that file quiet golangci-lint's gosec and nothing else, so a finding you silence there can still fail Security.

## Store tests

There are three backends (sqlite, postgres, mongo) and no memory store. They share one conformance suite, `storetest.Run` in `store/storetest/dashboard.go`, which covers the scoped dashboard surface (CRUD, paging, policy assignments, stale-edit rejection, PII totals and bounded retention) and, in `store/storetest/tenancy.go`, the tenant rules of `store.Store`.

SQLite runs it on every `go test ./...` against `:memory:`. Postgres and mongo call `t.Skip` unless you set:

- `SHIELD_TEST_POSTGRES`, a DSN for a disposable database. Each subtest creates a `shield_test_<nanos>` schema, sets `search_path` to it and drops it with `CASCADE` on cleanup.
- `SHIELD_TEST_MONGO`, a URI for a disposable server. Each subtest opens its own `shield_test_<nanos>` database and drops it, so the URI does not need a database name.

`presets/infra_agent_test.go` also seeds the InfraAgent bundle into Postgres, concurrently, when `SHIELD_TEST_POSTGRES` is set.

CI sets neither, and a skipped test reads as a pass unless you run with `-v`. When you change a store or a preset, run both against throwaway containers:

```sh
docker run -d --rm --name shield-test-pg -p 55433:5432 \
  -e POSTGRES_PASSWORD=shield -e POSTGRES_DB=shield_test postgres:17-alpine
docker run -d --rm --name shield-test-mongo -p 57018:27017 mongo:7

# once postgres accepts connections:
SHIELD_TEST_POSTGRES='postgres://postgres:shield@localhost:55433/shield_test?sslmode=disable' \
SHIELD_TEST_MONGO='mongodb://localhost:57018' \
GOWORK=off go test -count=1 -v ./store/... ./presets/...

docker rm -f shield-test-pg shield-test-mongo
```

## Lint

`.golangci.yml` is golangci-lint v2 config. By default golangci-lint prints at most three identical messages, so local runs and CI both under-report. Run it uncapped before you call a lint fix finished:

```sh
golangci-lint run --allow-serial-runners --max-same-issues=0 --max-issues-per-linter=0
```

`--allow-serial-runners` makes a second golangci-lint wait for the first one's lock. Without it, the second run exits with an error.

What bites here:

- revive's `exported` rule keeps its stutter check in this repo. A name like `scan.ScanResult` fails, so name it `scan.Result`.
- govet runs `enable-all` minus `fieldalignment`, shadow included. An inner `if err := f()` under an outer `err` is flagged, and gocritic's `sloppyReassign` rejects `if err = f(); err != nil { return err }` in non-test code. Give the inner error its own name, as the tree does with `operationErr`, `marshalErr` and `recErr`. `store/storetest/dashboard.go` is non-test code too. Test files can reuse `err`, because gocritic skips them.
- gosec, errcheck and gocritic are excluded for `_test.go`. revive and staticcheck aren't. A `//nolint` for one of the excluded three in a test file is unused, and nolintlint flags it, so write a plain comment there.
- errcheck has `check-blank: true` and `check-type-assertions: true`. A deliberate `_ = f()` needs `//nolint:errcheck // <reason>`, and every `//nolint` in the tree carries a reason. The stores do not open transactions today, so you have no rollback defer to copy.
- errorlint wants `errors.Is`, `errors.As` and `%w`. errname wants `Err...` sentinels and `...Error` types.
- goimports puts `github.com/xraph/shield` imports in the last group.

For govulncheck, use CI's Go. CI always resolves the newest 1.26 patch, and an older local toolchain reports stdlib advisories CI never sees. Run `GOTOOLCHAIN=go1.26.N govulncheck ./...` with N set to that patch.

## Layout

| Path | What lives there |
|---|---|
| `shield.go`, `config.go`, `options.go`, `errors.go`, `scope.go`, `entity.go`, `id.go` | `Version`, `Config`, top-level `Option`s, sentinel errors, `WithTenant`/`WithApp` and their readers, `Entity`, the `ID` re-export |
| `id/` | TypeID-based `id.ID` with a prefix per entity (`inst`, `awr`, `bnd`, `val`, `jdg`, `rflx`, `sprf`, `pol`, `scan`, `pii`, `crpt`...) |
| `instinct/`, `awareness/`, `boundary/`, `values/`, `judgment/`, `reflex/`, `profile/`, `policy/`, `scan/`, `pii/`, `compliance/` | One subsystem each: models and a `Store` interface |
| `engine/` | `engine.Engine`: the scan entry points, profile resolution and cache, one file per layer (`layer_*.go`), policies, tool calls (`toolcall.go`), the model judge (`judge.go`), `Capabilities`, health |
| `internal/textnorm/` | Text folding shared by the detectors and `scan.Quote`: case, width, confusable letters, spacing and hidden runes, with offsets mapped back to the original |
| `internal/scoring/` | The noisy-or score the detectors, the instinct layer and the values principles share |
| `internal/shieldtest/` | Test helpers: a SQLite store and a tenant and app context |
| `instinct/detection/` | The prompt-injection detectors instincts run: the phrase corpus by family, hidden and encoded text heuristics, canary tokens |
| `awareness/perception/` | The built-in PII and secret detectors, entropy checks, placeholders and redaction |
| `values/principles/` | The built-in lexicons of the values layer (`safety`, `toxicity`) in `lexicon/*.txt`, and their scorer |
| `presets/` | Ready-made bundles a host seeds per tenant: `InfraAgent` and `Bundle.Seed` |
| `redteam/` | Prompt-injection fixtures per untrusted source, as JSONL (`All`, `BySource`) |
| `integrations/nexusguard/` | Its own module: nexus input and output guards, the verdict cache and a nexus-backed `judgment.Judge` |
| `store/store.go` | `store.Store`, the composite of the eleven subsystem stores plus `Migrate`, `Ping`, `Close` |
| `store/dashboard.go` | The strict scoped interfaces the dashboard uses (`DashboardStore`, `AssignmentStore`, `PrivacyStore`, `PrivacyStatsStore`), `Scope`, `Filter`, `Page`, revision helpers |
| `store/sqlite`, `store/postgres`, `store/mongo` | The backends, on grove, each with `migrations.go` and a `dashboard.go` |
| `store/storetest/` | The shared conformance suite: dashboard surface and tenancy |
| `store/tenant.go` | The tenant and scope helpers every backend uses: `Tenant`, `ScopeVisible`, `ScopeLevels`, `ScopeWritable`, `ReportScope`, `ReportLevels` |
| `admin/` | `admin.Service`: validation, permissions, field schemas and audited retention between the contract and the scoped stores |
| `plugin/` | Lifecycle hook interfaces and the registry |
| `audit_hook/` (package `audithook`) | Plugin for an audit trail |
| `observability/` | Deprecated metrics plugin. It records nothing. Code that only builds and registers it still compiles; its old counter fields and hook methods are gone |
| `internal/telemetry/` | The shared tracer, the span error helper and the labelled metric vectors the engine, plugin registry and admin service use |
| `extension/` | The Forge extension, its `Config` and options |
| `extension/contract/` | The `shield` dashboard contributor: `manifest.yaml`, handlers, and the claim-based actor resolver in `scope.go` |
| `docs/` | The Fumadocs site |
| `MIGRATION.md` | Upgrade notes per release (v1.9.0 first), then the record of the move from the templ dashboard to the React plugin |

## Conventions

Errors are sentinels prefixed `shield:`. The subsystem ones live in `errors.go`, and the backends return them for a missing row through `notFoundOrWrap` (`shield.ErrInstinctNotFound` and so on), wrapping everything else with a backend prefix such as `shield/postgres: create instinct: %w`. The tenancy and scan sentinels are there too: `ErrTenantRequired`, `ErrTenantMismatch`, `ErrNoProfile`, `ErrProfileInvalid`, `ErrInputTooLarge`, `ErrInvalidInput`, `ErrNoStore`. The dashboard surface has its own set in `store/dashboard.go`: `ErrScope`, `ErrNotFound`, `ErrCollection`, `ErrConflict`, `ErrReadOnly`.

There are two store contracts, and both enforce the tenant. `store.Store` is what the engine uses. Every method resolves its tenant through `store.Tenant(ctx, want)`: an empty `want` takes the context tenant, both empty is `ErrTenantRequired`, both set and different is `ErrTenantMismatch`. A row of another tenant returns its not-found sentinel on get and update and is a no-op on delete. Policies and compliance reports check their scope with `store.ScopeVisible`, `ScopeLevels`, `ScopeWritable`, `ReportScope` and `ReportLevels`: under a tenant context only that tenant's org scope is writable, and with no tenant on the context the call is an operator call. A list filter that carries `TenantID` works without a context tenant, because cortex's catalogs call it that way. No backend reads `shield.TenantFromContext` directly; use the helpers. The `docs/content/docs/concepts/multi-tenancy.mdx` table lists every rule, so update it when one changes.

The `Dashboard*` interfaces are strict: every call takes a `store.Scope`, and `Scope.Validate` refuses an empty tenant or app, because a dashboard call must never widen an empty scope into every row. Policies follow `Scope.PolicyScope()`: a tenant scope writes org-level policies keyed by its tenant, reads the app-level policies assigned to it as `ErrReadOnly`, and can't assign. Only a scope with `AppScope()` true (`PolicyLevel "app"`, `PolicyKey == AppID`, granted by the host's resolver, never by request params) touches app-level policies. `DashboardCreate` maps a duplicate name to `ErrConflict`. Updates are optimistic. A patch carries `_expected_updated_at`, `store.UpdateRevision` returns `ErrConflict` when it does not match the stored `updated_at`, and `store.NextRevision` keeps revisions distinct under mongo's millisecond timestamps. If you add a dashboard collection, it goes in all three backends and in `store/storetest`.

Primitive and profile names are unique per `(app_id, tenant_id, name)` since migration `20261024000001`. Policy names stay unique per `scope_key`.

Each backend versions its migrations separately in its own `migrations.go`. When you add one, give it the next `Version` there.

On the dashboard, scope and permissions come only from the authenticated principal's claims (`tenant_id`, `app_id`), resolved by `contract.ResolveActor` unless the host passes its own through `WithDashboardActorResolver`. `ResolveActor` always builds a tenant actor; only a host resolver can grant the app scope. Request parameters never grant scope, so don't write a handler that reads a tenant or app from its input. `admin.Service` checks the read and manage permissions before it touches a store, and PII retention also needs the sensitive one. After a write it drops the engine's cached profiles: `InvalidateProfiles(tenant)`, or `InvalidateAllProfiles()` for an app-level policy.

Every scan needs a tenant on the context and a store, and resolves its profile from `Input.Profile` or `Config.DefaultProfile`. Finding messages are fixed templates and details hold names, counts and offsets, never matched text. The judge is untrusted: it only sees text with the built-in secret and PII placeholders applied, runs at most once per scan under `JudgeConcurrency` and `JudgeTimeout`, and can only raise a judgment's risk. Keep it that way. `docs/content/docs/concepts/evaluation.mdx` describes every layer and the action-to-decision mapping, so update it with the engine. Its "Known limits" list (and the README's) names the detection gaps we know about; add to it when you park one.

IDs come from the `id` package (`id.NewInstinctID()` and friends). Don't build them as strings.

`engine.New(opts...)` takes `type Option func(*Engine)` and returns `(*Engine, error)`. `extension.New(opts...)` takes `type Option func(*Extension)`. The extension reads YAML under `extensions.shield`, then `shield`, and merges it with the programmatic options. Its store comes from `WithStore`, a named grove DB (`WithGroveDatabase`), or the default `*grove.DB` in the container, chosen by driver name (`pg`, `sqlite`, `mongo`). With no store at all, `Health` reports that persistence is not configured. Shield mounts no HTTP routes of its own: `BasePath` is loaded and merged but nothing reads it, and `WithDisableRoutes` only stops the dashboard contract from registering.

Logging uses `github.com/xraph/go-utils/log`, with `log.NewNoopLogger()` as the engine default. The Forge extension passes the app logger, and the engine passes its logger on to the plugin registry.

Telemetry goes through `internal/telemetry`. Start spans from `telemetry.Tracer()` (scope `github.com/xraph/shield`), mark failures with `telemetry.Fail(span, "<class>", err)`, and never call `span.RecordError` or put an error message, scanned text, a tenant, app, subject or user-chosen name on a span or a label. Metrics take a go-utils `metrics.Metrics` through `engine.WithMetrics` (nil means off), and the extension wires `e.Metrics()`. Name them `shield_<object>_<verb>_total` or `shield_<operation>_duration_seconds`; Forge scrapes them with a `forge_` prefix. `docs/content/docs/guides/observability.mdx` lists every span and metric, so update it when you add one.

## Dependencies

Shield depends on grove (with `drivers/mongodriver`, `drivers/pgdriver` and `drivers/sqlitedriver`) and forge, plus `go-utils` and `vessel`. fabriq's root module (`github.com/xraph/fabriq`) consumes it, and so do cortex's root module and `cortex/extension`. See `go.mod` for versions. `integrations/nexusguard` adds nexus and requires a released shield; bump its nexus pin with `GOWORK=off go get github.com/xraph/nexus@vX.Y.Z` inside that directory.

Grove's drivers are tagged with grove, so bump the four together:

```sh
GOWORK=off go get github.com/xraph/grove@vX.Y.Z \
  github.com/xraph/grove/drivers/mongodriver@vX.Y.Z \
  github.com/xraph/grove/drivers/pgdriver@vX.Y.Z \
  github.com/xraph/grove/drivers/sqlitedriver@vX.Y.Z
GOWORK=off go get github.com/xraph/forge@vX.Y.Z
GOWORK=off go mod tidy
```

Never commit a `go.work` or a `replace` aimed at a sibling checkout. Use one locally if you must, then take it out before you push. CI cannot resolve the path, and fabriq and cortex ignore replaces in their dependencies anyway.

## Releasing

Dispatch the workflow. Don't push a tag by hand.

The two modules are tagged separately, shield first, because nexusguard's `go.mod` has to require the shield tag before nexusguard can be released:

```sh
# 1. Release shield.
gh run list --workflow ci.yml --branch main --limit 1   # main has to be green
gh workflow run release.yml --ref main -f tag=vX.Y.Z
GOPROXY=proxy.golang.org go list -m github.com/xraph/shield@vX.Y.Z   # wait until it resolves

# 2. Point nexusguard at that tag and prove it builds without the workspace.
cd integrations/nexusguard
GOWORK=off go get github.com/xraph/shield@vX.Y.Z
GOWORK=off go mod tidy
GOWORK=off go test -race -count=1 ./...
cd ../..
git add integrations/nexusguard/go.mod integrations/nexusguard/go.sum
git commit -m "chore(nexusguard): require shield vX.Y.Z"
git push origin main

# 3. Release nexusguard once CI on that commit is green.
gh run list --workflow ci.yml --branch main --limit 1
gh workflow run release.yml --ref main -f tag=integrations/nexusguard/vX.Y.Z
GOPROXY=proxy.golang.org go list -m github.com/xraph/shield/integrations/nexusguard@vX.Y.Z
```

`release.yml` creates the tag on the dispatched commit and pushes it before anything else. A tag under `integrations/nexusguard/` releases that module, any other tag releases shield. Then it runs `go build ./...` and `go test -race -count=1 ./...` at the root, and for a nexusguard tag it also builds, vets and tests `integrations/nexusguard` with `GOWORK=off`, against the versions its `go.mod` pins. It writes notes from the commits since the previous tag of the same module and publishes the GitHub release. If the tests fail, the tag stays without a release, and a second dispatch of that tag fails at `git tag`. Fix forward with the next patch.

Before you cut shield, bring its forge, grove (with the three drivers) and nexus dependencies up to their latest releases, and wait for any release shield needs. Afterwards fabriq and cortex re-pin with `go get github.com/xraph/shield@vX.Y.Z` (in cortex, for the root module and for `cortex/extension`), and hosts that use the guards add `github.com/xraph/shield/integrations/nexusguard@vX.Y.Z`.

## Branches and commits

`main` has no branch protection and no rulesets, and we push to it directly. Commit subjects are conventional commits, such as `feat: ...`, `fix(shield): ...` or `chore: ...`.
