# AGENTS.md

Shield is a Go library for AI safety configuration: instincts, awareness detectors, boundaries, values, judgments, reflexes, safety profiles and policies, stored per tenant and app, plus scan records, PII tokens and compliance reports. It comes with a Forge extension and an authenticated Forge dashboard contract. The module path is `github.com/xraph/shield`.

Read this before you trust the README. The six evaluation layers aren't implemented. `engine.ScanInput` and `ScanOutput` run no layer (each is a `TODO` in `engine/engine.go`), return `DecisionAllow` with no findings, and store the scan. `Engine.Capabilities()` reports `Evaluation: false` and lists all six layers as unavailable, and `MIGRATION.md` says the same.

It's one module with no `cmd/` and no binary.

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

`make build`, `make run`, `make dev`, `make install` and `make all` go through `./cmd/shield`. That directory does not exist, so they fail.

`.github/workflows/ci.yml` calls the shared `xraph/workflows/.github/workflows/go-ci.yml@v1` on Go 1.26 (setup-go resolves the newest patch) and adds a Format job and a Docs job. CI runs `make test`, a race-enabled coverage run, golangci-lint at the version go-ci.yml pins, `gofmt -l .`, `make vet`, a `go mod tidy` diff check, gosec and govulncheck (both fail on findings), `goimports -l -local github.com/xraph/shield .`, and the `pnpm types:check`, `pnpm lint` and `pnpm build` steps in `docs/`.

The Security job runs gosec by itself, with only `-exclude=G115`, and it does not read `.golangci.yml`. The G104, G117, G304, G402 and G704 excludes in that file quiet golangci-lint's gosec and nothing else, so a finding you silence there can still fail Security.

## Store tests

There are three backends (sqlite, postgres, mongo) and no memory store. They share one conformance suite, `storetest.Run` in `store/storetest/dashboard.go`, which covers the scoped dashboard surface: CRUD, paging, policy assignments, stale-edit rejection, PII totals and bounded retention.

SQLite runs it on every `go test ./...` against `:memory:`. Postgres and mongo call `t.Skip` unless you set:

- `SHIELD_TEST_POSTGRES`, a DSN for a disposable database. Each subtest creates a `shield_test_<nanos>` schema, sets `search_path` to it and drops it with `CASCADE` on cleanup.
- `SHIELD_TEST_MONGO`, a URI for a disposable server. Each subtest opens its own `shield_test_<nanos>` database and drops it, so the URI does not need a database name.

CI sets neither, and a skipped test reads as a pass unless you run with `-v`. When you change a store, run both against throwaway containers:

```sh
docker run -d --rm --name shield-test-pg -p 55433:5432 \
  -e POSTGRES_PASSWORD=shield -e POSTGRES_DB=shield_test postgres:17-alpine
docker run -d --rm --name shield-test-mongo -p 57018:27017 mongo:7

# once postgres accepts connections:
SHIELD_TEST_POSTGRES='postgres://postgres:shield@localhost:55433/shield_test?sslmode=disable' \
SHIELD_TEST_MONGO='mongodb://localhost:57018' \
GOWORK=off go test -count=1 -v ./store/...

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
| `engine/` | `engine.Engine`: scan entry points, `Capabilities`, health |
| `store/store.go` | `store.Store`, the composite of the eleven subsystem stores plus `Migrate`, `Ping`, `Close` |
| `store/dashboard.go` | The strict scoped interfaces the dashboard uses (`DashboardStore`, `AssignmentStore`, `PrivacyStore`, `PrivacyStatsStore`), `Scope`, `Filter`, `Page`, revision helpers |
| `store/sqlite`, `store/postgres`, `store/mongo` | The backends, on grove, each with `migrations.go` and a `dashboard.go` |
| `store/storetest/` | The shared dashboard conformance suite |
| `admin/` | `admin.Service`: validation, permissions, field schemas and audited retention between the contract and the scoped stores |
| `plugin/` | Lifecycle hook interfaces and the registry |
| `audit_hook/` (package `audithook`), `observability/` | Plugins for an audit trail and for metrics |
| `extension/` | The Forge extension, its `Config` and options |
| `extension/contract/` | The `shield` dashboard contributor: `manifest.yaml`, handlers, and the claim-based actor resolver in `scope.go` |
| `docs/` | The Fumadocs site |
| `MIGRATION.md` | Status of the move from the templ dashboard to the React plugin |

## Conventions

Errors are sentinels prefixed `shield:`. The subsystem ones live in `errors.go`, and the backends return them for a missing row through `notFoundOrWrap` (`shield.ErrInstinctNotFound` and so on), wrapping everything else with a backend prefix such as `shield/postgres: create instinct: %w`. The dashboard surface has its own set in `store/dashboard.go`: `ErrScope`, `ErrNotFound`, `ErrCollection`, `ErrConflict`.

There are two store contracts, and they don't behave alike. `store.Store` is what the engine uses, and it keeps its older semantics. The `Dashboard*` interfaces are strict: every call takes a `store.Scope`, and `Scope.Validate` refuses an empty tenant or app, because a dashboard call must never widen an empty scope into every row. Updates are optimistic. A patch carries `_expected_updated_at`, `store.UpdateRevision` returns `ErrConflict` when it does not match the stored `updated_at`, and `store.NextRevision` keeps revisions distinct under mongo's millisecond timestamps. If you add a dashboard collection, it goes in all three backends and in `store/storetest`.

Each backend versions its migrations separately in its own `migrations.go`. When you add one, give it the next `Version` there.

On the dashboard, scope and permissions come only from the authenticated principal's claims (`tenant_id`, `app_id`), resolved by `contract.ResolveActor` unless the host passes its own through `WithDashboardActorResolver`. Request parameters never grant scope, so don't write a handler that reads a tenant or app from its input. `admin.Service` checks the read and manage permissions before it touches a store, and PII retention also needs the sensitive one.

IDs come from the `id` package (`id.NewInstinctID()` and friends). Don't build them as strings.

`engine.New(opts...)` takes `type Option func(*Engine)` and returns `(*Engine, error)`. `extension.New(opts...)` takes `type Option func(*Extension)`. The extension reads YAML under `extensions.shield`, then `shield`, and merges it with the programmatic options. Its store comes from `WithStore`, a named grove DB (`WithGroveDatabase`), or the default `*grove.DB` in the container, chosen by driver name (`pg`, `sqlite`, `mongo`). With no store at all, `Health` reports that persistence is not configured. Shield mounts no HTTP routes of its own: `BasePath` is loaded and merged but nothing reads it, and `WithDisableRoutes` only stops the dashboard contract from registering.

Logging uses `github.com/xraph/go-utils/log`, with `log.NewNoopLogger()` as the engine default.

## Dependencies

Shield depends on grove (with `drivers/mongodriver`, `drivers/pgdriver` and `drivers/sqlitedriver`) and forge, plus `go-utils` and `vessel`. fabriq's root module (`github.com/xraph/fabriq`) consumes it, and so do cortex's root module and `cortex/extension`. See `go.mod` for versions.

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

```sh
gh run list --workflow ci.yml --branch main --limit 1   # main has to be green
gh workflow run release.yml --ref main -f tag=vX.Y.Z
```

`release.yml` creates the tag on the dispatched commit and pushes it before anything else. Then it runs `go build ./...` and `go test -race -count=1 ./...`, writes notes from the commits since the previous tag, and publishes the GitHub release. If the tests fail, the tag stays without a release, and a second dispatch of that tag fails at `git tag`. Fix forward with the next patch.

Wait for the grove and forge releases shield needs before you cut it. Afterwards fabriq and cortex re-pin with `go get github.com/xraph/shield@vX.Y.Z` (in cortex, for the root module and for `cortex/extension`).

## Branches and commits

`main` has no branch protection and no rulesets, and we push to it directly. Commit subjects are conventional commits, such as `feat: ...`, `fix(shield): ...` or `chore: ...`.
