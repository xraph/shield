# Migrating Shield

## Upgrading to v1.9.0

v1.9.0 is the release where scans start doing something. Before it, every scan came back `allow` with no findings. Now each scan runs the tenant's safety profile and can block, redact, flag, or (for tool calls) ask for approval. Most of the work of upgrading is making sure every call carries a tenant and every scan has a profile to run.

```bash
go get github.com/xraph/shield@v1.9.0
```

### Scans now evaluate

`ScanInput` and `ScanOutput` keep their signatures, and they now return real decisions: `allow`, `flag`, `redact` or `block`. `ScanToolCall` is new and returns `allow`, `block` or `require_approval`. Check `Result.Decision` (or `Blocked`) on every scan, and when it's `redact`, use `Result.Redacted` in place of your text. For input you mark `Untrusted`, `Redacted` is always set to the quoted text, even on `allow`, so hand that to the model.

A scan now needs a profile. Pass `scan.Input.Profile`, or set `default_profile` (`Config.DefaultProfile`). With neither, or with a profile that doesn't exist or is disabled, the scan returns `shield.ErrNoProfile`. A profile that references a missing primitive, or holds a regex or condition that doesn't parse, returns `shield.ErrProfileInvalid`. Treat any scan error as a block: it means there's no verdict.

`engine.Capabilities()` now reports `Evaluation: true` and `ToolCalls: true`, and `unavailable_layers` is an empty list. If you gated anything on `Evaluation` being false, take that out.

Six config keys are new, all with defaults you can leave alone: `max_scan_bytes` (1 MiB), `profile_cache_ttl` (30s), `store_redacted` (false), `model_judge` (false), `judge_timeout` (5s) and `judge_concurrency` (8). A scan larger than `max_scan_bytes` fails with `shield.ErrInputTooLarge`, so raise it if you scan long logs.

If you turn on the model judge, a judgment finding it pushed over the threshold carries the judge's score as `judge_score` in its details. You won't find the judge's reason there or in the stored scan. A model wrote it, and findings only hold names, counts and offsets.

The scan metrics gain label values: `direction` can be `tool_call`, and `decision` can be `require_approval`. The plugin hooks that never fired before (`OnScanBlocked`, `OnScanFailed`, the six layer hooks, the PII, policy and profile hooks) all fire now.

### Every call needs a tenant

Every scan needs `shield.WithTenant` on the context, or it returns `shield.ErrTenantRequired`. So does every `store.Store` read and write, unless a list filter carries `TenantID` itself. A list with an empty filter used to return every tenant's rows. It now returns `ErrTenantRequired`, or only the context tenant's rows when the context has one.

If you run Shield for one tenant, pick a constant and use it everywhere:

```go
ctx = shield.WithTenant(ctx, "default")
```

Under a tenant, another tenant's rows are invisible: a get by ID returns the not-found error, an update returns not-found, a delete does nothing, and a filter naming a different tenant returns `shield.ErrTenantMismatch`.

### Rows with an empty tenant are no longer read

The engine reads only the scan's own tenant's rows. A profile or primitive stored with an empty `tenant_id`, which the old defaults produced, is never part of a scan. Give those rows a tenant before you upgrade traffic. On SQL backends that's one statement per table, for example:

```sql
UPDATE shield_profiles SET tenant_id = 'default' WHERE tenant_id = '';
```

Repeat it for `shield_instincts`, `shield_awareness`, `shield_boundaries`, `shield_values`, `shield_judgments` and `shield_reflexes`, and for `shield_scans` and `shield_pii_tokens` if you want old scans and tokens to stay readable. On MongoDB, do the same with `updateMany`. Run it before you create rows under that tenant, or a name already taken there collides.

### Names are unique per app and tenant

Migration `20261024000001` (`unique_names_per_tenant`) changes the unique key of the seven primitive and profile tables from `(app_id, name)` to `(app_id, tenant_id, name)`, so two tenants can use the same name. `Migrate` runs it for you, or the Forge extension does on `Start`. If you run Shield's grove migrations from your own migration pass, it's in the same `shield` group. On MongoDB, `Migrate` swaps the index itself.

The down-migration puts `(app_id, name)` back, and it fails, before changing anything, as soon as two tenants share a name in one app. Rename one of them first if you need to roll back.

### Policies and reports belong to a tenant

An app-level policy now applies to a tenant only when it's assigned to it. Org-level policies with `ScopeKey` equal to the tenant always apply. Under a tenant context, the store writes only that tenant's org-level policies and reports: an app-level write returns `ErrTenantMismatch`. App-level policies are written by an operator, with no tenant on the context or, in the dashboard, by an actor your resolver grants the app scope (`PolicyLevel "app"`, `PolicyKey` equal to the app ID). Dashboard users keep working as tenant actors, who can't assign policies any more.

### An engine without a store now errors

Scans read their profile from the store, so an engine built without `WithStore` returns `shield.ErrNoStore` from every scan. Before, it allowed everything and kept nothing.

### `vault` redacts without storing

An awareness detector with the `vault` action redacts the same way `redact` does and stores no PII token. Shield doesn't encrypt PII. If you relied on tokens appearing during a scan, nothing ever wrote them, and nothing does now.

### New packages

`presets` holds `InfraAgent`, a ready-made bundle you seed per tenant, and `redteam` holds the injection fixtures Shield is tested against. `github.com/xraph/shield/integrations/nexusguard` is a separate module that puts Shield behind nexus guards; it's tagged `integrations/nexusguard/v1.9.0` and needs nexus v1.9.0 or later.

This release builds on forge v1.13.2 and grove v1.10.0 (with its `mongodriver`, `pgdriver` and `sqlitedriver`). Go's module resolution moves you up to them when you upgrade Shield.

## Dashboard migration status (v1.8)

The rest of this file is the record of the move from the templ dashboard to the React plugin. It was written before evaluation shipped, so its notes that evaluation is unavailable describe v1.8.

You can manage stored configuration through the new contract path once its checks pass. No scan runner or report generator is implied by this migration.

### Verification

- Lifecycle and engine characterization: in progress.
- Scoped SQLite contracts and React plugin: pending.
- PostgreSQL and MongoDB runtime checks: pending service availability.
- Real demo and browser review: pending.
- Legacy retirement: gated on parity and review.

### Legacy surface inventory

Source baseline: `9dbcac4`. The legacy contributor was already disconnected from the extension. The following inventory keeps the source fields and labels available during replacement.

| Template | Fields, labels and actions | Disposition |
| --- | --- | --- |
| `dashboard/components/confirm_dialog.templ` | on, target | Preserve domain fields; replace chrome with shared React kit |
| `dashboard/components/dialog_helpers.templ` | once | Preserve domain fields; replace chrome with shared React kit |
| `dashboard/components/empty_state.templ` |  | Preserve domain fields; replace chrome with shared React kit |
| `dashboard/components/footer_links.templ` | API Docs | Preserve domain fields; replace chrome with shared React kit |
| `dashboard/components/json_viewer.templ` |  | Preserve domain fields; replace chrome with shared React kit |
| `dashboard/components/page_header.templ` |  | Preserve domain fields; replace chrome with shared React kit |
| `dashboard/components/path_rewriter.templ` | htmx | Preserve domain fields; replace chrome with shared React kit |
| `dashboard/components/severity_badge.templ` | default | Preserve domain fields; replace chrome with shared React kit |
| `dashboard/components/stat_card.templ` | default | Preserve domain fields; replace chrome with shared React kit |
| `dashboard/components/state_badge.templ` | default | Preserve domain fields; replace chrome with shared React kit |
| `dashboard/pages/awareness_detail.templ` | + aw.Name,, Focus, Action, Enabled, Description, Usage, Created, Updated, Patterns, Config, md | Preserve domain fields; replace chrome with shared React kit |
| `dashboard/pages/awareness_form.templ` | Name, Focus, Description, Action, Enabled, Patterns, detectors, focus, name, description, action, enabled, e.g., email-detector, ssn-detector, Comma-separated regex patterns, PII, Topic, Sentiment, Intent, Language, Custom, Redact, Flag, Block, Vault, patterns, config, target, json, hover | Preserve domain fields; replace chrome with shared React kit |
| `dashboard/pages/awareness_list.templ` | focus, + aw.Name }
									hx-target=, + aw.Name,, All Focus Types, PII, Topic, Sentiment, Intent, Language, Custom, delay, hover | Preserve domain fields; replace chrome with shared React kit |
| `dashboard/pages/boundaries_detail.templ` | + bnd.Name,, Enabled, Description, Response, Usage, Created, Updated, Deny, Allow, md | Preserve domain fields; replace chrome with shared React kit |
| `dashboard/pages/boundaries_form.templ` | Name, Description, Response, Enabled, Scope, Deny List, Allow List, Use Allowlist Mode, limits, name, description, response, enabled, Comma-separated denied items, Comma-separated allowed items, Topic, Action, Data, Output, Custom, scope, deny, allow, use_allow, target, json, hover | Preserve domain fields; replace chrome with shared React kit |
| `dashboard/pages/boundaries_list.templ` | scope, + bnd.Name }
									hx-target=, + bnd.Name,, All Scopes, Topic, Action, Data, Output, Custom, delay, hover | Preserve domain fields; replace chrome with shared React kit |
| `dashboard/pages/compliance_list.templ` | framework, All Frameworks, EU AI Act, NIST AI RMF, Summary, View Details, hover, default | Preserve domain fields; replace chrome with shared React kit |
| `dashboard/pages/helpers.templ` |  | Preserve domain fields; replace chrome with shared React kit |
| `dashboard/pages/instincts_detail.templ` | + inst.Name,, Category, Sensitivity, Sensitivity Level, Paranoid, Permissive, Action, Enabled, Description, Usage, Created, Updated, md, width | Preserve domain fields; replace chrome with shared React kit |
| `dashboard/pages/instincts_form.templ` | Name, Category, Description, Sensitivity, Action, Enabled, Weight, strategies, name, category, description, sensitivity, action, enabled, e.g., classifier, canary, perplexity, Injection, Exfiltration, Manipulation, Jailbreak, Block, Flag, Log, weight, config, target, hover | Preserve domain fields; replace chrome with shared React kit |
| `dashboard/pages/instincts_list.templ` | category, + inst.Name }
									hx-target=, + inst.Name,, All Categories, Injection, Exfiltration, Manipulation, Jailbreak, delay, hover | Preserve domain fields; replace chrome with shared React kit |
| `dashboard/pages/judgments_detail.templ` | + jdg.Name,, Domain, Threshold, Strict, Lenient, Action, Enabled, Description, Usage, Created, Updated, md, width | Preserve domain fields; replace chrome with shared React kit |
| `dashboard/pages/judgments_form.templ` | Name, Description, Domain, Threshold, Action, Enabled, assessors, threshold, name, description, domain, action, enabled, e.g., grounding-scorer, relevance-checker, What this assessor evaluates..., Grounding, Relevance, Consistency, Compliance, Custom, Block, Flag, Log, target, json, hover | Preserve domain fields; replace chrome with shared React kit |
| `dashboard/pages/judgments_list.templ` | domain, + jdg.Name }
									hx-target=, + jdg.Name,, All Domains, Grounding, Relevance, Consistency, Compliance, Custom, delay, hover | Preserve domain fields; replace chrome with shared React kit |
| `dashboard/pages/overview.templ` | Safety Layers, lg, md | Preserve domain fields; replace chrome with shared React kit |
| `dashboard/pages/pii_vault.templ` | lg | Preserve domain fields; replace chrome with shared React kit |
| `dashboard/pages/policies_detail.templ` | + pol.Name,, Description, Scope Key, Scope Level, Enabled, Created, Updated, md | Preserve domain fields; replace chrome with shared React kit |
| `dashboard/pages/policies_form.templ` | Name, Description, Scope Key, Scope Level, Enabled, Check Type, Condition, Action, Error Message, Priority, rules, name, description, scope_key, scope_level, enabled, e.g., instinct, awareness, values, e.g., score > 0.8, Custom error message, App, Org, Add Rule, Block, Flag, Log, Warn, check_type, condition, action, error_message, priority, target, hover | Preserve domain fields; replace chrome with shared React kit |
| `dashboard/pages/policies_list.templ` | scope_level, + pol.Name }
									hx-target=, + pol.Name,, All Scope Levels, App, Org, delay, hover | Preserve domain fields; replace chrome with shared React kit |
| `dashboard/pages/profiles_detail.templ` | + prof.Name,, Description, Enabled, App ID, Tenant ID, Created, Updated, md | Preserve domain fields; replace chrome with shared React kit |
| `dashboard/pages/profiles_form.templ` | Name, Description, Instinct Name, Sensitivity, Awareness Name, Judgment Name, Threshold, Boundary Name, Value Name, Reflex Name, instincts, awareness, boundaries, values, judgments, reflexes, name, description, e.g., injection-detector, e.g., pii-detector, e.g., grounding-check, 0.0, e.g., no-medical-advice, e.g., helpfulness, e.g., rate-limiter, Add Instinct, Default, Paranoid, Cautious, Balanced, Relaxed, Permissive, Add Awareness, Add Judgment, Add Boundary, Add Value, Add Reflex, instinct_name, sensitivity, awareness_name, judgment_name, threshold, target, hover | Preserve domain fields; replace chrome with shared React kit |
| `dashboard/pages/profiles_list.templ` | + prof.Name }
									hx-target=, + prof.Name,, delay, hover | Preserve domain fields; replace chrome with shared React kit |
| `dashboard/pages/reflexes_detail.templ` | + rflx.Name,, Priority, Enabled, Description, Usage, Created, Updated, md | Preserve domain fields; replace chrome with shared React kit |
| `dashboard/pages/reflexes_form.templ` | Name, Description, Priority, Enabled, Type, Pattern, Threshold, Window, Target, Value, Fallback, triggers, actions, priority, name, description, enabled, Regex or matching pattern, e.g., 1m, 5m, 1h, What to act on, Action-specific value, Fallback response text, On Score, On Finding, On Pattern, On Context, On Rate, Always, Block, Redact, Flag, Rewrite, Escalate, Log, Throttle, type, pattern, threshold, window, target, value, fallback, json, hover | Preserve domain fields; replace chrome with shared React kit |
| `dashboard/pages/reflexes_list.templ` | + rflx.Name }
									hx-target=, + rflx.Name,, delay, hover | Preserve domain fields; replace chrome with shared React kit |
| `dashboard/pages/scans_detail.templ` | Direction, Decision, Blocked, Duration, PII Count, Profile Used, Policies Used, Tenant ID, App ID, Created, No expiry, md | Preserve domain fields; replace chrome with shared React kit |
| `dashboard/pages/scans_list.templ` | direction, decision, All Directions, Input, Output, All Decisions, Allow, Block, Flag, Redact, delay, hover | Preserve domain fields; replace chrome with shared React kit |
| `dashboard/pages/values_detail.templ` | + val.Name,, Severity, Action, Enabled, Description, Usage, Created, Updated, Threshold, Categories, Guidelines, md, width | Preserve domain fields; replace chrome with shared React kit |
| `dashboard/pages/values_form.templ` | Name, Description, Severity, Action, Enabled, Principle, Threshold, Categories, Guidelines, rules, name, description, severity, action, enabled, Comma-separated, e.g. hate, harassment, violence, Comma-separated, e.g. no profanity, family friendly, Low, Medium, High, Critical, Block, Flag, Log, Toxicity, Brand Safety, Honesty, Respect, Safety, Privacy, Custom, principle, threshold, categories, guidelines, target, json, hover | Preserve domain fields; replace chrome with shared React kit |
| `dashboard/pages/values_list.templ` | + val.Name }
									hx-target=, + val.Name,, delay, hover | Preserve domain fields; replace chrome with shared React kit |
| `dashboard/settings/engine_config.templ` | Default Profile, Scan Concurrency, Short-Circuit, Shutdown Timeout (seconds), e.g. standard, Stop evaluation when first layer blocks, Save Changes, Settings saved, md, hover, disabled, form, default_profile, scan_concurrency, short_circuit, shutdown_timeout, saving, saved | Preserve domain fields; replace chrome with shared React kit |
| `dashboard/widgets/layer_summary.templ` | lg | Preserve domain fields; replace chrome with shared React kit |
| `dashboard/widgets/pii_stats.templ` | Total PII Tokens, By Type | Preserve domain fields; replace chrome with shared React kit |
| `dashboard/widgets/recent_scans.templ` |  | Preserve domain fields; replace chrome with shared React kit |
| `dashboard/widgets/scan_stats.templ` | lg | Preserve domain fields; replace chrome with shared React kit |

### Route and contribution map

- `/`
- `/instincts`
- `/instincts/detail`
- `/instincts/create`
- `/instincts/edit`
- `/awareness`
- `/awareness/detail`
- `/awareness/create`
- `/awareness/edit`
- `/boundaries`
- `/boundaries/detail`
- `/boundaries/create`
- `/boundaries/edit`
- `/values`
- `/values/detail`
- `/values/create`
- `/values/edit`
- `/judgments`
- `/judgments/detail`
- `/judgments/create`
- `/judgments/edit`
- `/reflexes`
- `/reflexes/detail`
- `/reflexes/create`
- `/reflexes/edit`
- `/profiles`
- `/profiles/detail`
- `/profiles/create`
- `/profiles/edit`
- `/scans`
- `/scans/detail`
- `/policies`
- `/policies/detail`
- `/policies/create`
- `/policies/edit`
- `/pii`
- `/compliance`
- `shield-scan-stats`
- `shield-recent-scans`
- `shield-pii-stats`
- `shield-layer-summary`
- `shield-config`

The legacy Plugin, PageContributor, ScanDetailContributor and ProfileDetailContributor interfaces were audited across sibling Go repositories before retirement. Settings Save and scan execution are unavailable. Duplicate API Docs links move to host chrome. Stored scan decisions describe history, not evaluated protection.

### Git and dependencies

Work stays on main. The existing Forge/Grove upgrade in go.mod is required for current contracts; checksum reconciliation is included deliberately. No other local Shield branch or worktree existed at the audit.

### React administration and retirement (2026-10-08)

The React plugin is `@forge-go/dashboard-plugin-shield` in forge-dashboard.
It covers 39 routes: eight configuration collections with list/create/detail/edit,
overview, scans/detail, compliance/detail, PII metadata/retention and settings.
The contract contributor exposes 67 intents under `shield`, with authenticated
scope, separate read/manage/sensitive permissions, validated writes and command
invalidation. All six evaluation layers remain unavailable.

SQLite, PostgreSQL and MongoDB pass shared conformance for scoped CRUD,
structured values, explicit false/zero/empty arrays, stable paging, policy
assignments, every primitive reference filter and bounded retention. PostgreSQL
was tested with a disposable PostgreSQL 17 container; MongoDB used unique test
databases that were dropped. The full Go suite and build pass after retirement.

The real file-backed SQLite demo passes 93 HTTP acceptance requests across all
eight editable collections. Browser review covers disabled creation, a zero
strategy weight, cleared strategies, scoped profile choices, profile creation,
policy assign/unassign, retention preview/cancel and a 390px responsive layout.
Deletion and audited retention execution are verified by isolated backend and
HTTP transport tests. The browser did not confirm permanent PII deletion.

The sibling Go source audit found no external imports or implementations of the
legacy contributor interfaces. The 95 tracked files in `dashboard/` are retired;
the inventory above remains the parity record. Overview widgets are represented
by compact summary counts and stored scans. New contributions use React slots
`shield.overview.widgets`, `shield.scan.detail`, `shield.profile.detail` and
`shield.settings`. There is no implicit adapter for third-party templ plugins.

The administration migration does not qualify the unfinished evaluation engine,
report generation or writable runtime settings. Those capabilities remain
visible as unavailable. Name and app/name uniqueness are preserved; changing
cross-tenant naming rules requires a separate data migration.
