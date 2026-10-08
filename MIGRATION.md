# Shield dashboard migration status

You can manage stored configuration through the new contract path once its checks pass. Safety evaluation remains unavailable. No scan runner or report generator is implied by this migration.

## Verification

- Lifecycle and engine characterization: in progress.
- Scoped SQLite contracts and React plugin: pending.
- PostgreSQL and MongoDB runtime checks: pending service availability.
- Real demo and browser review: pending.
- Legacy retirement: gated on parity and review.

## Legacy surface inventory

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

## Route and contribution map

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

The legacy Plugin, PageContributor, ScanDetailContributor and ProfileDetailContributor interfaces require an external consumer audit before removal. Settings Save and scan execution are unavailable. Duplicate API Docs links move to host chrome. Stored scan decisions describe history, not evaluated protection.

## Git and dependencies

Work stays on main. The existing Forge/Grove upgrade in go.mod is required for current contracts; checksum reconciliation is included deliberately. No other local Shield branch or worktree existed at the audit.
