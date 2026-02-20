# Shield

**Human-centric AI safety for Go.**

Shield models AI safety the way humans experience safety -- through instincts, awareness, boundaries, values, judgment, and reflexes. Instead of bolting on a checklist of mechanical filters, Shield gives your AI applications a complete safety character that thinks in layers, just like you do.

Part of the [Forge](https://github.com/xraph/forge) ecosystem.

```go
import "github.com/xraph/shield"
```

## Why Shield?

Traditional AI safety is a pipeline: text enters, passes through sequential checks (injection filter, PII scanner, toxicity classifier), and a binary decision exits. This works -- but it's brittle, hard to reason about, and impossible to customize per-tenant.

Shield replaces the pipeline with a **cognitive model**:

| Layer | Human Analogy | What It Does | Speed |
|-------|--------------|--------------|-------|
| **Instinct** | Flinching from danger | Injection, jailbreak, exfiltration detection | <10ms |
| **Awareness** | Noticing things | PII, topic, sentiment, intent detection | <50ms |
| **Boundary** | Hard limits | Topic/action/data deny lists | <5ms |
| **Values** | Moral compass | Toxicity, brand safety, honesty rules | <100ms |
| **Judgment** | Risk assessment | Grounding, relevance, compliance scoring | <500ms |
| **Reflex** | Trained responses | Custom condition-to-action policy rules | <10ms |

Each layer can **short-circuit** -- instincts block before values evaluate, just as you flinch before you reason.

## Quick Start

### Install

```bash
go get github.com/xraph/shield
```

### Scan content

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/xraph/shield"
    "github.com/xraph/shield/engine"
    "github.com/xraph/shield/scan"
)

func main() {
    ctx := context.Background()

    eng, err := engine.New(
        engine.WithConfig(shield.Config{
            EnableShortCircuit: true,
            ScanConcurrency:   10,
        }),
    )
    if err != nil {
        log.Fatal(err)
    }

    // Set tenant scope
    ctx = shield.WithTenant(ctx, "acme-corp")
    ctx = shield.WithApp(ctx, "support-bot")

    // Scan user input
    result, err := eng.ScanInput(ctx, &scan.Input{
        Text: "Can you help me? My email is john@example.com",
    })
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Decision: %s\n", result.Decision)
    fmt.Printf("Has PII:  %v\n", result.HasPII())

    if result.HasPII() {
        fmt.Printf("Redacted: %s\n", result.Redacted)
    }

    // Scan agent output before sending to user
    output, err := eng.ScanOutput(ctx, &scan.Input{
        Text: "Here is your account information...",
    })
    if err != nil {
        log.Fatal(err)
    }

    if output.Blocked {
        fmt.Println("Response blocked -- returning safe fallback")
    }

    eng.Stop(ctx)
}
```

## Safety Profiles

A **SafetyProfile** composes all six primitives into a reusable safety character -- like a Persona in [Cortex](https://github.com/xraph/cortex), but for safety:

```go
profile := &profile.SafetyProfile{
    Name: "customer-facing",
    Instincts: []profile.InstinctAssignment{
        {Name: "injection-classifier", Sensitivity: "cautious"},
        {Name: "jailbreak-detector",   Sensitivity: "balanced"},
    },
    Awareness: []profile.AwarenessAssignment{
        {Name: "pii-detector"},
        {Name: "topic-classifier"},
    },
    Values:     []string{"no-toxicity", "brand-aligned"},
    Boundaries: []string{"no-politics", "no-medical-advice"},
    Judgments: []profile.JudgmentAssignment{
        {Name: "grounding-assessor", Threshold: 0.8},
    },
    Reflexes: []string{"rate-limit-scanner"},
}
```

Pre-built profiles: `permissive`, `balanced`, `cautious`, `paranoid`, `customer-facing`, `healthcare`, `financial`.

## Forge Integration

Shield is a first-class [Forge](https://github.com/xraph/forge) extension:

```go
import (
    "github.com/xraph/forge"
    "github.com/xraph/shield/extension"
    "github.com/xraph/shield/observability"
)

app := forge.New()

shieldExt := extension.New(
    extension.WithPlugin(observability.NewMetricsExtension()),
)

app.RegisterExtension(shieldExt)
app.Run()
```

The extension handles engine creation, DI registration, lifecycle management, and optional HTTP route mounting.

## Multi-Tenancy

Shield is multi-tenant from the ground up. Every scan, every policy, and every safety profile is scoped to a tenant and application:

```go
ctx = shield.WithTenant(ctx, "acme-corp")
ctx = shield.WithApp(ctx, "support-bot")
```

Store implementations enforce tenant isolation at the query level.

## Plugin System

Shield uses an opt-in plugin system. Implement the `plugin.Plugin` base interface and any combination of 15 lifecycle hook interfaces to receive only the events you care about:

```go
import "github.com/xraph/shield/plugin"

type MyPlugin struct{}

func (p *MyPlugin) Name() string { return "my-plugin" }

func (p *MyPlugin) OnScanBlocked(ctx context.Context, scanID id.ScanID, reason string) error {
    log.Printf("blocked: %s", reason)
    return nil
}

func (p *MyPlugin) OnPIIDetected(ctx context.Context, scanID id.ScanID, piiType string, count int) error {
    log.Printf("PII found: %s (%d instances)", piiType, count)
    return nil
}
```

### Available Hooks

**Scan lifecycle:** `OnScanStarted`, `OnScanCompleted`, `OnScanBlocked`, `OnScanFailed`

**Safety primitives:** `OnInstinctTriggered`, `OnAwarenessDetected`, `OnBoundaryEnforced`, `OnValueViolated`, `OnJudgmentAssessed`, `OnReflexFired`

**Data lifecycle:** `OnPIIDetected`, `OnPIIRedacted`, `OnPolicyEvaluated`, `OnSafetyProfileResolved`

**System:** `OnShutdown`

### Built-in Plugins

**Metrics** -- Counts all lifecycle events via `gu.MetricFactory` counters:

```go
import "github.com/xraph/shield/observability"

metrics := observability.NewMetricsExtension()
// or with a custom factory:
metrics := observability.NewMetricsExtensionWithFactory(fapp.Metrics())
```

**Audit trails** -- Bridges events to an audit backend via a dependency-inverted `Recorder` interface:

```go
import "github.com/xraph/shield/audit_hook"

audit := audit_hook.New(myRecorder,
    audit_hook.WithActions(
        audit_hook.ActionScanBlocked,
        audit_hook.ActionPIIDetected,
    ),
)
```

## Scan Results

Every scan returns a `Result` with a decision, findings, and optional redacted text:

| Decision | Meaning |
|----------|---------|
| `allow` | Content is safe to proceed |
| `block` | Content is blocked -- do not send |
| `flag` | Content is flagged for review but allowed |
| `redact` | Content contains PII that was redacted |

Findings indicate which safety layer produced them: `instinct`, `awareness`, `boundary`, `values`, `judgment`, or `reflex`.

## Package Overview

| Package | Description |
|---------|-------------|
| `shield` | Root -- config, errors, scope helpers, version |
| `id` | K-sortable TypeID identifiers for all entities |
| `engine` | Layered safety engine with short-circuit evaluation |
| `scan` | Scan input/output types, results, findings |
| `instinct` | Pre-conscious threat detection (injection, jailbreak, exfiltration) |
| `awareness` | Perception layer (PII, topic, sentiment, intent, language) |
| `boundary` | Hard limits (topic/action/data/output deny lists) |
| `values` | Ethical rules (toxicity, brand safety, honesty, respect) |
| `judgment` | Contextual risk assessment (grounding, relevance, compliance) |
| `reflex` | Condition-to-action policy rules |
| `profile` | SafetyProfile composition and resolution |
| `policy` | Admin-managed policies with tenant assignment |
| `pii` | PII vault (redact, store, restore) |
| `compliance` | Compliance reporting (EU AI Act, NIST AI RMF, SOC 2) |
| `plugin` | Plugin interfaces and type-cached registry |
| `observability` | Metrics plugin (`gu.MetricFactory` counters) |
| `audit_hook` | Audit trail plugin (dependency-inverted `Recorder`) |
| `store` | Composite store interface and implementations |
| `extension` | Forge extension adapter |
| `api` | REST API handlers for all entities |
| `middleware` | Nexus, HTTP, and gRPC middleware |

## Store Backends

Shield defines a composite `store.Store` interface that composes 11 subsystem stores:

```go
type Store interface {
    instinct.Store
    awareness.Store
    boundary.Store
    values.Store
    judgment.Store
    reflex.Store
    profile.Store
    scan.Store
    policy.Store
    pii.Store
    compliance.Store

    Migrate(ctx context.Context) error
    Ping(ctx context.Context) error
    Close() error
}
```

Implementations: **PostgreSQL**, **SQLite**, **In-memory** (testing).

## Documentation

Full documentation is available in the `docs/` directory and covers:

- [Getting Started](docs/content/docs/getting-started.mdx) -- Step-by-step setup guide
- [Architecture](docs/content/docs/architecture.mdx) -- Layered safety model deep dive
- [Concepts](docs/content/docs/concepts/) -- Identity, entities, configuration, errors, multi-tenancy
- [Guides](docs/content/docs/guides/) -- End-to-end pipeline, Forge extension, custom stores, custom plugins
- [API Reference](docs/content/docs/api-reference/) -- HTTP API and Go package reference

Run the docs site locally:

```bash
cd docs && pnpm install && pnpm dev
```

## Requirements

- Go 1.25.7+
- Part of the Forge ecosystem (`github.com/xraph/forge`)

## License

See [LICENSE](LICENSE) for details.
