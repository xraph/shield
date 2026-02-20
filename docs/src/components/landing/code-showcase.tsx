"use client";

import { motion } from "framer-motion";
import { CodeBlock } from "./code-block";
import { SectionHeader } from "./section-header";

const scanCode = `package main

import (
  "context"
  "log/slog"

  "github.com/xraph/shield"
  "github.com/xraph/shield/profile"
  "github.com/xraph/shield/store/memory"
)

func main() {
  ctx := context.Background()

  engine, _ := shield.NewEngine(
    shield.WithStore(memory.New()),
    shield.WithProfile(profile.Default()),
    shield.WithLogger(slog.Default()),
  )

  ctx = shield.WithTenant(ctx, "tenant-1")
  ctx = shield.WithApp(ctx, "myapp")

  // Scan an AI agent's input through safety layers
  result, _ := engine.Scan(ctx,
    shield.ScanInput{
      Content:   "Process this user request...",
      Direction: shield.DirectionInput,
      Source:    "chat-agent",
    })
  // result.Safe=true layers=6 elapsed=12ms
}`;

const pluginCode = `package main

import (
  "context"
  "log/slog"

  "github.com/xraph/shield"
)

// Implement a custom plugin for audit trails
type AuditPlugin struct {
  logger *slog.Logger
}

func (p *AuditPlugin) OnScanCompleted(
  ctx context.Context,
  input shield.ScanInput,
  result shield.ScanResult,
) {
  p.logger.Info("scan completed",
    "safe", result.Safe,
    "layers", len(result.LayerResults),
    "pii_detected", result.PIICount,
    "tenant", shield.TenantFromCtx(ctx),
  )
}

func (p *AuditPlugin) OnPolicyViolation(
  ctx context.Context,
  violation shield.PolicyViolation,
) {
  p.logger.Warn("policy violation",
    "policy", violation.PolicyID,
    "severity", violation.Severity,
  )
}`;

export function CodeShowcase() {
  return (
    <section className="relative w-full py-20 sm:py-28">
      <div className="container max-w-(--fd-layout-width) mx-auto px-4 sm:px-6">
        <SectionHeader
          badge="Developer Experience"
          title="Simple API. Powerful safety."
          description="Scan AI agent inputs and outputs through six safety layers in under 20 lines. Shield handles the rest."
        />

        <div className="mt-14 grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Safety scan side */}
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5, delay: 0.1 }}
          >
            <div className="mb-3 flex items-center gap-2">
              <div className="size-2 rounded-full bg-blue-500" />
              <span className="text-xs font-medium text-fd-muted-foreground uppercase tracking-wider">
                Safety Scan
              </span>
            </div>
            <CodeBlock code={scanCode} filename="main.go" />
          </motion.div>

          {/* Plugin side */}
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5, delay: 0.2 }}
          >
            <div className="mb-3 flex items-center gap-2">
              <div className="size-2 rounded-full bg-green-500" />
              <span className="text-xs font-medium text-fd-muted-foreground uppercase tracking-wider">
                Plugin System
              </span>
            </div>
            <CodeBlock code={pluginCode} filename="plugin.go" />
          </motion.div>
        </div>
      </div>
    </section>
  );
}
