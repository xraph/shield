"use client";

import { motion } from "framer-motion";
import { cn } from "@/lib/cn";
import { CodeBlock } from "./code-block";
import { SectionHeader } from "./section-header";

interface FeatureCard {
  title: string;
  description: string;
  icon: React.ReactNode;
  code: string;
  filename: string;
  colSpan?: number;
}

const features: FeatureCard[] = [
  {
    title: "Layered Safety Engine",
    description:
      "Six cognitive layers from instincts to reflexes. Shield processes every input through a composable pipeline of safety checks, each layer building on the last.",
    icon: (
      <svg
        className="size-5"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
      >
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      </svg>
    ),
    code: `result, err := engine.Scan(ctx,
  shield.ScanInput{
    Content:   "Process this request...",
    Direction: shield.DirectionInput,
    Source:    "chat-agent",
  })
// result.Safe=true layers=6`,
    filename: "scan.go",
  },
  {
    title: "PII Detection & Vault",
    description:
      "Detect, redact, and vault PII with AES-256-GCM encryption. Sensitive data is identified, tokenized, and stored securely with reversible access controls.",
    icon: (
      <svg
        className="size-5"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
      >
        <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
        <path d="M7 11V7a5 5 0 0110 0v4" />
      </svg>
    ),
    code: `result, err := engine.DetectPII(ctx,
  shield.PIIInput{
    Content: "Email john@example.com, SSN 123-45-6789",
  })
// result.Entities=[email, ssn]
// result.Redacted="Email [REDACTED], SSN [REDACTED]"`,
    filename: "pii.go",
  },
  {
    title: "Multi-Tenant Isolation",
    description:
      "Every scan, policy evaluation, and audit record is scoped to a tenant via context. Cross-tenant access is structurally impossible.",
    icon: (
      <svg
        className="size-5"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
      >
        <path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2" />
        <circle cx="9" cy="7" r="4" />
        <path d="M23 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75" />
      </svg>
    ),
    code: `ctx = shield.WithTenant(ctx, "tenant-1")
ctx = shield.WithApp(ctx, "myapp")

// All scans and policy evaluations are
// automatically scoped to tenant-1`,
    filename: "scope.go",
  },
  {
    title: "Plugin System",
    description:
      "15 lifecycle hooks for metrics, audit trails, and tracing. Wire in custom logic at every stage of the safety pipeline without modifying engine code.",
    icon: (
      <svg
        className="size-5"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
      >
        <path d="M20.24 12.24a6 6 0 00-8.49-8.49L5 10.5V19h8.5z" />
        <line x1="16" y1="8" x2="2" y2="22" />
        <line x1="17.5" y1="15" x2="9" y2="15" />
      </svg>
    ),
    code: `func (p *MetricsPlugin) OnScanCompleted(
  ctx context.Context,
  input shield.ScanInput,
  result shield.ScanResult,
) {
  metrics.Inc("shield.scans.total")
  metrics.Observe("shield.scan.duration", result.Elapsed)
}`,
    filename: "plugin.go",
  },
  {
    title: "Safety Profiles",
    description:
      "Compose instincts, awareness, boundaries, values, judgment, and reflexes into reusable safety profiles. Switch profiles per tenant, agent, or environment.",
    icon: (
      <svg
        className="size-5"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
      >
        <path d="M3 6h18M3 12h18M3 18h18" />
        <rect x="2" y="3" width="20" height="18" rx="2" />
      </svg>
    ),
    code: `p := profile.New("strict",
  profile.WithInstincts(instinct.BlockInjection()),
  profile.WithAwareness(awareness.DetectPII()),
  profile.WithBoundaries(boundary.RateLimit(100)),
  profile.WithValues(values.NoHarm()),
  profile.WithJudgment(judgment.Threshold(0.95)),
  profile.WithReflexes(reflex.AutoBlock()),
)`,
    filename: "profile.go",
  },
  {
    title: "Compliance Reporting",
    description:
      "Generate compliance reports for EU AI Act, NIST AI RMF, and SOC2. Automated evidence collection from scan results, policy evaluations, and audit trails.",
    icon: (
      <svg
        className="size-5"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
      >
        <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" />
        <polyline points="14 2 14 8 20 8" />
        <line x1="16" y1="13" x2="8" y2="13" />
        <line x1="16" y1="17" x2="8" y2="17" />
        <polyline points="10 9 9 9 8 9" />
      </svg>
    ),
    code: `report, _ := engine.GenerateReport(ctx,
  shield.ReportInput{
    Framework:  shield.FrameworkEUAIAct,
    Period:     "2025-Q1",
    TenantID:   "tenant-1",
    IncludeEvidence: true,
  })
// report.Score=94 controls=23 findings=2`,
    filename: "compliance.go",
    colSpan: 2,
  },
];

const containerVariants = {
  hidden: {},
  visible: {
    transition: {
      staggerChildren: 0.08,
    },
  },
};

const itemVariants = {
  hidden: { opacity: 0, y: 20 },
  visible: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.5, ease: "easeOut" as const },
  },
};

export function FeatureBento() {
  return (
    <section className="relative w-full py-20 sm:py-28">
      <div className="container max-w-(--fd-layout-width) mx-auto px-4 sm:px-6">
        <SectionHeader
          badge="Features"
          title="Everything you need for AI safety"
          description="Shield handles the hard parts — safety scanning, PII detection, policy governance, and compliance reporting — so you can focus on your application."
        />

        <motion.div
          variants={containerVariants}
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true, margin: "-50px" }}
          className="mt-14 grid grid-cols-1 md:grid-cols-2 gap-4"
        >
          {features.map((feature) => (
            <motion.div
              key={feature.title}
              variants={itemVariants}
              className={cn(
                "group relative rounded-xl border border-fd-border bg-fd-card/50 backdrop-blur-sm p-6 hover:border-blue-500/20 hover:bg-fd-card/80 transition-all duration-300",
                feature.colSpan === 2 && "md:col-span-2",
              )}
            >
              {/* Header */}
              <div className="flex items-start gap-3 mb-4">
                <div className="flex items-center justify-center size-9 rounded-lg bg-blue-500/10 text-blue-600 dark:text-blue-400 shrink-0">
                  {feature.icon}
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-fd-foreground">
                    {feature.title}
                  </h3>
                  <p className="text-xs text-fd-muted-foreground mt-1 leading-relaxed">
                    {feature.description}
                  </p>
                </div>
              </div>

              {/* Code snippet */}
              <CodeBlock
                code={feature.code}
                filename={feature.filename}
                showLineNumbers={false}
                className="text-xs"
              />
            </motion.div>
          ))}
        </motion.div>
      </div>
    </section>
  );
}
