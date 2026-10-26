// Package nexusguard puts a shield engine behind nexus guards, so the
// prompts, tool results and model replies that pass through a nexus
// gateway are scanned by shield.
//
// Register an input guard and an output guard on the gateway's guard
// service:
//
//	gw.Guard().Register(nexusguard.Input(eng, nexusguard.WithProfile(presets.InfraAgentInput), nexusguard.WithApp("loomplane")))
//	gw.Guard().Register(nexusguard.Output(eng, nexusguard.WithProfile(presets.InfraAgentOutput), nexusguard.WithApp("loomplane")))
//
// Both guards are named "shield". Every scanned message is one shield scan,
// stored like any other.
//
// The input guard scans the messages of the roles WithRoles lists ("user"
// and "tool" by default) plus those WithUntrustedRoles lists ("tool" by
// default). It never scans "system". A message of an untrusted role is
// scanned with scan.Input.Untrusted set and Source "<role>_message", and
// always comes back as shield's quoted text, so the model sees it as data.
// Other roles change only when the scan redacts. The output guard scans the
// assistant's reply with Engine.ScanOutput and replaces it when the scan
// redacts.
//
// A scan that blocks makes the guard block with shield's fixed reason,
// which never quotes the content. A flag passes with Action warn. The
// result's Details["scan_ids"] lists the stored scans that did not allow
// their text, so a host can look them up. Assistant tool calls are not
// scanned here: hosts check them with Engine.ScanToolCall.
//
// The guards read the text of string content and of content parts, both
// []provider.ContentPart and the []any of JSON objects a decoded HTTP body
// holds. A message of a scanned role whose content has any other shape is
// an error, so content the guard cannot read never reaches the model
// unscanned. A message with several text parts is scanned as one text; when
// it changes, the first text part takes the new text and the other text
// parts are dropped. Parts without text, such as images, are kept as they
// are.
//
// # Tenants
//
// Every scan needs a shield tenant. By default the guards use the tenant
// already on the context (shield.WithTenant) and fall back to the nexus
// tenant of the request (CheckInput.TenantID). WithTenant maps the nexus
// tenant instead. No tenant from either source is shield.ErrTenantRequired,
// and the request fails.
//
// From nexus v1.9.0 on, CheckInput.Metadata holds a copy of the request's
// metadata in both phases, and the guards copy it onto each stored scan
// (shield's own "source" and "untrusted" keys win). With nexus v1.8.0 it is
// empty. The guards never write to it.
//
// # Model judge
//
// NewJudge and GatewayJudge build a judgment.Judge that asks a model,
// through nexus, how risky a text is. Register it with engine.WithJudge and
// turn it on with shield.Config.ModelJudge. The judge only ever sees the
// text shield has already redacted, and its completion carries a context
// marker that makes both guards pass it unscanned, so judging a scan never
// starts another. The marker is a private key type: callers cannot set it.
// WithJudgeProvider pins the judge's calls to one provider instead of the
// gateway's routing strategy.
package nexusguard
