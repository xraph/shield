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
// Both guards are named "shield". Each text of a scanned message is one
// shield scan, stored like any other.
//
// The input guard scans the messages of the roles WithRoles lists ("user"
// and "tool" by default) plus those WithUntrustedRoles lists ("tool" by
// default). It never scans "system". A message with an empty role is
// scanned as "user". A message whose role neither option names passes
// unscanned, so list every role that carries text the model reads, such as
// the legacy "function" role. A message of an untrusted role is
// scanned with scan.Input.Untrusted set and Source "<role>_message", and
// always comes back as shield's quoted text, so the model sees it as data.
// Other roles change only when the scan redacts. The output guard scans
// every reply message, whatever role the provider gives it, with
// Engine.ScanOutput and replaces its text when the scan redacts.
//
// A scan that blocks makes the guard block with shield's fixed reason,
// which never quotes the content. A flag passes with Action warn. The
// result's Details["scan_ids"] lists the stored scans that did not allow
// their text, so a host can look them up. Assistant tool calls are not
// scanned here: hosts check them with Engine.ScanToolCall.
//
// # Content
//
// The guards read string content, []provider.ContentPart and the []any of
// JSON parts a decoded HTTP body holds. They know these part types:
//
//   - text parts "text", "refusal" and "thinking", whose text sits under
//     the key of the same name or under "content", both scanned, and must
//     be a string;
//   - "tool_result", whose "content" is a string or parts, nested at most
//     four deep, and whose "text", if it has one, is scanned too;
//   - media parts "image_url", "image", "image_base64", "input_audio",
//     "audio", "file", "redacted_thinking" and "tool_use", which pass
//     unchanged and may hold no "text" or "content" key. Text inside media,
//     such as the words in an image or a PDF, is not scanned.
//
// Any other part type, a text part whose text is not a string, a
// tool_result whose "text" is not a string, and any
// other content shape fail the request in a scanned role, so text the
// guard cannot read never reaches the model unscanned. Each text is
// scanned on its own and its replacement is written back into the part it
// came from, so the layout of text and media parts is kept.
//
// # History
//
// nexus runs the input guard on the whole conversation of every request.
// Each guard keeps the verdicts of the texts it scanned (see
// WithVerdictCache), so only new or changed messages are scanned and
// stored, and the model judge runs only for them. A block is never cached.
// Keep your own unguarded history: the guardrail middleware writes the
// guarded messages back into the request. If you send the guarded copy
// back anyway, the guard strips its own quoting first and quotes each text
// once.
//
// # Tenants
//
// Every scan needs a shield tenant. By default the guards use the tenant
// already on the context (shield.WithTenant), which wins over the nexus
// tenant of the request (CheckInput.TenantID), and fall back to the nexus
// tenant. WithTenant maps the nexus tenant instead. No tenant from either
// source is shield.ErrTenantRequired, and the request fails.
//
// # nexus versions
//
// The module builds against nexus v1.8.0 and later. From v1.9.0 on,
// CheckInput.Metadata holds a copy of the request's metadata in both
// phases, and the guards copy it onto each stored scan, leaving out the
// keys shield owns ("source", "untrusted", "secret_count"). With v1.8.0 it
// is empty. The guards never write to it. On v1.8.0 output guards see only
// non-streamed replies; v1.9.0 also runs them on streamed output.
//
// # Model judge
//
// NewJudge and GatewayJudge build a judgment.Judge that asks a model,
// through nexus, how risky a text is. Register it with engine.WithJudge and
// turn it on with shield.Config.ModelJudge. The engine replaces every
// secret and personal data value that awareness or shield's built-in
// detectors find with a placeholder before the judge sees the text,
// whatever the profile's awareness settings. The judge's completion carries
// a context marker that makes both guards pass it unscanned, so judging a
// scan never starts another. The marker is a private key type: callers
// cannot set it. WithJudgeProvider pins the judge's calls to one provider
// instead of the gateway's routing strategy.
package nexusguard
