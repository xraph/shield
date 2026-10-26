package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/xraph/shield"
	"github.com/xraph/shield/scan"
	"github.com/xraph/shield/store"
)

// MaxArgumentDepth bounds how deeply the JSON arguments of a tool call may
// nest objects and arrays. Deeper arguments are shield.ErrInvalidInput. Tool
// arguments are flat in practice; the bound keeps a hostile body from
// costing a deep walk.
const MaxArgumentDepth = 32

// riskPrefix marks an action limit entry that matches the risk class rather
// than the tool name.
const riskPrefix = "risk:"

// ScanToolCall evaluates a proposed tool call. The decision is allow, block or
// require_approval. It is advisory and can only restrict: the host enforces its
// own risk table first and combines with scan.Stricter, so nothing here can turn
// a host refusal into an allow.
//
// The arguments are flattened into one line path=value for each string,
// number and bool, keys sorted (items.0.name=x), and the text layers run over
// that text with Direction tool_call. Action boundaries match the tool name,
// or with a risk: prefix the risk class. on_context reflexes see tool,
// risk_class (unknown when empty) and every Metadata key. The result never
// carries text, and the stored scan keeps the tool, the risk class and the
// metadata but no argument value.
//
// Besides the errors of ScanInput, a nil input, an empty Tool, arguments that
// are not one JSON value or nest deeper than MaxArgumentDepth are
// shield.ErrInvalidInput, and arguments, flattened text or metadata over
// Config.MaxScanBytes are shield.ErrInputTooLarge.
func (e *Engine) ScanToolCall(ctx context.Context, in *scan.ToolCallInput) (*scan.Result, error) {
	if in == nil {
		return nil, shield.ErrInvalidInput
	}
	return e.executeScan(ctx, &scan.Input{Direction: scan.DirectionToolCall, Profile: in.Profile}, in)
}

// toolCall is what the layers read of a tool call besides its flattened
// arguments.
type toolCall struct {
	tool      string
	riskClass string // RiskUnknown when the input names none
}

// prepareToolCall checks the call and fills input with what the layers
// scan: the flattened arguments as the text, and the tool, risk class and
// metadata as both context and metadata. The tool and class win over
// metadata keys of the same name.
func (e *Engine) prepareToolCall(ctx context.Context, in *scan.ToolCallInput, input *scan.Input) (*toolCall, error) {
	if _, err := store.Tenant(ctx, ""); err != nil {
		return nil, err
	}
	if strings.TrimSpace(in.Tool) == "" {
		return nil, shield.ErrInvalidInput
	}
	limit := e.config.MaxScanBytes
	size := len(in.Arguments) + len(in.Tool) + len(in.RiskClass)
	for k, v := range in.Metadata {
		size += len(k) + len(v)
	}
	if size > limit {
		return nil, shield.ErrInputTooLarge
	}
	text, err := flattenArguments(in.Arguments, limit)
	if err != nil {
		return nil, err
	}
	call := &toolCall{tool: in.Tool, riskClass: strings.TrimSpace(in.RiskClass)}
	if call.riskClass == "" {
		call.riskClass = scan.RiskUnknown
	}
	input.Text = text
	input.Context = make(map[string]any, len(in.Metadata)+2)
	input.Metadata = make(map[string]any, len(in.Metadata)+2)
	for k, v := range in.Metadata {
		input.Context[k] = v
		input.Metadata[k] = v
	}
	for k, v := range map[string]string{"tool": call.tool, "risk_class": call.riskClass} {
		input.Context[k] = v
		input.Metadata[k] = v
	}
	return call, nil
}

// jsonNode is one parsed JSON value. An object keeps every key, duplicates
// included, so a value a host parser would keep is never skipped.
type jsonNode struct {
	leaf     string
	isLeaf   bool
	isObject bool
	keys     []string // object keys, parallel to kids
	kids     []*jsonNode
}

// flattenArguments parses raw as one JSON value and returns its leaves as
// lines path=value. Empty and null arguments give no text. Text longer than
// limit is shield.ErrInputTooLarge.
func flattenArguments(raw json.RawMessage, limit int) (string, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return "", nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	root, err := parseJSON(dec, 0)
	if err != nil {
		return "", err
	}
	if _, err = dec.Token(); !errors.Is(err, io.EOF) {
		return "", shield.ErrInvalidInput
	}
	f := &flattener{limit: limit}
	if !f.walk(root) {
		return "", shield.ErrInputTooLarge
	}
	return f.b.String(), nil
}

// parseJSON reads one value from dec. depth is the number of objects and
// arrays around it.
func parseJSON(dec *json.Decoder, depth int) (*jsonNode, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, shield.ErrInvalidInput
	}
	switch v := tok.(type) {
	case json.Delim:
		if v != '{' && v != '[' {
			return nil, shield.ErrInvalidInput
		}
		if depth >= MaxArgumentDepth {
			return nil, shield.ErrInvalidInput
		}
		n := &jsonNode{isObject: v == '{'}
		for dec.More() {
			if n.isObject {
				keyTok, keyErr := dec.Token()
				key, ok := keyTok.(string)
				if keyErr != nil || !ok {
					return nil, shield.ErrInvalidInput
				}
				n.keys = append(n.keys, key)
			}
			kid, kidErr := parseJSON(dec, depth+1)
			if kidErr != nil {
				return nil, kidErr
			}
			n.kids = append(n.kids, kid)
		}
		if _, err = dec.Token(); err != nil {
			return nil, shield.ErrInvalidInput
		}
		if n.isObject {
			sortKeys(n)
		}
		return n, nil
	case string:
		return &jsonNode{leaf: v, isLeaf: true}, nil
	case json.Number:
		return &jsonNode{leaf: v.String(), isLeaf: true}, nil
	case bool:
		return &jsonNode{leaf: strconv.FormatBool(v), isLeaf: true}, nil
	default: // null
		return &jsonNode{}, nil
	}
}

// sortKeys orders an object's keys, keeping duplicates in document order.
func sortKeys(n *jsonNode) {
	order := make([]int, len(n.keys))
	for i := range order {
		order[i] = i
	}
	slices.SortStableFunc(order, func(a, b int) int { return strings.Compare(n.keys[a], n.keys[b]) })
	keys, kids := make([]string, len(order)), make([]*jsonNode, len(order))
	for i, j := range order {
		keys[i], kids[i] = n.keys[j], n.kids[j]
	}
	n.keys, n.kids = keys, kids
}

// flattener writes leaves as lines. The path is a stack of segments, joined
// only when a leaf is written, so empty containers under a long key cost
// nothing and the work stays within limit.
type flattener struct {
	b     strings.Builder
	path  []string
	limit int
}

// walk writes the leaves under n. It reports false once the text would
// pass the limit.
func (f *flattener) walk(n *jsonNode) bool {
	if n.isLeaf {
		return f.line(n.leaf)
	}
	for i, kid := range n.kids {
		seg := strconv.Itoa(i)
		if n.isObject {
			seg = n.keys[i]
		}
		f.path = append(f.path, seg)
		ok := f.walk(kid)
		f.path = f.path[:len(f.path)-1]
		if !ok {
			return false
		}
	}
	return true
}

// line writes path=value, or the value alone for a top-level leaf.
func (f *flattener) line(value string) bool {
	n := len(value)
	if f.b.Len() > 0 {
		n++
	}
	for _, seg := range f.path {
		n += len(seg) + 1
	}
	if f.b.Len()+n > f.limit {
		return false
	}
	if f.b.Len() > 0 {
		f.b.WriteByte('\n')
	}
	for i, seg := range f.path {
		if i > 0 {
			f.b.WriteByte('.')
		}
		f.b.WriteString(seg)
	}
	if len(f.path) > 0 {
		f.b.WriteByte('=')
	}
	f.b.WriteString(value)
	return true
}

// actionCrossed reports whether call crosses an action limit: a deny entry
// matches, or the limit is an allowlist and no allow entry does. An entry
// is a path.Match glob on the tool name, or with a risk: prefix on the risk
// class. Deny entries also match ignoring case and surrounding space, and
// one that does not parse counts as a match (the admin service refuses
// such an entry; one written through the store fails closed); allow entries must match
// exactly. Both ways an odd entry or name restricts the call.
func (l compiledLimit) actionCrossed(call *toolCall) bool {
	for _, entry := range l.deny {
		glob, value := actionTarget(entry, call)
		if ok, err := path.Match(glob, value); ok || err != nil {
			return true
		}
		if ok, err := path.Match(strings.ToLower(glob), strings.ToLower(strings.TrimSpace(value))); ok && err == nil {
			return true
		}
	}
	if !l.useAllow {
		return false
	}
	for _, entry := range l.allow {
		glob, value := actionTarget(entry, call)
		if ok, err := path.Match(glob, value); ok && err == nil {
			return false
		}
	}
	return true
}

// actionTarget splits an action entry into its glob and the value it
// matches.
func actionTarget(entry string, call *toolCall) (glob, value string) {
	if g, ok := strings.CutPrefix(entry, riskPrefix); ok {
		return g, call.riskClass
	}
	return entry, call.tool
}
