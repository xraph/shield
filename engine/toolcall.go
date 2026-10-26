package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"

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
// Every object key, whatever its value, and every string and number value
// of the arguments is a unit, scanned on its own and unchanged, the way
// ScanInput would see that text, with Direction tool_call. Keys come sorted,
// each before what it holds. A finding from a unit lists the JSON path of
// each unit in its paths details (a.b.0, key:a.b for a key, $ for a
// top-level value); a key that is not a short identifier, that a layer
// found something in, or that a built-in secret or personal data detector
// matches whatever the profile runs, shows as #N, its place among its
// sorted siblings. The judge's lines name units the same way.
// Topic and data boundaries match the units joined by newlines. Action
// boundaries match the tool name, or with a risk: prefix the risk class.
// on_context reflexes see tool, risk_class (unknown when empty) and every
// Metadata key. The result never carries text, and the stored scan keeps the
// tool, the risk class and the metadata but no argument.
//
// Besides the errors of ScanInput, a nil input, a blank Tool or one holding a
// control or invisible rune, and arguments that are not one JSON value or
// nest deeper than MaxArgumentDepth are shield.ErrInvalidInput. Arguments,
// tool, risk class and metadata over Config.MaxScanBytes are
// shield.ErrInputTooLarge.
func (e *Engine) ScanToolCall(ctx context.Context, in *scan.ToolCallInput) (*scan.Result, error) {
	if in == nil {
		return nil, shield.ErrInvalidInput
	}
	return e.executeScan(ctx, &scan.Input{Direction: scan.DirectionToolCall, Profile: in.Profile}, in)
}

// toolCall is what the layers read of a tool call.
type toolCall struct {
	tool      string // trimmed
	riskClass string // RiskUnknown when the input names none
	args      *flatArguments
}

// hiddenRune reports a rune a tool name may not hold: one that does not
// print, or a format rune such as a zero-width space.
func hiddenRune(r rune) bool { return !unicode.IsGraphic(r) || unicode.Is(unicode.Cf, r) }

// prepareToolCall checks the call and fills input with what the layers
// scan: the argument units joined as the text, and the tool, risk class and
// metadata as both context and metadata. The tool and class win over
// metadata keys of the same name.
func (e *Engine) prepareToolCall(ctx context.Context, in *scan.ToolCallInput, input *scan.Input) (*toolCall, error) {
	if _, err := store.Tenant(ctx, ""); err != nil {
		return nil, err
	}
	tool := strings.TrimSpace(in.Tool)
	if tool == "" || strings.IndexFunc(tool, hiddenRune) >= 0 {
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
	flat, err := flattenArguments(in.Arguments, limit)
	if err != nil {
		return nil, err
	}
	call := &toolCall{tool: tool, riskClass: strings.TrimSpace(in.RiskClass), args: flat}
	if call.riskClass == "" {
		call.riskClass = scan.RiskUnknown
	}
	input.Text = flat.text
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

// leafKind is the kind of a JSON leaf.
type leafKind uint8

const (
	leafNull leafKind = iota
	leafString
	leafNumber
	leafBool
)

// jsonNode is one parsed JSON value. An object keeps every key, duplicates
// included, so a value a host parser would keep is never skipped.
type jsonNode struct {
	leaf     string
	kind     leafKind
	isLeaf   bool
	isObject bool
	keys     []string // object keys, parallel to kids
	kids     []*jsonNode
}

// argPath locates an argument unit: an object member (its key, and the
// key's place among its sorted siblings) or an array element under parent.
// It is rendered only into finding details, never into the scanned text.
type argPath struct {
	parent  *argPath
	key     string
	place   int  // index among the sorted members, or the array index
	isIndex bool // an array element
	keyUnit int  // the unit holding the key, for a member
}

// argUnit is what a scan unit of a tool call is: a key, or a string or
// number value, at path (nil for a top-level value).
type argUnit struct {
	path  *argPath
	isKey bool
}

// flatArguments is a tool call's arguments as the layers scan them: every
// key and every string and number value is its own unit, its text
// unchanged, and the text is the units joined by newlines.
type flatArguments struct {
	text  string
	units []unit
	args  []argUnit
}

// flattenArguments parses raw as one JSON value and splits it into units:
// each object key whatever its value, and each string and number value.
// Booleans and nulls carry no text. Empty and null arguments give no units.
// A text longer than limit is shield.ErrInputTooLarge.
func flattenArguments(raw json.RawMessage, limit int) (*flatArguments, error) {
	out := &flatArguments{}
	if len(bytes.TrimSpace(raw)) == 0 {
		return out, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	root, err := parseJSON(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err = dec.Token(); !errors.Is(err, io.EOF) {
		return nil, shield.ErrInvalidInput
	}
	f := &flattener{limit: limit, out: out}
	if !f.walk(root, nil) {
		return nil, shield.ErrInputTooLarge
	}
	out.text = f.b.String()
	return out, nil
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
		return &jsonNode{leaf: v, kind: leafString, isLeaf: true}, nil
	case json.Number:
		return &jsonNode{leaf: v.String(), kind: leafNumber, isLeaf: true}, nil
	case bool:
		return &jsonNode{leaf: strconv.FormatBool(v), kind: leafBool, isLeaf: true}, nil
	default:
		return &jsonNode{isLeaf: true, kind: leafNull}, nil
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

// flattener writes units. Each unit is written once, so the text is no
// longer than the keys and values it holds plus a newline each.
type flattener struct {
	b     strings.Builder
	out   *flatArguments
	limit int
}

// walk writes the units under n, which sits at path. It reports false once
// the text would pass the limit.
func (f *flattener) walk(n *jsonNode, at *argPath) bool {
	if n.isLeaf {
		if n.kind != leafString && n.kind != leafNumber {
			return true
		}
		return f.unit(n.leaf, argUnit{path: at})
	}
	for i, kid := range n.kids {
		p := &argPath{parent: at, place: i, isIndex: !n.isObject, keyUnit: -1}
		if n.isObject {
			p.key = n.keys[i]
			p.keyUnit = len(f.out.units)
			if !f.unit(p.key, argUnit{path: p, isKey: true}) {
				return false
			}
		}
		if !f.walk(kid, p) {
			return false
		}
	}
	return true
}

// unit writes one unit on its own line. An empty one is not written.
func (f *flattener) unit(text string, au argUnit) bool {
	if text == "" {
		return true
	}
	start := f.b.Len()
	if start > 0 {
		start++
	}
	if start+len(text) > f.limit {
		return false
	}
	if f.b.Len() > 0 {
		f.b.WriteByte('\n')
	}
	f.b.WriteString(text)
	f.out.units = append(f.out.units, unit{start: start, end: start + len(text)})
	f.out.args = append(f.out.args, au)
	return true
}

// maxFindingPaths bounds the paths one finding lists.
const maxFindingPaths = 16

// plainKey matches a key shown by name in a finding path: a short
// identifier. Any other key is shown by its place among its sorted
// siblings, as is a key a layer found something in or a built-in secret or
// personal data detector matches (hideSensitiveKeys), so a path never
// carries matched or free text.
var plainKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]{0,31}$`)

// renderPaths sets the paths details of the findings that name units: the
// JSON path of each unit (key units as key:<path>), a top-level value as $.
func (ev *evaluation) renderPaths() {
	for f, units := range ev.findingUnits {
		seen := map[string]bool{}
		paths := []string{}
		for _, u := range units {
			p := ev.unitPath(u)
			if seen[p] {
				continue
			}
			seen[p] = true
			paths = append(paths, p)
			if len(paths) == maxFindingPaths {
				break
			}
		}
		f.Details["paths"] = paths
	}
}

// unitPath renders the path of unit u.
func (ev *evaluation) unitPath(u int) string {
	au := ev.call.args.args[u]
	var segs []string
	for p := au.path; p != nil; p = p.parent {
		switch {
		case p.isIndex:
			segs = append(segs, strconv.Itoa(p.place))
		case plainKey.MatchString(p.key) && !ev.unitHits[p.keyUnit]:
			segs = append(segs, p.key)
		default:
			segs = append(segs, "#"+strconv.Itoa(p.place))
		}
	}
	slices.Reverse(segs)
	at := strings.Join(segs, ".")
	if at == "" {
		at = "$"
	}
	if au.isKey {
		return "key:" + at
	}
	return at
}

// actionCrossed reports whether call crosses an action limit: a deny entry
// matches, or the limit is an allowlist and no allow entry does (see
// ActionGlob for the entry forms). Deny entries also match ignoring case and
// surrounding space, and one that does not parse counts as a match: the
// admin service refuses such an entry, and one written straight to the
// store fails closed. Allow entries must match exactly. Both ways an odd
// entry or name restricts the call.
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

// ActionGlob splits an action-scope boundary entry into its path.Match
// glob and what it matches: the risk class for an entry with a risk:
// prefix (in any case), the tool name otherwise. The entry and the glob
// after the prefix are trimmed.
func ActionGlob(entry string) (glob string, risk bool) {
	entry = strings.TrimSpace(entry)
	if len(entry) >= len(riskPrefix) && strings.EqualFold(entry[:len(riskPrefix)], riskPrefix) {
		return strings.TrimSpace(entry[len(riskPrefix):]), true
	}
	return entry, false
}

// actionTarget returns the glob of an action entry and the value of call
// it matches.
func actionTarget(entry string, call *toolCall) (glob, value string) {
	glob, risk := ActionGlob(entry)
	if risk {
		return glob, call.riskClass
	}
	return glob, call.tool
}
