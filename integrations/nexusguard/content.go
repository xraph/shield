package nexusguard

import (
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/xraph/nexus/provider"
)

// maxPartDepth bounds how deep tool_result blocks may nest parts.
const maxPartDepth = 4

var errUnreadableContent = errors.New("nexusguard: message content has a shape the guard cannot read")

// Part types the guard understands. Text parts carry their text under the
// key of the same name. Media parts carry no text the guard can read and
// pass unchanged; they may not hold a "text" or "content" key.
var (
	textPartTypes  = []string{"text", "refusal", "thinking"}
	mediaPartTypes = []string{"image_url", "image", "image_base64", "input_audio", "audio", "file", "redacted_thinking", "tool_use"}
)

// textSlot is one text of a message's content and how to write its
// replacement into the content's copy.
type textSlot struct {
	text string
	set  func(string)
}

// contentCopy is a copy of a message's content, deep along every path to a
// text, with its texts in reading order. Setting a slot edits the copy,
// never the caller's content.
type contentCopy struct {
	value any
	slots []textSlot
}

// readContent reads content: nil, a string, []provider.ContentPart, or the
// []any or []map[string]any of JSON parts a decoded body holds. Any other
// shape, a part of a type the guard does not know, and a text part whose
// text is not a string are errors, so nothing the guard cannot read passes
// unscanned.
func readContent(content any) (*contentCopy, error) {
	cc := &contentCopy{value: content}
	switch c := content.(type) {
	case nil:
	case string:
		cc.slots = append(cc.slots, textSlot{text: c, set: func(s string) { cc.value = s }})
	case []provider.ContentPart:
		parts := slices.Clone(c)
		cc.value = parts
		for i := range parts {
			if err := cc.readStruct(&parts[i], func() {}); err != nil {
				return nil, err
			}
		}
	case []map[string]any:
		parts := slices.Clone(c)
		cc.value = parts
		for i, p := range parts {
			m, err := cc.readMap(p, 0)
			if err != nil {
				return nil, err
			}
			parts[i] = m
		}
	case []any:
		parts := slices.Clone(c)
		cc.value = parts
		if err := cc.readParts(parts, 0); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("%w: content of type %T", errUnreadableContent, content)
	}
	return cc, nil
}

// text is the content's texts joined, for reading a reply.
func (cc *contentCopy) text() string {
	var out string
	for _, s := range cc.slots {
		out += s.text
	}
	return out
}

// readParts reads parts in place: each element is replaced by its copy.
func (cc *contentCopy) readParts(parts []any, depth int) error {
	for i, el := range parts {
		switch p := el.(type) {
		case map[string]any:
			m, err := cc.readMap(p, depth)
			if err != nil {
				return err
			}
			parts[i] = m
		case provider.ContentPart:
			cp := p
			if err := cc.readStruct(&cp, func() { parts[i] = cp }); err != nil {
				return err
			}
		case *provider.ContentPart:
			if p == nil {
				continue
			}
			cp := *p
			parts[i] = &cp
			if err := cc.readStruct(&cp, func() {}); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%w: a part of type %T", errUnreadableContent, el)
		}
	}
	return nil
}

// readStruct reads a provider.ContentPart. Its Text is scanned whatever
// its type, because some providers send the text of every part; commit
// writes the edited part back.
func (cc *contentCopy) readStruct(p *provider.ContentPart, commit func()) error {
	if !slices.Contains(textPartTypes, p.Type) && !slices.Contains(mediaPartTypes, p.Type) {
		return fmt.Errorf("%w: a part of an unknown type", errUnreadableContent)
	}
	if p.Text != "" {
		cc.slots = append(cc.slots, textSlot{text: p.Text, set: func(s string) { p.Text = s; commit() }})
	}
	return nil
}

// readMap reads a JSON part and returns its copy.
func (cc *contentCopy) readMap(m map[string]any, depth int) (map[string]any, error) {
	typ, ok := m["type"].(string)
	if !ok {
		return nil, fmt.Errorf("%w: a part with no type", errUnreadableContent)
	}
	out := maps.Clone(m)
	switch {
	case slices.Contains(textPartTypes, typ):
		v, present := m[typ]
		if !present || v == nil {
			return out, nil
		}
		s, isString := v.(string)
		if !isString {
			return nil, fmt.Errorf("%w: a %s part whose text is not a string", errUnreadableContent, typ)
		}
		cc.slot(out, typ, s)
	case typ == "tool_result":
		switch c := m["content"].(type) {
		case nil:
		case string:
			cc.slot(out, "content", c)
		case []any:
			if depth >= maxPartDepth {
				return nil, fmt.Errorf("%w: tool results nested deeper than %d", errUnreadableContent, maxPartDepth)
			}
			inner := slices.Clone(c)
			out["content"] = inner
			if err := cc.readParts(inner, depth+1); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("%w: a tool_result whose content is not text or parts", errUnreadableContent)
		}
	case slices.Contains(mediaPartTypes, typ):
		if _, has := m["text"]; has {
			return nil, fmt.Errorf("%w: a %s part that holds text", errUnreadableContent, typ)
		}
		if _, has := m["content"]; has {
			return nil, fmt.Errorf("%w: a %s part that holds content", errUnreadableContent, typ)
		}
	default:
		return nil, fmt.Errorf("%w: a part of an unknown type", errUnreadableContent)
	}
	return out, nil
}

// slot records the string under key of the part copy m.
func (cc *contentCopy) slot(m map[string]any, key, s string) {
	if s == "" {
		return
	}
	cc.slots = append(cc.slots, textSlot{text: s, set: func(t string) { m[key] = t }})
}
