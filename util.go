package main

import (
	"fmt"
	"sort"
	"strings"
)

// Helpers for walking loosely-typed decoded YAML/JSON.

func asMap(v any) map[string]any {
	switch m := v.(type) {
	case map[string]any:
		return m
	case map[any]any:
		out := make(map[string]any, len(m))
		for k, val := range m {
			out[fmt.Sprint(k)] = val
		}
		return out
	}
	return nil
}

func asList(v any) []any {
	if l, ok := v.([]any); ok {
		return l
	}
	return nil
}

// str renders a scalar as text. Control characters (newlines, ANSI escape
// sequences, ...) are stripped so that a hostile state file cannot inject
// terminal escapes or break the markdown tables.
func str(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return stripControl(x)
	default:
		return stripControl(fmt.Sprint(x))
	}
}

func stripControl(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

func strList(v any) []string {
	var out []string
	for _, x := range asList(v) {
		out = append(out, str(x))
	}
	return out
}

// ref resolves an entity reference, which decK allows as a plain string
// or as an object with a name or id.
func ref(v any) string {
	if m := asMap(v); m != nil {
		return firstNonEmpty(str(m["name"]), str(m["id"]))
	}
	return str(v)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func contains(in []string, s string) bool {
	for _, x := range in {
		if x == s {
			return true
		}
	}
	return false
}

func sorted(in []string) []string {
	out := append([]string{}, in...)
	sort.Strings(out)
	return out
}
