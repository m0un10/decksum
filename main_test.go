package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func summarizeFile(t *testing.T, path string) *Summary {
	t.Helper()
	var out, errOut bytes.Buffer
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if code := run([]string{"-f", "json"}, f, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	var s Summary
	if err := json.Unmarshal(out.Bytes(), &s); err != nil {
		t.Fatal(err)
	}
	return &s
}

func count(s *Summary, entity string) int {
	for _, c := range s.Counts {
		if c.Entity == entity {
			return c.Total
		}
	}
	return -1
}

func TestSampleCounts(t *testing.T) {
	s := summarizeFile(t, "testdata/kong.yaml")
	want := map[string]int{"services": 4, "routes": 8, "plugins": 9, "consumers": 2, "upstreams": 1, "certificates": 1, "vaults": 1}
	for e, n := range want {
		if got := count(s, e); got != n {
			t.Errorf("%s = %d, want %d", e, got, n)
		}
	}
}

func TestAuthInheritance(t *testing.T) {
	s := summarizeFile(t, "testdata/kong.yaml")
	auth := map[string][]string{}
	for _, r := range s.allRoutes() {
		auth[r.Name] = r.Auth
	}
	cases := map[string]string{
		"orders-api": "key-auth",       // inherited from service
		"healthz":    "key-auth",       // top-level route attached by service ref
		"checkout":   "openid-connect", // route-level
	}
	for route, plugin := range cases {
		if !contains(auth[route], plugin) {
			t.Errorf("route %s auth = %v, want %s", route, auth[route], plugin)
		}
	}
	for _, route := range []string{"public-docs", "legacy-checkout", "stray"} {
		if len(auth[route]) != 0 {
			t.Errorf("route %s should have no auth, got %v", route, auth[route])
		}
	}
}

func TestFindings(t *testing.T) {
	s := summarizeFile(t, "testdata/kong.yaml")
	var all []string
	for _, f := range s.Findings {
		all = append(all, f.Level+": "+f.Message)
	}
	joined := strings.Join(all, "\n")
	for _, want := range []string{
		"warn: 4 of 8 routes have no auth plugin",
		"warn: path /docs is defined on multiple routes",
		`warn: route stray references service "billing"`,
		"info: 1 service has no routes: reporting",
		"info: disabled plugins: request-transformer (1)",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing finding %q in:\n%s", want, joined)
		}
	}
}

func TestGlobalAuthCoversEverything(t *testing.T) {
	in := strings.NewReader(`{"_format_version":"3.0","plugins":[{"name":"key-auth"}],
		"services":[{"name":"a","url":"https://a","routes":[{"name":"r","paths":["/a"],"protocols":["https"]}]}]}`)
	var out, errOut bytes.Buffer
	if code := run([]string{"--fail-on-warn"}, in, &out, &errOut); code != 0 {
		t.Fatalf("exit %d, output:\n%s%s", code, out.String(), errOut.String())
	}
}

func TestFailOnWarnAndBadInput(t *testing.T) {
	var out, errOut bytes.Buffer
	in := strings.NewReader("services:\n  - name: a\n    url: https://a\n    routes:\n      - name: r\n        paths: [/a]\n")
	if code := run([]string{"--fail-on-warn"}, in, &out, &errOut); code != 2 {
		t.Errorf("want exit 2 for unauthenticated route, got %d", code)
	}
	if code := run(nil, strings.NewReader("- just\n- a list\n"), &out, &errOut); code != 1 {
		t.Errorf("want exit 1 for non-map input, got %d", code)
	}
	if code := run(nil, strings.NewReader("   \n"), &out, &errOut); code != 1 {
		t.Errorf("want exit 1 for empty input, got %d", code)
	}
}

func TestMarkdownRenders(t *testing.T) {
	f, _ := os.Open("testdata/kong.yaml")
	defer f.Close()
	var out, errOut bytes.Buffer
	if code := run([]string{"--format", "markdown"}, f, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	for _, want := range []string{"## decK config summary", "| `rate-limiting` | 3 |", "### Findings"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("markdown missing %q", want)
		}
	}
}

func TestHostileNamesAreNeutralised(t *testing.T) {
	in := `{"services":[{"name":"evil\u001b[31m|x\nsvc","url":"https://a","routes":[{"name":"r|1","paths":["/a"]}]}]}`
	var out, errOut bytes.Buffer
	if code := run([]string{"-f", "markdown"}, strings.NewReader(in), &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	got := out.String()
	if strings.Contains(got, "\x1b") || strings.Contains(got, "evil\n") {
		t.Errorf("control characters leaked into output:\n%s", got)
	}
	if !strings.Contains(got, `evil[31m\|xsvc`) || !strings.Contains(got, `r\|1`) {
		t.Errorf("pipes not escaped in markdown table:\n%s", got)
	}
}
