package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

type renderOpts struct {
	tree  bool
	color bool
}

func renderJSON(w io.Writer, s *Summary) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(s)
}

func renderText(w io.Writer, s *Summary, o renderOpts) {
	bold := func(t string) string { return t }
	dim := bold
	yellow, cyan := bold, bold
	if o.color {
		bold = func(t string) string { return "\033[1m" + t + "\033[0m" }
		dim = func(t string) string { return "\033[2m" + t + "\033[0m" }
		yellow = func(t string) string { return "\033[33m" + t + "\033[0m" }
		cyan = func(t string) string { return "\033[36m" + t + "\033[0m" }
	}

	head := "decK config summary"
	var meta []string
	if s.FormatVersion != "" {
		meta = append(meta, "format "+s.FormatVersion)
	}
	if s.Workspace != "" {
		meta = append(meta, "workspace "+s.Workspace)
	}
	if len(s.SelectTags) > 0 {
		meta = append(meta, "select_tags "+strings.Join(s.SelectTags, ","))
	}
	fmt.Fprintln(w, bold(head))
	if len(meta) > 0 {
		fmt.Fprintln(w, dim(strings.Join(meta, " · ")))
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, bold("ENTITIES"))
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, c := range s.Counts {
		detail := ""
		if c.Detail != "" {
			detail = dim("(" + c.Detail + ")")
		}
		fmt.Fprintf(tw, "  %s\t%4d\t%s\n", strings.ReplaceAll(c.Entity, "_", " "), c.Total, detail)
	}
	tw.Flush()

	if len(s.Plugins) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, bold("PLUGINS"))
		tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, dim("  NAME\tTOTAL\tGLOBAL\tSERVICE\tROUTE\tCONSUMER\tDISABLED"))
		for _, p := range s.Plugins {
			fmt.Fprintf(tw, "  %s\t%d\t%s\t%s\t%s\t%s\t%s\n", p.Name, p.Total,
				blank(p.Global), blank(p.Service), blank(p.Route), blank(p.Consumer+p.ConsumerGroup), blank(p.Disabled))
		}
		tw.Flush()
	}

	if o.tree && (len(s.Services) > 0 || len(s.OrphanRoutes) > 0) {
		fmt.Fprintln(w)
		fmt.Fprintln(w, bold("SERVICES"))
		for _, svc := range s.Services {
			line := "  " + cyan(svc.Name)
			if svc.Target != "" {
				line += dim(" → " + svc.Target)
			}
			if len(svc.Plugins) > 0 {
				line += "  [" + strings.Join(svc.Plugins, ", ") + "]"
			}
			fmt.Fprintln(w, line)
			writeRoutes(w, svc.Routes, dim, yellow)
		}
		if len(s.OrphanRoutes) > 0 {
			fmt.Fprintln(w, "  "+cyan("(routes without a matching service)"))
			writeRoutes(w, s.OrphanRoutes, dim, yellow)
		}
	}

	if len(s.Findings) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, bold("FINDINGS"))
		for _, f := range s.Findings {
			tag := dim("info")
			if f.Level == "warn" {
				tag = yellow("warn")
			}
			fmt.Fprintf(w, "  %s  %s\n", tag, f.Message)
		}
	}
}

func writeRoutes(w io.Writer, routes []RouteInfo, dim, yellow func(string) string) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for i, r := range routes {
		branch := "├─"
		if i == len(routes)-1 {
			branch = "└─"
		}
		methods := strings.Join(r.Methods, ",")
		if methods == "" {
			methods = "ANY"
		}
		match := strings.Join(r.Paths, " ")
		if len(r.Hosts) > 0 {
			match = strings.Join(r.Hosts, ",") + " " + match
		}
		auth := yellow("no auth")
		if len(r.Auth) > 0 {
			auth = "auth: " + strings.Join(r.Auth, ",")
		}
		extra := ""
		if len(r.Plugins) > 0 {
			extra = " [" + strings.Join(r.Plugins, ", ") + "]"
		}
		fmt.Fprintf(tw, "    %s %s\t%s\t%s\t%s%s\n", dim(branch), r.Name, dim(methods), strings.TrimSpace(match), auth, extra)
	}
	tw.Flush()
}

func renderMarkdown(w io.Writer, s *Summary, o renderOpts) {
	fmt.Fprintln(w, "## decK config summary")
	fmt.Fprintln(w)
	var meta []string
	if s.FormatVersion != "" {
		meta = append(meta, "format `"+s.FormatVersion+"`")
	}
	if s.Workspace != "" {
		meta = append(meta, "workspace `"+s.Workspace+"`")
	}
	if len(s.SelectTags) > 0 {
		meta = append(meta, "select_tags `"+strings.Join(s.SelectTags, ",")+"`")
	}
	if len(meta) > 0 {
		fmt.Fprintln(w, strings.Join(meta, " · "))
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, "| Entity | Count | Detail |")
	fmt.Fprintln(w, "|---|--:|---|")
	for _, c := range s.Counts {
		fmt.Fprintf(w, "| %s | %d | %s |\n", cell(strings.ReplaceAll(c.Entity, "_", " ")), c.Total, cell(c.Detail))
	}

	if len(s.Plugins) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "### Plugins")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "| Plugin | Total | Global | Service | Route | Consumer | Disabled |")
		fmt.Fprintln(w, "|---|--:|--:|--:|--:|--:|--:|")
		for _, p := range s.Plugins {
			fmt.Fprintf(w, "| `%s` | %d | %s | %s | %s | %s | %s |\n", cell(p.Name), p.Total,
				blank(p.Global), blank(p.Service), blank(p.Route), blank(p.Consumer+p.ConsumerGroup), blank(p.Disabled))
		}
	}

	if o.tree && len(s.allRoutes()) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "### Routes")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "| Service | Route | Methods | Match | Auth | Plugins |")
		fmt.Fprintln(w, "|---|---|---|---|---|---|")
		for _, r := range s.allRoutes() {
			methods := strings.Join(r.Methods, ",")
			if methods == "" {
				methods = "ANY"
			}
			match := strings.Join(r.Paths, " ")
			if len(r.Hosts) > 0 {
				match = strings.Join(r.Hosts, ",") + " " + match
			}
			auth := "⚠️ none"
			if len(r.Auth) > 0 {
				auth = strings.Join(r.Auth, ", ")
			}
			fmt.Fprintf(w, "| %s | %s | %s | `%s` | %s | %s |\n", cell(r.Service), cell(r.Name), cell(methods),
				cell(strings.TrimSpace(match)), cell(auth), cell(strings.Join(r.Plugins, ", ")))
		}
	}

	if len(s.Findings) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "### Findings")
		fmt.Fprintln(w)
		for _, f := range s.Findings {
			icon := "ℹ️"
			if f.Level == "warn" {
				icon = "⚠️"
			}
			fmt.Fprintf(w, "- %s %s\n", icon, cell(f.Message))
		}
	}
}

// cell escapes a value for use inside a markdown table row.
func cell(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}

func blank(n int) string {
	if n == 0 {
		return "·"
	}
	return fmt.Sprint(n)
}
