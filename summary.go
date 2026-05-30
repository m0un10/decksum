package main

import (
	"fmt"
	"sort"
	"strings"
)

// Summary is the structured result of analysing a decK state file.
type Summary struct {
	FormatVersion string        `json:"format_version,omitempty"`
	Workspace     string        `json:"workspace,omitempty"`
	SelectTags    []string      `json:"select_tags,omitempty"`
	Counts        []Count       `json:"counts"`
	Plugins       []PluginUsage `json:"plugins"`
	Services      []ServiceInfo `json:"services"`
	OrphanRoutes  []RouteInfo   `json:"orphan_routes,omitempty"`
	Findings      []Finding     `json:"findings"`
	pluginIndex   map[string]*PluginUsage
}

type Count struct {
	Entity string `json:"entity"`
	Total  int    `json:"total"`
	Detail string `json:"detail,omitempty"`
}

type PluginUsage struct {
	Name          string `json:"name"`
	Total         int    `json:"total"`
	Global        int    `json:"global"`
	Service       int    `json:"service"`
	Route         int    `json:"route"`
	Consumer      int    `json:"consumer"`
	ConsumerGroup int    `json:"consumer_group"`
	Disabled      int    `json:"disabled"`
}

type ServiceInfo struct {
	Name    string      `json:"name"`
	Target  string      `json:"target"`
	Plugins []string    `json:"plugins,omitempty"`
	Routes  []RouteInfo `json:"routes"`
	id      string
}

type RouteInfo struct {
	Name      string   `json:"name"`
	Paths     []string `json:"paths,omitempty"`
	Hosts     []string `json:"hosts,omitempty"`
	Methods   []string `json:"methods,omitempty"`
	Protocols []string `json:"protocols,omitempty"`
	Plugins   []string `json:"plugins,omitempty"`
	Auth      []string `json:"auth,omitempty"` // effective auth plugins (global + service + route)
	Service   string   `json:"service,omitempty"`
}

type Finding struct {
	Level   string `json:"level"` // "warn" or "info"
	Message string `json:"message"`
}

// authPlugins are the plugins treated as "this route requires authentication".
var authPlugins = map[string]bool{
	"key-auth": true, "key-auth-enc": true, "basic-auth": true, "jwt": true,
	"oauth2": true, "oauth2-introspection": true, "openid-connect": true,
	"hmac-auth": true, "ldap-auth": true, "ldap-auth-advanced": true,
	"mtls-auth": true, "jwt-signer": true, "saml": true, "vault-auth": true,
}

// Summarize walks a decoded decK document and builds a Summary.
func Summarize(doc map[string]any) *Summary {
	s := &Summary{pluginIndex: map[string]*PluginUsage{}}
	s.FormatVersion = str(doc["_format_version"])
	s.Workspace = str(doc["_workspace"])
	if info := asMap(doc["_info"]); info != nil {
		s.SelectTags = strList(info["select_tags"])
	}

	var globalAuth []string
	var globalPlugins int
	serviceByKey := map[string]*ServiceInfo{}
	routeTotal, targetTotal, sniTotal := 0, 0, 0

	// Top-level plugins: global unless scoped to a service/route/consumer/group.
	type scoped struct {
		name, service, route string
	}
	var scopedTop []scoped
	for _, p := range asList(doc["plugins"]) {
		pm := asMap(p)
		name := str(pm["name"])
		switch {
		case pm["route"] != nil:
			s.addPlugin(pm, "route")
			scopedTop = append(scopedTop, scoped{name: name, route: ref(pm["route"])})
		case pm["service"] != nil:
			s.addPlugin(pm, "service")
			scopedTop = append(scopedTop, scoped{name: name, service: ref(pm["service"])})
		case pm["consumer"] != nil:
			s.addPlugin(pm, "consumer")
		case pm["consumer_group"] != nil:
			s.addPlugin(pm, "consumer_group")
		default:
			s.addPlugin(pm, "global")
			globalPlugins++
			if authPlugins[name] && enabled(pm) {
				globalAuth = append(globalAuth, name)
			}
		}
	}

	// Services with nested routes and plugins.
	for _, sv := range asList(doc["services"]) {
		sm := asMap(sv)
		si := ServiceInfo{Name: firstNonEmpty(str(sm["name"]), str(sm["id"]), "(unnamed)"), Target: serviceTarget(sm), id: str(sm["id"])}
		svcAuth := []string{}
		for _, p := range asList(sm["plugins"]) {
			pm := asMap(p)
			s.addPlugin(pm, "service")
			si.Plugins = append(si.Plugins, pluginLabel(pm))
			if authPlugins[str(pm["name"])] && enabled(pm) {
				svcAuth = append(svcAuth, str(pm["name"]))
			}
		}
		for _, r := range asList(sm["routes"]) {
			ri := s.route(asMap(r))
			ri.Service = si.Name
			ri.Auth = uniq(append(append(append([]string{}, globalAuth...), svcAuth...), ri.Auth...))
			si.Routes = append(si.Routes, ri)
			routeTotal++
		}
		s.Services = append(s.Services, si)
	}
	for i := range s.Services {
		svc := &s.Services[i]
		serviceByKey[svc.Name] = svc
		if svc.id != "" {
			serviceByKey[svc.id] = svc
		}
	}

	// Top-level routes, attached to their service by name or id.
	for _, r := range asList(doc["routes"]) {
		rm := asMap(r)
		ri := s.route(rm)
		routeTotal++
		svcRef := ref(rm["service"])
		if svc, ok := serviceByKey[svcRef]; ok && svcRef != "" {
			ri.Service = svc.Name
			ri.Auth = uniq(append(append(append([]string{}, globalAuth...), svcAuthOf(svc)...), ri.Auth...))
			svc.Routes = append(svc.Routes, ri)
		} else {
			ri.Service = svcRef
			ri.Auth = uniq(append(append([]string{}, globalAuth...), ri.Auth...))
			s.OrphanRoutes = append(s.OrphanRoutes, ri)
		}
	}

	// Apply top-level scoped plugins to their service/route in the tree.
	for _, sp := range scopedTop {
		for i := range s.Services {
			svc := &s.Services[i]
			if sp.service != "" && (svc.Name == sp.service || svc.id == sp.service) {
				svc.Plugins = append(svc.Plugins, sp.name)
				if authPlugins[sp.name] {
					for j := range svc.Routes {
						svc.Routes[j].Auth = uniq(append(svc.Routes[j].Auth, sp.name))
					}
				}
			}
			for j := range svc.Routes {
				if sp.route != "" && svc.Routes[j].Name == sp.route {
					svc.Routes[j].Plugins = append(svc.Routes[j].Plugins, sp.name)
					if authPlugins[sp.name] {
						svc.Routes[j].Auth = uniq(append(svc.Routes[j].Auth, sp.name))
					}
				}
			}
		}
	}

	// Consumers and consumer groups (plugins are consumer-scoped).
	consumers := asList(doc["consumers"])
	credCount := 0
	for _, c := range consumers {
		cm := asMap(c)
		for _, p := range asList(cm["plugins"]) {
			s.addPlugin(asMap(p), "consumer")
		}
		for k, v := range cm {
			if strings.HasSuffix(k, "_credentials") || k == "acls" || k == "jwt_secrets" {
				credCount += len(asList(v))
			}
		}
	}
	for _, g := range asList(doc["consumer_groups"]) {
		for _, p := range asList(asMap(g)["plugins"]) {
			s.addPlugin(asMap(p), "consumer_group")
		}
	}
	for _, u := range asList(doc["upstreams"]) {
		targetTotal += len(asList(asMap(u)["targets"]))
	}
	for _, c := range asList(doc["certificates"]) {
		sniTotal += len(asList(asMap(c)["snis"]))
	}
	sniTotal += len(asList(doc["snis"]))

	// Counts, in a stable, readable order.
	pluginTotal := 0
	for _, p := range s.pluginIndex {
		pluginTotal += p.Total
	}
	s.add("services", len(s.Services), "")
	s.add("routes", routeTotal, "")
	s.add("plugins", pluginTotal, s.pluginScopeDetail())
	s.add("consumers", len(consumers), plural(credCount, "credential"))
	s.add("consumer_groups", len(asList(doc["consumer_groups"])), "")
	s.add("upstreams", len(asList(doc["upstreams"])), plural(targetTotal, "target"))
	s.add("certificates", len(asList(doc["certificates"])), plural(sniTotal, "SNI"))
	known := map[string]bool{"services": true, "routes": true, "plugins": true, "consumers": true,
		"consumer_groups": true, "upstreams": true, "certificates": true, "snis": true}
	var extra []string
	for k, v := range doc {
		if strings.HasPrefix(k, "_") || known[k] {
			continue
		}
		if _, ok := v.([]any); ok {
			extra = append(extra, k)
		}
	}
	sort.Strings(extra)
	for _, k := range extra {
		s.add(k, len(asList(doc[k])), "")
	}

	// Plugin table sorted by usage.
	for _, p := range s.pluginIndex {
		s.Plugins = append(s.Plugins, *p)
	}
	sort.Slice(s.Plugins, func(i, j int) bool {
		if s.Plugins[i].Total != s.Plugins[j].Total {
			return s.Plugins[i].Total > s.Plugins[j].Total
		}
		return s.Plugins[i].Name < s.Plugins[j].Name
	})

	s.findings(globalPlugins)
	return s
}

func (s *Summary) route(rm map[string]any) RouteInfo {
	ri := RouteInfo{
		Name:      firstNonEmpty(str(rm["name"]), str(rm["id"]), "(unnamed)"),
		Paths:     strList(rm["paths"]),
		Hosts:     strList(rm["hosts"]),
		Methods:   strList(rm["methods"]),
		Protocols: strList(rm["protocols"]),
	}
	for _, p := range asList(rm["plugins"]) {
		pm := asMap(p)
		s.addPlugin(pm, "route")
		ri.Plugins = append(ri.Plugins, pluginLabel(pm))
		if authPlugins[str(pm["name"])] && enabled(pm) {
			ri.Auth = append(ri.Auth, str(pm["name"]))
		}
	}
	return ri
}

func (s *Summary) addPlugin(pm map[string]any, scope string) {
	name := firstNonEmpty(str(pm["name"]), "(unnamed)")
	p, ok := s.pluginIndex[name]
	if !ok {
		p = &PluginUsage{Name: name}
		s.pluginIndex[name] = p
	}
	p.Total++
	switch scope {
	case "global":
		p.Global++
	case "service":
		p.Service++
	case "route":
		p.Route++
	case "consumer":
		p.Consumer++
	case "consumer_group":
		p.ConsumerGroup++
	}
	if !enabled(pm) {
		p.Disabled++
	}
}

func (s *Summary) pluginScopeDetail() string {
	var g, sv, r, c, cg int
	for _, p := range s.pluginIndex {
		g += p.Global
		sv += p.Service
		r += p.Route
		c += p.Consumer
		cg += p.ConsumerGroup
	}
	var parts []string
	for _, x := range []struct {
		n int
		l string
	}{{g, "global"}, {sv, "service"}, {r, "route"}, {c, "consumer"}, {cg, "consumer group"}} {
		if x.n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", x.n, x.l))
		}
	}
	return strings.Join(parts, ", ")
}

func (s *Summary) add(entity string, n int, detail string) {
	if n == 0 && entity != "services" && entity != "routes" && entity != "plugins" {
		return
	}
	s.Counts = append(s.Counts, Count{Entity: entity, Total: n, Detail: detail})
}

func (s *Summary) findings(globalPlugins int) {
	var noAuth, plainHTTP []string
	routeKeys := map[string][]string{}
	all := s.allRoutes()
	for _, r := range all {
		label := r.Name
		if r.Service != "" {
			label = r.Service + "/" + r.Name
		}
		if len(r.Auth) == 0 {
			noAuth = append(noAuth, label)
		}
		if len(r.Protocols) == 0 || contains(r.Protocols, "http") {
			if !contains(r.Protocols, "grpc") && !contains(r.Protocols, "tcp") {
				plainHTTP = append(plainHTTP, label)
			}
		}
		for _, p := range r.Paths {
			key := strings.Join(sorted(r.Hosts), ",") + " " + strings.Join(sorted(r.Methods), ",") + " " + p
			routeKeys[key] = append(routeKeys[key], label)
		}
	}
	if len(noAuth) > 0 {
		s.Findings = append(s.Findings, Finding{"warn", fmt.Sprintf("%d of %d routes have no auth plugin (global, service or route): %s",
			len(noAuth), len(all), list(noAuth))})
	}
	keys := make([]string, 0, len(routeKeys))
	for k := range routeKeys {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		labels := routeKeys[key]
		if len(labels) > 1 {
			f := strings.Fields(key)
			s.Findings = append(s.Findings, Finding{"warn", fmt.Sprintf("path %s is defined on multiple routes with the same hosts/methods: %s", f[len(f)-1], list(labels))})
		}
	}
	for _, r := range s.OrphanRoutes {
		if r.Service == "" {
			s.Findings = append(s.Findings, Finding{"info", fmt.Sprintf("route %s is not attached to a service", r.Name)})
		} else {
			s.Findings = append(s.Findings, Finding{"warn", fmt.Sprintf("route %s references service %q, which is not in this file", r.Name, r.Service)})
		}
	}
	var empty []string
	for _, svc := range s.Services {
		if len(svc.Routes) == 0 {
			empty = append(empty, svc.Name)
		}
	}
	if len(empty) > 0 {
		s.Findings = append(s.Findings, Finding{"info", fmt.Sprintf("%s no routes: %s", countNoun(len(empty), "service has", "services have"), list(empty))})
	}
	var plainUp []string
	for _, svc := range s.Services {
		if strings.HasPrefix(svc.Target, "http://") {
			plainUp = append(plainUp, svc.Name)
		}
	}
	if len(plainUp) > 0 {
		s.Findings = append(s.Findings, Finding{"info", fmt.Sprintf("%s a plain http upstream: %s", countNoun(len(plainUp), "service uses", "services use"), list(plainUp))})
	}
	if len(plainHTTP) > 0 {
		s.Findings = append(s.Findings, Finding{"info", fmt.Sprintf("%s plain http (protocols unset or include http): %s", countNoun(len(plainHTTP), "route accepts", "routes accept"), list(plainHTTP))})
	}
	var disabled []string
	for _, p := range s.Plugins {
		if p.Disabled > 0 {
			disabled = append(disabled, fmt.Sprintf("%s (%d)", p.Name, p.Disabled))
		}
	}
	if len(disabled) > 0 {
		s.Findings = append(s.Findings, Finding{"info", "disabled plugins: " + strings.Join(disabled, ", ")})
	}
	sort.SliceStable(s.Findings, func(i, j int) bool {
		return s.Findings[i].Level == "warn" && s.Findings[j].Level != "warn"
	})
}

func (s *Summary) allRoutes() []RouteInfo {
	var out []RouteInfo
	for _, svc := range s.Services {
		out = append(out, svc.Routes...)
	}
	return append(out, s.OrphanRoutes...)
}

func svcAuthOf(svc *ServiceInfo) []string {
	var out []string
	for _, p := range svc.Plugins {
		name := strings.TrimSuffix(p, " (disabled)")
		if authPlugins[name] && name == p {
			out = append(out, name)
		}
	}
	return out
}

func serviceTarget(sm map[string]any) string {
	if u := str(sm["url"]); u != "" {
		return u
	}
	proto := firstNonEmpty(str(sm["protocol"]), "http")
	host := str(sm["host"])
	if host == "" {
		return ""
	}
	t := proto + "://" + host
	if port := str(sm["port"]); port != "" {
		t += ":" + port
	}
	return t + str(sm["path"])
}

func pluginLabel(pm map[string]any) string {
	name := str(pm["name"])
	if !enabled(pm) {
		return name + " (disabled)"
	}
	return name
}

func enabled(pm map[string]any) bool {
	if v, ok := pm["enabled"].(bool); ok {
		return v
	}
	return true
}

func list(items []string) string {
	const max = 8
	if len(items) <= max {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:max], ", ") + fmt.Sprintf(", … (+%d more)", len(items)-max)
}

func plural(n int, word string) string {
	if n == 0 {
		return ""
	}
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

func countNoun(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}
