package server

import (
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/sinezty/hermad/internal/config"
)

// dnsRecordTypes are the DNS record types the local DNS editor offers. AdGuard
// Home implements custom local DNS records as $dnsrewrite filtering rules, which
// support far more record types than the dedicated "DNS rewrites" feature (that
// one is limited to A/AAAA/CNAME). These are the types verified to actually
// resolve against AdGuard Home v0.107.x; NS is intentionally excluded because
// AdGuard does not answer NS rewrites (the query times out).
var dnsRecordTypes = []string{"A", "AAAA", "CNAME", "MX", "TXT", "SRV", "PTR"}

// dnsRecord is a custom local DNS record backed by a $dnsrewrite rule. All fields
// are strings so the value is comparable and round-trips through the rule text
// without loss.
type dnsRecord struct {
	Domain string
	Type   string
	Value  string
}

// dnsRecordRow is one record rendered under its base-domain group. Host is the
// label relative to the base domain ("@" for the domain itself); Domain is the
// full domain the edit/delete actions operate on.
type dnsRecordRow struct {
	Host   string
	Domain string
	Type   string
	Value  string
}

// dnsDomainGroup is a base domain (e.g. home.lab) and all records that belong to
// it or its subdomains, for the grouped, collapsible UI.
type dnsDomainGroup struct {
	Domain  string
	Records []dnsRecordRow
}

// dnsData is the view model for the full local DNS page. The record set is the
// deduplicated union across all active servers (the panel presents the two HA
// servers as a single logical record set).
type dnsData struct {
	basePage
	Domains     []dnsDomainGroup
	Types       []string
	Unreachable []string
}

// dnsFragment is the view model for the HTMX-refreshed local DNS list.
type dnsFragment struct {
	Lang        string
	Domains     []dnsDomainGroup
	Types       []string
	Unreachable []string
}

// dnsPage renders the full local DNS management page.
func (s *Server) dnsPage(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg.Get()
	union, unreachable := s.dnsUnionRecords(cfg)
	data := dnsData{
		basePage:    s.basePage(r, "dns"),
		Domains:     groupByBaseDomain(union),
		Types:       dnsRecordTypes,
		Unreachable: unreachable,
	}
	if err := s.tmpl.page(w, "dns", data); err != nil {
		s.fail(w, err)
	}
}

// partialDNS returns just the local DNS list for HTMX refresh.
func (s *Server) partialDNS(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg.Get()
	union, unreachable := s.dnsUnionRecords(cfg)
	data := dnsFragment{
		Lang:        s.lang(r),
		Domains:     groupByBaseDomain(union),
		Types:       dnsRecordTypes,
		Unreachable: unreachable,
	}
	if err := s.tmpl.partial(w, "dns_list", data); err != nil {
		s.fail(w, err)
	}
}

// actionDNSSave adds a new record (when no old_* fields are present) or replaces
// an existing one (when old_* fields are present) on every active server. It
// backs the add/edit modal. When editing, a server that lacks the original still
// receives the new record so the servers converge.
func (s *Server) actionDNSSave(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg.Get()
	rec, msgKey := validateDNS(r.FormValue("domain"), r.FormValue("type"), r.FormValue("value"))
	if msgKey != "" {
		s.toast(w, r, "err", msgKey)
		return
	}
	old := dnsRecord{
		Domain: strings.TrimSpace(r.FormValue("old_domain")),
		Type:   strings.ToUpper(strings.TrimSpace(r.FormValue("old_type"))),
		Value:  strings.TrimSpace(r.FormValue("old_value")),
	}
	editing := old.Domain != "" && old.Type != "" && old.Value != ""

	if editing && old == rec {
		s.refresh(w)
		s.toast(w, r, "ok", "msg.dns_updated")
		return
	}

	okKey := "msg.dns_added"
	apply := func(records []dnsRecord) []dnsRecord {
		if slices.Contains(records, rec) {
			return records
		}
		return append(records, rec)
	}
	if editing {
		okKey = "msg.dns_updated"
		// Remove the original record and add the edited one only if absent. This
		// converges a server that lacks the original and never writes a duplicate
		// rule when editing a record into a value that already exists.
		apply = func(records []dnsRecord) []dnsRecord {
			out := make([]dnsRecord, 0, len(records))
			for _, e := range records {
				if e != old {
					out = append(out, e)
				}
			}
			if !slices.Contains(out, rec) {
				out = append(out, rec)
			}
			return out
		}
	}
	failed := s.applyToAll(cfg, apply)
	s.dnsResult(w, r, len(cfg.ServerKeys()), failed, okKey)
}

// actionDNSDelete removes a record from every active server. The record is
// identified by its exact domain/type/value triple.
func (s *Server) actionDNSDelete(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg.Get()
	target := dnsRecord{
		Domain: strings.TrimSpace(r.FormValue("domain")),
		Type:   strings.ToUpper(strings.TrimSpace(r.FormValue("type"))),
		Value:  strings.TrimSpace(r.FormValue("value")),
	}
	failed := s.applyToAll(cfg, func(records []dnsRecord) []dnsRecord {
		kept := make([]dnsRecord, 0, len(records))
		for _, e := range records {
			if e != target {
				kept = append(kept, e)
			}
		}
		return kept
	})
	s.dnsResult(w, r, len(cfg.ServerKeys()), failed, "msg.dns_deleted")
}

// actionDNSReconcile makes every active server's custom DNS records identical to
// the deduplicated union of all servers' records, leaving each server's other
// rules untouched. It is only meaningful when a backup server exists.
func (s *Server) actionDNSReconcile(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg.Get()
	if !cfg.HasBackup() {
		s.toast(w, r, "err", "msg.error")
		return
	}
	union, _ := s.dnsUnionRecords(cfg)
	failed := s.applyToAll(cfg, func([]dnsRecord) []dnsRecord {
		return slices.Clone(union)
	})
	s.dnsResult(w, r, len(cfg.ServerKeys()), failed, "msg.dns_reconciled")
}

// ---- multi-server aggregation and fan-out ----

// dnsUnionRecords reads every active server's custom DNS records and returns the
// deduplicated union plus the names of any servers that could not be read (so
// the UI can warn that the view may be incomplete).
func (s *Server) dnsUnionRecords(cfg *config.Config) ([]dnsRecord, []string) {
	keys := cfg.ServerKeys()
	perServer := make([][]dnsRecord, len(keys))
	ok := make([]bool, len(keys))
	var wg sync.WaitGroup
	for i, k := range keys {
		wg.Go(func() {
			if f, err := s.ag.Filtering(toAG(cfg.Servers[k])); err == nil {
				ok[i] = true
				_, perServer[i] = splitDNS(f.UserRules)
			}
		})
	}
	wg.Wait()

	seen := map[dnsRecord]bool{}
	var union []dnsRecord
	var unreachable []string
	for i, k := range keys {
		if !ok[i] {
			unreachable = append(unreachable, cfg.Servers[k].Name)
			continue
		}
		for _, rec := range perServer[i] {
			if !seen[rec] {
				seen[rec] = true
				union = append(union, rec)
			}
		}
	}
	return union, unreachable
}

// applyToAll transforms each active server's record set with fn and writes the
// result back. Each server is read and written independently so its own
// passthrough rules (block/allow) are preserved. It returns the names of servers
// that failed (on read or write).
func (s *Server) applyToAll(cfg *config.Config, fn func(records []dnsRecord) []dnsRecord) []string {
	var failed []string
	for _, k := range cfg.ServerKeys() {
		srv := toAG(cfg.Servers[k])
		cur, err := s.ag.Filtering(srv)
		if err != nil {
			failed = append(failed, cfg.Servers[k].Name)
			continue
		}
		passthrough, records := splitDNS(cur.UserRules)
		if err := s.ag.SetRules(srv, rebuildRules(passthrough, fn(records))); err != nil {
			failed = append(failed, cfg.Servers[k].Name)
		}
	}
	return failed
}

// dnsResult reports the outcome of a fan-out write: full success, partial
// failure (naming the servers that failed), or total failure.
func (s *Server) dnsResult(w http.ResponseWriter, r *http.Request, total int, failed []string, okKey string) {
	switch {
	case len(failed) == 0:
		s.refresh(w)
		s.toast(w, r, "ok", okKey)
	case len(failed) < total:
		s.refresh(w)
		s.toastRaw(w, "err", s.i18n.T(s.lang(r), "msg.dns_partial")+" "+strings.Join(failed, ", "))
	default:
		s.toast(w, r, "err", "msg.dns_failed")
	}
}

// toastRaw renders a toast alert with a literal message (used when the text is
// composed at runtime, e.g. naming failed servers).
func (s *Server) toastRaw(w http.ResponseWriter, kind, msg string) {
	if err := s.tmpl.partial(w, "alert", alertData{Kind: kind, Msg: msg}); err != nil {
		s.fail(w, err)
	}
}

// ---- $dnsrewrite rule helpers ----

// groupByBaseDomain groups records under their base domain (the zone), so the
// base domain (e.g. home.lab) is the top-level entry and its subdomains
// (nas.home.lab, _sip._tcp.home.lab, ...) appear as records beneath it. Domains
// and records are sorted so the rendered list is deterministic.
func groupByBaseDomain(records []dnsRecord) []dnsDomainGroup {
	byBase := map[string][]dnsRecordRow{}
	var order []string
	for _, rec := range records {
		base := baseDomain(rec.Domain)
		if _, ok := byBase[base]; !ok {
			order = append(order, base)
		}
		byBase[base] = append(byBase[base], dnsRecordRow{
			Host:   relativeHost(rec.Domain, base),
			Domain: rec.Domain,
			Type:   rec.Type,
			Value:  rec.Value,
		})
	}
	slices.Sort(order)
	out := make([]dnsDomainGroup, 0, len(order))
	for _, b := range order {
		rows := byBase[b]
		slices.SortFunc(rows, func(a, c dnsRecordRow) int {
			if x := strings.Compare(a.Host, c.Host); x != 0 {
				return x
			}
			if x := strings.Compare(a.Type, c.Type); x != 0 {
				return x
			}
			return strings.Compare(a.Value, c.Value)
		})
		out = append(out, dnsDomainGroup{Domain: b, Records: rows})
	}
	return out
}

// baseDomain returns the zone a domain belongs to: its last two labels (e.g.
// nas.home.lab and _sip._tcp.home.lab both map to home.lab). Domains with two or
// fewer labels are their own base. This is a deliberate heuristic for local
// homelab zones (.lab/.home/.lan/...), which are not on any public suffix list.
func baseDomain(d string) string {
	labels := strings.Split(d, ".")
	if len(labels) <= 2 {
		return d
	}
	return strings.Join(labels[len(labels)-2:], ".")
}

// relativeHost returns the label of d relative to its base ("@" when d is the
// base domain itself).
func relativeHost(d, base string) string {
	if d == base {
		return "@"
	}
	if host, ok := strings.CutSuffix(d, "."+base); ok {
		return host
	}
	return d
}

// splitDNS partitions user_rules into pass-through lines (everything that is not
// a recognized custom DNS record) and the parsed records. Only the canonical
// ||domain^$dnsrewrite=NOERROR;TYPE;VALUE form is treated as a managed record;
// every other rule — block forms, short forms, allow rules, comments — is left
// in passthrough so a rebuild never drops a line it does not own.
func splitDNS(rules []string) (passthrough []string, records []dnsRecord) {
	for _, line := range rules {
		if rec, ok := parseDNSRecord(line); ok {
			records = append(records, rec)
		} else {
			passthrough = append(passthrough, line)
		}
	}
	return passthrough, records
}

// parseDNSRecord parses a canonical custom DNS record rule. It returns false for
// any line that is not exactly ||domain^$dnsrewrite=NOERROR;TYPE;VALUE.
func parseDNSRecord(line string) (dnsRecord, bool) {
	s := strings.TrimSpace(line)
	if !strings.HasPrefix(s, "||") {
		return dnsRecord{}, false
	}
	const marker = "^$dnsrewrite="
	i := strings.Index(s, marker)
	if i < 0 {
		return dnsRecord{}, false
	}
	domain := s[len("||"):i]
	// SplitN with 3 keeps any further ';' inside VALUE intact (e.g. TXT records).
	parts := strings.SplitN(s[i+len(marker):], ";", 3)
	if len(parts) != 3 || !strings.EqualFold(parts[0], "NOERROR") {
		return dnsRecord{}, false
	}
	rtype := strings.ToUpper(strings.TrimSpace(parts[1]))
	value := strings.TrimSpace(parts[2])
	if domain == "" || rtype == "" || value == "" {
		return dnsRecord{}, false
	}
	return dnsRecord{Domain: domain, Type: rtype, Value: value}, true
}

// buildDNSRule renders a custom DNS record as a canonical $dnsrewrite rule.
func buildDNSRule(r dnsRecord) string {
	return "||" + r.Domain + "^$dnsrewrite=NOERROR;" + r.Type + ";" + r.Value
}

// rebuildRules combines pass-through lines (verbatim) with the canonical record
// lines, producing the full user_rules list to push via set_rules.
func rebuildRules(passthrough []string, records []dnsRecord) []string {
	out := make([]string, 0, len(passthrough)+len(records))
	out = append(out, passthrough...)
	for _, r := range records {
		out = append(out, buildDNSRule(r))
	}
	return out
}

// validateDNS normalizes and validates record input. It returns the cleaned
// record, or an empty record and an i18n message key describing the problem.
func validateDNS(domain, rtype, value string) (dnsRecord, string) {
	domain = strings.TrimSpace(domain)
	rtype = strings.ToUpper(strings.TrimSpace(rtype))
	value = strings.TrimSpace(value)
	if domain == "" || value == "" {
		return dnsRecord{}, "msg.dns_invalid"
	}
	// These characters would corrupt the generated rule structure.
	if strings.ContainsAny(domain, " \t;^") || strings.ContainsAny(value, "\r\n") {
		return dnsRecord{}, "msg.dns_invalid"
	}
	if !slices.Contains(dnsRecordTypes, rtype) {
		return dnsRecord{}, "msg.dns_invalid"
	}
	switch rtype {
	case "A":
		if ip := net.ParseIP(value); ip == nil || ip.To4() == nil {
			return dnsRecord{}, "msg.dns_bad_ipv4"
		}
	case "AAAA":
		if ip := net.ParseIP(value); ip == nil || ip.To4() != nil {
			return dnsRecord{}, "msg.dns_bad_ipv6"
		}
	}
	return dnsRecord{Domain: domain, Type: rtype, Value: value}, ""
}
