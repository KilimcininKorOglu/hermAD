package server

import (
	"slices"
	"testing"
)

func TestValidateDNS(t *testing.T) {
	tests := []struct {
		name, domain, typ, value, wantMsg string
	}{
		{"valid A", "nas.home.lab", "A", "192.168.1.5", ""},
		{"valid AAAA", "h.home.lab", "AAAA", "fd00::1", ""},
		{"valid CNAME", "a.home.lab", "CNAME", "nas.home.lab", ""},
		{"valid MX", "home.lab", "MX", "10 mail.home.lab", ""},
		{"valid TXT", "home.lab", "TXT", "v=spf1 -all", ""},
		{"valid SRV", "_x._tcp.home.lab", "SRV", "10 20 5060 s.home.lab", ""},
		{"valid PTR", "5.1.168.192.in-addr.arpa", "PTR", "nas.home.lab", ""},
		{"lowercase type accepted", "x.home.lab", "a", "1.2.3.4", ""},
		{"empty domain", "", "A", "1.2.3.4", "msg.dns_invalid"},
		{"empty value", "x.home.lab", "A", "", "msg.dns_invalid"},
		{"unsupported type", "x.home.lab", "NS", "ns.home.lab", "msg.dns_invalid"},
		{"unknown type", "x.home.lab", "FOO", "1.2.3.4", "msg.dns_invalid"},
		{"A with non-ip", "x.home.lab", "A", "not-an-ip", "msg.dns_bad_ipv4"},
		{"A with ipv6", "x.home.lab", "A", "fd00::1", "msg.dns_bad_ipv4"},
		{"AAAA with ipv4", "x.home.lab", "AAAA", "1.2.3.4", "msg.dns_bad_ipv6"},
		{"domain with semicolon", "a;b.home.lab", "A", "1.2.3.4", "msg.dns_invalid"},
		{"domain with caret", "a^.home.lab", "A", "1.2.3.4", "msg.dns_invalid"},
		{"domain with space", "a b.home.lab", "A", "1.2.3.4", "msg.dns_invalid"},
		{"value with newline", "x.home.lab", "TXT", "a\nb", "msg.dns_invalid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec, msg := validateDNS(tt.domain, tt.typ, tt.value)
			if msg != tt.wantMsg {
				t.Fatalf("validateDNS(%q,%q,%q) msg=%q, want %q", tt.domain, tt.typ, tt.value, msg, tt.wantMsg)
			}
			if tt.wantMsg == "" && (rec.Domain == "" || rec.Type == "" || rec.Value == "") {
				t.Fatalf("valid input produced empty record: %+v", rec)
			}
		})
	}
}

func TestParseDNSRecordRoundTrip(t *testing.T) {
	for _, rec := range []dnsRecord{
		{Domain: "nas.home.lab", Type: "A", Value: "192.168.1.5"},
		{Domain: "home.lab", Type: "MX", Value: "10 mail.home.lab"},
		{Domain: "info.home.lab", Type: "TXT", Value: "v=spf1 -all"},
	} {
		line := buildDNSRule(rec)
		got, ok := parseDNSRecord(line)
		if !ok || got != rec {
			t.Errorf("round trip failed for %+v: line=%q got=%+v ok=%v", rec, line, got, ok)
		}
	}
}

func TestParseDNSRecordRejectsNonRecords(t *testing.T) {
	for _, line := range []string{
		"||ads.example^",                     // plain block rule
		"@@||allowed.dev^",                   // allow rule
		"# a comment",                        // comment
		"||x.home.lab^$dnsrewrite=REFUSED;;", // block form, not a managed record
		"||x.home.lab^$dnsrewrite=1.2.3.4",   // short form, not canonical
		"",                                   // empty
	} {
		if _, ok := parseDNSRecord(line); ok {
			t.Errorf("parseDNSRecord(%q) accepted, want rejected", line)
		}
	}
}

func TestSplitDNSPreservesPassthrough(t *testing.T) {
	rules := []string{
		"@@||allowed.dev^",
		"||ads.example^",
		"||nas.home.lab^$dnsrewrite=NOERROR;A;192.168.1.5",
		"# a comment",
	}
	pass, recs := splitDNS(rules)
	if len(recs) != 1 || recs[0].Domain != "nas.home.lab" {
		t.Fatalf("records = %+v, want one nas.home.lab record", recs)
	}
	wantPass := []string{"@@||allowed.dev^", "||ads.example^", "# a comment"}
	if !slices.Equal(pass, wantPass) {
		t.Fatalf("passthrough = %v, want %v", pass, wantPass)
	}
	rebuilt := rebuildRules(pass, recs)
	for _, want := range append(wantPass, "||nas.home.lab^$dnsrewrite=NOERROR;A;192.168.1.5") {
		if !slices.Contains(rebuilt, want) {
			t.Errorf("rebuilt missing %q: %v", want, rebuilt)
		}
	}
}

func TestBaseDomainAndRelativeHost(t *testing.T) {
	cases := []struct{ domain, base, host string }{
		{"home.lab", "home.lab", "@"},
		{"nas.home.lab", "home.lab", "nas"},
		{"_sip._tcp.home.lab", "home.lab", "_sip._tcp"},
		{"a.b.c.home.lab", "home.lab", "a.b.c"},
		{"single", "single", "@"},
		{"50.1.168.192.in-addr.arpa", "in-addr.arpa", "50.1.168.192"},
	}
	for _, c := range cases {
		if got := baseDomain(c.domain); got != c.base {
			t.Errorf("baseDomain(%q)=%q, want %q", c.domain, got, c.base)
		}
		if got := relativeHost(c.domain, c.base); got != c.host {
			t.Errorf("relativeHost(%q,%q)=%q, want %q", c.domain, c.base, got, c.host)
		}
	}
}
