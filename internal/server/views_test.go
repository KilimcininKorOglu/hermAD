package server

import (
	"slices"
	"testing"
)

func TestMergeWhitelistPreservesNonAllowRules(t *testing.T) {
	current := []string{
		"||ads.example^",
		"@@||old.dev^",
		"||x.home.lab^$dnsrewrite=NOERROR;A;1.2.3.4",
	}
	merged := mergeWhitelist(current, "a.com\nb.com")

	// Block rules and $dnsrewrite records must survive a whitelist save.
	for _, want := range []string{"||ads.example^", "||x.home.lab^$dnsrewrite=NOERROR;A;1.2.3.4"} {
		if !slices.Contains(merged, want) {
			t.Errorf("merged dropped non-allow rule %q: %v", want, merged)
		}
	}
	// The stale allow rule is replaced by the editor's content.
	if slices.Contains(merged, "@@||old.dev^") {
		t.Errorf("merged kept stale allow rule: %v", merged)
	}
	for _, want := range []string{"@@||a.com^", "@@||b.com^"} {
		if !slices.Contains(merged, want) {
			t.Errorf("merged missing rebuilt allow rule %q: %v", want, merged)
		}
	}
}

func TestWhitelistDomains(t *testing.T) {
	got := whitelistDomains([]string{"@@||a.com^", "||block^", "@@||b.com^"})
	if want := []string{"a.com", "b.com"}; !slices.Equal(got, want) {
		t.Fatalf("whitelistDomains = %v, want %v", got, want)
	}
}
