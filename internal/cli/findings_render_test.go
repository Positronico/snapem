package cli

import (
	"testing"

	"github.com/positronico/snapem/internal/scanner"
)

func TestAdvisoryURL(t *testing.T) {
	tests := []struct {
		name string
		in   scanner.Finding
		want string
	}{
		{
			name: "GHSA gets canonical github advisory URL",
			in:   scanner.Finding{ID: "GHSA-29mw-wpgm-hmr9"},
			want: "https://github.com/advisories/GHSA-29mw-wpgm-hmr9",
		},
		{
			name: "CVE gets canonical NVD URL",
			in:   scanner.Finding{ID: "CVE-2021-44228"},
			want: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
		},
		{
			name: "GHSA canonical preferred over References list",
			in: scanner.Finding{
				ID:         "GHSA-abc",
				References: []string{"https://example.com/other"},
			},
			want: "https://github.com/advisories/GHSA-abc",
		},
		{
			name: "Unknown ID falls back to first non-empty reference",
			in: scanner.Finding{
				ID:         "VENDOR-001",
				References: []string{"", "https://example.com/advisory"},
			},
			want: "https://example.com/advisory",
		},
		{
			name: "No ID and no references returns empty",
			in:   scanner.Finding{},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := advisoryURL(tt.in); got != tt.want {
				t.Errorf("advisoryURL=%q, want %q", got, tt.want)
			}
		})
	}
}

func TestDisplayTitle(t *testing.T) {
	if got := displayTitle(scanner.Finding{Title: "Hello"}); got != "Hello" {
		t.Errorf("Title path: got %q", got)
	}
	if got := displayTitle(scanner.Finding{Description: "x"}); got != "x" {
		t.Errorf("Description fallback: got %q", got)
	}
	if got := displayTitle(scanner.Finding{}); got != "(no description available)" {
		t.Errorf("empty fallback: got %q", got)
	}
	// Description truncation at 120 chars.
	long := make([]byte, 200)
	for i := range long {
		long[i] = 'a'
	}
	got := displayTitle(scanner.Finding{Description: string(long)})
	if len(got) != 120 {
		t.Errorf("truncated length=%d, want 120", len(got))
	}
}
