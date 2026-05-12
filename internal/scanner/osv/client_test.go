package osv

import (
	"testing"

	"github.com/positronico/snapem/internal/types"
)

func TestMapSeverity(t *testing.T) {
	c := &Client{}

	tests := []struct {
		name string
		v    vulnerability
		want types.Severity
	}{
		{
			name: "database_specific severity wins over CVSS",
			v: vulnerability{
				DatabaseSpecific: databaseSpecific{Severity: "CRITICAL"},
				Severity: []severity{
					// Score that would compute to ~7.5 (high), but
					// database_specific CRITICAL must take precedence.
					{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
				},
			},
			want: types.SeverityCritical,
		},
		{
			name: "CVSS v3 vector parsed to high",
			v: vulnerability{
				Severity: []severity{
					{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
				},
			},
			want: types.SeverityHigh,
		},
		{
			name: "CVSS v3 vector for Log4Shell scope-changed -> critical",
			v: vulnerability{
				Severity: []severity{
					{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"},
				},
			},
			want: types.SeverityCritical,
		},
		{
			name: "Numeric CVSS score also parsed",
			v: vulnerability{
				Severity: []severity{
					{Type: "CVSS_V3", Score: "6.1"},
				},
			},
			want: types.SeverityMedium,
		},
		{
			name: "Ecosystem-typed MODERATE alias of medium",
			v: vulnerability{
				Severity: []severity{
					{Type: "ECOSYSTEM", Score: "MODERATE"},
				},
			},
			want: types.SeverityMedium,
		},
		{
			name: "Unrecognized inputs fall back to medium",
			v:    vulnerability{},
			want: types.SeverityMedium,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := c.mapSeverity(tt.v)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
