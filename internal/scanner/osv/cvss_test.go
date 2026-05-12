package osv

import (
	"math"
	"testing"
)

func TestCVSSScore(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  float64
		ok    bool
	}{
		// Real-world reference vectors with NVD-reported base scores.
		{
			name:  "Log4Shell CVE-2021-44228",
			input: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
			want:  10.0,
			ok:    true,
		},
		{
			name:  "Heartbleed-style network high-confidentiality unchanged scope",
			input: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			want:  7.5,
			ok:    true,
		},
		{
			name:  "Spring4Shell-ish, network/low complexity, all high impact",
			input: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			want:  9.8,
			ok:    true,
		},
		{
			name:  "Physical access, low complexity, only confidentiality",
			input: "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			want:  4.6,
			ok:    true,
		},
		{
			name:  "No impact at all (degenerate)",
			input: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
			want:  0,
			ok:    true,
		},
		{
			name:  "CVSS 3.0 prefix also accepted",
			input: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			want:  9.8,
			ok:    true,
		},
		{
			name:  "Bare numeric score",
			input: "9.8",
			want:  9.8,
			ok:    true,
		},
		// Rejected inputs
		{
			name:  "Empty string",
			input: "",
			ok:    false,
		},
		{
			name:  "Unsupported CVSS v2",
			input: "AV:N/AC:L/Au:N/C:P/I:P/A:P",
			ok:    false,
		},
		{
			name:  "Missing metrics",
			input: "CVSS:3.1/AV:N",
			ok:    false,
		},
		{
			name:  "Bad metric value",
			input: "CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			ok:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := cvssScore(tt.input)
			if ok != tt.ok {
				t.Fatalf("ok=%v, want %v (score=%v)", ok, tt.ok, got)
			}
			if !ok {
				return
			}
			if math.Abs(got-tt.want) > 0.05 {
				t.Errorf("score=%v, want %v", got, tt.want)
			}
		})
	}
}
