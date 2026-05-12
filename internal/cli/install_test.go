package cli

import "testing"

func TestParsePackageArg(t *testing.T) {
	tests := []struct {
		input       string
		wantName    string
		wantVersion string
	}{
		// Unscoped package, no version.
		{"lodash", "lodash", "latest"},
		// Unscoped package with version.
		{"lodash@4.17.21", "lodash", "4.17.21"},
		// Unscoped with prerelease tag.
		{"react@18.3.0-beta.1", "react", "18.3.0-beta.1"},
		// Scoped package without version — the leading @ is part of the name.
		{"@types/node", "@types/node", "latest"},
		// Scoped package with version.
		{"@types/node@20.10.0", "@types/node", "20.10.0"},
		// Scoped package with prerelease version.
		{"@scope/pkg@1.0.0-beta.1", "@scope/pkg", "1.0.0-beta.1"},
		// Trailing @ — treat as version separator with empty version.
		// This is npm's actual behaviour (it errors out), but the parser
		// shouldn't crash. We choose to pass the trailing '' to the
		// downstream scanner which will fail safely.
		{"foo@", "foo", ""},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			gotName, gotVersion := parsePackageArg(tt.input)
			if gotName != tt.wantName || gotVersion != tt.wantVersion {
				t.Errorf("parsePackageArg(%q) = (%q, %q), want (%q, %q)",
					tt.input, gotName, gotVersion, tt.wantName, tt.wantVersion)
			}
		})
	}
}

// Degenerate inputs that historically caused index-out-of-range panics in
// hand-rolled @-splitting code. We don't promise sensible names back for
// these, but parsePackageArg must not panic.
func TestParsePackageArg_DegenerateInputs(t *testing.T) {
	for _, input := range []string{"", "@", "@@", "@/"} {
		t.Run("input="+input, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("parsePackageArg(%q) panicked: %v", input, r)
				}
			}()
			_, _ = parsePackageArg(input)
		})
	}
}
