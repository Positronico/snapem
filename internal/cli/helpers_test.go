package cli

import (
	"strings"
	"testing"
)

func TestValidateEnum(t *testing.T) {
	// Caller opts in to "empty allowed" by including "" in the list — this
	// is how global flags like --package-manager say "unset is acceptable".
	allowedWithEmpty := []string{"", "auto", "npm", "bun"}
	if err := validateEnum("package-manager", "", allowedWithEmpty); err != nil {
		t.Errorf("empty value should be allowed when '' in allowed: %v", err)
	}

	// Required enum (no "" in allowed) rejects empty.
	requiredAllowed := []string{"all", "prod", "dev"}
	if err := validateEnum("include", "", requiredAllowed); err == nil {
		t.Errorf("empty value should be rejected when '' not in allowed")
	}

	if err := validateEnum("package-manager", "npm", allowedWithEmpty); err != nil {
		t.Errorf("npm should be allowed: %v", err)
	}

	err := validateEnum("package-manager", "pnpm", allowedWithEmpty)
	if err == nil {
		t.Fatalf("pnpm should be rejected, got nil error")
	}
	if !strings.Contains(err.Error(), "pnpm") {
		t.Errorf("error should mention the bad value: %v", err)
	}
	if !strings.Contains(err.Error(), "package-manager") {
		t.Errorf("error should mention the flag name: %v", err)
	}
	// Empty string should not appear in the user-visible allowed list.
	if strings.Contains(err.Error(), `""`) {
		t.Errorf("error should not show empty string as a valid option: %v", err)
	}
}

func TestUseColor(t *testing.T) {
	cases := []struct {
		cfgColor    bool
		noColorFlag bool
		want        bool
	}{
		{true, false, true},
		{true, true, false},
		{false, false, false},
		{false, true, false},
	}
	for _, tc := range cases {
		got := useColor(tc.cfgColor, tc.noColorFlag)
		if got != tc.want {
			t.Errorf("useColor(cfg=%v, no=%v)=%v, want %v",
				tc.cfgColor, tc.noColorFlag, got, tc.want)
		}
	}
}
