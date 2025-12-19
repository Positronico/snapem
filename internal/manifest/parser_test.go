package manifest

import "testing"

func TestExtractPackageName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		// Unscoped packages
		{"node_modules/lodash", "lodash"},
		{"node_modules/express", "express"},

		// Scoped packages - this was the bug!
		{"node_modules/@babel/core", "@babel/core"},
		{"node_modules/@babel/helper-plugin-utils", "@babel/helper-plugin-utils"},
		{"node_modules/@tailwindcss/vite", "@tailwindcss/vite"},
		{"node_modules/@vitejs/plugin-react", "@vitejs/plugin-react"},
		{"node_modules/@types/node", "@types/node"},

		// Nested dependencies (unscoped)
		{"node_modules/express/node_modules/debug", "debug"},
		{"node_modules/foo/node_modules/bar", "bar"},

		// Nested dependencies (scoped)
		{"node_modules/@babel/core/node_modules/@types/node", "@types/node"},
		{"node_modules/foo/node_modules/@babel/helper-plugin-utils", "@babel/helper-plugin-utils"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := extractPackageName(tt.input)
			if result != tt.expected {
				t.Errorf("extractPackageName(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
