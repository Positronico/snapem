package cli

import "fmt"

// useColor resolves whether the CLI should emit colored output by composing
// the config-file setting (ui.color: positive enable) with the --no-color
// CLI override (negative). The CLI override always wins.
//
// Truth table:
//
//	cfg.color | --no-color | result
//	true      | false      | true
//	true      | true       | false
//	false     | false      | false
//	false     | true       | false
func useColor(cfgColor bool, noColorFlag bool) bool {
	return cfgColor && !noColorFlag
}

// validateEnum returns an error if value is not in allowed. Empty values
// in `allowed` represent "unset is acceptable" and are filtered out of the
// error message. Used by command PreRunE hooks to fail fast on garbage
// flag values that would otherwise silently fall through to a default.
func validateEnum(flag, value string, allowed []string) error {
	for _, a := range allowed {
		if value == a {
			return nil
		}
	}
	visible := make([]string, 0, len(allowed))
	for _, a := range allowed {
		if a != "" {
			visible = append(visible, a)
		}
	}
	return fmt.Errorf("invalid value %q for --%s, must be one of: %v", value, flag, visible)
}
