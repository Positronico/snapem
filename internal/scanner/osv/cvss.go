package osv

import (
	"math"
	"strconv"
	"strings"
)

// CVSS v3.x base score computation per FIRST CVSS specification v3.1.
// Spec: https://www.first.org/cvss/v3.1/specification-document
//
// We support both CVSS:3.0 and CVSS:3.1 vectors and a small set of common
// shorthand forms we have seen from OSV (e.g. a bare numeric "9.8" score).
//
// The previous implementation in this package counted substring occurrences
// and produced wildly wrong scores; replacing it is tracked in CLAUDE.md §8.2.

// cvssScore parses a CVSS score string (vector OR numeric) and returns the
// base score and ok=true. If the input cannot be parsed it returns ok=false.
func cvssScore(s string) (float64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}

	// Plain numeric, e.g. "9.8".
	if v, err := strconv.ParseFloat(s, 64); err == nil {
		return v, true
	}

	// Otherwise expect a vector. Accept CVSS:3.0 and CVSS:3.1 only.
	if !strings.HasPrefix(s, "CVSS:3.") {
		return 0, false
	}
	parts := strings.Split(s, "/")
	if len(parts) < 2 {
		return 0, false
	}
	metrics := make(map[string]string, len(parts))
	for _, p := range parts[1:] {
		kv := strings.SplitN(p, ":", 2)
		if len(kv) != 2 {
			continue
		}
		metrics[kv[0]] = kv[1]
	}

	// All eight base metrics must be present.
	required := []string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
	for _, r := range required {
		if _, ok := metrics[r]; !ok {
			return 0, false
		}
	}

	av, ok := attackVectorWeight(metrics["AV"])
	if !ok {
		return 0, false
	}
	ac, ok := attackComplexityWeight(metrics["AC"])
	if !ok {
		return 0, false
	}
	scopeChanged := metrics["S"] == "C"
	pr, ok := privilegesRequiredWeight(metrics["PR"], scopeChanged)
	if !ok {
		return 0, false
	}
	ui, ok := userInteractionWeight(metrics["UI"])
	if !ok {
		return 0, false
	}
	c, ok := ciaWeight(metrics["C"])
	if !ok {
		return 0, false
	}
	i, ok := ciaWeight(metrics["I"])
	if !ok {
		return 0, false
	}
	a, ok := ciaWeight(metrics["A"])
	if !ok {
		return 0, false
	}

	iss := 1 - ((1 - c) * (1 - i) * (1 - a))

	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}

	exploitability := 8.22 * av * ac * pr * ui

	if impact <= 0 {
		return 0, true
	}

	var base float64
	if scopeChanged {
		base = math.Min(1.08*(impact+exploitability), 10)
	} else {
		base = math.Min(impact+exploitability, 10)
	}

	return roundup(base), true
}

// roundup per CVSS spec §B: round up to nearest 0.1.
func roundup(x float64) float64 {
	// Round to 5 decimals to dodge floating point noise before ceil.
	scaled := math.Round(x*100000) / 100000
	return math.Ceil(scaled*10) / 10
}

func attackVectorWeight(v string) (float64, bool) {
	switch v {
	case "N":
		return 0.85, true
	case "A":
		return 0.62, true
	case "L":
		return 0.55, true
	case "P":
		return 0.2, true
	}
	return 0, false
}

func attackComplexityWeight(v string) (float64, bool) {
	switch v {
	case "L":
		return 0.77, true
	case "H":
		return 0.44, true
	}
	return 0, false
}

func privilegesRequiredWeight(v string, scopeChanged bool) (float64, bool) {
	switch v {
	case "N":
		return 0.85, true
	case "L":
		if scopeChanged {
			return 0.68, true
		}
		return 0.62, true
	case "H":
		if scopeChanged {
			return 0.5, true
		}
		return 0.27, true
	}
	return 0, false
}

func userInteractionWeight(v string) (float64, bool) {
	switch v {
	case "N":
		return 0.85, true
	case "R":
		return 0.62, true
	}
	return 0, false
}

func ciaWeight(v string) (float64, bool) {
	switch v {
	case "H":
		return 0.56, true
	case "L":
		return 0.22, true
	case "N":
		return 0, true
	}
	return 0, false
}
