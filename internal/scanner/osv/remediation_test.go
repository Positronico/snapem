package osv

import (
	"reflect"
	"testing"
)

func TestRemediationFor(t *testing.T) {
	tests := []struct {
		name          string
		vuln          vulnerability
		pkg           string
		want          string
		wantVersions  []string
	}{
		{
			name: "single range with fixed event",
			pkg:  "lodash",
			vuln: vulnerability{
				Affected: []affected{
					{
						Package: packageInfo{Name: "lodash", Ecosystem: "npm"},
						Ranges: []rangeInfo{
							{Events: []event{
								{Introduced: "0"},
								{Fixed: "4.17.21"},
							}},
						},
					},
				},
			},
			want: "Fixed in 4.17.21",
		},
		{
			name: "multiple ranges across majors (backport)",
			pkg:  "express",
			vuln: vulnerability{
				Affected: []affected{
					{
						Package: packageInfo{Name: "express", Ecosystem: "npm"},
						Ranges: []rangeInfo{
							{Events: []event{{Introduced: "0"}, {Fixed: "3.20.0"}}},
						},
					},
					{
						Package: packageInfo{Name: "express", Ecosystem: "npm"},
						Ranges: []rangeInfo{
							{Events: []event{{Introduced: "4.0.0"}, {Fixed: "4.18.2"}}},
						},
					},
				},
			},
			want: "Fixed in 3.20.0, 4.18.2",
		},
		{
			name: "no fix available — returns empty",
			pkg:  "abandoned-pkg",
			vuln: vulnerability{
				Affected: []affected{
					{
						Package: packageInfo{Name: "abandoned-pkg", Ecosystem: "npm"},
						Ranges: []rangeInfo{
							{Events: []event{{Introduced: "0"}}},
						},
					},
				},
			},
			want: "",
		},
		{
			name: "no affected entries — returns empty",
			pkg:  "x",
			vuln: vulnerability{},
			want: "",
		},
		{
			name: "ignores affected entries for other packages",
			pkg:  "lodash",
			vuln: vulnerability{
				Affected: []affected{
					{
						Package: packageInfo{Name: "underscore"},
						Ranges: []rangeInfo{
							{Events: []event{{Fixed: "1.0.0"}}},
						},
					},
				},
			},
			want: "",
		},
		{
			name: "case-insensitive package name match",
			pkg:  "Lodash",
			vuln: vulnerability{
				Affected: []affected{
					{
						Package: packageInfo{Name: "lodash"},
						Ranges: []rangeInfo{
							{Events: []event{{Fixed: "4.17.21"}}},
						},
					},
				},
			},
			want: "Fixed in 4.17.21",
		},
		{
			name: "deduplicates identical fixed versions across ranges",
			pkg:  "lodash",
			vuln: vulnerability{
				Affected: []affected{
					{
						Package: packageInfo{Name: "lodash"},
						Ranges: []rangeInfo{
							{Events: []event{{Fixed: "4.17.21"}}},
							{Events: []event{{Fixed: "4.17.21"}}},
						},
					},
				},
			},
			want: "Fixed in 4.17.21",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotVersions, got := remediationFor(tt.vuln, tt.pkg)
			if got != tt.want {
				t.Errorf("human string: got %q, want %q", got, tt.want)
			}
			if tt.wantVersions != nil {
				if !reflect.DeepEqual(gotVersions, tt.wantVersions) {
					t.Errorf("structured versions: got %v, want %v", gotVersions, tt.wantVersions)
				}
			}
		})
	}
}

func TestRemediationFor_StructuredVersionsAreParseable(t *testing.T) {
	v := vulnerability{
		Affected: []affected{{
			Package: packageInfo{Name: "lodash"},
			Ranges: []rangeInfo{
				{Events: []event{{Fixed: "0.2.4"}}},
				{Events: []event{{Fixed: "1.2.6"}}},
				{Events: []event{{Fixed: "1.2.6"}}}, // dup
			},
		}},
	}
	versions, _ := remediationFor(v, "lodash")
	want := []string{"0.2.4", "1.2.6"}
	if !reflect.DeepEqual(versions, want) {
		t.Errorf("got %v, want %v (sorted + deduped)", versions, want)
	}
}
