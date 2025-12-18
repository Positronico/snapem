package manifest

import (
	"regexp"
	"strconv"
)

// FrameworkPort maps frameworks to their default development ports
var FrameworkPort = map[string]int{
	// React ecosystem
	"next":                3000,
	"react-scripts":       3000,
	"create-react-app":    3000,
	"remix":               3000,
	"gatsby":              8000,

	// Vue ecosystem
	"vite":                5173,
	"@vitejs/plugin-vue":  5173,
	"@vitejs/plugin-react": 5173,
	"vue-cli-service":     8080,
	"@vue/cli-service":    8080,
	"nuxt":                3000,

	// Angular
	"@angular/cli":        4200,

	// Svelte
	"@sveltejs/kit":       5173,
	"svelte-kit":          5173,

	// Other frameworks
	"astro":               4321,
	"express":             3000,
	"fastify":             3000,
	"koa":                 3000,
	"hono":                3000,

	// Bundlers with dev servers
	"webpack-dev-server":  8080,
	"parcel":              1234,
}

// DetectPort attempts to detect the development server port from package.json
func (p *Parser) DetectPort() int {
	pkg, err := p.ParseManifest()
	if err != nil {
		return 0
	}

	// First, check scripts for explicit port configurations
	if port := detectPortFromScripts(pkg.Scripts); port > 0 {
		return port
	}

	// Then, check dependencies for known frameworks
	allDeps := make(map[string]string)
	for k, v := range pkg.Dependencies {
		allDeps[k] = v
	}
	for k, v := range pkg.DevDependencies {
		allDeps[k] = v
	}

	// Check in priority order (more specific frameworks first)
	priorityOrder := []string{
		"next", "remix", "gatsby", "nuxt", "@sveltejs/kit", "astro",
		"@angular/cli", "vite", "@vitejs/plugin-vue", "@vitejs/plugin-react",
		"react-scripts", "@vue/cli-service", "parcel", "webpack-dev-server",
		"express", "fastify", "koa", "hono",
	}

	for _, framework := range priorityOrder {
		if _, exists := allDeps[framework]; exists {
			if port, ok := FrameworkPort[framework]; ok {
				return port
			}
		}
	}

	return 0
}

// detectPortFromScripts looks for port patterns in npm scripts
func detectPortFromScripts(scripts map[string]string) int {
	// Common dev script names
	devScripts := []string{"dev", "start", "serve", "develop"}

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`--port[=\s]+(\d+)`),
		regexp.MustCompile(`-p[=\s]+(\d+)`),
		regexp.MustCompile(`PORT=(\d+)`),
		regexp.MustCompile(`:(\d{4,5})`), // matches :3000, :8080, etc.
	}

	for _, scriptName := range devScripts {
		if script, ok := scripts[scriptName]; ok {
			for _, pattern := range patterns {
				if matches := pattern.FindStringSubmatch(script); len(matches) > 1 {
					if port, err := strconv.Atoi(matches[1]); err == nil && port > 0 && port < 65536 {
						return port
					}
				}
			}
		}
	}

	return 0
}
