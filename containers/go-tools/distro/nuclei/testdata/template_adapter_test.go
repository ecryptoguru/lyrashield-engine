// This file is copied into the signed Nuclei source tree for the package test.
package customtemplates

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

type lyraGitHubTransport func(*http.Request) (*http.Response, error)

func (f lyraGitHubTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestLyraTemplateRepositoryLookup(t *testing.T) {
	previous := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = previous })
	const cloneURL = "https://fixture.invalid/template-source.git"
	requests := 0
	http.DefaultTransport = lyraGitHubTransport(func(r *http.Request) (*http.Response, error) {
		requests++
		if r.Method != "GET" || r.URL.Host != "api.github.com" || r.URL.Path != "/repos/example/templates" {
			return nil, fmt.Errorf("unexpected template repository request: %s %s", r.Method, r.URL)
		}
		body := `{"name":"templates","clone_url":"` + cloneURL + `"}`
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})
	oldDirectory := config.DefaultConfig.CustomGitHubTemplatesDirectory
	config.DefaultConfig.CustomGitHubTemplatesDirectory = t.TempDir()
	t.Cleanup(func() { config.DefaultConfig.CustomGitHubTemplatesDirectory = oldDirectory })
	providers, err := NewGitHubProviders(&types.Options{GitHubTemplateRepo: []string{"example/templates"}})
	if err != nil || requests != 1 || len(providers) != 1 || providers[0].gitCloneURL != cloneURL {
		t.Fatalf("expected the clone URL returned by the GitHub API, providers=%v requests=%d error=%v", providers, requests, err)
	}
}
