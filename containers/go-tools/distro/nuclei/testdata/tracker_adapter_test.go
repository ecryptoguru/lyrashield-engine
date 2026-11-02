// Exercise Nuclei's actual issue reporter with an isolated GitHub server.
package github

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/format"
)

func TestLyraIssueLifecycle(t *testing.T) {
	event := &output.ResultEvent{TemplateID: "fixture", Host: "host.example.invalid", Type: "http"}
	event.Info.Name = "Fixture"
	title := format.Summary(event)
	const issueURL = "https://fixture.invalid/issues/7"
	issue := map[string]any{"id": 91, "number": 7, "title": title, "html_url": issueURL, "state": "closed"}
	var calls []string
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		action := r.Method + " " + r.URL.Path
		var body map[string]any
		if r.Method != "GET" {
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
		}
		switch action {
		case "GET /search/issues":
			if !strings.Contains(r.URL.Query().Get("q"), title) {
				t.Error("search omitted finding title")
			}
			items := []any{}
			if len(calls) > 0 {
				items = append(items, issue)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"items": items, "total_count": len(items)})
		case "POST /repos/example/project/issues":
			description, _ := body["body"].(string)
			if body["title"] != title || !strings.Contains(description, event.Host) {
				t.Errorf("incorrect issue: %v", body)
			}
			_ = json.NewEncoder(w).Encode(issue)
		case "PATCH /repos/example/project/issues/7":
			state, _ := body["state"].(string)
			action += " " + state
			_ = json.NewEncoder(w).Encode(issue)
		case "POST /repos/example/project/issues/7/comments":
			description, _ := body["body"].(string)
			if !strings.Contains(description, event.Host) {
				t.Error("issue comment omitted finding details")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 2})
		default:
			t.Errorf("unexpected request %s", action)
			http.NotFound(w, r)
		}
		calls = append(calls, action)
	}))
	defer server.Close()
	tracker, err := New(&Options{BaseURL: server.URL, Username: "fixture", Owner: "example", ProjectName: "project", Token: "fixture", DuplicateIssueCheck: true, OmitRaw: true})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		response, err := tracker.CreateIssue(event)
		if err != nil || response == nil || response.IssueID != "91" || response.IssueURL != issueURL {
			t.Fatalf("wrong tracker result: %v, error=%v", response, err)
		}
	}
	if err := tracker.CloseIssue(event); err != nil {
		t.Fatal(err)
	}
	want := []string{"GET /search/issues", "POST /repos/example/project/issues", "GET /search/issues",
		"PATCH /repos/example/project/issues/7 open", "POST /repos/example/project/issues/7/comments",
		"GET /search/issues", "PATCH /repos/example/project/issues/7 closed"}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(calls, "|") != strings.Join(want, "|") {
		t.Errorf("issue operations: %v", calls)
	}
}
