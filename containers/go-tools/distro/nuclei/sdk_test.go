// Verify the replacement SDK used by both Nuclei and its transitive update client.
package sdk_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/google/go-github/v30/github"
)

func TestGitHubCommitSigning(t *testing.T) {
	signatures := make(chan string, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "POST /repos/test/repo/git/commits":
			var body struct{ Signature string }
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			signatures <- body.Signature
			fmt.Fprint(w, `{"sha":"fixture"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := github.NewClient(server.Client())
	var err error
	client.BaseURL, err = url.Parse(server.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	commit := &github.Commit{
		Message: github.String("fixture"),
		Author: &github.CommitAuthor{Name: github.String("test"), Email: github.String("test@example.invalid"),
			Date: &github.Timestamp{Time: time.Unix(1, 0).UTC()}},
	}
	if _, _, err := client.Git.CreateCommit(ctx, "test", "repo", commit); err != nil {
		t.Fatal(err)
	}
	key, err := openpgp.NewEntity("test", "", "test@example.invalid", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA})
	if err != nil {
		t.Fatal(err)
	}
	commit.SigningKey = key
	if _, _, err := client.Git.CreateCommit(ctx, "test", "repo", commit); err != nil {
		t.Fatal(err)
	}
	if len(signatures) != 2 || <-signatures != "" {
		t.Fatal("expected an unsigned commit and a signed commit")
	}
	const payload = "author test <test@example.invalid> 1 +0000\ncommitter test <test@example.invalid> 1 +0000\n\nfixture"
	if _, err := openpgp.CheckArmoredDetachedSignature(openpgp.EntityList{key}, strings.NewReader(payload), strings.NewReader(<-signatures), nil); err != nil {
		t.Fatalf("signature did not verify against the submitted commit: %v", err)
	}
}
