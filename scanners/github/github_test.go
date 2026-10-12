package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestParseGitHubTarget(t *testing.T) {
	tests := []struct {
		input     string
		wantOwner string
		wantRepo  string
		wantIsOrg bool
		wantErr   bool
	}{
		{"owner/repo", "owner", "repo", false, false},
		{"https://github.com/owner/repo", "owner", "repo", false, false},
		{"https://github.com/owner/repo.git", "owner", "repo", false, false},
		{"git@github.com:owner/repo.git", "owner", "repo", false, false},
		{"org:my-company", "my-company", "", true, false},
		{"my-company", "my-company", "", true, false},
	}

	for _, tt := range tests {
		owner, repo, isOrg, err := parseGitHubTarget(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("parseGitHubTarget(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if owner != tt.wantOwner || repo != tt.wantRepo || isOrg != tt.wantIsOrg {
			t.Errorf("parseGitHubTarget(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tt.input, owner, repo, isOrg, tt.wantOwner, tt.wantRepo, tt.wantIsOrg)
		}
	}
}

func TestAuditBranchProtectionCompliant(t *testing.T) {
	// Mock GitHub server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/acme/secure-repo" {
			_ = json.NewEncoder(w).Encode(Repository{
				Name:          "secure-repo",
				FullName:      "acme/secure-repo",
				DefaultBranch: "main",
			})
			return
		}
		if r.URL.Path == "/repos/acme/secure-repo/branches/main/protection" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(BranchProtection{
				RequiredReviews: &RequiredReviews{
					RequiredApprovingReviewCount: 2,
					RequireCodeOwnerReviews:      true,
					DismissStaleReviews:          true,
				},
				EnforceAdmins: &EnforceAdmins{
					Enabled: true,
				},
			})
			return
		}
		if r.URL.Path == "/repos/acme/secure-repo/git/trees/main" {
			_ = json.NewEncoder(w).Encode(TreeResponse{
				Tree: []TreeEntry{
					{Path: "README.md", Type: "blob", Size: 100},
				},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	scanner := NewScanner("mock-token")
	scanner.Client.BaseURL = ts.URL

	rawArtifact, err := scanner.Scan(context.Background(), "acme/secure-repo")
	if err != nil {
		t.Fatalf("Scanner failed: %v", err)
	}

	artifact := rawArtifact.(*GitHubArtifact)
	if len(artifact.Repositories) != 1 {
		t.Fatalf("Expected 1 repo, got %d", len(artifact.Repositories))
	}

	repo := artifact.Repositories[0]
	if repo.BranchProtection.Status != "PASS" {
		t.Errorf("Expected branch protection PASS, got %s (msg: %s)", repo.BranchProtection.Status, repo.BranchProtection.Message)
	}
	if repo.BranchProtection.RequiredReviews != 2 {
		t.Errorf("Expected 2 required reviews, got %d", repo.BranchProtection.RequiredReviews)
	}
}

func TestAuditBranchProtectionMissing(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/acme/insecure-repo" {
			_ = json.NewEncoder(w).Encode(Repository{
				Name:          "insecure-repo",
				FullName:      "acme/insecure-repo",
				DefaultBranch: "main",
			})
			return
		}
		// Return 404 for branch protection (not enabled)
		if r.URL.Path == "/repos/acme/insecure-repo/branches/main/protection" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.URL.Path == "/repos/acme/insecure-repo/git/trees/main" {
			_ = json.NewEncoder(w).Encode(TreeResponse{Tree: []TreeEntry{}})
			return
		}
	}))
	defer ts.Close()

	scanner := NewScanner("mock-token")
	scanner.Client.BaseURL = ts.URL

	rawArtifact, err := scanner.Scan(context.Background(), "acme/insecure-repo")
	if err != nil {
		t.Fatalf("Scanner failed: %v", err)
	}

	artifact := rawArtifact.(*GitHubArtifact)
	repo := artifact.Repositories[0]
	if repo.BranchProtection.Status != "FAIL" {
		t.Errorf("Expected branch protection FAIL when unconfigured, got %s", repo.BranchProtection.Status)
	}
}

func TestAuditSecretLeaksDetection(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/acme/leaky-repo" {
			_ = json.NewEncoder(w).Encode(Repository{
				Name:          "leaky-repo",
				FullName:      "acme/leaky-repo",
				DefaultBranch: "main",
			})
			return
		}
		if r.URL.Path == "/repos/acme/leaky-repo/branches/main/protection" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.URL.Path == "/repos/acme/leaky-repo/git/trees/main" {
			_ = json.NewEncoder(w).Encode(TreeResponse{
				Tree: []TreeEntry{
					{Path: ".env", Type: "blob", Size: 50},
					{Path: "config.yaml", Type: "blob", Size: 120},
				},
			})
			return
		}
		if r.URL.Path == "/repos/acme/leaky-repo/contents/config.yaml" {
			content := "aws_key: AKIAIOSFODNN7EXAMPLE\n"
			_ = json.NewEncoder(w).Encode(ContentResponse{
				Path:     "config.yaml",
				Encoding: "base64",
				Content:  base64.StdEncoding.EncodeToString([]byte(content)),
			})
			return
		}
	}))
	defer ts.Close()

	scanner := NewScanner("mock-token")
	scanner.Client.BaseURL = ts.URL

	rawArtifact, err := scanner.Scan(context.Background(), "acme/leaky-repo")
	if err != nil {
		t.Fatalf("Scanner failed: %v", err)
	}

	artifact := rawArtifact.(*GitHubArtifact)
	repo := artifact.Repositories[0]
	if repo.SecretScan.Status != "FAIL" {
		t.Errorf("Expected secret scan FAIL, got %s", repo.SecretScan.Status)
	}
	if len(repo.SecretScan.Findings) < 2 {
		t.Errorf("Expected at least 2 secret findings (.env and AWS key), got %d", len(repo.SecretScan.Findings))
	}
}

func TestRateLimitHandling(t *testing.T) {
	resetEpoch := time.Now().Add(10 * time.Minute).Unix()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetEpoch, 10))
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message": "API rate limit exceeded"}`))
	}))
	defer ts.Close()

	client := NewAPIClient("token")
	client.BaseURL = ts.URL

	_, err := client.GetRepository(context.Background(), "owner", "repo")
	if err == nil {
		t.Fatalf("Expected rate limit error, got nil")
	}

	_, ok := err.(*RateLimitError)
	if !ok {
		t.Errorf("Expected *RateLimitError, got %T: %v", err, err)
	}
}
