package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// APIClient encapsulates interaction with the GitHub REST API.
type APIClient struct {
	BaseURL    string
	Token      string
	HTTPClient *http.Client
}

// NewAPIClient creates a new GitHub API client.
func NewAPIClient(token string) *APIClient {
	if token == "" {
		token = osGetenvToken()
	}
	return &APIClient{
		BaseURL: "https://api.github.com",
		Token:   token,
		HTTPClient: &http.Client{
			Timeout: 20 * time.Second,
		},
	}
}

func osGetenvToken() string {
	// Standard GitHub token environment variables
	for _, env := range []string{"GITHUB_TOKEN", "GH_TOKEN", "GITHUB_PAT"} {
		if val := strings.TrimSpace(os.Getenv(env)); val != "" {
			return val
		}
	}
	return ""
}

// RateLimitError indicates GitHub API rate limit has been reached.
type RateLimitError struct {
	Remaining int
	ResetTime time.Time
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("GitHub API rate limit exceeded (resets at %s). Provide a personal access token with GITHUB_TOKEN or --token",
		e.ResetTime.Format("15:04:05 MST"))
}

// Repository represents repository details from GitHub API.
type Repository struct {
	Name          string `json:"name"`
	FullName      string `json:"full_name"`
	DefaultBranch string `json:"default_branch"`
	Private       bool   `json:"private"`
	Archived      bool   `json:"archived"`
	Fork          bool   `json:"fork"`
}

// BranchProtection represents protection rules configured on a branch.
type BranchProtection struct {
	RequiredReviews     *RequiredReviews     `json:"required_pull_request_reviews,omitempty"`
	EnforceAdmins       *EnforceAdmins       `json:"enforce_admins,omitempty"`
	RequiredStatusCheck *RequiredStatusCheck `json:"required_status_checks,omitempty"`
	AllowForcePushes    *BoolSetting         `json:"allow_force_pushes,omitempty"`
	AllowDeletions      *BoolSetting         `json:"allow_deletions,omitempty"`
}

// RequiredReviews holds PR review requirements.
type RequiredReviews struct {
	DismissStaleReviews          bool `json:"dismiss_stale_reviews"`
	RequireCodeOwnerReviews      bool `json:"require_code_owner_reviews"`
	RequiredApprovingReviewCount int  `json:"required_approving_review_count"`
}

// EnforceAdmins indicates whether admin overrides are blocked.
type EnforceAdmins struct {
	Enabled bool `json:"enabled"`
}

// RequiredStatusCheck holds CI status requirements.
type RequiredStatusCheck struct {
	Strict   bool     `json:"strict"`
	Contexts []string `json:"contexts"`
}

// BoolSetting wraps simple enabled/disabled fields.
type BoolSetting struct {
	Enabled bool `json:"enabled"`
}

// TreeResponse represents recursive Git Tree API response.
type TreeResponse struct {
	SHA       string      `json:"sha"`
	Tree      []TreeEntry `json:"tree"`
	Truncated bool        `json:"truncated"`
}

// TreeEntry represents an individual item in a Git tree.
type TreeEntry struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
	Type string `json:"type"` // "blob" or "tree"
	SHA  string `json:"sha"`
	Size int64  `json:"size"`
	URL  string `json:"url"`
}

// ContentResponse represents the contents API response for a single file.
type ContentResponse struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	SHA      string `json:"sha"`
	Size     int64  `json:"size"`
	Encoding string `json:"encoding"`
	Content  string `json:"content"`
}

func (c *APIClient) doRequest(ctx context.Context, method, endpoint string) (*http.Response, error) {
	url := endpoint
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = fmt.Sprintf("%s%s", c.BaseURL, endpoint)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "iso-guard-auditor/1.0")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	if c.Token != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.Token))
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}

	// Check rate limit headers
	remainingStr := resp.Header.Get("X-RateLimit-Remaining")
	resetStr := resp.Header.Get("X-RateLimit-Reset")

	if (resp.StatusCode == http.StatusForbidden || resp.StatusCode == 429) && remainingStr == "0" {
		_ = resp.Body.Close()
		resetSec, _ := strconv.ParseInt(resetStr, 10, 64)
		resetTime := time.Unix(resetSec, 0)
		return nil, &RateLimitError{Remaining: 0, ResetTime: resetTime}
	}

	return resp, nil
}

// GetRepository fetches repository metadata.
func (c *APIClient) GetRepository(ctx context.Context, owner, repo string) (*Repository, error) {
	endpoint := fmt.Sprintf("/repos/%s/%s", owner, repo)
	resp, err := c.doRequest(ctx, http.MethodGet, endpoint)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("repository %s/%s not found or access denied", owner, repo)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to fetch repository (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var r Repository
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	return &r, nil
}

// GetBranchProtection retrieves branch protection configuration.
// Returns (nil, nil) if branch protection is not enabled (HTTP 404).
func (c *APIClient) GetBranchProtection(ctx context.Context, owner, repo, branch string) (*BranchProtection, error) {
	endpoint := fmt.Sprintf("/repos/%s/%s/branches/%s/protection", owner, repo, branch)
	resp, err := c.doRequest(ctx, http.MethodGet, endpoint)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// Branch protection is not enabled on this branch
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get branch protection (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var bp BranchProtection
	if err := json.NewDecoder(resp.Body).Decode(&bp); err != nil {
		return nil, err
	}
	return &bp, nil
}

// GetTree retrieves the recursive git tree for a given branch or commit SHA.
func (c *APIClient) GetTree(ctx context.Context, owner, repo, treeSHA string) (*TreeResponse, error) {
	endpoint := fmt.Sprintf("/repos/%s/%s/git/trees/%s?recursive=1", owner, repo, treeSHA)
	resp, err := c.doRequest(ctx, http.MethodGet, endpoint)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to fetch tree (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var tr TreeResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return nil, err
	}
	return &tr, nil
}

// GetFileContent fetches and decodes the file content from a repository.
func (c *APIClient) GetFileContent(ctx context.Context, owner, repo, path, ref string) ([]byte, error) {
	endpoint := fmt.Sprintf("/repos/%s/%s/contents/%s", owner, repo, path)
	if ref != "" {
		endpoint = fmt.Sprintf("%s?ref=%s", endpoint, ref)
	}

	resp, err := c.doRequest(ctx, http.MethodGet, endpoint)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch file %s (HTTP %d)", path, resp.StatusCode)
	}

	var cr ContentResponse
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		return nil, err
	}

	if cr.Encoding == "base64" {
		cleaned := strings.ReplaceAll(cr.Content, "\n", "")
		cleaned = strings.ReplaceAll(cleaned, "\r", "")
		return base64.StdEncoding.DecodeString(cleaned)
	}

	return []byte(cr.Content), nil
}

// ListOrgRepositories retrieves non-fork repositories for an organization.
func (c *APIClient) ListOrgRepositories(ctx context.Context, org string) ([]Repository, error) {
	endpoint := fmt.Sprintf("/orgs/%s/repos?per_page=100&type=all", org)
	resp, err := c.doRequest(ctx, http.MethodGet, endpoint)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to list organization repos (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var repos []Repository
	if err := json.NewDecoder(resp.Body).Decode(&repos); err != nil {
		return nil, err
	}
	return repos, nil
}
