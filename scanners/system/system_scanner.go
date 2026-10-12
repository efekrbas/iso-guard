package system

import (
	"context"
	"os"
	"os/user"
	"runtime"
	"strings"
	"time"

	"github.com/efekrbas/iso-guard/scanners"
)

// SystemArtifact represents system and environment details.
type SystemArtifact struct {
	Hostname        string            `json:"hostname"`
	OS              string            `json:"os"`
	Arch            string            `json:"arch"`
	NumCPU          int               `json:"num_cpu"`
	CurrentUser     string            `json:"current_user"`
	IsRoot          bool              `json:"is_root"`
	ExposedEnvVars  []string          `json:"exposed_env_vars"`
	SystemVariables map[string]string `json:"system_variables"`
	ScanDuration    time.Duration     `json:"scan_duration"`
}

// Scanner implements scanners.Scanner for host system security baseline checks.
type Scanner struct{}

// NewScanner initializes a new System Scanner.
func NewScanner() *Scanner {
	return &Scanner{}
}

func (s *Scanner) Name() string {
	return "system"
}

func (s *Scanner) Description() string {
	return "Audits host operating system baseline, user privileges, and environment hygiene"
}

var secretEnvPatterns = []string{
	"SECRET",
	"PASSWORD",
	"TOKEN",
	"PRIVATE_KEY",
	"API_KEY",
	"ACCESS_KEY",
	"CREDENTIAL",
}

func (s *Scanner) Scan(ctx context.Context, target string) (interface{}, error) {
	start := time.Now()
	artifact := &SystemArtifact{
		OS:              runtime.GOOS,
		Arch:            runtime.GOARCH,
		NumCPU:          runtime.NumCPU(),
		ExposedEnvVars:  make([]string, 0),
		SystemVariables: make(map[string]string),
	}

	if host, err := os.Hostname(); err == nil {
		artifact.Hostname = host
	}

	if u, err := user.Current(); err == nil {
		artifact.CurrentUser = u.Username
		if u.Uid == "0" || strings.EqualFold(u.Username, "root") || strings.EqualFold(u.Username, "Administrator") {
			artifact.IsRoot = true
		}
	}

	// Check environment variables for sensitive exposed keys
	for _, env := range os.Environ() {
		pair := strings.SplitN(env, "=", 2)
		if len(pair) == 2 {
			key := pair[0]
			keyUpper := strings.ToUpper(key)
			for _, pattern := range secretEnvPatterns {
				if strings.Contains(keyUpper, pattern) {
					artifact.ExposedEnvVars = append(artifact.ExposedEnvVars, key)
					break
				}
			}
		}
	}

	artifact.ScanDuration = time.Since(start)
	return artifact, nil
}

var _ scanners.Scanner = (*Scanner)(nil)
