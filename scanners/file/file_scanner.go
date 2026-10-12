package file

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/efekrbas/iso-guard/scanners"
)

// FileInfo holds metadata about an audited file.
type FileInfo struct {
	Path         string      `json:"path"`
	RelPath      string      `json:"rel_path"`
	Size         int64       `json:"size"`
	Mode         os.FileMode `json:"mode"`
	ModeString   string      `json:"mode_string"`
	ModTime      time.Time   `json:"mod_time"`
	IsDir        bool        `json:"is_dir"`
	IsExecutable bool        `json:"is_executable"`
	IsSensitive  bool        `json:"is_sensitive"`
	Tags         []string    `json:"tags"`
}

// FileArtifact represents the aggregate data collected from the filesystem.
type FileArtifact struct {
	RootPath          string     `json:"root_path"`
	TotalFilesScanned int        `json:"total_files_scanned"`
	TotalDirsScanned  int        `json:"total_dirs_scanned"`
	SensitiveFiles    []FileInfo `json:"sensitive_files"`
	PermissiveFiles   []FileInfo `json:"permissive_files"`
	AllFiles          []FileInfo `json:"all_files"`
	ScanDuration      time.Duration
}

// Scanner implements scanners.Scanner for file-system and configuration audits.
type Scanner struct {
	ExcludeDirs    []string
	MaxDepth       int
	MaxFiles       int
	ExcludeRegexes []*regexp.Regexp
}

// NewScanner initializes a new File Scanner.
func NewScanner(excludeDirs []string) *Scanner {
	if len(excludeDirs) == 0 {
		excludeDirs = []string{".git", "node_modules", "vendor", ".idea", ".vscode", "dist", "build"}
	}
	return &Scanner{
		ExcludeDirs: excludeDirs,
		MaxDepth:    15,
		MaxFiles:    10000,
	}
}

func (s *Scanner) Name() string {
	return "filesystem"
}

func (s *Scanner) Description() string {
	return "Scans local directory for sensitive files, insecure permissions, and configuration leaks"
}

// Sensitive file patterns
var (
	sensitiveNamePatterns = []string{
		".env",
		".env.local",
		".env.production",
		"id_rsa",
		"id_dsa",
		"id_ecdsa",
		"id_ed25519",
		"credentials.json",
		"service-account.json",
		"client_secret.json",
		"htpasswd",
		".htpasswd",
		"wp-config.php",
		"secrets.yaml",
		"secrets.json",
	}

	sensitiveExtensionPatterns = []string{
		".key",
		".pem",
		".p12",
		".pfx",
		".kdbx",
		".keystore",
	}
)

func isSensitiveFile(filename string) (bool, []string) {
	lower := strings.ToLower(filename)
	var tags []string

	for _, pattern := range sensitiveNamePatterns {
		if strings.EqualFold(filename, pattern) || strings.HasSuffix(lower, "/"+pattern) || strings.HasSuffix(lower, "\\"+pattern) {
			tags = append(tags, "sensitive_name", pattern)
			return true, tags
		}
	}

	for _, ext := range sensitiveExtensionPatterns {
		if strings.HasSuffix(lower, ext) {
			tags = append(tags, "crypto_key", ext)
			return true, tags
		}
	}

	return false, tags
}

func (s *Scanner) Scan(ctx context.Context, target string) (interface{}, error) {
	start := time.Now()
	artifact := &FileArtifact{
		RootPath:        target,
		SensitiveFiles:  make([]FileInfo, 0),
		PermissiveFiles: make([]FileInfo, 0),
		AllFiles:        make([]FileInfo, 0),
	}

	absTarget, err := filepath.Abs(target)
	if err != nil {
		absTarget = target
	}
	artifact.RootPath = absTarget

	targetStat, err := os.Stat(absTarget)
	if err != nil {
		return artifact, err
	}

	if !targetStat.IsDir() {
		// Single file audit
		rel, _ := filepath.Rel(absTarget, absTarget)
		fInfo := toFileInfo(absTarget, rel, targetStat)
		artifact.TotalFilesScanned = 1
		artifact.AllFiles = append(artifact.AllFiles, fInfo)
		if fInfo.IsSensitive {
			artifact.SensitiveFiles = append(artifact.SensitiveFiles, fInfo)
		}
		artifact.ScanDuration = time.Since(start)
		return artifact, nil
	}

	err = filepath.WalkDir(absTarget, func(path string, d fs.DirEntry, walkErr error) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if walkErr != nil {
			return nil // Skip unreadable paths
		}

		if d.IsDir() {
			name := d.Name()
			for _, excl := range s.ExcludeDirs {
				if strings.EqualFold(name, excl) {
					return filepath.SkipDir
				}
			}
			artifact.TotalDirsScanned++
			return nil
		}

		if artifact.TotalFilesScanned >= s.MaxFiles {
			return filepath.SkipAll
		}

		info, err := d.Info()
		if err != nil {
			return nil
		}

		artifact.TotalFilesScanned++
		rel, _ := filepath.Rel(absTarget, path)
		fInfo := toFileInfo(path, rel, info)

		// Check sensitive files
		if fInfo.IsSensitive {
			artifact.SensitiveFiles = append(artifact.SensitiveFiles, fInfo)
		}

		// Check insecure permissions (e.g. world-writable: 0002 on POSIX systems)
		if runtime.GOOS != "windows" && info.Mode().Perm()&0002 != 0 {
			fInfo.Tags = append(fInfo.Tags, "world_writable")
			artifact.PermissiveFiles = append(artifact.PermissiveFiles, fInfo)
		}

		artifact.AllFiles = append(artifact.AllFiles, fInfo)
		return nil
	})

	artifact.ScanDuration = time.Since(start)
	return artifact, err
}

func toFileInfo(path, rel string, info os.FileInfo) FileInfo {
	isSens, tags := isSensitiveFile(filepath.Base(path))
	return FileInfo{
		Path:         path,
		RelPath:      rel,
		Size:         info.Size(),
		Mode:         info.Mode(),
		ModeString:   info.Mode().String(),
		ModTime:      info.ModTime(),
		IsDir:        info.IsDir(),
		IsExecutable: info.Mode()&0111 != 0,
		IsSensitive:  isSens,
		Tags:         tags,
	}
}

var _ scanners.Scanner = (*Scanner)(nil)
