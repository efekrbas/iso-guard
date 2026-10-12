package network

import (
	"context"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/efekrbas/iso-guard/scanners"
)

// PortResult describes the status of a probed port.
type PortResult struct {
	Port         int           `json:"port"`
	Protocol     string        `json:"protocol"`
	Service      string        `json:"service"`
	IsOpen       bool          `json:"is_open"`
	IsInsecure   bool          `json:"is_insecure"`
	Warning      string        `json:"warning,omitempty"`
	ResponseTime time.Duration `json:"response_time"`
}

// NetworkArtifact represents network scan findings.
type NetworkArtifact struct {
	TargetHost   string        `json:"target_host"`
	ProbedPorts  []PortResult  `json:"probed_ports"`
	OpenPorts    []PortResult  `json:"open_ports"`
	ScanDuration time.Duration `json:"scan_duration"`
}

// Common ports with ISO 27001 significance (e.g. unencrypted protocols A.8.20 / A.8.24)
var standardPorts = []struct {
	Port       int
	Service    string
	IsInsecure bool
	Warning    string
}{
	{21, "FTP", true, "Unencrypted FTP protocol exposes credentials in plaintext"},
	{22, "SSH", false, "Secure Shell service"},
	{23, "Telnet", true, "Telnet transmits credentials and traffic in plaintext (violation of A.8.20/A.8.24)"},
	{25, "SMTP", false, "Mail transfer agent"},
	{80, "HTTP", true, "Cleartext HTTP traffic detected; enforce HTTPS redirect (A.8.24)"},
	{443, "HTTPS", false, "Encrypted Web service"},
	{3306, "MySQL", true, "Database port should not be publicly accessible (A.8.20)"},
	{5432, "PostgreSQL", true, "Database port should not be publicly accessible (A.8.20)"},
	{6379, "Redis", true, "Redis typically lacks strong authentication on default ports (A.8.20)"},
	{27017, "MongoDB", true, "MongoDB exposed without proper network boundary (A.8.20)"},
}

// Scanner implements scanners.Scanner for network interface and service audits.
type Scanner struct {
	Timeout time.Duration
}

// NewScanner initializes a new Network Scanner.
func NewScanner(timeout time.Duration) *Scanner {
	if timeout <= 0 {
		timeout = 250 * time.Millisecond
	}
	return &Scanner{Timeout: timeout}
}

func (s *Scanner) Name() string {
	return "network"
}

func (s *Scanner) Description() string {
	return "Audits exposed network ports, cleartext communication protocols, and boundary controls"
}

func (s *Scanner) Scan(ctx context.Context, target string) (interface{}, error) {
	start := time.Now()
	host := "127.0.0.1"

	// If target looks like a host or IP, use it
	if strings.Contains(target, ".") && !strings.Contains(target, "/") && !strings.Contains(target, "\\") {
		host = target
	}

	artifact := &NetworkArtifact{
		TargetHost:  host,
		ProbedPorts: make([]PortResult, 0),
		OpenPorts:   make([]PortResult, 0),
	}

	for _, p := range standardPorts {
		select {
		case <-ctx.Done():
			return artifact, ctx.Err()
		default:
		}

		address := net.JoinHostPort(host, strconv.Itoa(p.Port))
		portStart := time.Now()
		conn, err := net.DialTimeout("tcp", address, s.Timeout)

		res := PortResult{
			Port:         p.Port,
			Protocol:     "tcp",
			Service:      p.Service,
			IsInsecure:   p.IsInsecure,
			Warning:      p.Warning,
			ResponseTime: time.Since(portStart),
		}

		if err == nil {
			_ = conn.Close()
			res.IsOpen = true
			artifact.OpenPorts = append(artifact.OpenPorts, res)
		} else {
			res.IsOpen = false
		}

		artifact.ProbedPorts = append(artifact.ProbedPorts, res)
	}

	artifact.ScanDuration = time.Since(start)
	return artifact, nil
}

var _ scanners.Scanner = (*Scanner)(nil)
