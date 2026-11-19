package audit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// SourceOptions control how a source is opened.
type SourceOptions struct {
	Follow  bool // keep reading as the log grows (tail -F)
	Backlog int  // follow mode: lines of existing log to read first; <0 = whole file
	Sudo    bool // ssh sources: run the remote command via sudo
	// SudoPassword is fed to `sudo -S` on the remote side (over ssh's stdin,
	// never in argv). Empty means passwordless sudo (`sudo -n`).
	SudoPassword string
	// History (ssh sources): how many rotated logs next to the log
	// (audit-2026-11-19T13-36-10.525.log, also .gz) to read before it,
	// newest ones first in the cut. 0 = none, <0 = all.
	History int
}

// Source is an open log stream. Close stops it (and kills any child process).
type Source struct {
	io.Reader
	Name   string
	cancel func()
	wait   func() error
	stderr *bytes.Buffer
}

// Wait waits for a source that reached EOF to finish and returns its exit error.
func (s *Source) Wait() error { return s.wait() }

// Close stops the source, killing its child process if it has one.
func (s *Source) Close() error {
	s.cancel()
	return s.wait()
}

// Err returns the last stderr line of a child process, if any. Useful to
// explain why an ssh source ended (auth failure, permission denied, ...).
func (s *Source) Err() string {
	if s.stderr == nil {
		return ""
	}
	lines := strings.Split(strings.TrimSpace(s.stderr.String()), "\n")
	return lines[len(lines)-1]
}

// DefaultRemoteLog is where the API server writes its audit log on the masters.
const DefaultRemoteLog = "/var/log/kubernetes/audit/audit.log"

// ResolveSpec expands a bare [user@]host[:port] (no "/", not an existing
// local file) and an ssh:// URL without a path to ssh://.../remoteLog.
// The login user is left to ssh: the local user unless ~/.ssh/config says otherwise.
func ResolveSpec(spec, remoteLog string) string {
	if spec == "-" {
		return spec
	}
	if h, ok := strings.CutPrefix(spec, "ssh://"); ok {
		if !strings.Contains(h, "/") {
			return spec + remoteLog
		}
		if strings.HasSuffix(h, "/") && strings.Count(h, "/") == 1 {
			return strings.TrimSuffix(spec, "/") + remoteLog
		}
		return spec
	}
	if strings.Contains(spec, "/") {
		return spec
	}
	if _, err := os.Stat(spec); err == nil {
		return spec
	}
	return "ssh://" + spec + remoteLog
}

// OpenSource opens "-" (stdin), a local path, or ssh://[user@]host[:port]/path.
func OpenSource(ctx context.Context, spec string, opt SourceOptions) (*Source, error) {
	if spec == "-" {
		return &Source{Reader: os.Stdin, Name: "stdin", cancel: func() {}, wait: func() error { return nil }}, nil
	}
	if strings.HasPrefix(spec, "ssh://") {
		return openSSH(ctx, spec, opt)
	}
	if opt.Follow {
		return run(ctx, spec, nil, "tail", tailArgs(opt, spec)...)
	}
	f, err := os.Open(spec)
	if err != nil {
		return nil, err
	}
	return &Source{Reader: f, Name: spec, cancel: func() {}, wait: f.Close}, nil
}

func tailArgs(opt SourceOptions, path string) []string {
	n := "+1"
	if opt.Backlog >= 0 {
		n = fmt.Sprint(opt.Backlog)
	}
	return []string{"-n", n, "-F", path}
}

func parseSSH(spec string) (*url.URL, error) {
	u, err := url.Parse(spec)
	if err != nil {
		return nil, err
	}
	if u.Host == "" || u.Path == "" || u.Path == "/" {
		return nil, fmt.Errorf("want ssh://[user@]host[:port]/path/to/audit.log")
	}
	return u, nil
}

// sshCmd builds the ssh argv running remote (quoted) on u's host, with sudo
// if requested, plus the stdin to feed it.
func sshCmd(u *url.URL, opt SourceOptions, remote ...string) ([]string, io.Reader) {
	var stdin io.Reader
	if opt.Sudo {
		if opt.SudoPassword != "" {
			remote = append([]string{"sudo", "-S", "-p", ""}, remote...)
			stdin = strings.NewReader(opt.SudoPassword + "\n")
		} else {
			remote = append([]string{"sudo", "-n"}, remote...)
		}
	}
	for i, a := range remote {
		remote[i] = shellQuote(a)
	}
	// BatchMode: never prompt for a password, it would fight the TUI for the terminal.
	args := []string{"-o", "BatchMode=yes", "-o", "ServerAliveInterval=15"}
	if p := u.Port(); p != "" {
		args = append(args, "-p", p)
	}
	host := u.Hostname()
	if u.User != nil {
		host = u.User.Username() + "@" + host
	}
	return append(args, host, "--", strings.Join(remote, " ")), stdin
}

func openSSH(ctx context.Context, spec string, opt SourceOptions) (*Source, error) {
	u, err := parseSSH(spec)
	if err != nil {
		return nil, err
	}
	remote := []string{"cat", u.Path}
	if opt.Follow {
		remote = append([]string{"tail"}, tailArgs(opt, u.Path)...)
	}
	if opt.History != 0 {
		n := "+1" // tail -n +1: all files
		if opt.History > 0 {
			n = fmt.Sprint(opt.History)
		}
		remote = append([]string{"sh", "-c", historyScript, "sh", u.Path, n}, remote...)
	}
	args, stdin := sshCmd(u, opt, remote...)
	src, err := run(ctx, spec, stdin, "ssh", args...)
	if src != nil {
		src.Name = u.Hostname()
	}
	return src, err
}

// historyScript prints the rotated siblings of $1 ($dir/$stem-*.$ext and
// .gz), oldest first, keeping the last $2 of them, then execs the rest of
// argv (cat/tail of the live log). Rotated names carry a timestamp, so
// lexical order is time order. Unreadable files are reported and skipped.
const historyScript = `log=$1 n=$2; shift 2
d=${log%/*} b=${log##*/}; stem=${b%.*} ext=${b##*.}
for f in "$d/$stem"-*."$ext" "$d/$stem"-*."$ext".gz; do [ -f "$f" ] && printf '%s\n' "$f"; done |
sort | tail -n "$n" | while IFS= read -r f; do
  case $f in *.gz) gzip -dc -- "$f";; *) cat -- "$f";; esac
done
exec "$@"`

// ErrSudoPassword means the remote sudo wants a password (or rejected the one given).
var ErrSudoPassword = errors.New("sudo needs a password")

// CheckSudo verifies that the remote sudo of an ssh:// source works with opt,
// and can read the log file. Non-ssh specs are not checked.
func CheckSudo(ctx context.Context, spec string, opt SourceOptions) error {
	if !strings.HasPrefix(spec, "ssh://") {
		return nil
	}
	u, err := parseSSH(spec)
	if err != nil {
		return err
	}
	opt.Sudo = true
	args, stdin := sshCmd(u, opt, "test", "-r", u.Path)
	c := exec.CommandContext(ctx, "ssh", args...)
	c.Stdin = stdin
	out, err := c.CombinedOutput()
	if err == nil {
		return nil
	}
	msg := strings.TrimSpace(string(out))
	if strings.Contains(msg, "password") || strings.Contains(msg, "terminal is required") {
		return fmt.Errorf("%s: %w (%s)", u.Hostname(), ErrSudoPassword, msg)
	}
	if msg == "" && c.ProcessState != nil && c.ProcessState.ExitCode() == 1 {
		msg = "cannot read " + u.Path
	}
	return fmt.Errorf("%s: %v: %s", u.Hostname(), err, msg)
}

func run(ctx context.Context, name string, stdin io.Reader, cmd string, args ...string) (*Source, error) {
	ctx, cancel := context.WithCancel(ctx)
	c := exec.CommandContext(ctx, cmd, args...)
	c.Stdin = stdin
	// Own process group: terminal signals don't reach the child, and on
	// cancel we kill the whole group, including anything the child spawned.
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	c.Cancel = func() error { return syscall.Kill(-c.Process.Pid, syscall.SIGKILL) }
	out, err := c.StdoutPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	stderr := &bytes.Buffer{}
	c.Stderr = stderr // never let a child write over the TUI
	if err := c.Start(); err != nil {
		cancel()
		return nil, err
	}
	return &Source{Reader: out, Name: name, stderr: stderr, cancel: cancel, wait: func() error {
		defer cancel()
		return c.Wait()
	}}, nil
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
