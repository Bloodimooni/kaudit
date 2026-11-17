package audit

import (
	"bufio"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeSSH puts an `ssh` on PATH that records its args and runs the remote
// command locally, so the real ssh:// code path runs without a server.
func fakeSSH(t *testing.T) (argsFile string) {
	dir := t.TempDir()
	argsFile = filepath.Join(dir, "args")
	script := "#!/bin/sh\necho \"$@\" > " + argsFile + "\nfor a; do last=$a; done\nexec sh -c \"$last\"\n"
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	// and a sudo: -n works unless $FAKE_SUDO_PW is set; -S wants that password
	sudo := `#!/bin/sh
case "$1" in
-n) [ -z "$FAKE_SUDO_PW" ] || { echo "sudo: a password is required" >&2; exit 1; }; shift;;
-S) shift 3; read pw; [ "$pw" = "$FAKE_SUDO_PW" ] || { echo "sudo: 1 incorrect password attempt" >&2; exit 1; };;
esac
exec "$@"
`
	os.WriteFile(filepath.Join(dir, "sudo"), []byte(sudo), 0o755)
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	return argsFile
}

func TestLoadSSH(t *testing.T) {
	argsFile := fakeSSH(t)
	log, _ := filepath.Abs("../../testdata/sample.jsonl")
	res, err := LoadFiles([]string{"ssh://admin@m1:2222" + log}, LoadOptions{Sudo: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) == 0 {
		t.Fatal("no events")
	}
	args, _ := os.ReadFile(argsFile)
	want := "-p 2222 admin@m1 -- 'sudo' '-n' 'cat' '" + log + "'"
	if !strings.Contains(string(args), want) {
		t.Fatalf("ssh args %q, want %q", args, want)
	}
}

func TestFollowSSH(t *testing.T) {
	fakeSSH(t)
	log := filepath.Join(t.TempDir(), "audit.log")
	line := `{"kind":"Event","stage":"ResponseComplete","stageTimestamp":"2026-01-01T00:00:00Z","verb":"get"}` + "\n"
	os.WriteFile(log, []byte(line+line), 0o644)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	src, err := OpenSource(ctx, "ssh://m1"+log, SourceOptions{Follow: true, Backlog: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	sc := bufio.NewScanner(src)
	read := func() {
		if !sc.Scan() {
			t.Fatalf("stream ended: %v %s", sc.Err(), src.Err())
		}
	}
	read() // backlog of 1 line
	f, _ := os.OpenFile(log, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(line)
	f.Close()
	read() // the appended line arrives live
}

func TestCheckSudoPassword(t *testing.T) {
	argsFile := fakeSSH(t)
	t.Setenv("FAKE_SUDO_PW", "s3cret")
	log, _ := filepath.Abs("../../testdata/sample.jsonl")
	spec := "ssh://m1" + log
	ctx := context.Background()

	if err := CheckSudo(ctx, spec, SourceOptions{}); !errors.Is(err, ErrSudoPassword) {
		t.Fatalf("passwordless check: got %v, want ErrSudoPassword", err)
	}
	if err := CheckSudo(ctx, spec, SourceOptions{SudoPassword: "wrong"}); !errors.Is(err, ErrSudoPassword) {
		t.Fatalf("wrong password: got %v, want ErrSudoPassword", err)
	}
	if err := CheckSudo(ctx, spec, SourceOptions{SudoPassword: "s3cret"}); err != nil {
		t.Fatalf("right password: %v", err)
	}
	if err := CheckSudo(ctx, "ssh://m1/no/such/file", SourceOptions{SudoPassword: "s3cret"}); err == nil ||
		!strings.Contains(err.Error(), "cannot read /no/such/file") {
		t.Fatalf("missing file: got %v", err)
	}
	res, err := LoadFiles([]string{spec}, LoadOptions{Sudo: true, SudoPassword: "s3cret"})
	if err != nil || len(res.Events) == 0 {
		t.Fatalf("load with password: %v", err)
	}
	if args, _ := os.ReadFile(argsFile); strings.Contains(string(args), "s3cret") {
		t.Fatalf("password leaked into ssh argv: %s", args)
	}
}

func TestResolveSpec(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	os.WriteFile("audit.log", nil, 0o644)
	const def = "/var/log/kubernetes/audit/audit.log"
	for in, want := range map[string]string{
		"master-1":             "ssh://master-1" + def,
		"admin@master-1:2222":  "ssh://admin@master-1:2222" + def,
		"ssh://master-1":       "ssh://master-1" + def,
		"ssh://master-1/":      "ssh://master-1" + def,
		"ssh://master-1/x.log": "ssh://master-1/x.log",
		"audit.log":            "audit.log", // exists locally
		"./missing.log":        "./missing.log",
		"/var/log/a.log":       "/var/log/a.log",
		"-":                    "-",
	} {
		if got := ResolveSpec(in, def); got != want {
			t.Errorf("ResolveSpec(%q) = %q, want %q", in, got, want)
		}
	}
}
