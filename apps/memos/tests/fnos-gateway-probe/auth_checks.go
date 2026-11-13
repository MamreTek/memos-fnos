package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"
)

var suites = []string{"endpoint", "memosclient", "browserflow", "oauthbridge"}

type checkResult struct {
	Status       string            `json:"status"`
	MemosVersion string            `json:"memos_version"`
	Cases        map[string]string `json:"cases,omitempty"`
	ErrorCode    string            `json:"error_code,omitempty"`
}

type authChecks struct {
	mu     sync.Mutex
	result checkResult
}

func (a *authChecks) snapshot() checkResult {
	a.mu.Lock()
	defer a.mu.Unlock()
	result := a.result
	if result.Status == "" {
		result.Status, result.MemosVersion = "unavailable", "26.11.0"
	}
	result.Cases = make(map[string]string, len(a.result.Cases))
	for name, status := range a.result.Cases {
		result.Cases[name] = status
	}
	return result
}

func (a *authChecks) set(result checkResult) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.result = result
	a.result.Cases = make(map[string]string, len(result.Cases))
	for name, status := range result.Cases {
		a.result.Cases[name] = status
	}
}

func checkedPayload(dest string) (map[string]string, error) {
	data, err := os.ReadFile(filepath.Join(dest, "auth-payload.json"))
	if err != nil || len(data) > 16384 {
		return nil, errors.New("E_AUTH_PAYLOAD")
	}
	var manifest struct {
		Version      string                       `json:"version"`
		MemosVersion string                       `json:"memos_version"`
		SHA256       map[string]map[string]string `json:"sha256"`
	}
	if json.Unmarshal(data, &manifest) != nil || manifest.Version != version || manifest.MemosVersion != "26.11.0" {
		return nil, errors.New("E_AUTH_PAYLOAD")
	}
	hashes := manifest.SHA256[runtime.GOARCH]
	paths := make(map[string]string)
	for _, name := range append([]string{"memos"}, suites...) {
		filename := "auth-suite-" + name + "-" + runtime.GOARCH
		if name == "memos" {
			filename = "memos-" + runtime.GOARCH
		}
		path := filepath.Join(dest, "bin", filename)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Size() > 128<<20 {
			return nil, errors.New("E_AUTH_PAYLOAD")
		}
		file, err := os.Open(path)
		if err != nil {
			return nil, errors.New("E_AUTH_PAYLOAD")
		}
		hash := sha256.New()
		_, err = io.Copy(hash, file)
		file.Close()
		if err != nil || len(hashes[name]) != 64 || hex.EncodeToString(hash.Sum(nil)) != hashes[name] {
			return nil, errors.New("E_AUTH_PAYLOAD")
		}
		paths[name] = path
	}
	return paths, nil
}

// runOwned creates a new process group and signals only that group on cancel.
// The disposable Memos subprocess inherits the group's identity as well.
func runOwned(ctx context.Context, command *exec.Cmd) error {
	if ctx.Err() != nil {
		return errors.New("E_AUTH_CANCELLED")
	}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		return errors.New("E_AUTH_START")
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			<-done
		}
		// Reap any remaining fixture child in this owned process group.
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		return errors.New("E_AUTH_CANCELLED")
	}
}

func (a *authChecks) run(parent context.Context, dest, privateDir string) {
	result := checkResult{Status: "running", MemosVersion: "26.11.0", Cases: make(map[string]string)}
	fail := func(code string) {
		result.Status, result.ErrorCode = "failed", code
		a.set(result)
	}
	paths, err := checkedPayload(dest)
	if err != nil {
		fail("E_AUTH_PAYLOAD")
		return
	}
	work, err := os.MkdirTemp(privateDir, "auth-check-")
	if err != nil {
		fail("E_AUTH_DIRECTORY")
		return
	}
	defer os.RemoveAll(work)
	log, err := privateFile(filepath.Join(privateDir, "auth-check.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC)
	if err != nil {
		fail("E_AUTH_LOG")
		return
	}
	defer log.Close()
	ctx, cancel := context.WithTimeout(parent, 2*time.Minute)
	defer cancel()
	for _, name := range suites {
		command := exec.Command(paths[name], "-test.v", "-test.count=1", "-test.timeout=90s")
		command.Dir = work
		command.Env = []string{"PATH=" + os.Getenv("PATH"), "LANG=C.UTF-8", "TMPDIR=" + work, "MEMOS_BINARY=" + paths["memos"]}
		command.Stdout, command.Stderr = log, log
		if err := runOwned(ctx, command); err != nil {
			result.Cases[name] = "failed"
			if ctx.Err() != nil {
				fail("E_AUTH_CANCELLED")
			} else {
				fail("E_AUTH_SUITE")
			}
			return
		}
		result.Cases[name] = "passed"
		a.set(result)
	}
	result.Status = "passed"
	a.set(result)
}
