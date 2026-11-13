package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestCheckResultCopiesAndMissingPayloadFailsClosed(t *testing.T) {
	a := &authChecks{}
	result := checkResult{Status: "running", Cases: map[string]string{"endpoint": "passed"}}
	a.set(result)
	result.Cases["endpoint"] = "changed"
	read := a.snapshot()
	read.Cases["endpoint"] = "changed"
	if a.snapshot().Cases["endpoint"] != "passed" {
		t.Fatal("diagnostic state exposed a mutable map")
	}
	a.run(context.Background(), t.TempDir(), t.TempDir())
	if got := a.snapshot(); got.Status != "failed" || got.ErrorCode != "E_AUTH_PAYLOAD" {
		t.Fatal("missing payload reported success")
	}
}

func TestOwnedFixtureChild(t *testing.T) {
	if os.Getenv("FNOS_PROBE_HELPER") != "1" {
		return
	}
	if err := os.WriteFile(os.Getenv("FNOS_PROBE_READY"), []byte("ready"), 0600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Second)
}

func TestOwnedProcessCancellation(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ready := filepath.Join(t.TempDir(), "ready")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	command := exec.Command(executable, "-test.run=^TestOwnedFixtureChild$")
	command.Env = []string{"FNOS_PROBE_HELPER=1", "FNOS_PROBE_READY=" + ready}
	done := make(chan error, 1)
	go func() { done <- runOwned(ctx, command) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatal("fixture did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled fixture reported success")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("owned fixture did not stop")
	}
}
