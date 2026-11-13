// A disposable fnOS capability probe. This does not authenticate Memos users.
package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"
)

const version = "0.0.2"
const prefix = "/app/memos-sso-probe"

var uidPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,19})$`)

func fingerprint(key []byte, kind, value string) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(kind + "\x00" + value))
	return hex.EncodeToString(h.Sum(nil))
}

func oneHeader(r *http.Request, name string) (string, bool) {
	values := r.Header.Values(name)
	if len(values) != 1 || values[0] == "" {
		return "", false
	}
	return values[0], true
}

func respond(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'self'")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(value)
}

func gatewayHandler(key []byte, checks *authChecks) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only this Unix-socket handler reads gateway identity. There is no TCP listener.
		if r.URL.Path != prefix && r.URL.Path != prefix+"/" {
			respond(w, http.StatusNotFound, map[string]string{"error": "E_ROUTE"})
			return
		}
		if r.Method != http.MethodGet || r.URL.RawQuery != "" {
			respond(w, http.StatusBadRequest, map[string]string{"error": "E_REQUEST"})
			return
		}
		uid, uidOK := oneHeader(r, "X-Trim-Userid")
		name, nameOK := oneHeader(r, "X-Trim-Username")
		admin, adminOK := oneHeader(r, "X-Trim-Isadmin")
		validName := nameOK && len(name) <= 256 && utf8.ValidString(name) && strings.TrimSpace(name) == name
		for _, c := range name {
			validName = validName && !unicode.IsControl(c)
		}
		if !uidOK || !uidPattern.MatchString(uid) || !validName || !adminOK || (admin != "true" && admin != "false") {
			respond(w, http.StatusUnauthorized, map[string]string{"error": "E_GATEWAY_IDENTITY"})
			return
		}
		respond(w, http.StatusOK, map[string]any{
			"probe_version": version,
			"architecture":  runtime.GOARCH,
			// Keep the installation fingerprint compatible with probe 0.0.1.
			"installation_fingerprint": fingerprint(key, "installation", "0.0.1"),
			"uid_fingerprint":          fingerprint(key, "uid", uid),
			"username_fingerprint":     fingerprint(key, "username", name),
			"is_admin":                 admin == "true",
			"gateway_headers_present":  true,
			"memos_sso_implemented":    false,
			"auth_checks":              checks.snapshot(),
		})
	})
}

type paths struct{ runtime, gateway, control string }

func appPaths() (paths, error) {
	dest, variable := os.Getenv("TRIM_APPDEST"), os.Getenv("TRIM_PKGVAR")
	if !filepath.IsAbs(dest) || !filepath.IsAbs(variable) {
		return paths{}, errors.New("E_PLATFORM_PATHS")
	}
	runtimeDir := filepath.Join(variable, "probe")
	if err := os.Mkdir(runtimeDir, 0700); err != nil && !os.IsExist(err) {
		return paths{}, errors.New("E_RUNTIME_DIRECTORY")
	}
	info, err := os.Lstat(runtimeDir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Getuid()) {
		return paths{}, errors.New("E_RUNTIME_PERMISSIONS")
	}
	return paths{runtimeDir, filepath.Join(dest, "app.sock"), filepath.Join(runtimeDir, "control.sock")}, nil
}

func privateFile(path string, flags int) (*os.File, error) {
	f, err := os.OpenFile(path, flags|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, errors.New("E_PRIVATE_FILE")
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Getuid()) {
		f.Close()
		return nil, errors.New("E_PRIVATE_PERMISSIONS")
	}
	return f, nil
}

func loadKey(dir string) ([]byte, error) {
	path := filepath.Join(dir, "fingerprint.key")
	f, err := privateFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err == nil {
		key := make([]byte, 32)
		if _, err = rand.Read(key); err == nil {
			_, err = f.Write(key)
		}
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil || closeErr != nil {
			return nil, errors.New("E_KEY_WRITE")
		}
		return key, nil
	}
	// Existing keys must be private regular files; never replace invalid state.
	f, err = privateFile(path, os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	key, err := io.ReadAll(io.LimitReader(f, 33))
	if err != nil || len(key) != 32 {
		return nil, errors.New("E_KEY_READ")
	}
	return key, nil
}

func removeStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Getuid()) {
		return errors.New("E_SOCKET_PATH")
	}
	if err := os.Remove(path); err != nil {
		return errors.New("E_SOCKET_REMOVE")
	}
	return nil
}

func listen(path string, mode os.FileMode) (net.Listener, error) {
	if err := removeStaleSocket(path); err != nil {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, errors.New("E_SOCKET_LISTEN")
	}
	if err := os.Chmod(path, mode); err != nil {
		listener.Close()
		return nil, errors.New("E_SOCKET_MODE")
	}
	return listener, nil
}

func controlRequest(p paths, method, route string) bool {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", p.control)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 300 * time.Millisecond}
	req, _ := http.NewRequest(method, "http://probe"+route, nil)
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

func serve(p paths) error {
	key, err := loadKey(p.runtime)
	if err != nil {
		return err
	}
	gate, err := listen(p.gateway, 0660)
	if err != nil {
		return err
	}
	defer gate.Close()
	control, err := listen(p.control, 0600)
	if err != nil {
		return err
	}
	defer control.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	checks := &authChecks{result: checkResult{Status: "running", MemosVersion: "26.11.0"}}
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		checks.run(ctx, os.Getenv("TRIM_APPDEST"), p.runtime)
	}()
	defer func() { cancel(); <-finished }()
	controlHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/healthz":
			respond(w, 200, map[string]string{"status": "ready"})
		case r.Method == http.MethodPost && r.URL.Path == "/stop":
			respond(w, 202, map[string]string{"status": "stopping"})
			cancel()
		default:
			respond(w, 404, map[string]string{"error": "E_ROUTE"})
		}
	})
	server := func(handler http.Handler) *http.Server {
		return &http.Server{Handler: handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 4096}
	}
	gateServer, controlServer := server(gatewayHandler(key, checks)), server(controlHandler)
	errChan := make(chan error, 2)
	go func() { errChan <- gateServer.Serve(gate) }()
	go func() { errChan <- controlServer.Serve(control) }()
	select {
	case <-ctx.Done():
	case <-errChan:
		err = errors.New("E_SERVER")
	}
	cancel()
	<-finished
	shutdown, stop := context.WithTimeout(context.Background(), 2*time.Second)
	defer stop()
	_ = gateServer.Shutdown(shutdown)
	_ = controlServer.Shutdown(shutdown)
	return err
}

func lifecycle(action string, p paths) error {
	if action == "serve" {
		return serve(p)
	}
	if action == "status" {
		if controlRequest(p, "GET", "/healthz") {
			return nil
		}
		return errors.New("E_STOPPED")
	}
	if action != "start" && action != "stop" {
		return errors.New("E_ACTION")
	}
	lock, err := privateFile(filepath.Join(p.runtime, "lifecycle.lock"), os.O_CREATE|os.O_RDWR)
	if err != nil {
		return err
	}
	defer lock.Close()
	if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return errors.New("E_BUSY")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	running := controlRequest(p, "GET", "/healthz")
	if action == "stop" {
		if !running {
			return nil
		}
		if !controlRequest(p, "POST", "/stop") {
			return errors.New("E_STOP")
		}
		for range 100 {
			time.Sleep(50 * time.Millisecond)
			if !controlRequest(p, "GET", "/healthz") {
				return nil
			}
		}
		return errors.New("E_STOP_TIMEOUT")
	}
	if running {
		return nil
	}
	executable, err := os.Executable()
	if err != nil {
		return errors.New("E_EXECUTABLE")
	}
	logFile, err := privateFile(filepath.Join(p.runtime, "service.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND)
	if err != nil {
		return err
	}
	defer logFile.Close()
	command := exec.Command(executable, "serve")
	command.Stdout, command.Stderr = logFile, logFile
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := command.Start(); err != nil {
		return errors.New("E_START")
	}
	exited := make(chan error, 1)
	go func() { exited <- command.Wait() }()
	for range 60 {
		select {
		case <-exited:
			return errors.New("E_START_EXIT")
		default:
		}
		if controlRequest(p, "GET", "/healthz") {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = command.Process.Kill()
	<-exited
	return errors.New("E_START_TIMEOUT")
}

func main() {
	syscall.Umask(0077)
	if len(os.Args) != 2 {
		os.Stderr.WriteString("E_ACTION\n")
		os.Exit(1)
	}
	p, err := appPaths()
	if err == nil {
		err = lifecycle(os.Args[1], p)
	}
	if err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		if os.Args[1] == "status" {
			os.Exit(3)
		}
		os.Exit(1)
	}
}
