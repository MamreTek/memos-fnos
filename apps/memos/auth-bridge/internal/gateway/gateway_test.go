package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cedarot/fn-apps/apps/memos/auth-bridge/internal/oauthbridge"
)

const testSecret = "test-gateway-client-secret-0123456789"
const verifier = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"

func config(t *testing.T, resolver Resolver) Config {
	t.Helper()
	p, err := oauthbridge.New(oauthbridge.Config{ClientID: "memos", ClientSecret: testSecret, RedirectURIs: []string{"http://memos.example.invalid/fnos-auth/callback"}})
	if err != nil {
		t.Fatal(err)
	}
	return Config{Prefix: "/app/memos-fnos", PublicOrigin: "http://memos.example.invalid", ClientID: "memos", Provider: p, Resolve: resolver}
}

func query() url.Values {
	hash := sha256.Sum256([]byte(verifier))
	return url.Values{
		"client_id": {"memos"}, "redirect_uri": {"http://memos.example.invalid/fnos-auth/callback"},
		"response_type": {"code"}, "state": {strings.Repeat("s", 43)},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(hash[:])}, "code_challenge_method": {"S256"},
	}
}

func unixClient(t *testing.T, handler http.Handler) *http.Client {
	t.Helper()
	directory, err := os.MkdirTemp("", "memos-gateway-")
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(directory, "app.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		os.RemoveAll(directory)
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler, ConnContext: ConnContext, ReadHeaderTimeout: time.Second}
	go func() { _ = server.Serve(listener) }()
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	t.Cleanup(func() { transport.CloseIdleConnections(); _ = server.Close(); _ = os.RemoveAll(directory) })
	return &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func request(t *testing.T, client *http.Client, method, path string, mutate func(*http.Request)) *http.Response {
	t.Helper()
	r, err := http.NewRequest(method, "http://ignored-host.invalid"+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("X-Trim-Userid", "1000")
	r.Header.Set("X-Trim-Username", "fixture-admin")
	r.Header.Set("X-Trim-Isadmin", "true")
	r.Header.Set("X-Forwarded-Host", "attacker.invalid")
	if mutate != nil {
		mutate(r)
	}
	response, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { response.Body.Close() })
	return response
}

func TestGatewayAuthorizationOverUnix(t *testing.T) {
	seenIdentity := make(chan Identity, 1)
	cfg := config(t, func(_ context.Context, identity Identity) (oauthbridge.Principal, error) {
		seenIdentity <- identity
		return oauthbridge.Principal{Subject: "verified-fixture-generation-a", DisplayName: "Fixture member"}, nil
	})
	handler, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	client := unixClient(t, handler)
	launch := request(t, client, "GET", cfg.Prefix, nil)
	if launch.StatusCode != 303 || launch.Header.Get("Location") != cfg.PublicOrigin+"/fnos-auth/login" {
		t.Fatal("launch did not use the configured public origin")
	}
	response := request(t, client, "GET", cfg.Prefix+"/authorize?"+query().Encode(), nil)
	if response.StatusCode != 303 || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("trusted authorization failed")
	}
	target, err := url.Parse(response.Header.Get("Location"))
	if err != nil || target.Host != "memos.example.invalid" || target.Query().Get("state") != query().Get("state") {
		t.Fatal("authorization used an unconfigured redirect")
	}
	token, err := cfg.Provider.Exchange(oauthbridge.Exchange{
		ClientID: "memos", ClientSecret: testSecret, RedirectURI: cfg.PublicOrigin + "/fnos-auth/callback",
		Code: target.Query().Get("code"), CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	principal, err := cfg.Provider.UserInfo(token.AccessToken)
	seen := <-seenIdentity
	if err != nil || principal.Subject != "verified-fixture-generation-a" || !seen.IsAdmin || seen.UID != "1000" {
		t.Fatal("gateway bypassed the verified resolver")
	}
	if strings.Contains(response.Header.Get("Location"), "fixture-admin") {
		t.Fatal("redirect disclosed identity")
	}
}

func TestGatewayRejectsPublicTCP(t *testing.T) {
	cfg := config(t, func(context.Context, Identity) (oauthbridge.Principal, error) {
		t.Error("untrusted request reached identity resolver")
		return oauthbridge.Principal{}, nil
	})
	handler, _ := New(cfg)
	server := httptest.NewUnstartedServer(handler)
	server.Config.ConnContext = ConnContext
	server.Start()
	defer server.Close()
	r, _ := http.NewRequest("GET", server.URL+cfg.Prefix+"/authorize?"+query().Encode(), nil)
	r.Header.Set("X-Trim-Userid", "1000")
	r.Header.Set("X-Trim-Username", "fixture-admin")
	r.Header.Set("X-Trim-Isadmin", "true")
	response, err := server.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatal("TCP headers created trusted identity")
	}
}

func TestGatewayValidationAndLifecycleFailure(t *testing.T) {
	var calls atomic.Int64
	cfg := config(t, func(context.Context, Identity) (oauthbridge.Principal, error) {
		calls.Add(1)
		return oauthbridge.Principal{}, errors.New("private identity diagnostics must not escape")
	})
	handler, _ := New(cfg)
	client := unixClient(t, handler)
	base := cfg.Prefix + "/authorize?" + query().Encode()
	tests := []struct {
		name, method, path string
		mutate             func(*http.Request)
		status             int
	}{
		{"missing identity", "GET", base, func(r *http.Request) { r.Header.Del("X-Trim-Userid") }, 403},
		{"duplicate identity", "GET", base, func(r *http.Request) { r.Header.Add("X-Trim-Userid", "1001") }, 403},
		{"overflow UID", "GET", base, func(r *http.Request) { r.Header.Set("X-Trim-Userid", "4294967296") }, 403},
		{"invalid admin", "GET", base, func(r *http.Request) { r.Header.Set("X-Trim-Isadmin", "1") }, 403},
		{"duplicate state", "GET", base + "&state=" + strings.Repeat("b", 43), nil, 400},
		{"unknown parameter", "GET", base + "&return_to=https://attacker.invalid", nil, 400},
		{"wrong method", "POST", base, nil, 405},
		{"private endpoint", "GET", "/oauth/userinfo", nil, 404},
		{"encoded route", "GET", "/app/memos%2Dfnos/authorize?" + query().Encode(), nil, 404},
		{"launch query", "GET", cfg.Prefix + "?next=/", nil, 400},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := request(t, client, test.method, test.path, test.mutate)
			if response.StatusCode != test.status {
				t.Fatalf("status %d, expected %d", response.StatusCode, test.status)
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatal("invalid request reached resolver")
	}
	response := request(t, client, "GET", base, nil)
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != 503 || calls.Load() != 1 || string(body) != "E_IDENTITY_LIFECYCLE\n" || response.Header.Get("Location") != "" {
		t.Fatal("unresolved lifecycle was not closed or error leaked")
	}
}

func TestGatewayRequiresExplicitConfiguration(t *testing.T) {
	resolver := func(context.Context, Identity) (oauthbridge.Principal, error) { return oauthbridge.Principal{}, nil }
	for _, change := range []func(*Config){
		func(c *Config) { c.Resolve = nil },
		func(c *Config) { c.Provider = nil },
		func(c *Config) { c.PublicOrigin = "https://memos.example.invalid/other" },
		func(c *Config) { c.Prefix = "/app/../../other" },
		func(c *Config) { c.ClientID = "" },
	} {
		cfg := config(t, resolver)
		change(&cfg)
		if _, err := New(cfg); err == nil {
			t.Fatal("invalid gateway configuration accepted")
		}
	}
}
