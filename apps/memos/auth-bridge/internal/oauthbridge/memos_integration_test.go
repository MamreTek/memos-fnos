package oauthbridge

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cedarot/fn-apps/apps/memos/auth-bridge/internal/browserflow"
	"github.com/cedarot/fn-apps/apps/memos/auth-bridge/internal/memosclient"
)

// This is a real Memos contract test for the OAuth core. Principals are explicit
// test fixtures, not real NAS identities, and no gateway/browser launch is tested.
func TestRealMemosIntegration(t *testing.T) {
	binary := os.Getenv("MEMOS_BINARY")
	if binary == "" {
		t.Skip("separate auth-integration target requires verified MEMOS_BINARY")
	}
	if os.Getuid() == 0 {
		t.Fatal("run the temporary Memos instance as an ordinary user")
	}
	file, err := os.Open(binary)
	if err != nil {
		t.Fatal("cannot open MEMOS_BINARY")
	}
	hash := sha256.New()
	_, err = io.Copy(hash, file)
	file.Close()
	expected := map[string]string{
		"amd64": "bd62d659f01efca3fdab21df3fa301e9dcd8c426203ffcdfa7fe7c686edab405",
		"arm64": "06e8b9cda66209abb5dcdd5c9c512e172fc6dce088e19af8c0ddb94d1ffca9b6",
	}[runtime.GOARCH]
	if err != nil || expected == "" || hex.EncodeToString(hash.Sum(nil)) != expected {
		t.Fatal("use the verified official Memos 26.11.0 Linux release for this architecture")
	}
	version, err := exec.Command(binary, "--version").Output()
	if err != nil || strings.TrimSpace(string(version)) != "26.11.0" {
		t.Fatal("unexpected Memos version")
	}
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reservation.Addr().(*net.TCPAddr).Port
	reservation.Close()
	base := "http://127.0.0.1:" + strconv.Itoa(port)
	directory := t.TempDir()
	log, err := os.OpenFile(filepath.Join(directory, "server.log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })
	command := exec.Command(binary, "--addr", "127.0.0.1", "--port", strconv.Itoa(port), "--data", directory)
	for _, variable := range os.Environ() {
		if !strings.HasPrefix(variable, "MEMOS_") {
			command.Env = append(command.Env, variable)
		}
	}
	command.Stdout, command.Stderr = log, log
	if err := command.Start(); err != nil {
		t.Fatal("cannot start isolated Memos process")
	}
	exited := make(chan error, 1)
	go func() { exited <- command.Wait() }()
	t.Cleanup(func() {
		_ = command.Process.Signal(syscall.SIGTERM)
		select {
		case <-exited:
		case <-time.After(5 * time.Second):
			_ = command.Process.Kill()
			<-exited
		}
	})
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	ready := false
	for range 100 {
		response, err := client.Get(base + "/healthz")
		if err == nil {
			response.Body.Close()
			if response.StatusCode == 200 {
				ready = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		t.Fatal("isolated Memos did not become ready")
	}

	api := func(path string, body any, token, cookie string, expected int) (map[string]any, []*http.Cookie) {
		t.Helper()
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		method := "POST"
		if body == nil {
			method = "GET"
		}
		request, err := http.NewRequest(method, base+path, bytes.NewReader(data))
		if err != nil {
			t.Fatal("invalid fixture request")
		}
		request.Header.Set("Content-Type", "application/json")
		if strings.HasPrefix(path, "/memos.api.") {
			request.Header.Set("Connect-Protocol-Version", "1")
		}
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		if cookie != "" {
			request.Header.Set("Cookie", cookie)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("fixture API request failed")
		}
		defer response.Body.Close()
		if response.StatusCode != expected {
			t.Fatalf("%s: HTTP %d, expected %d", path, response.StatusCode, expected)
		}
		var result map[string]any
		if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
			t.Fatal("invalid fixture API response")
		}
		return result, response.Cookies()
	}
	password, err := randomToken()
	if err != nil {
		t.Fatal(err)
	}
	api("/api/users", map[string]string{"username": "core-test-admin", "password": password, "role": "ADMIN"}, "", "", 200)
	login, _ := api("/memos.api.AuthService/SignIn", map[string]any{"passwordCredentials": map[string]string{"username": "core-test-admin", "password": password}}, "", "", 200)
	adminToken := login["accessToken"].(string)
	redirect := base + "/fnos-auth/callback"
	secureOrigin := "https://memos.example.invalid"
	provider, err := New(Config{ClientID: "memos", ClientSecret: secret, RedirectURIs: []string{redirect, secureOrigin + "/fnos-auth/callback"}})
	if err != nil {
		t.Fatal(err)
	}
	private := httptest.NewServer(provider.PrivateHandler())
	t.Cleanup(private.Close)
	identity, _ := api("/api/identity-providers", map[string]any{
		"type": "OAUTH2", "title": "Temporary real-core contract fixture",
		"config": map[string]any{"oauth2Config": map[string]any{
			"clientId": "memos", "clientSecret": secret, "authUrl": private.URL + "/not-exposed-authorize",
			"tokenUrl": private.URL + "/oauth/token", "userInfoUrl": private.URL + "/oauth/userinfo",
			"scopes": []string{"identity"}, "fieldMapping": map[string]string{"identifier": "sub", "displayName": "display_name"},
		}},
	}, adminToken, "", 200)

	// Exercise the actual browser-transaction module and native Connect client.
	// Only the gateway principal is a fixture. No NAS request, browser DOM,
	// public proxy or browser-cookie publication occurs in this contract test.
	for _, origin := range []string{base, secureOrigin} {
		native, err := memosclient.New(base, origin)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(native.Close)
		flow, err := browserflow.New(browserflow.Config{
			PublicOrigin: origin, NASOrigin: "https://nas.example.invalid", GatewayPrefix: "/app/memos-fnos",
			ClientID: "memos", IdentityProvider: identity["name"].(string),
		}, native)
		if err != nil {
			t.Fatal(err)
		}
		started, err := flow.Begin()
		if err != nil {
			t.Fatal(err)
		}
		authorizationURL, _ := url.Parse(started.Location)
		q := authorizationURL.Query()
		callbackURL, err := provider.Authorize(Authorization{
			ClientID: q.Get("client_id"), RedirectURI: q.Get("redirect_uri"), ResponseType: q.Get("response_type"),
			State: q.Get("state"), CodeChallenge: q.Get("code_challenge"), CodeChallengeMethod: q.Get("code_challenge_method"),
		}, Principal{Subject: "temporary-flow-" + authorizationURL.Query().Get("redirect_uri"), DisplayName: "Temporary flow fixture"})
		if err != nil {
			t.Fatal(err)
		}
		callback, _ := url.Parse(callbackURL)
		session, clear, err := flow.Complete(context.Background(), callback.Query(), []*http.Cookie{started.Cookie})
		if err != nil {
			t.Fatalf("real native browser-transaction exchange failed: %v", err)
		}
		if session.User.Role != "USER" || clear == nil || clear.MaxAge != -1 || session.RefreshCookie.Secure != strings.HasPrefix(origin, "https:") || started.Cookie.Secure != session.RefreshCookie.Secure {
			t.Fatal("native user, consumed flow cookie or configured Secure cookie contract failed")
		}
		if _, _, err := flow.Complete(context.Background(), callback.Query(), []*http.Cookie{started.Cookie}); err != browserflow.Invalid {
			t.Fatal("real native browser-transaction replay accepted")
		}
		refreshed, err := native.Refresh(context.Background(), session.RefreshCookie.Value)
		if err != nil || refreshed.User.Name != session.User.Name || refreshed.RefreshCookie.Value == session.RefreshCookie.Value {
			t.Fatal("native client refresh changed account or failed to rotate cookie")
		}
		if err := native.SignOut(context.Background(), refreshed.AccessToken, refreshed.RefreshCookie.Value); err != nil {
			t.Fatal("native client logout failed")
		}
		if _, err := native.Refresh(context.Background(), refreshed.RefreshCookie.Value); err != memosclient.Rejected {
			t.Fatal("native client accepted refresh after logout")
		}
	}

	signIn := func(subject string) (map[string]any, *http.Cookie) {
		t.Helper()
		request := authorization()
		request.RedirectURI = redirect
		target, err := provider.Authorize(request, Principal{Subject: subject, DisplayName: "Temporary fixture member"})
		if err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(target)
		code := u.Query().Get("code")
		result, cookies := api("/memos.api.AuthService/SignIn", map[string]any{"ssoCredentials": map[string]string{
			"identityProvider": identity["name"].(string), "code": code, "redirectUri": redirect, "codeVerifier": verifier,
		}}, "", "", 200)
		if _, err := provider.Exchange(Exchange{ClientID: "memos", ClientSecret: secret, Code: code, RedirectURI: redirect, CodeVerifier: verifier}); err != InvalidGrant {
			t.Fatal("Memos did not consume the real core authorization code")
		}
		for _, cookie := range cookies {
			if cookie.Name == "memos_refresh" {
				if !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" {
					t.Fatal("unexpected native cookie contract")
				}
				return result, cookie
			}
		}
		t.Fatal("native Connect SignIn did not return refresh cookie")
		return nil, nil
	}
	a, cookie := signIn("fixture-install:member-A")
	b, _ := signIn("fixture-install:member-B")
	aUser, bUser := a["user"].(map[string]any), b["user"].(map[string]any)
	if aUser["name"] == bUser["name"] || aUser["role"] != "USER" || bUser["role"] != "USER" {
		t.Fatal("real core mappings or ordinary roles are wrong")
	}
	again, _ := signIn("fixture-install:member-A")
	if again["user"].(map[string]any)["name"] != aUser["name"] {
		t.Fatal("linked identity did not remain stable")
	}
	memo, _ := api("/api/memos", map[string]string{"content": "isolated real OAuth core note", "visibility": "PRIVATE"}, a["accessToken"].(string), "", 200)
	api("/api/memos", map[string]string{"content": "other member excluded from recovery archive", "visibility": "PRIVATE"}, b["accessToken"].(string), "", 200)
	api("/api/"+memo["name"].(string), nil, b["accessToken"].(string), "", 403)
	refreshed, cookies := api("/memos.api.AuthService/RefreshToken", map[string]any{}, "", cookie.Name+"="+cookie.Value, 200)
	me, _ := api("/api/auth/me", nil, refreshed["accessToken"].(string), "", 200)
	if me["user"].(map[string]any)["name"] != aUser["name"] {
		t.Fatal("native refresh session belongs to wrong user")
	}
	var newCookie *http.Cookie
	for _, item := range cookies {
		if item.Name == "memos_refresh" {
			newCookie = item
		}
	}
	if newCookie == nil {
		t.Fatal("native refresh cookie was not rotated")
	}
	api("/memos.api.AuthService/SignOut", map[string]any{}, refreshed["accessToken"].(string), newCookie.Name+"="+newCookie.Value, 200)
	api("/memos.api.AuthService/RefreshToken", map[string]any{}, "", newCookie.Name+"="+newCookie.Value, 401)
	// Provider setup must not globally disable the existing password entry point.
	// Recovery uses a fresh native administrator login, not the NAS admin flag.
	adminLogin, _ := api("/memos.api.AuthService/SignIn", map[string]any{"passwordCredentials": map[string]string{"username": "core-test-admin", "password": password}}, "", "", 200)
	recoveryToken := adminLogin["accessToken"].(string)
	// Upstream instance administrators may read a known private memo by name;
	// ordinary members cannot. Keep that native policy instead of inventing one.
	api("/api/"+memo["name"].(string), nil, recoveryToken, "", 200)
	// Archive only this disposable Memos fixture. This verifies upstream data
	// retention/recovery, not fnOS deletion detection or NAS session revocation.
	api("/memos.api.UserService/UpdateUser", map[string]any{
		"user":       map[string]any{"name": aUser["name"], "state": "ARCHIVED"},
		"updateMask": "state",
	}, recoveryToken, "", 200)
	api("/api/"+memo["name"].(string), nil, recoveryToken, "", 200)
	api("/api/"+memo["name"].(string), nil, b["accessToken"].(string), "", 403)
	api("/api/auth/me", nil, a["accessToken"].(string), "", 401)
	exportPath := "/file/users/" + url.PathEscape(aUser["username"].(string)) + "/export"
	export := func(token string, expected int) []byte {
		t.Helper()
		request, err := http.NewRequest(http.MethodGet, base+exportPath, nil)
		if err != nil {
			t.Fatal("invalid fixture export request")
		}
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("fixture export request failed")
		}
		defer response.Body.Close()
		if response.StatusCode != expected {
			t.Fatalf("native member export: HTTP %d, expected %d", response.StatusCode, expected)
		}
		const maxArchive = 2 << 20
		body, err := io.ReadAll(io.LimitReader(response.Body, maxArchive+1))
		if err != nil || len(body) > maxArchive {
			t.Fatal("unexpected fixture export size or read failure")
		}
		if expected == http.StatusOK && response.Header.Get("Content-Type") != "application/vnd.usememos.export+zip" {
			t.Fatal("unexpected native export media type")
		}
		return body
	}
	export("", http.StatusUnauthorized)
	export(b["accessToken"].(string), http.StatusForbidden)
	archiveBytes := export(recoveryToken, http.StatusOK)
	archive, err := zip.NewReader(bytes.NewReader(archiveBytes), int64(len(archiveBytes)))
	if err != nil {
		t.Fatal("native member export is not a ZIP archive")
	}
	foundNote := false
	for _, entry := range archive.File {
		reader, err := entry.Open()
		if err != nil {
			t.Fatal("cannot open native export entry")
		}
		content, readErr := io.ReadAll(io.LimitReader(reader, (2<<20)+1))
		reader.Close()
		if readErr != nil || len(content) > 2<<20 {
			t.Fatal("unexpected native export entry")
		}
		if bytes.Contains(content, []byte("isolated real OAuth core note")) {
			foundNote = true
		}
		if bytes.Contains(content, []byte("other member excluded from recovery archive")) {
			t.Fatal("native member export included another member's private note")
		}
	}
	if !foundNote {
		t.Fatal("archived member's private note missing from native administrator export")
	}
	t.Log("PASS: real browser transaction + Go OAuth core + native Connect client -> Memos 26.11.0; HTTP/HTTPS-context cookies, replay rejection, distinct ordinary users, private notes, native refresh/signout, password login and administrator recovery; no fnOS deletion or browser/proxy handoff tested")
}
