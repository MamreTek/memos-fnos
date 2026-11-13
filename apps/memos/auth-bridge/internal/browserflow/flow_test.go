package browserflow

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cedarot/fn-apps/apps/memos/auth-bridge/internal/memosclient"
)

func config() Config {
	return Config{PublicOrigin: "https://memos.example", NASOrigin: "https://nas.example:5666", GatewayPrefix: "/app/memos-fnos", ClientID: "memos", IdentityProvider: "identity-providers/1"}
}

func fixture(t *testing.T, reject bool) (*Flow, *atomic.Int32, <-chan map[string]string) {
	t.Helper()
	var calls atomic.Int32
	payloads := make(chan map[string]string, 32)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/memos.api.AuthService/SignIn":
			var payload struct {
				SSO map[string]string `json:"ssoCredentials"`
			}
			if json.NewDecoder(r.Body).Decode(&payload) != nil {
				t.Error("invalid SSO request body")
			}
			payloads <- payload.SSO
			if reject {
				w.WriteHeader(503)
				_, _ = w.Write([]byte(`{"message":"private fixture failure"}`))
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "memos_refresh", Value: "fixture-refresh", Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, Expires: time.Now().Add(time.Hour)})
			_, _ = w.Write([]byte(`{"accessToken":"fixture-access"}`))
		case "/memos.api.AuthService/GetCurrentUser":
			_, _ = w.Write([]byte(`{"user":{"name":"users/1","username":"fixture","role":"USER"}}`))
		default:
			t.Error("unexpected backend route")
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(backend.Close)
	client, err := memosclient.New(backend.URL, config().PublicOrigin)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	f, err := New(config(), client)
	if err != nil {
		t.Fatal(err)
	}
	return f, &calls, payloads
}

func begin(t *testing.T, f *Flow) (Started, url.Values) {
	t.Helper()
	started, err := f.Begin()
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(started.Location)
	if err != nil {
		t.Fatal(err)
	}
	return started, u.Query()
}

func callback(query url.Values) url.Values {
	return url.Values{"state": {query.Get("state")}, "code": {strings.Repeat("c", 43)}}
}

func TestBrowserBoundNativeCompletion(t *testing.T) {
	f, calls, payloads := fixture(t, false)
	started, request := begin(t, f)
	u, _ := url.Parse(started.Location)
	if u.Scheme != "https" || u.Host != "nas.example:5666" || u.Path != "/app/memos-fnos/authorize" || request.Get("redirect_uri") != "https://memos.example/fnos-auth/callback" || request.Get("code_challenge_method") != "S256" || request.Get("client_id") != "memos" || request.Get("response_type") != "code" {
		t.Fatal("configured authorization boundary changed")
	}
	c := started.Cookie
	if c.Name != CookieName || !c.HttpOnly || !c.Secure || c.Path != "/fnos-auth" || c.Domain != "" || c.SameSite != http.SameSiteLaxMode || c.MaxAge != 300 || c.Value == request.Get("state") || strings.Contains(started.Location, c.Value) {
		t.Fatal("browser binding leaked or its cookie attributes are unsafe")
	}
	session, cleared, err := f.Complete(context.Background(), callback(request), []*http.Cookie{c})
	if err != nil || session.User.Name != "users/1" || cleared == nil || cleared.MaxAge != -1 || cleared.Value != "" || cleared.Path != c.Path || calls.Load() != 2 {
		t.Fatal("valid browser-bound completion failed")
	}
	payload := <-payloads
	hash := sha256.Sum256([]byte(payload["codeVerifier"]))
	if payload["identityProvider"] != config().IdentityProvider || payload["redirectUri"] != request.Get("redirect_uri") || base64.RawURLEncoding.EncodeToString(hash[:]) != request.Get("code_challenge") || strings.Contains(started.Location, payload["codeVerifier"]) {
		t.Fatal("server-side PKCE or exact callback binding failed")
	}
	if _, _, err := f.Complete(context.Background(), callback(request), []*http.Cookie{c}); err != Invalid || calls.Load() != 2 {
		t.Fatal("callback replay reached native sign-in")
	}
}

func TestWrongBrowserAndMalformedCallbacks(t *testing.T) {
	f, calls, _ := fixture(t, false)
	a, qa := begin(t, f)
	b, _ := begin(t, f)
	valid := callback(qa)
	for _, input := range []struct {
		query   url.Values
		cookies []*http.Cookie
	}{
		{valid, nil}, {valid, []*http.Cookie{b.Cookie}},
		{valid, []*http.Cookie{a.Cookie, a.Cookie}},
		{valid, []*http.Cookie{{Name: CookieName, Value: ""}, a.Cookie}},
		{valid, []*http.Cookie{{Name: CookieName, Value: "bad"}}},
		{url.Values{"state": {qa.Get("state"), qa.Get("state")}, "code": {valid.Get("code")}}, []*http.Cookie{a.Cookie}},
		{url.Values{"state": {qa.Get("state")}, "code": {valid.Get("code"), valid.Get("code")}}, []*http.Cookie{a.Cookie}},
		{url.Values{"state": {qa.Get("state")}, "code": {valid.Get("code")}, "redirect_uri": {"https://foreign.example"}}, []*http.Cookie{a.Cookie}},
		{url.Values{"state": {"missing"}, "code": {valid.Get("code")}}, []*http.Cookie{a.Cookie}},
		{url.Values{"state": {qa.Get("state")}, "error": {"private-error-text"}}, []*http.Cookie{a.Cookie}},
	} {
		if _, clear, err := f.Complete(context.Background(), input.query, input.cookies); err != Invalid || clear != nil {
			t.Fatal("unbound or malformed callback accepted or changed the browser cookie")
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid callbacks reached Memos")
	}
	// An unrelated caller must not consume the legitimate browser's state.
	if _, _, err := f.Complete(context.Background(), valid, []*http.Cookie{a.Cookie}); err != nil {
		t.Fatal("wrong-browser attempts consumed the legitimate transaction")
	}
}

func TestExpiryAndCapacity(t *testing.T) {
	f, calls, _ := fixture(t, false)
	now := time.Now()
	f.now = func() time.Time { return now }
	a, q := begin(t, f)
	now = now.Add(ttl)
	if _, _, err := f.Complete(context.Background(), callback(q), []*http.Cookie{a.Cookie}); err != Invalid || calls.Load() != 0 {
		t.Fatal("expired state reached native login")
	}
	for range maxPending {
		begin(t, f)
	}
	if _, err := f.Begin(); err != Busy {
		t.Fatal("pending-state capacity was not enforced")
	}
	now = now.Add(ttl)
	if _, err := f.Begin(); err != nil {
		t.Fatal("expired transactions did not release capacity")
	}
}

func TestConcurrentAndFailedCompletionAreOneUse(t *testing.T) {
	for _, reject := range []bool{false, true} {
		f, calls, _ := fixture(t, reject)
		a, q := begin(t, f)
		var workers sync.WaitGroup
		var winners, rejected atomic.Int32
		for range 16 {
			workers.Go(func() {
				_, clear, err := f.Complete(context.Background(), callback(q), []*http.Cookie{a.Cookie})
				if err == Invalid {
					rejected.Add(1)
				} else if clear != nil && ((!reject && err == nil) || (reject && err == memosclient.Unavailable)) {
					winners.Add(1)
				} else {
					t.Error("unexpected completion outcome")
				}
			})
		}
		workers.Wait()
		expectedCalls := int32(2)
		if reject {
			expectedCalls = 1
		}
		if winners.Load() != 1 || rejected.Load() != 15 || calls.Load() != expectedCalls {
			t.Fatal("callback raced multiple native sign-ins")
		}
	}
}

func TestUnsafeConfiguration(t *testing.T) {
	for _, field := range []string{"public", "nas", "prefix", "client", "provider", "mismatched-client", "nil-client"} {
		c := config()
		client, err := memosclient.New("http://backend.invalid", c.PublicOrigin)
		if err != nil {
			t.Fatal(err)
		}
		switch field {
		case "public":
			c.PublicOrigin += "/path"
		case "nas":
			c.NASOrigin += "?target=foreign"
		case "prefix":
			c.GatewayPrefix = "/app/memos-fnos/../other"
		case "client":
			c.ClientID = "client with spaces"
		case "provider":
			c.IdentityProvider = "identity-providers/../other"
		case "mismatched-client":
			c.PublicOrigin = "https://other.example"
		case "nil-client":
			client.Close()
			client = nil
		}
		if _, err := New(c, client); err == nil {
			t.Fatal("unsafe browser configuration accepted")
		}
		if client != nil {
			client.Close()
		}
	}
	client, err := memosclient.New("http://backend.invalid", "http://memos.example:5230")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	c := config()
	c.PublicOrigin = "http://memos.example:5230"
	f, err := New(c, client)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := begin(t, f)
	if a.Cookie.Secure {
		t.Fatal("HTTP deployments received an unusable Secure flow cookie")
	}
}
