package oauthbridge

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const callback = "http://memos.test:5230/fnos-auth/callback"
const secret = "unit-test-only-secret-at-least-32-characters"
const verifier = "0123456789abcdefghijklmnopqrstuvwxyz-._~ABCDEFG"

func newProvider(t *testing.T) *Provider {
	t.Helper()
	p, err := New(Config{ClientID: "memos", ClientSecret: secret, RedirectURIs: []string{callback, "http://memos.test:5230/auth/callback"}})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func authorization() Authorization {
	hash := sha256.Sum256([]byte(verifier))
	return Authorization{ClientID: "memos", RedirectURI: callback, ResponseType: "code", State: "browser-state+&?", CodeChallenge: base64.RawURLEncoding.EncodeToString(hash[:]), CodeChallengeMethod: "S256"}
}

func issue(t *testing.T, p *Provider, subject string) Exchange {
	t.Helper()
	target, err := p.Authorize(authorization(), Principal{Subject: subject, DisplayName: "Fixture member"})
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(target)
	if err != nil || u.Scheme+"://"+u.Host+u.Path != callback || u.Query().Get("state") != authorization().State {
		t.Fatal("redirect or opaque state changed")
	}
	code := u.Query().Get("code")
	if !challengePattern.MatchString(code) || strings.Contains(target, subject) || strings.Contains(target, secret) || strings.Contains(target, verifier) {
		t.Fatal("invalid code or secrets in redirect")
	}
	return Exchange{ClientID: "memos", ClientSecret: secret, Code: code, RedirectURI: callback, CodeVerifier: verifier}
}

func TestCodeExchangeIsolationAndReplay(t *testing.T) {
	p := newProvider(t)
	aRequest, bRequest := issue(t, p, "namespace:member-A"), issue(t, p, "namespace:member-B")
	if aRequest.Code == bRequest.Code {
		t.Fatal("authorization codes collided")
	}
	a, err := p.Exchange(aRequest)
	if err != nil || a.TokenType != "Bearer" || a.ExpiresIn != 60 {
		t.Fatal("valid exchange rejected")
	}
	b, err := p.Exchange(bRequest)
	if err != nil || a.AccessToken == b.AccessToken {
		t.Fatal("tokens collided or exchange failed")
	}
	for token, expected := range map[string]string{a.AccessToken: "namespace:member-A", b.AccessToken: "namespace:member-B"} {
		principal, err := p.UserInfo(token)
		if err != nil || principal.Subject != expected {
			t.Fatal("userinfo returned the wrong principal")
		}
	}
	if _, err := p.Exchange(aRequest); err != InvalidGrant {
		t.Fatal("replayed code accepted")
	}
	if _, err := p.UserInfo(aRequest.Code); err != InvalidToken {
		t.Fatal("authorization code accepted as bearer")
	}
}

func TestExactRedirectsRequiredStateAndS256(t *testing.T) {
	changes := map[string]func(*Authorization){
		"foreign callback":       func(r *Authorization) { r.RedirectURI = "https://attacker.test/callback" },
		"callback prefix":        func(r *Authorization) { r.RedirectURI = callback + "/extra" },
		"callback query":         func(r *Authorization) { r.RedirectURI = callback + "?return=https://attacker.test" },
		"empty state":            func(r *Authorization) { r.State = "" },
		"state header injection": func(r *Authorization) { r.State = "state\r\nLocation: bad" },
		"wrong client":           func(r *Authorization) { r.ClientID = "other-client" },
		"implicit flow":          func(r *Authorization) { r.ResponseType = "token" },
		"plain PKCE":             func(r *Authorization) { r.CodeChallengeMethod = "plain" },
		"missing PKCE":           func(r *Authorization) { r.CodeChallenge = "" },
		"invalid PKCE encoding":  func(r *Authorization) { r.CodeChallenge = strings.Repeat("_", 43) },
	}
	for name, mutate := range changes {
		t.Run(name, func(t *testing.T) {
			p := newProvider(t)
			r := authorization()
			mutate(&r)
			if target, err := p.Authorize(r, Principal{Subject: "verified-subject", DisplayName: "Member"}); err != InvalidRequest || target != "" {
				t.Fatal("invalid authorization accepted")
			}
		})
	}
	for _, principal := range []Principal{{DisplayName: "Member"}, {Subject: "subject"}, {Subject: "subject\nadmin", DisplayName: "Member"}} {
		if _, err := newProvider(t).Authorize(authorization(), principal); err != InvalidRequest {
			t.Fatal("invalid principal accepted")
		}
	}
}

func TestExchangeRejectsBadBindingsAndConsumesAuthenticatedAttempt(t *testing.T) {
	for _, kind := range []string{"bad verifier", "missing verifier", "wrong redirect", "other registered redirect"} {
		t.Run(kind, func(t *testing.T) {
			p := newProvider(t)
			valid := issue(t, p, "member-A")
			bad := valid
			switch kind {
			case "bad verifier":
				bad.CodeVerifier = strings.Repeat("a", 43)
			case "missing verifier":
				bad.CodeVerifier = ""
			case "wrong redirect":
				bad.RedirectURI = callback + "/extra"
			case "other registered redirect":
				bad.RedirectURI = "http://memos.test:5230/auth/callback"
			}
			if _, err := p.Exchange(bad); err != InvalidGrant {
				t.Fatal("invalid binding accepted")
			}
			if _, err := p.Exchange(valid); err != InvalidGrant {
				t.Fatal("failed authenticated attempt did not consume code")
			}
		})
	}
	p := newProvider(t)
	valid := issue(t, p, "member-A")
	for _, field := range []string{"id", "secret"} {
		bad := valid
		if field == "id" {
			bad.ClientID = "other"
		} else {
			bad.ClientSecret = "wrong"
		}
		if _, err := p.Exchange(bad); err != InvalidClient {
			t.Fatal("invalid client accepted")
		}
	}
	if _, err := p.Exchange(valid); err != nil {
		t.Fatal("untrusted client consumed code")
	}
}

func TestExpiryAtBoundaryAndCapacityRecovery(t *testing.T) {
	p := newProvider(t)
	now := time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)
	p.now = func() time.Time { return now }
	request := issue(t, p, "member-A")
	now = now.Add(codeTTL)
	if _, err := p.Exchange(request); err != InvalidGrant {
		t.Fatal("expired code accepted")
	}
	request = issue(t, p, "member-A")
	token, err := p.Exchange(request)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(tokenTTL)
	if _, err := p.UserInfo(token.AccessToken); err != InvalidToken {
		t.Fatal("expired bearer accepted")
	}
	for range maxActive {
		issue(t, p, "member-A")
	}
	if _, err := p.Authorize(authorization(), Principal{Subject: "member-A", DisplayName: "Member"}); err != ServerError {
		t.Fatal("unbounded capacity")
	}
	now = now.Add(codeTTL)
	issue(t, p, "member-A")
}

func TestConcurrentExchangeHasOneWinner(t *testing.T) {
	p := newProvider(t)
	request := issue(t, p, "member-A")
	var winners atomic.Int32
	var group sync.WaitGroup
	for range 24 {
		group.Go(func() {
			_, err := p.Exchange(request)
			if err == nil {
				winners.Add(1)
			} else if err != InvalidGrant {
				t.Error(err)
			}
		})
	}
	group.Wait()
	if winners.Load() != 1 {
		t.Fatal("authorization code had multiple winners")
	}
}

func tokenForm(request Exchange) url.Values {
	return url.Values{"grant_type": {"authorization_code"}, "code": {request.Code}, "redirect_uri": {request.RedirectURI}, "code_verifier": {request.CodeVerifier}}
}

func TestPrivateHTTPExchangeWithBasicAndFormClientAuth(t *testing.T) {
	for _, auth := range []string{"basic", "form"} {
		t.Run(auth, func(t *testing.T) {
			p := newProvider(t)
			exchange := issue(t, p, "member-A")
			form := tokenForm(exchange)
			if auth == "form" {
				form.Set("client_id", "memos")
				form.Set("client_secret", secret)
			}
			r := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if auth == "basic" {
				r.SetBasicAuth("memos", secret)
			}
			w := httptest.NewRecorder()
			p.PrivateHandler().ServeHTTP(w, r)
			var token TokenResponse
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &token) != nil || token.AccessToken == "" || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("HTTP exchange failed or cached")
			}
			r = httptest.NewRequest("GET", "/oauth/userinfo", nil)
			r.Header.Set("Authorization", "Bearer "+token.AccessToken)
			w = httptest.NewRecorder()
			p.PrivateHandler().ServeHTTP(w, r)
			var principal map[string]string
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &principal) != nil || principal["sub"] != "member-A" || len(principal) != 2 {
				t.Fatal("wrong or excessive userinfo")
			}
		})
	}
}

func TestPrivateHTTPRejectsAmbiguityAndReflectsNoSecrets(t *testing.T) {
	for _, kind := range []string{"mixed auth", "duplicate code", "duplicate auth", "query", "JSON", "oversize", "missing client"} {
		t.Run(kind, func(t *testing.T) {
			p := newProvider(t)
			exchange := issue(t, p, "private-member")
			form := tokenForm(exchange)
			path, contentType := "/oauth/token", "application/x-www-form-urlencoded"
			if kind == "mixed auth" {
				form.Set("client_id", "memos")
			}
			if kind == "duplicate code" {
				form.Add("code", "other-secret")
			}
			if kind == "query" {
				path += "?code=other-secret"
			}
			if kind == "JSON" {
				contentType = "application/json"
			}
			if kind == "oversize" {
				form.Set("code", strings.Repeat("x", 9000))
			}
			r := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", contentType)
			if kind != "missing client" {
				r.SetBasicAuth("memos", secret)
			}
			if kind == "duplicate auth" {
				r.Header.Add("Authorization", "Basic invalid")
			}
			r.Header.Set("X-Trim-Userid", "1000")
			r.Header.Set("X-Trim-Isadmin", "true")
			w := httptest.NewRecorder()
			p.PrivateHandler().ServeHTTP(w, r)
			if w.Code < 400 {
				t.Fatal("ambiguous request accepted")
			}
			for _, value := range []string{exchange.Code, verifier, secret, "other-secret", "private-member"} {
				if strings.Contains(w.Body.String(), value) {
					t.Fatal("error reflected sensitive request data")
				}
			}
		})
	}
}

func TestNoGrantRouteAndStrictBearer(t *testing.T) {
	p := newProvider(t)
	for _, path := range []string{"/authorize", "/app/memos-fnos/authorize", "/fnos-auth/login", "/oauth/token/"} {
		r := httptest.NewRequest("GET", path, nil)
		r.Header.Set("X-Trim-Userid", "1000")
		r.Header.Set("X-Trim-Isadmin", "true")
		w := httptest.NewRecorder()
		p.PrivateHandler().ServeHTTP(w, r)
		if w.Code != 404 {
			t.Fatal("unexpected grant route exposed")
		}
	}
	token, err := p.Exchange(issue(t, p, "member-A"))
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"missing", "query", "duplicate", "wrong scheme", "extra space"} {
		path := "/oauth/userinfo"
		if kind == "query" {
			path += "?access_token=" + token.AccessToken
		}
		r := httptest.NewRequest("GET", path, nil)
		if kind != "missing" {
			r.Header.Set("Authorization", "Bearer "+token.AccessToken)
		}
		if kind == "duplicate" {
			r.Header.Add("Authorization", "Bearer "+token.AccessToken)
		}
		if kind == "wrong scheme" {
			r.Header.Set("Authorization", "Basic "+token.AccessToken)
		}
		if kind == "extra space" {
			r.Header.Set("Authorization", "Bearer  "+token.AccessToken)
		}
		w := httptest.NewRecorder()
		p.PrivateHandler().ServeHTTP(w, r)
		if w.Code != 401 || strings.Contains(w.Body.String(), token.AccessToken) {
			t.Fatal("invalid bearer accepted or leaked")
		}
	}
}

func TestRejectUnsafeProviderConfig(t *testing.T) {
	for _, target := range []string{"", "/auth/callback", "https://user:pass@memos.test/cb", "javascript:alert(1)", callback + "#fragment", callback + "?code=bad"} {
		if _, err := New(Config{ClientID: "memos", ClientSecret: secret, RedirectURIs: []string{target}}); err == nil {
			t.Fatal("unsafe provider config accepted")
		}
	}
	if _, err := New(Config{ClientID: "memos", ClientSecret: "short", RedirectURIs: []string{callback}}); err == nil {
		t.Fatal("weak client secret accepted")
	}
}
