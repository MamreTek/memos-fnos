package memosclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const public = "https://memos.example"

func fixtureCookie() *http.Cookie {
	return &http.Cookie{Name: "memos_refresh", Value: "fixture-refresh-secret", Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, Expires: time.Now().Add(time.Hour)}
}

func newFixture(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := New(server.URL, public)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}

func fixtureSignIn(t *testing.T, client *Client) (Session, error) {
	t.Helper()
	return client.SSOSignIn(context.Background(), "identity-providers/1", strings.Repeat("c", 43), public+"/fnos-auth/callback", strings.Repeat("v", 43))
}

func TestNativeConnectContract(t *testing.T) {
	var calls atomic.Int32
	client := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "POST" || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Connect-Protocol-Version") != "1" || r.Header.Get("X-Forwarded-Proto") != "https" || r.URL.RawQuery != "" || r.Header.Get("X-Trim-Userid") != "" {
			t.Error("unexpected native Connect request boundary")
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case service + "SignIn":
			if r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
				t.Error("credentials crossed into SSO sign-in")
			}
			var body struct {
				SSO map[string]string `json:"ssoCredentials"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil || body.SSO["identityProvider"] != "identity-providers/1" || body.SSO["redirectUri"] != public+"/fnos-auth/callback" || body.SSO["codeVerifier"] != strings.Repeat("v", 43) {
				t.Error("native SSO payload differs from the contract")
			}
			http.SetCookie(w, fixtureCookie())
			http.SetCookie(w, &http.Cookie{Name: "unrelated", Value: "not-forwarded"})
			_, _ = w.Write([]byte(`{"accessToken":"fixture-access-secret"}`))
		case service + "GetCurrentUser":
			if r.Header.Get("Authorization") != "Bearer fixture-access-secret" || r.Header.Get("Cookie") != "" {
				t.Error("current user must be verified by native bearer authentication")
			}
			_, _ = w.Write([]byte(`{"user":{"name":"users/1","username":"fixture","role":"USER"}}`))
		case service + "RefreshToken":
			cookie, err := r.Cookie("memos_refresh")
			if err != nil || cookie.Value != "fixture-refresh-secret" || r.Header.Get("Authorization") != "" || len(r.Cookies()) != 1 {
				t.Error("refresh must carry only its native cookie")
			}
			http.SetCookie(w, fixtureCookie())
			_, _ = w.Write([]byte(`{"accessToken":"fixture-access-secret"}`))
		case service + "SignOut":
			cookie, err := r.Cookie("memos_refresh")
			if err != nil || cookie.Value != "fixture-refresh-secret" || r.Header.Get("Authorization") != "Bearer fixture-access-secret" {
				t.Error("logout did not receive its own native session credentials")
			}
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Error("unexpected native endpoint")
			w.WriteHeader(404)
		}
	})
	session, err := fixtureSignIn(t, client)
	if err != nil || session.User.Name != "users/1" || session.RefreshCookie.Name != "memos_refresh" {
		t.Fatal("native sign-in failed")
	}
	if data, err := json.Marshal(session); err != nil || string(data) != "{}" || strings.Contains(fmt.Sprint(session), "secret") {
		t.Fatal("session credentials accidentally serialized")
	}
	if _, err := client.Refresh(context.Background(), session.RefreshCookie.Value); err != nil {
		t.Fatal("native refresh failed")
	}
	if err := client.SignOut(context.Background(), session.AccessToken, session.RefreshCookie.Value); err != nil || calls.Load() != 5 {
		t.Fatal("native logout or call boundary failed")
	}
}

func TestRejectMalformedNativeSession(t *testing.T) {
	for _, name := range []string{"missing", "duplicate", "domain", "path", "not-http-only", "not-secure", "same-site", "expired", "deleted", "bad-value", "bad-user", "no-token"} {
		t.Run(name, func(t *testing.T) {
			client := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == service+"GetCurrentUser" {
					_, _ = w.Write([]byte(`{"user":{"name":"users/1","username":"fixture","role":"UNRECOGNIZED"}}`))
					return
				}
				cookie := fixtureCookie()
				switch name {
				case "domain":
					cookie.Domain = "memos.example"
				case "path":
					cookie.Path = "/other"
				case "not-http-only":
					cookie.HttpOnly = false
				case "not-secure":
					cookie.Secure = false
				case "same-site":
					cookie.SameSite = http.SameSiteNoneMode
				case "expired":
					cookie.Expires = time.Now().Add(-time.Hour)
				case "deleted":
					cookie.MaxAge = -1
				case "bad-value":
					cookie.Value = "value with spaces"
				}
				if name != "missing" {
					http.SetCookie(w, cookie)
				}
				if name == "duplicate" {
					http.SetCookie(w, cookie)
				}
				if name == "no-token" {
					_, _ = w.Write([]byte(`{}`))
				} else {
					_, _ = w.Write([]byte(`{"accessToken":"fixture-access-secret"}`))
				}
			})
			if _, err := fixtureSignIn(t, client); err != Invalid {
				t.Fatal("malformed native session was not rejected")
			}
		})
	}
}

func TestRedactedUpstreamFailures(t *testing.T) {
	for _, name := range []string{"401", "403", "500", "redirect", "malformed", "oversize", "wrong-media", "encoded"} {
		t.Run(name, func(t *testing.T) {
			var followed atomic.Bool
			client := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/leak" {
					followed.Store(true)
				}
				switch name {
				case "401":
					w.WriteHeader(401)
				case "403":
					w.WriteHeader(403)
				case "500":
					w.WriteHeader(500)
				case "redirect":
					w.Header().Set("Location", "/leak")
					w.WriteHeader(302)
				case "oversize":
					_, _ = w.Write([]byte(strings.Repeat("x", maxResponse+1)))
				case "wrong-media":
					w.Header().Set("Content-Type", "text/html")
				case "encoded":
					w.Header().Set("Content-Encoding", "gzip")
				}
				_, _ = w.Write([]byte("private upstream failure: fixture-access-secret"))
			})
			_, err := fixtureSignIn(t, client)
			if err == nil || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "upstream failure") || followed.Load() {
				t.Fatal("upstream error exposed credentials or followed a redirect")
			}
			if (name == "401" || name == "403") && err != Rejected {
				t.Fatal("native rejection classification lost")
			}
		})
	}
}

func TestInvalidCredentialsStayLocal(t *testing.T) {
	client := newFixture(t, func(w http.ResponseWriter, r *http.Request) { t.Error("invalid local input reached upstream") })
	for _, input := range [][4]string{
		{"identity-providers/1", strings.Repeat("c", 43), "https://foreign.example/fnos-auth/callback", strings.Repeat("v", 43)},
		{"1", strings.Repeat("c", 43), client.CallbackURI(), strings.Repeat("v", 43)},
		{"identity-providers/1", "bad-code", client.CallbackURI(), strings.Repeat("v", 43)},
		{"identity-providers/1", strings.Repeat("c", 43), client.CallbackURI(), "bad-verifier"},
	} {
		if _, err := client.SSOSignIn(context.Background(), input[0], input[1], input[2], input[3]); err != Invalid {
			t.Fatal("unsafe SSO input accepted")
		}
	}
	if _, err := client.CurrentUser(context.Background(), "token\r\nheader"); err != Invalid {
		t.Fatal("unsafe bearer accepted")
	}
	if _, err := client.Refresh(context.Background(), "cookie;other=value"); err != Invalid {
		t.Fatal("unsafe refresh cookie accepted")
	}
	if err := client.SignOut(context.Background(), "", ""); err != Invalid {
		t.Fatal("empty logout accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.CurrentUser(ctx, "valid-looking-fixture-token"); err != Unavailable {
		t.Fatal("canceled request did not stop")
	}
	for _, origins := range [][2]string{{"http://backend.invalid/extra", public}, {"http://backend.invalid", public + "?override=1"}} {
		if c, err := New(origins[0], origins[1]); err == nil {
			c.Close()
			t.Fatal("unsafe native client origin accepted")
		}
	}
}
